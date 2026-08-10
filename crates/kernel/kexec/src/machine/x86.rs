// x86_64 `machine_kexec_prepare` + `relocate_kernel`.
//
// ENTRY CONTRACT the trampoline is called under (SysV, five arguments):
//   rdi = image->head, the first relocation entry
//   rsi = physical address of the control page
//   rdx = image->start, the new kernel's entry point
//   rcx = physical address of the identity page-table root
//   r8  = physical address of this code's own `identity` label
// It is CALLED at the control page's kernel (direct-map) address and never
// returns. The fifth argument is a label difference an assembler could
// compute; it is computed in Rust instead — same value, arrived at where a
// test can see it.
//
// WHY IT RUNS FROM THE CONTROL PAGE. See `machine.rs`: the pages it copies
// include the ones the running kernel occupies. It first switches to the
// identity tables — which is why a transition mapping for the control page's
// kernel address exists, so the instruction after `mov cr3` is still mapped —
// then jumps to its OWN identity address and never touches a kernel address
// again.
//
// ENTRY STATE OF THE NEW KERNEL, which is the part a wrong guess makes
// unbootable: interrupts masked, IDT and GDT limits zeroed, flags cleared
// (which is also what guarantees DF=0 for the copy), CR0 = PG|PE with
// AM/WP/TS/EM clear, CR4 = PAE plus LA57 if it was on, CR3 = the identity
// root, every general register zero, RSP at the top of the control page, and a
// zero word below the entry address on the stack. That last one is not
// decoration: it is how a purgatory tells a plain kexec from a jump-back one.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

extern crate alloc;
use alloc::vec::Vec;

use hal::pt_walker::WalkErr;
use hal_x86_64::vmm::PtWalkerX86;

use crate::frames::{clear_page, Frames};
use crate::image::KImage;
use crate::machine::{idmap, plan, quiesce};
use crate::uapi::PAGE_SIZE;
use crate::validate::{Error, KResult};

core::arch::global_asm!(
    ".section .text.kexec_relocate,\"ax\",@progbits",
    ".globl oxide_kexec_relocate_start",
    ".type  oxide_kexec_relocate_start, @function",
    "oxide_kexec_relocate_start:",
    // rdi = head, rsi = pa_control, rdx = start, rcx = pa_pgt, r8 = pa_identity.
    "    cli",
    // Force every data segment register to the kernel data selector while the
    // table that describes it is still live. Loading a selector is the ONLY
    // thing that refreshes the hidden descriptor a segment register carries,
    // so doing it here means those descriptors hold known-good flat ring-0
    // segments across the window in which no descriptor table exists at all.
    // Without it this code is correct only because it happens never to touch a
    // segment register in that window — a property nothing would check.
    //
    // Nothing after this instruction may reference per-CPU state: loading GS
    // with a selector replaces its base with the descriptor's, which is zero.
    "    mov  eax, {kernel_ds}",
    "    mov  ds, eax",
    "    mov  es, eax",
    "    mov  ss, eax",
    "    mov  fs, eax",
    "    mov  gs, eax",
    // Invalidate the IDT and the GDT with a zero-limit descriptor built on the
    // kernel stack — the last kernel-stack access this code makes. Both point
    // into an address space that is about to stop existing; leaving them live
    // means an NMI would dispatch through a table the relocation has already
    // overwritten. The trailing popfq zeroes the flags, which is where DF=0
    // for the copy below comes from.
    "    push 0",
    "    push 0",
    "    lidt [rsp]",
    "    lgdt [rsp]",
    "    add  rsp, 8",
    "    popfq",
    // Switch to the identity tables. Legal here only because the transition
    // mapping keeps this very page executable at this very address.
    "    mov  r9, rcx",
    "    mov  cr3, r9",
    // Drop global pages immediately: a global TLB entry from the old tables
    // survives the CR3 write and would translate an address the new tables do
    // not describe.
    "    mov  rax, cr4",
    "    and  rax, {cr4_no_pge}",
    "    mov  cr4, rax",
    "    mov  r13, rax",
    // Stack at the top of the control page, addressed physically, and away to
    // this code's own identity address.
    "    lea  rsp, [rsi + {page_size}]",
    "    jmp  r8",

    ".globl oxide_kexec_identity",
    "oxide_kexec_identity:",
    // rdi = head, rdx = start, r9 = pgt, r13 = cr4.
    // Install the flat descriptor table that travelled here inside this blob.
    // The entry sequence above invalidated the running kernel's, and leaving
    // nothing behind means the first segment load anything does from here on —
    // in this code, in a purgatory, or in the image itself before it builds
    // its own table — faults with no table to describe a handler. Legal only
    // at this point: the table's address is the one the identity map
    // describes, which is the map now in force.
    "    lea  rax, [rip + oxide_kexec_gdt]",
    "    sub  rsp, 16",
    "    mov  word ptr [rsp + 6], {gdt_limit}",
    "    mov  [rsp + 8], rax",
    "    lgdt [rsp + 6]",
    "    add  rsp, 16",
    "    push 0",                        // jump-back entry the purgatory reads
    "    push rdx",                      // new kernel entry, consumed by the final ret
    // CR4 first, so CET is off before CR0.WP is cleared.
    "    and  r13d, {cr4_keep}",
    "    mov  cr4, r13",
    "    mov  rax, cr0",
    "    and  rax, {cr0_clear}",
    "    or   eax, {cr0_set}",
    "    mov  cr0, rax",
    "    mov  cr3, r9",
    "    call oxide_kexec_swap_pages",
    // Reload CR3 as a serialising instruction: the copy just rewrote memory
    // this code may have prefetched from.
    "    mov  rax, cr3",
    "    mov  cr3, rax",
    "    xor  eax, eax",
    "    xor  ebx, ebx",
    "    xor  ecx, ecx",
    "    xor  edx, edx",
    "    xor  esi, esi",
    "    xor  edi, edi",
    "    xor  ebp, ebp",
    "    xor  r8d, r8d",
    "    xor  r9d, r9d",
    "    xor  r10d, r10d",
    "    xor  r11d, r11d",
    "    xor  r12d, r12d",
    "    xor  r13d, r13d",
    "    xor  r14d, r14d",
    "    xor  r15d, r15d",
    "    ret",

    // rdi = head. Walks the chain and copies each source page onto the running
    // destination. The flag test order is the contract `machine::walk` pins.
    "oxide_kexec_swap_pages:",
    "    mov  rcx, rdi",
    "    xor  edi, edi",
    "    xor  esi, esi",
    "    xor  ebx, ebx",
    "    jmp  3f",
    "2:",                                // read the next entry
    "    mov  rcx, [rbx]",
    "    add  rbx, 8",
    "3:",
    "    test cl, {ind_destination}",
    "    jz   4f",
    "    mov  rdi, rcx",
    "    and  rdi, {page_mask}",
    "    jmp  2b",
    "4:",
    "    test cl, {ind_indirection}",
    "    jz   5f",
    "    mov  rbx, rcx",
    "    and  rbx, {page_mask}",
    "    jmp  2b",
    "5:",
    "    test cl, {ind_done}",
    "    jnz  7f",
    "    test cl, {ind_source}",
    "    jz   2b",
    "    mov  rsi, rcx",
    "    and  rsi, {page_mask}",
    "    mov  rax, rsi",
    "    mov  ecx, {qwords_per_page}",
    "    rep  movsq",
    "    lea  rsi, [rax + {page_size}]",
    "    jmp  2b",
    "7:",
    "    ret",

    // The table itself, travelling inside the blob so it lands in the control
    // page alongside the code that installs it — the one page guaranteed to
    // sit outside every destination the relocation writes.
    ".balign 16",
    ".globl oxide_kexec_gdt",
    "oxide_kexec_gdt:",
    "    .quad {gdt_null}",
    "    .quad {gdt_code32}",             // selector 0x08
    "    .quad {gdt_code64}",             // selector 0x10
    "    .quad {gdt_data}",               // selector 0x18
    ".size oxide_kexec_relocate_start, . - oxide_kexec_relocate_start",
    cr4_no_pge = const !(plan::CR4_PGE as i64),
    cr4_keep = const plan::CR4_KEEP as u32,
    cr0_clear = const !(plan::CR0_CLEAR as i64),
    cr0_set = const plan::CR0_SET as u32,
    page_size = const PAGE_SIZE as u32,
    page_mask = const crate::uapi::PAGE_MASK as i64,
    ind_destination = const crate::uapi::IND_DESTINATION as u32,
    ind_indirection = const crate::uapi::IND_INDIRECTION as u32,
    ind_done = const crate::uapi::IND_DONE as u32,
    ind_source = const crate::uapi::IND_SOURCE as u32,
    qwords_per_page = const (PAGE_SIZE / 8) as u32,
    kernel_ds = const hal_x86_64::KERNEL_DS as u32,
    gdt_limit = const plan::GDT_LIMIT as u16,
    gdt_null = const plan::GDT_ENTRY_NULL as i64,
    gdt_code32 = const plan::GDT_ENTRY_CODE32 as i64,
    gdt_code64 = const plan::GDT_ENTRY_CODE64 as i64,
    gdt_data = const plan::GDT_ENTRY_DATA as i64,
);

// The blob's bounds come from the LINKER, for two reasons: nothing else can
// be placed between them, and the "does it fit in a control page" check is a
// link failure rather than a runtime one. The linker script also asserts the
// section STARTS with the entry point, which is what lets the copy go to
// offset 0 of the page.
extern "C" {
    static __relocate_kernel_start: u8;
    static __relocate_kernel_end: u8;
    static oxide_kexec_identity: u8;
}

/// `relocate_kernel`'s C signature. Declared `-> !` because the only way it
/// returns is by not having replaced the kernel, which cannot happen: the
/// final `ret` lands in the new image.
type RelocateFn =
    unsafe extern "C" fn(head: u64, pa_control: u64, start: u64, pa_pgt: u64, pa_ident: u64) -> !;

fn sym(s: &'static u8) -> usize { s as *const u8 as usize }

/// Trampoline blob and the offset of its identity-mapped half within it.
fn trampoline() -> (&'static [u8], u64) {
    // SAFETY: the linker places `.text.kexec_relocate` between the two bound
    // symbols and the identity label lies inside it; the range is kernel text,
    // mapped for the kernel's whole life, and only addresses are read here.
    let (start, ident, end) = unsafe {
        (sym(&__relocate_kernel_start), sym(&oxide_kexec_identity),
         sym(&__relocate_kernel_end))
    };
    // SAFETY: `start..end` is that same emitted range, byte-addressable.
    let code = unsafe { core::slice::from_raw_parts(start as *const u8, end - start) };
    (code, (ident - start) as u64)
}

fn walk_err(e: WalkErr) -> Error {
    match e { WalkErr::AllocFailed => Error::Nomem, _ => Error::Inval }
}

/// `machine_kexec_prepare`.
///
/// Order is deliberate: count the control pages, TAKE them all, and only then
/// write a table entry. `alloc_control_page` can fail, and a half-built table
/// that the image still holds would be indistinguishable from a good one at
/// the moment it matters.
/// # C: O(RAM / 2 MiB)
pub fn prepare<F: Frames>(image: &mut KImage, f: &mut F) -> KResult<()> {
    let (code, ident_off) = trampoline();

    let hhdm = pmm::user_as::hhdm_offset();
    if hhdm == 0 { return Err(Error::Nomem); }

    let mut ram: Vec<(u64, u64)> = Vec::new();
    for i in 0..f.ram_range_count() {
        if let Some(r) = f.ram_range(i) { ram.push(r); }
    }
    let mut fw: Vec<(u64, u64)> = Vec::new();
    for i in 0..f.firmware_range_count() {
        if let Some(r) = f.firmware_range(i) { fw.push(r); }
    }
    let ranges = plan::ranges_for(&ram, &image.segments, &fw);
    if ranges.is_empty() { return Err(Error::Inval); }

    let mut pool: Vec<u64> = Vec::new();
    for _ in 0..plan::control_pages_needed(&ranges) {
        let p = image.alloc_control_page(f)?;
        clear_page(f, p);
        pool.push(p);
    }
    let root = pool.pop().ok_or(Error::Nomem)?;
    let mut take = || pool.pop();

    // SAFETY: `root` and every page `take` yields are image-owned control
    // pages, freshly zeroed, reachable through the HHDM the PMM published.
    unsafe {
        idmap::build::<PtWalkerX86, _>(root, &ranges, hhdm, &mut take).map_err(walk_err)?;
        idmap::map_transition::<PtWalkerX86, _>(
            root, hhdm.wrapping_add(image.control_code_page), image.control_code_page,
            hhdm, &mut take).map_err(walk_err)?;
    }

    let dst = f.ptr(image.control_code_page).ok_or(Error::Nomem)?;
    // SAFETY: `control_code_page` is an image-owned control page of PAGE_SIZE
    // bytes and `code.len()` was checked against the page's usable half above.
    unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), dst, code.len()) };

    // The trampoline is CALLED at this page's kernel address, so that mapping
    // has to permit instruction fetch. Narrow it explicitly and then ASSERT the
    // result, rather than inheriting executability from how the boot tables
    // happened to build the direct map — a kernel that only works because
    // nothing set a no-execute control has no check that would notice that
    // changing.
    //
    // Read-only as well as executable: the copy above is the last write this
    // page takes through its kernel address. The trampoline's own stack writes
    // go through the IDENTITY map, which is installed writable, and they happen
    // only after it has switched to those tables.
    let code_va = hhdm.wrapping_add(image.control_code_page);
    pmm::setup::set_memory_rox(code_va, 1).map_err(|_| Error::Nomem)?;
    if !pmm::setup::kernel_range_is_executable(code_va, 1) { return Err(Error::Nomem); }

    image.arch_pgt = root;
    image.arch_entry_off = ident_off;
    #[cfg(feature = "debug-kexec")]
    { klog::write_raw(b"kexec: relocation tables built\n"); }
    Ok(())
}

/// `machine_kexec_cleanup`: return the control page's kernel mapping to the
/// linear map's default before the page is released.
///
/// Silent about failure on purpose — this runs on teardown paths that have no
/// caller left to report to, and the alternative to restoring what it can is
/// restoring nothing.
/// # C: O(1)
pub fn cleanup(image: &KImage) {
    if image.control_code_page == 0 { return; }
    let hhdm = pmm::user_as::hhdm_offset();
    if hhdm == 0 { return; }
    let _ = pmm::setup::set_memory_rw_nx(hhdm.wrapping_add(image.control_code_page), 1);
}

/// Stop the machine: every other CPU halted, every interrupt source silent,
/// and the interrupt hardware handed back in the state firmware left it in.
///
/// THE ORDER IS THE CONTRACT, and each step is where it is for a reason a
/// different order would break:
///
/// 1. The I/O APIC's redirection entries are cleared FIRST, while every local
///    APIC is still able to accept and retire what is already in flight. Some
///    implementations wedge if an interrupt is delivered to a local APIC that
///    is midway through being disabled, so the source is stopped before the
///    sink.
/// 2. Local interrupts off on this CPU, then every other CPU halted. This CPU
///    performs the relocation, so it is the one that must survive.
/// 3. The local APIC taken down — every local-vector entry masked, the APIC
///    software-disabled.
/// 4. The boot interrupt mode restored: the APIC re-enabled on the spurious
///    vector with the legacy pin delivering ExtINT and the NMI pin delivering
///    NMI. Whatever runs next did not program this hardware and is entitled to
///    find it the way a machine powers on — a kernel handed a fully masked
///    APIC gets no legacy delivery at all before it builds its own routing.
///
/// # SAFETY: irreversible; the caller is committed to leaving this kernel.
unsafe fn machine_shutdown() {
    // SAFETY: the I/O APIC window was mapped at boot; clearing every
    // redirection entry stops device lines from asserting during the copy and
    // retires any level assertion still in service.
    unsafe { hal_x86_64::ioapic::clear_all() };
    klog::announce_emergency("kexec: io-apic silent");
    // SAFETY: CPL 0; disabling interrupts is always legal and nothing after
    // this point re-enables them.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    quiesce::stop_other_cpus();
    klog::announce_emergency("kexec: other cpus stopped");
    // SAFETY: this CPU has interrupts masked and is the only one still
    // running, so no delivery can be in flight while the entries are masked.
    unsafe { arch_irq::lapic::shutdown() };
    // SAFETY: same — the local APIC has just been taken down and this CPU is
    // its only writer.
    unsafe { arch_irq::lapic::restore_boot_irq_mode() };
    klog::announce_emergency("kexec: local apic in boot mode");
}

/// `machine_kexec`. Allocates nothing: everything it needs was built by
/// `prepare`, which is what makes this half unable to fail.
/// # C: O(image size)
pub fn kexec(image: &KImage) -> KResult<()> {
    if image.arch_pgt == 0 || image.control_code_page == 0 { return Err(Error::Inval); }
    // Announced BEFORE the machine stops, not after. Everything from here on
    // runs with interrupts off and the other CPUs halted, so a step that wedges
    // produces no further output at all — and a console that simply stops is
    // indistinguishable from a jump that landed in a kernel which said nothing.
    // The two lines together bracket the irreversible half.
    klog::announce_emergency("kexec: stopping the machine");
    // SAFETY: the machine is committed; this stops every other CPU and silences
    // every interrupt source, and nothing after it can be undone.
    unsafe { machine_shutdown() };
    klog::announce_emergency("kexec: starting new kernel");
    let entry = pmm::user_as::hhdm_offset().wrapping_add(image.control_code_page);
    let ident = image.control_code_page + image.arch_entry_off;
    // SAFETY: `entry` is the kernel address of the control page `prepare`
    // copied the trampoline to; the identity tables it is handed map that same
    // address (transition mapping) and every page the relocation touches. It
    // does not return.
    unsafe {
        let f: RelocateFn = core::mem::transmute(entry);
        f(image.head, image.control_code_page, image.start, image.arch_pgt, ident)
    }
}
