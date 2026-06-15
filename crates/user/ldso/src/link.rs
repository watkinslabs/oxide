// Link + run a dynamic executable (docs/59§5, docs/31§4). Builds the global
// link map from the kernel-mapped app + its DT_NEEDED graph (mmap each lib),
// applies every object's RELA + JMPREL + TLS relocations resolving symbols
// across the global scope, runs DT_INIT / DT_INIT_ARRAY dependency-first, and
// returns the app entry. The link map is a process-global the rtld owns so
// dlopen (G12h) can extend it at runtime. Freestanding; verified by the
// dynamic-run harness (xtask ldso --check).
#![cfg(feature = "freestanding")]
use crate::dynamic::Dyn;
use crate::objview::{build_objview, OwnedObj};
use crate::reloc::Rela;
use crate::relocate::RelocCtx;
use crate::{auxv, linkmap, loader, phdr, relocate, search, syscall};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

const RELAENT: usize = 24;

#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = elf::EM_X86_64;
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = elf::EM_AARCH64;

// Process-global link map. Accessed single-threaded during startup; the lock
// guards dlopen vs the running program once threads exist.
struct GlobalLink {
    objs: UnsafeCell<Vec<OwnedObj>>,
    sonames: UnsafeCell<Vec<&'static [u8]>>,
    lock: AtomicBool,
}
// SAFETY: all access goes through with_lock(), which serializes mutation; the
// objects' backing mmaps live for the process.
unsafe impl Sync for GlobalLink {}
static LINK: GlobalLink = GlobalLink {
    objs: UnsafeCell::new(Vec::new()),
    sonames: UnsafeCell::new(Vec::new()),
    lock: AtomicBool::new(false),
};

fn lock() {
    while LINK.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Acquire).is_err() {
        core::hint::spin_loop();
    }
}
fn unlock() { LINK.lock.store(false, Ordering::Release); }

#[allow(clippy::mut_from_ref)]
unsafe fn objs() -> &'static mut Vec<OwnedObj> {
    // SAFETY: caller holds the lock; the Vec lives in the global.
    unsafe { &mut *LINK.objs.get() }
}
#[allow(clippy::mut_from_ref)]
unsafe fn sonames() -> &'static mut Vec<&'static [u8]> {
    // SAFETY: caller holds the lock; the Vec lives in the global.
    unsafe { &mut *LINK.sonames.get() }
}

// Value of LD_LIBRARY_PATH from the environment, or empty.
unsafe fn ld_library_path(sp: *const usize) -> &'static [u8] {
    // SAFETY: envp is the kernel env array; each entry is a NUL-terminated
    // "KEY=VALUE" string. We scan for our key and return its value slice.
    unsafe {
        const KEY: &[u8] = b"LD_LIBRARY_PATH=";
        let mut e = auxv::envp(sp);
        while !(*e).is_null() {
            let s = *e;
            let mut n = 0usize;
            while *s.add(n) != 0 { n += 1; }
            let bytes = core::slice::from_raw_parts(s, n);
            if bytes.len() > KEY.len() && &bytes[..KEY.len()] == KEY {
                return &bytes[KEY.len()..];
            }
            e = e.add(1);
        }
        &[]
    }
}

// Resolve `soname` to a NUL-terminated path in `out` via the search path.
unsafe fn find_lib(soname: &[u8], llp: &[u8], out: &mut [u8]) -> bool {
    // SAFETY: probes the filesystem with faccessat over a local NUL buffer.
    unsafe {
        search::resolve(soname, llp, out, |p| {
            let mut c = [0u8; search::PATH_MAX];
            c[..p.len()].copy_from_slice(p);
            syscall::access(c.as_ptr(), syscall::F_OK) == 0
        }).is_some()
    }
}

// open + read + parse + mmap one library by path; append it to the global map.
// Returns the new object's index, or None on any failure.
unsafe fn load_one(path: *const u8) -> Option<usize> {
    // SAFETY: path is NUL-terminated; we open/read/parse/map then push the
    // resulting OwnedObj onto the global objs vec (lock held by caller).
    unsafe {
        let fd = syscall::open(path, syscall::O_RDONLY);
        if fd < 0 { return None; }
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            let r = syscall::read(fd as i32, chunk.as_mut_ptr(), chunk.len());
            if r <= 0 { break; }
            buf.extend_from_slice(&chunk[..r as usize]);
        }
        if buf.is_empty() { syscall::close(fd as i32); return None; }
        let parsed = match elf::parse(&buf, MACHINE) { Ok(p) => p, Err(_) => { syscall::close(fd as i32); return None; } };
        let dep_dyn_v = phdr::find_vaddr(&buf[parsed.phoff as usize..], parsed.phnum as usize, phdr::PT_DYNAMIC);
        let mapped = loader::map_object(fd as i32, &parsed);
        syscall::close(fd as i32);
        let (base, end) = mapped.ok()?;
        let dv = dep_dyn_v?;
        objs().push(build_objview(base, end, (base + dv) as *const Dyn));
        Some(objs().len() - 1)
    }
}

// Breadth-first DT_NEEDED load over the global map, starting at index `from`.
unsafe fn load_needed(llp: &[u8], from: usize) {
    // SAFETY: walks each object's DT_NEEDED, loading missing libs into the
    // global map; lock held by caller.
    unsafe {
        let mut i = from;
        while i < objs().len() {
            let needed = objs()[i].info.needed.clone();
            for off in needed {
                let soname = objs()[i].str_at(off);
                if sonames().contains(&soname) { continue; }
                let mut pb = [0u8; search::PATH_MAX];
                if !find_lib(soname, llp, &mut pb) { continue; }
                if load_one(pb.as_ptr()).is_some() { sonames().push(soname); }
            }
            i += 1;
        }
    }
}

// Relocate objects [from..] against the full global scope. `app_tls_off` is
// the TLS tp offset for object 0 (the app); other objects get 0 for now.
unsafe fn relocate_range(from: usize, app_tls_off: i64) {
    // SAFETY: applies each object's RELA+JMPREL+TLS in place; resolver reads
    // the global link map's windows.
    unsafe {
        let map: Vec<linkmap::ObjView> = objs().iter().map(|o| o.view()).collect();
        let resolve = |name: &[u8]| linkmap::lookup_global(&map, name, None).map(|(_, a)| a);
        for oi in from..objs().len() {
            let o = &objs()[oi];
            let v = o.view();
            let (off, modid) = if oi == 0 { (app_tls_off, 1) } else { (0, (oi + 1) as u64) };
            let ctx = RelocCtx { base: o.base, sym: v.sym, tls_offset: off, tls_modid: modid };
            if let Some(ra) = o.info.rela {
                let cnt = (o.info.relasz as usize) / RELAENT;
                let _ = relocate::apply(&ctx, (o.base + ra) as *const Rela, cnt, &resolve);
            }
            if let Some(jr) = o.info.jmprel {
                let cnt = (o.info.pltrelsz as usize) / RELAENT;
                let _ = relocate::apply(&ctx, (o.base + jr) as *const Rela, cnt, &resolve);
            }
        }
    }
}

// Run DT_INIT then each DT_INIT_ARRAY entry of one object.
unsafe fn run_init(o: &OwnedObj) {
    // SAFETY: init pointers are fn() in the object's mapping; called once.
    unsafe {
        if let Some(init) = o.info.init {
            let f: extern "C" fn() = core::mem::transmute(o.base + init);
            f();
        }
        if let Some(arr) = o.info.init_array {
            let n = o.info.init_arraysz as usize / 8;
            let p = (o.base + arr) as *const usize;
            for i in 0..n {
                let f: extern "C" fn() = core::mem::transmute(*p.add(i));
                f();
            }
        }
    }
}

// Allocate the static TLS block for an object's PT_TLS, install the thread
// pointer, and return its tp offset (0 if no TLS). Initial-exec.
unsafe fn setup_static_tls(base: u64, phdrs: &[u8], phnum: usize) -> i64 {
    // SAFETY: reads PT_TLS, mmaps a zeroed block, copies the init image, sets tp.
    unsafe {
        let (vaddr, filesz, memsz, align) = match phdr::find_tls(phdrs, phnum) { Some(t) => t, None => return 0 };
        let (offs, total) = crate::tls::layout(&[(memsz, align)], crate::tls::target_variant());
        let tp_off = offs[0];
        let size = ((total as usize) + 4096 + 4095) & !4095;
        let blk = syscall::mmap(0, size, syscall::PROT_READ | syscall::PROT_WRITE,
            syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS, -1, 0);
        if blk < 0 { return 0; }
        let blk = blk as usize;
        let tp = match crate::tls::target_variant() {
            crate::tls::Variant::Two => blk + total as usize,
            crate::tls::Variant::One => blk,
        };
        let data = (tp as i64 + tp_off) as usize;
        core::ptr::copy_nonoverlapping((base + vaddr) as *const u8, data as *mut u8, filesz as usize);
        *(tp as *mut usize) = tp;
        syscall::set_thread_pointer(tp);
        tp_off
    }
}

/// Link the app + its DT_NEEDED graph and return the app entry point.
/// # C: build the global link map, relocate all, run init, return AT_ENTRY
pub unsafe fn link(sp: *const usize) -> usize {
    // SAFETY: sp is the initial stack; AT_* describe the kernel-mapped app.
    unsafe {
        let at_phdr = auxv::auxval(sp, auxv::AT_PHDR).unwrap_or(0);
        let phnum = auxv::auxval(sp, auxv::AT_PHNUM).unwrap_or(0);
        let entry = auxv::auxval(sp, auxv::AT_ENTRY).unwrap_or(0);
        if at_phdr == 0 || phnum == 0 { return entry; }
        let phdrs = core::slice::from_raw_parts(at_phdr as *const u8, phnum * phdr::PHDR_SIZE);
        let app_base = phdr::load_bias(phdrs, phnum, at_phdr as u64).unwrap_or(0);
        let app_dyn_v = match phdr::find_vaddr(phdrs, phnum, phdr::PT_DYNAMIC) { Some(v) => v, None => return entry };
        let (_, app_hi) = phdr::load_vaddr_span(phdrs, phnum).unwrap_or((0, 0));
        let llp = ld_library_path(sp);

        lock();
        objs().push(build_objview(app_base, app_base + app_hi, (app_base + app_dyn_v) as *const Dyn));
        load_needed(llp, 0);
        let app_tls_off = setup_static_tls(app_base, phdrs, phnum);
        relocate_range(0, app_tls_off);
        // Initializers run dependency-first (deps were pushed after the app).
        let n = objs().len();
        for i in (0..n).rev() { run_init(&objs()[i]); }
        unlock();
        entry
    }
}
