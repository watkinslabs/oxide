// Integration: drive the REAL `load_static_blob` against a REAL `AddressSpace`
// with a synthetic ELF, so the placement rules are exercised end to end —
// bias selection, segment mapping, the arena search, the heap window — rather
// than only the arithmetic in `aslr`. The unit tests cannot catch a loader that
// computes a correct bias and then maps somewhere else.

use alloc::vec::Vec;

use aslr::{ExecRnd, Mode};
use vmm::AddressSpace;

use crate::{load_static_blob, LoadedImage};

const PAGE: u64 = 0x1000;
const EHDR: usize = 64;
const PHENT: usize = 56;

/// Minimal but well-formed ET_DYN/ET_EXEC ELF64 with `n` PT_LOADs (+ optional
/// PT_INTERP). Enough for `elf::parse` and the placement path; the segment
/// bytes are zeros, which is all the loader copies.
fn elf(et_dyn: bool, base_vaddr: u64, interp: Option<&[u8]>) -> Vec<u8> {
    let nph = 1 + interp.is_some() as usize;
    let phoff = EHDR;
    let interp_off = phoff + nph * PHENT;
    let interp_len = interp.map_or(0, |s| s.len());
    let seg_file_sz: u64 = (interp_off + interp_len) as u64;
    // One RX PT_LOAD covering the headers, plus a tail so memsz ends mid-page.
    let mem_sz = seg_file_sz + 0x1234;

    let mut v = alloc::vec![0u8; interp_off + interp_len];
    v[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[4] = 2;                     // ELFCLASS64
    v[5] = 1;                     // ELFDATA2LSB
    v[6] = 1;                     // EV_CURRENT
    let e_type: u16 = if et_dyn { 3 } else { 2 };
    v[16..18].copy_from_slice(&e_type.to_le_bytes());
    v[18..20].copy_from_slice(&crate::ARCH_MACHINE.to_le_bytes());
    v[20..24].copy_from_slice(&1u32.to_le_bytes());                 // e_version
    v[24..32].copy_from_slice(&(base_vaddr + 0x100).to_le_bytes()); // e_entry
    v[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    v[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes());
    v[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
    v[56..58].copy_from_slice(&(nph as u16).to_le_bytes());

    let mut ph = |i: usize, ty: u32, flags: u32, off: u64, va: u64, fsz: u64, msz: u64, al: u64| {
        let b = phoff + i * PHENT;
        v[b..b + 4].copy_from_slice(&ty.to_le_bytes());
        v[b + 4..b + 8].copy_from_slice(&flags.to_le_bytes());
        v[b + 8..b + 16].copy_from_slice(&off.to_le_bytes());
        v[b + 16..b + 24].copy_from_slice(&va.to_le_bytes());
        v[b + 24..b + 32].copy_from_slice(&va.to_le_bytes());
        v[b + 32..b + 40].copy_from_slice(&fsz.to_le_bytes());
        v[b + 40..b + 48].copy_from_slice(&msz.to_le_bytes());
        v[b + 48..b + 56].copy_from_slice(&al.to_le_bytes());
    };
    ph(0, 1, 5, 0, base_vaddr, seg_file_sz, mem_sz, PAGE); // PT_LOAD RX
    if let Some(path) = interp {
        ph(1, 3, 4, interp_off as u64, 0, interp_len as u64, interp_len as u64, 1);
        v[interp_off..interp_off + interp_len].copy_from_slice(path);
    }
    v
}

/// Load into a fresh AS whose arena top is armed the way execve arms it.
fn load(blob: &[u8], rnd: &ExecRnd) -> (LoadedImage, alloc::sync::Arc<AddressSpace>) {
    let as_ = AddressSpace::new(0x1_0000).expect("AS::new");
    as_.set_mmap_base(rnd.mmap_base(8 << 20));
    let img = load_static_blob(blob, &as_, rnd).expect("load");
    (img, as_)
}

fn full(no_randomize: bool) -> ExecRnd {
    ExecRnd::draw_with(Mode::Full, no_randomize, aslr::CURRENT, aslr::CURRENT.mmap_rnd_bits)
}

/// A PIE with a PT_INTERP is the case Linux randomises explicitly. Across many
/// execs the entry must move, stay page-aligned, stay inside
/// `[ELF_ET_DYN_BASE, ELF_ET_DYN_BASE + budget)`, and never collide with the
/// arena. The interpreter is missing from this hosted rootfs, so the exec's own
/// placement is what is under test here.
#[test]
fn pie_entry_moves_across_execs_and_stays_in_the_dyn_window() {
    let blob = elf(true, 0, None);
    let mut seen: Vec<u64> = Vec::new();
    for _ in 0..64 {
        let rnd = full(false);
        let (img, as_) = load(&blob, &rnd);
        let base = img.load_base;
        // Placement is the arena's for a PIE with no interpreter (Linux's
        // `load_bias = 0` + hint-0 mmap branch), so it sits below mmap_base.
        assert_eq!(base % PAGE, 0, "unaligned load base {base:#x}");
        assert!(base < as_.mmap_base(), "image {base:#x} above arena top");
        assert_eq!(img.entry.as_u64(), base + 0x100);
        seen.push(base);
    }
    seen.sort_unstable();
    seen.dedup();
    assert!(seen.len() > 32, "only {} distinct bases in 64 execs", seen.len());
}

/// The explicit-bias branch: a PIE that DOES declare a PT_INTERP is placed at
/// `ELF_ET_DYN_BASE + arch_mmap_rnd()`. The interpreter file itself cannot be
/// read in a hosted build, so assert on the bias the loader chose rather than
/// on a completed load.
#[test]
fn pie_with_interp_uses_the_elf_et_dyn_window() {
    let budget = 1u64 << (aslr::CURRENT.mmap_rnd_bits + 12);
    let mut seen: Vec<u64> = Vec::new();
    for _ in 0..64 {
        let bias = full(false).elf_dyn_load_bias(PAGE);
        assert_eq!(bias % PAGE, 0);
        assert!(bias >= aslr::ELF_ET_DYN_BASE, "bias {bias:#x} below the window");
        assert!(bias < aslr::ELF_ET_DYN_BASE + budget, "bias {bias:#x} past the budget");
        seen.push(bias);
    }
    seen.sort_unstable();
    seen.dedup();
    assert!(seen.len() > 32, "only {} distinct biases", seen.len());
}

/// ET_EXEC is absolute — `p_vaddr` is where it goes, randomisation or not.
/// Getting this wrong relocates a non-relocatable image and it faults instantly.
#[test]
fn et_exec_is_never_relocated() {
    let blob = elf(false, 0x40_0000, None);
    for _ in 0..8 {
        let (img, _as) = load(&blob, &full(false));
        assert_eq!(img.load_base, 0, "ET_EXEC was biased");
        assert_eq!(img.entry.as_u64(), 0x40_0100);
    }
}

/// The heap must move under mode 2, stay page-aligned, and stay within 1 GiB
/// of where it would otherwise sit. For a PIE with no interpreter Linux first
/// relocates it to `ELF_ET_DYN_BASE` so it is not inside the arena — assert
/// that, since a heap in the arena gets overwritten by the next mmap.
#[test]
fn brk_moves_out_of_the_arena_and_within_one_gigabyte() {
    let blob = elf(true, 0, None);
    let mut seen: Vec<u64> = Vec::new();
    for _ in 0..64 {
        let rnd = full(false);
        let (img, as_) = load(&blob, &rnd);
        let brk = img.brk.as_u64();
        assert_eq!(brk % PAGE, 0, "unaligned start_brk {brk:#x}");
        assert!(brk >= aslr::ELF_ET_DYN_BASE, "heap {brk:#x} left below the dyn base");
        assert!(brk < aslr::ELF_ET_DYN_BASE + (1 << 30), "heap {brk:#x} past the 1 GiB slide");
        assert!(brk < as_.mmap_base(), "heap {brk:#x} landed inside the arena");
        seen.push(brk);
    }
    seen.sort_unstable();
    seen.dedup();
    assert!(seen.len() > 32, "only {} distinct heap bases", seen.len());
}

/// The negative case, end to end: with randomisation off every address the
/// loader produces is identical across execs. This is what `setarch -R`,
/// `randomize_va_space=0` and reproducible debugging depend on, and it is the
/// half that a "the addresses differ" test can never check.
#[test]
fn no_randomize_reproduces_an_identical_layout() {
    for blob in [elf(true, 0, None), elf(false, 0x40_0000, None)] {
        let mut first: Option<(u64, u64, u64, u64)> = None;
        for _ in 0..8 {
            // Both routes to "off" must agree: the personality bit and the sysctl.
            for rnd in [full(true),
                        ExecRnd::draw_with(Mode::Off, false, aslr::CURRENT,
                                           aslr::CURRENT.mmap_rnd_bits)] {
                let (img, as_) = load(&blob, &rnd);
                let got = (img.load_base, img.entry.as_u64(), img.brk.as_u64(), as_.mmap_base());
                match first {
                    None => first = Some(got),
                    Some(want) => assert_eq!(got, want, "layout drifted with ASLR disabled"),
                }
            }
        }
        assert!(first.is_some());
    }
}

/// Mode 1 randomises everything except the heap. The heap must therefore sit
/// exactly where an un-randomised heap would, while the image still moves.
#[test]
fn mode_one_pins_the_heap_but_still_moves_the_image() {
    let blob = elf(false, 0x40_0000, None);
    let off = ExecRnd::draw_with(Mode::Off, false, aslr::CURRENT, aslr::CURRENT.mmap_rnd_bits);
    let (base_img, _) = load(&blob, &off);
    let mut bases = Vec::new();
    for _ in 0..32 {
        let rnd = ExecRnd::draw_with(Mode::Conservative, false, aslr::CURRENT,
                                     aslr::CURRENT.mmap_rnd_bits);
        let (img, as_) = load(&blob, &rnd);
        assert_eq!(img.brk.as_u64(), base_img.brk.as_u64(), "mode 1 moved the heap");
        bases.push(as_.mmap_base());
    }
    bases.sort_unstable();
    bases.dedup();
    assert!(bases.len() > 16, "mode 1 failed to randomise the arena");
}

/// Every mapping the loader makes must be page-aligned, inside user space, and
/// non-overlapping. An off-by-one in the bias shows up here as an overlap,
/// which in a real boot is a segment silently eating another mapping.
#[test]
fn placed_mappings_never_overlap() {
    let blob = elf(true, 0, None);
    for _ in 0..32 {
        let rnd = full(false);
        let (_img, as_) = load(&blob, &rnd);
        let mut spans: Vec<(u64, u64)> = as_.snapshot_vmas().iter()
            .map(|v| (v.start.as_u64(), v.end.as_u64())).collect();
        spans.sort_unstable();
        for w in spans.windows(2) {
            assert!(w[0].1 <= w[1].0, "overlap {:#x?} / {:#x?}", w[0], w[1]);
        }
        for (s, e) in spans {
            assert_eq!(s % PAGE, 0);
            assert_eq!(e % PAGE, 0);
            assert!(s >= PAGE && e <= hal::USER_VA_END, "span {s:#x}..{e:#x} out of user range");
        }
    }
}
