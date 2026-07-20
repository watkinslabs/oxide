// Deterministic hosted reproduction of the ld.so `dl-version.c
// _dl_check_map_versions: needed != NULL` boot blocker
// (docs/investigations/gnome-ldso-blocker.md).
//
// ROOT CAUSE (found by inspection of the write-protection fault path in
// `handle_page_fault_cow_rmap`): the Protection→NotPresent normalization
// reads `M::translate(va)` ONCE to decide, then the CoW arm re-reads it a
// SECOND time into `cur`. If a peer CPU of the same mm zaps the leaf BETWEEN
// those two reads (an SMP TOCTOU the single-`translate` normalization cannot
// see), the fault stays `Protection` while `cur == None`, and the old
// fall-through alloc+ZERO-filled a fresh frame — installing zeros over the
// File / KernelBytes backing (the EOF-straddling .data/.dynamic tail of a
// freshly-mapped shared library). ld.so then read a zeroed version/verneed
// record, silently skipped DT_NEEDED deps, and tripped `needed != NULL`.
//
// This harness drives the REAL `AddressSpace::handle_page_fault_cow_rmap`
// against a page-table model whose `translate` returns Some on its first
// call and None on its second — modelling the exact peer-CPU zap. It asserts
// the handler NEVER installs a zero page over backing content, and that a
// clean refault restores the correct backing bytes.
//
// Single-threaded + deterministic: the TOCTOU is injected via the MmuOps
// model, not a real race, so this reproduces the corruption every run.

#![cfg(test)]

use alloc::sync::Arc;
use core::cell::RefCell;
use std::collections::HashMap;
use std::thread_local;
use std::vec::Vec;

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

use crate::address_space::AddressSpace;
use crate::vma::{FaultAccess, FaultKind, VmaBacking, VmaFlags, VmaProt};

const PAGE: u64 = 0x1000;
const FILL: u8 = 0xAB; // sentinel backing byte — a zero-over-file bug reads 0.

thread_local! {
    /// va -> (pa, flags): the real installed leaves the handler produces.
    static LEAF: RefCell<HashMap<u64, (u64, u64)>> = RefCell::new(HashMap::new());
    /// TOCTOU injector: while `Some(n)`, `translate` returns the armed
    /// "present" leaf for its first `n` calls, then `None` (peer-CPU zap).
    /// `None` = normal LEAF-backed translate.
    static ZAP_AFTER: RefCell<Option<u64>> = RefCell::new(None);
    static TSEQ: RefCell<u64> = RefCell::new(0);
    static ARMED_PA: RefCell<u64> = RefCell::new(0);
}

fn reset() {
    LEAF.with(|l| l.borrow_mut().clear());
    ZAP_AFTER.with(|z| *z.borrow_mut() = None);
    TSEQ.with(|t| *t.borrow_mut() = 0);
    ARMED_PA.with(|a| *a.borrow_mut() = 0);
}

/// Real zeroed 4 KiB host frame (hhdm=0 → PA is a valid host pointer, so the
/// handler's CoW memcpy and our byte assertions touch real memory).
fn fresh_pa() -> u64 {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(4096, 4096).unwrap();
    // SAFETY: non-zero 4 KiB layout; alloc_zeroed yields a valid aligned block.
    (unsafe { alloc_zeroed(layout) }) as u64
}

fn alloc_frame() -> Option<u64> { Some(fresh_pa()) }

struct ToctouMmu;
impl MmuOps for ToctouMmu {
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, _s: PageSize) -> Option<Pa> {
        LEAF.with(|l| l.borrow_mut().insert(va.0, (pa.0, flags.bits())).map(|(o, _)| Pa(o)))
    }
    unsafe fn unmap(va: Va, _s: PageSize) {
        LEAF.with(|l| { l.borrow_mut().remove(&va.0); });
    }
    fn translate(va: Va) -> Option<(Pa, PageFlags)> {
        if let Some(n) = ZAP_AFTER.with(|z| *z.borrow()) {
            let seq = TSEQ.with(|t| { let mut t = t.borrow_mut(); let v = *t; *t += 1; v });
            // First `n` calls: armed present (RO, W-stripped) leaf → fault
            // stays Protection. After that: zapped → None → cur becomes None.
            if seq < n {
                let pa = ARMED_PA.with(|a| *a.borrow());
                return Some((Pa(pa), PageFlags::empty()));
            }
            return None;
        }
        LEAF.with(|l| l.borrow().get(&va.0)
            .map(|(p, f)| (Pa(*p), PageFlags::from_bits_truncate(*f))))
    }
    unsafe fn flush_va(_va: Va) {}
    fn flush_all_local() {}
    unsafe fn map_at(_root: u64, va: Va, pa: Pa, flags: PageFlags, _s: PageSize) -> Option<Pa> {
        LEAF.with(|l| l.borrow_mut().insert(va.0, (pa.0, flags.bits())).map(|(o, _)| Pa(o)))
    }
    unsafe fn activate(_root_pa: u64) {}
}

fn drive(mm: &AddressSpace, va: u64, fault: FaultKind) {
    let uva = hal::UserVirtAddr::new(va).unwrap();
    // SAFETY: hosted; ToctouMmu is the active model; closures are trivial
    // no-op refcount/rmap stand-ins (this test asserts CONTENT, not
    // accounting — the accounting invariant is covered by tests_cow_invariant).
    let _ = unsafe {
        mm.handle_page_fault_cow_rmap::<ToctouMmu, _, _, _, _, _, _, _, _>(
            uva, fault, 0,
            alloc_frame,
            |_pa| 2,        // frame_refcount: pretend shared (>1) so CoW never reuses
            |_pa| {},       // dec_ref
            |_pa, _av, _i| {}, // set_rmap
            |_pa| {},       // inc_ref
            |_pa| false,    // reuse_ok: never take the anon reuse fast path
            || Ok(()),
            || {},
        )
    };
}

fn map_kernelbytes_rw(mm: &AddressSpace) -> u64 {
    let data: Arc<[u8]> = Arc::from(std::vec![FILL; PAGE as usize].into_boxed_slice());
    let va = mm.mmap(
        None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data, off: 0 },
        false,
    ).expect("mmap kernelbytes");
    va.as_u64()
}

/// THE REPRODUCTION: a write-protection fault whose leaf is zapped between the
/// normalization translate and the CoW re-read must NOT install a zero page
/// over the KernelBytes backing; a clean refault must restore FILL bytes.
#[test]
fn protection_toctou_never_zero_fills_over_backing() {
    reset();
    let mm = AddressSpace::new(0x1_0000_0000).expect("AS::new");
    let va = map_kernelbytes_rw(&mm);

    // Arm the peer-CPU zap: translate returns the armed present leaf for call
    // #0 (normalization, keeps the fault Protection) and None for call #1
    // (the CoW re-read → cur == None). One armed RO frame stands in for the
    // pre-zap leaf.
    ARMED_PA.with(|a| *a.borrow_mut() = fresh_pa());
    TSEQ.with(|t| *t.borrow_mut() = 0);
    ZAP_AFTER.with(|z| *z.borrow_mut() = Some(1));

    drive(&mm, va, FaultKind::Protection { access: FaultAccess::Write });

    // FIX: the handler saw cur==None, flushed, and returned WITHOUT installing
    // anything. The pre-fix code alloc+zero-filled and mapped a zero frame
    // here — which this assertion catches.
    let installed = LEAF.with(|l| l.borrow().get(&va).copied());
    assert!(
        installed.is_none(),
        "TOCTOU write-protection fault installed a leaf over backing (pre-fix \
         zero-fill regression): {:#x?}", installed,
    );

    // Clean refault (zap disarmed → leaf genuinely absent → NotPresent path).
    ZAP_AFTER.with(|z| *z.borrow_mut() = None);
    TSEQ.with(|t| *t.borrow_mut() = 0);
    drive(&mm, va, FaultKind::NotPresent { access: FaultAccess::Write });

    let (pa, _) = LEAF.with(|l| l.borrow().get(&va).copied())
        .expect("refault must install the backing page");
    // SAFETY: hhdm=0 → pa is a valid host frame pointer; read 4 backing bytes.
    let bytes = unsafe { core::slice::from_raw_parts(pa as *const u8, 4) };
    assert_eq!(bytes, &[FILL; 4],
        "refault restored zeros/garbage instead of KernelBytes backing content");
}

/// GUARD: a genuine write-protection CoW (cur == Some, a shared frame) still
/// copies the SOURCE bytes into the fresh frame — the fix must not have
/// broken the real CoW copy path.
#[test]
fn protection_cow_copies_source_bytes() {
    reset();
    let mm = AddressSpace::new(0x2_0000_0000).expect("AS::new");
    let va = map_kernelbytes_rw(&mm);

    // Present, W-stripped leaf pointing at a frame full of 0xCD (the "shared"
    // pre-CoW source). translate reads LEAF (no zap armed) → consistent Some.
    let src = fresh_pa();
    // SAFETY: hhdm=0 → src is a valid host frame; fill 4 KiB with the sentinel.
    unsafe { core::ptr::write_bytes(src as *mut u8, 0xCD, PAGE as usize); }
    LEAF.with(|l| { l.borrow_mut().insert(va, (src, PageFlags::empty().bits())); });

    drive(&mm, va, FaultKind::Protection { access: FaultAccess::Write });

    let (pa, _) = LEAF.with(|l| l.borrow().get(&va).copied()).expect("leaf present");
    assert_ne!(pa, src, "CoW must install a FRESH frame, not reuse the shared source");
    // SAFETY: hhdm=0 → pa is a valid host frame pointer.
    let bytes = unsafe { core::slice::from_raw_parts(pa as *const u8, 4) };
    assert_eq!(bytes, &[0xCD; 4], "CoW copy lost the source bytes");
}
