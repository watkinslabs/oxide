//! In-guest full-RAM memtest (`debug-memtest`). Complements the hosted
//! buddy proptests (which use a fake buffer) by exercising EVERY real free
//! page through the live HHDM mapping.
//!
//! Strategy (zero extra allocation — the test set is held in itself):
//!   1. Drain ALL free order-0 pages from the buddy. Thread a singly-linked
//!      list through the tested pages themselves — 8 bytes `next` pfn at
//!      offset 0, 8 bytes self-`stamp` pfn at offset 8 — so the whole pfn
//!      set is held allocated with no container.
//!   2. Moving-inversions over each page BODY (offset 16..4096): for each
//!      pattern, write `pattern ^ pfn` to every 8-byte cell, then read the
//!      whole set back and compare. The `^ pfn` makes the expected value
//!      address-dependent (catches stuck address lines / page aliasing).
//!   3. On every read pass also verify the per-page `stamp` still equals the
//!      page's own pfn — catches buddy double-handout (two pfns mapping the
//!      same frame) and HHDM aliasing (page_ptr collisions).
//!   4. Free every page via the same in-page list; assert free_pages()
//!      returns to the pre-test baseline.
//!
//! Gated behind `debug-memtest` (opt-in): draining + pattern-sweeping all of
//! RAM is slow under TCG and pointless on a normal boot.

use pmm::{Order, PageBacking, Pmm};
use hal::Pfn;

const PAGE_BYTES: usize = 4096;
/// Offset of the intrusive `next` pfn link (u64). Never overwritten by the
/// body sweep, so the list stays walkable across every pass.
const LINK_OFF: usize = 0;
/// Offset of the per-page self-stamp (u64 == this pfn). Double-handout /
/// aliasing tripwire; also never touched by the body sweep.
const STAMP_OFF: usize = 8;
/// First body offset swept with the moving-inversions patterns.
const BODY_OFF: usize = 16;
/// Empty-list sentinel (no real pfn reaches u64::MAX).
const NIL: u64 = u64::MAX;

/// Moving-inversions patterns (XORed with the pfn per page). 0 / all-ones /
/// alternating both phases — the classic minimal set that flips every bit.
const PATTERNS: [u64; 4] = [
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF,
    0xA5A5_A5A5_A5A5_A5A5,
    0x5A5A_5A5A_5A5A_5A5A,
];

/// Run the in-guest full-RAM memtest. Drains all free RAM, sweeps it, frees
/// it, and asserts the free count is conserved. Pre-scheduler boot context:
/// single-CPU, no other allocator user, so draining everything is safe.
/// # C: O(N_free_pages × PATTERNS × PAGE_BYTES)
pub fn run<B: PageBacking>(p: &Pmm<B>) {
    let baseline = p.free_pages();

    // ---- 1. Drain every free order-0 page into an in-page linked list ----
    let mut head: u64 = NIL;
    let mut count: u64 = 0;
    loop {
        let pfn = match p.alloc(Order(0)) {
            Ok(pfn) => pfn,
            Err(_) => break, // buddy exhausted
        };
        // SAFETY: pfn was just returned by alloc(0); we exclusively own the
        // frame. page_ptr is the HHDM virt for it; LINK_OFF/STAMP_OFF are
        // 8-aligned within the 4 KiB page. Single-CPU pre-init context.
        unsafe {
            let v = p.page_ptr(pfn);
            core::ptr::write_volatile(v.add(LINK_OFF) as *mut u64, head);
            core::ptr::write_volatile(v.add(STAMP_OFF) as *mut u64, pfn.0);
        }
        head = pfn.0;
        count += 1;
    }
    klog::write_raw(b"[INFO]  memtest: drained ");
    klog::write_dec_u64(count);
    klog::write_raw(b" free page(s)\n");

    // ---- 2+3. Moving-inversions sweep + stamp verify ----
    let mut errors: u64 = 0;
    for &pat in PATTERNS.iter() {
        // write pass
        let mut cur = head;
        while cur != NIL {
            // SAFETY: cur is a pfn we own (in the drained list); page_ptr is
            // its HHDM virt; reads/writes stay within the 4 KiB page; the
            // body sweep (BODY_OFF..) never touches LINK_OFF/STAMP_OFF.
            unsafe {
                let v = p.page_ptr(Pfn(cur));
                let next = core::ptr::read_volatile(v.add(LINK_OFF) as *const u64);
                let want = pat ^ cur;
                let mut o = BODY_OFF;
                while o + 8 <= PAGE_BYTES {
                    core::ptr::write_volatile(v.add(o) as *mut u64, want);
                    o += 8;
                }
                cur = next;
            }
        }
        // read-back pass
        let mut cur = head;
        while cur != NIL {
            // SAFETY: as above; read-only verify of the cells just written
            // plus the stamp/link metadata.
            unsafe {
                let v = p.page_ptr(Pfn(cur));
                let next = core::ptr::read_volatile(v.add(LINK_OFF) as *const u64);
                let stamp = core::ptr::read_volatile(v.add(STAMP_OFF) as *const u64);
                if stamp != cur { errors = errors.saturating_add(1); }
                let want = pat ^ cur;
                let mut o = BODY_OFF;
                while o + 8 <= PAGE_BYTES {
                    let got = core::ptr::read_volatile(v.add(o) as *const u64);
                    if got != want { errors = errors.saturating_add(1); }
                    o += 8;
                }
                cur = next;
            }
        }
    }

    // ---- 4. Free via the same list, conserve the count ----
    let mut cur = head;
    let mut freed: u64 = 0;
    while cur != NIL {
        // SAFETY: read `next` BEFORE freeing (free returns the frame to the
        // buddy). Each pfn was alloc(0)'d above and freed exactly once here;
        // single-CPU, no concurrent re-alloc during this loop.
        unsafe {
            let v = p.page_ptr(Pfn(cur));
            let next = core::ptr::read_volatile(v.add(LINK_OFF) as *const u64);
            p.free(Pfn(cur), Order(0));
            cur = next;
        }
        freed += 1;
    }

    let after = p.free_pages();
    klog::write_raw(b"[INFO]  memtest: freed ");
    klog::write_dec_u64(freed);
    klog::write_raw(b" errors=");
    klog::write_dec_u64(errors);
    klog::write_raw(b" free_after=");
    klog::write_dec_u64(after);
    klog::write_raw(b" baseline=");
    klog::write_dec_u64(baseline);
    if errors == 0 && after == baseline && freed == count {
        klog::write_raw(b" -> PASS\n");
    } else {
        klog::write_raw(b" -> FAIL\n");
    }
}
