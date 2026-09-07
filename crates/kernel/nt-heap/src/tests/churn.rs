// A long mixed workload: every live block keeps its own bytes, sizes stay
// exact, and the address-space cost stays bounded while blocks recycle.

use super::backend::TestBackend;
use crate::backend::HeapBackend;
use crate::flags::HEAP_GROWABLE;
use crate::Heap;

fn next(state: &mut u64) -> u64 { *state ^= *state << 13; *state ^= *state >> 7; *state ^= *state << 17; *state }

#[test]
fn mixed_allocate_free_resize_keeps_every_body_intact() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let mut live: alloc::vec::Vec<(u64, usize, u8)> = alloc::vec::Vec::new();
    let mut state = 0x2545_f491_4f6c_dd1d;
    for step in 0..20_000u64 {
        let roll = next(&mut state) % 100;
        if roll < 45 || live.is_empty() {
            let size = 1 + (next(&mut state) % 3000) as usize;
            let tag = step as u8;
            let ptr = heap.allocate(&mut backend, 0, size).unwrap();
            assert_eq!(heap.size(&backend, ptr), Some(size));
            assert!(backend.fill(ptr, size, tag));
            live.push((ptr, size, tag));
        } else if roll < 80 {
            let victim = (next(&mut state) as usize) % live.len();
            let (ptr, _, _) = live.swap_remove(victim);
            assert!(heap.free(&mut backend, ptr));
        } else {
            let victim = (next(&mut state) as usize) % live.len();
            let (ptr, size, tag) = live[victim];
            let grown = 1 + (next(&mut state) % 3000) as usize;
            let moved = heap.reallocate(&mut backend, 0, ptr, grown).unwrap();
            assert_eq!(heap.size(&backend, moved), Some(grown));
            let kept = size.min(grown);
            let mut body = alloc::vec![0u8; kept];
            assert!(backend.read(moved, &mut body));
            assert!(body.iter().all(|byte| *byte == tag), "resize lost the body at step {step}");
            assert!(backend.fill(moved, grown, tag));
            live[victim] = (moved, grown, tag);
        }
        if step % 512 == 0 {
            for (ptr, size, tag) in &live {
                let mut body = alloc::vec![0u8; *size];
                assert!(backend.read(*ptr, &mut body));
                assert!(body.iter().all(|byte| byte == tag), "block {ptr:#x} was overwritten at step {step}");
            }
        }
    }
    assert!(backend.reserves < 64, "{} reservations for 20000 heap operations", backend.reserves);
}
