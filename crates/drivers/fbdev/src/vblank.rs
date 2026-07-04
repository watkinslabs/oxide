use super::*;

pub static VBLANK_SEQ: AtomicU64 = AtomicU64::new(0);
pub static YIELD_HOOK: Spinlock<Option<fn()>, DriverLockClass> = Spinlock::new(None);
pub static NOW_HOOK: Spinlock<Option<fn() -> u64>, DriverLockClass> = Spinlock::new(None);

pub fn vblank_tick() { VBLANK_SEQ.fetch_add(1, Ordering::Relaxed); }

pub fn vblank_seq() -> u64 { VBLANK_SEQ.load(Ordering::Relaxed) }

pub fn set_yield_hook(f: fn()) { *YIELD_HOOK.lock() = Some(f); }

pub fn set_now_hook(f: fn() -> u64) { *NOW_HOOK.lock() = Some(f); }

pub fn clear_wait_hooks() {
    *YIELD_HOOK.lock() = None;
    *NOW_HOOK.lock() = None;
}

pub const VSYNC_DEADLINE_NS: u64 = 100_000_000;

pub fn wait_vblank(start_seq: u64) -> u64 {
    let now = *NOW_HOOK.lock();
    let yield_f = *YIELD_HOOK.lock();
    let deadline = now.map(|f| f().wrapping_add(VSYNC_DEADLINE_NS));
    let mut spins: u32 = 0;
    loop {
        let cur = VBLANK_SEQ.load(Ordering::Relaxed);
        if cur != start_seq { return cur; }
        match (deadline, now) {
            (Some(d), Some(f)) => {
                if f() >= d {
                    return VBLANK_SEQ.load(Ordering::Relaxed);
                }
            }
            _ => {
                spins += 1;
                if spins >= 1_000_000 {
                    return VBLANK_SEQ.load(Ordering::Relaxed);
                }
            }
        }
        match yield_f {
            Some(y) => y(),
            None => core::hint::spin_loop(),
        }
    }
}
