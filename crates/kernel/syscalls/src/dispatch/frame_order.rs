//! Entry-frame publication order, kept hosted so the interrupt race is causal.

/// Publish the architecture-owned entry frame before enabling process IRQs.
///
/// The frame is the entry ABI argument, not a value rediscovered from mutable
/// per-CPU state. Taking both effects as closures pins the only ordering that
/// closes the entry-to-task handoff race while remaining executable hosted.
/// # C: O(1)
pub fn bind_then_enable<F, B, E, R>(frame: F, bind: B, enable: E) -> R
where
    B: FnOnce(F),
    E: FnOnce() -> R,
{
    bind(frame);
    enable()
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::cell::RefCell;

    use super::bind_then_enable;

    #[test]
    fn the_live_frame_is_bound_before_irqs_can_schedule() {
        let events = RefCell::new(Vec::new());
        let rv = bind_then_enable(
            0x1234usize,
            |frame| events.borrow_mut().push(("bind", frame)),
            || {
                events.borrow_mut().push(("enable", 0));
                7
            },
        );
        assert_eq!(rv, 7);
        assert_eq!(&*events.borrow(), &[("bind", 0x1234), ("enable", 0)]);
    }
}
