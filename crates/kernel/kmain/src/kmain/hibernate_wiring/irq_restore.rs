//! Diagnostic bracket for the first IRQ admitted during hibernation unwind.

pub(super) fn restore(state: u64) {
    softirq::hibernate_irq_restore(true);
    (power::suspend::wire::backend().irqs_on)(state);
    softirq::hibernate_irq_restore(false);
}
