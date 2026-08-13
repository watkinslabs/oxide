use super::*;
use crate::AmdViIrMode;

#[test] fn translation_requires_programmed_and_attached_domains() {
    let mut u = AmdViUnit::new(0xfed8_0000, 3, AmdViIrMode::Legacy);
    assert_eq!(u.state(), AmdViState::Discovered); assert!(u.mapped());
    assert_eq!(u.state(), AmdViState::Mapped);
}
#[test] fn initial_dtes_remain_admissible_after_table_programming() {
    let mut u = AmdViUnit::new(0xfed8_0000, 3, AmdViIrMode::Legacy);
    assert!(!u.accepts_initial_dte()); assert!(u.mapped()); assert!(u.accepts_initial_dte());
    u.state = AmdViState::TablesProgrammed; assert!(u.accepts_initial_dte());
    u.state = AmdViState::DomainsAttached; assert!(!u.accepts_initial_dte());
}
#[test] fn table_registers_require_aligned_permanent_memory() {
    let t = AmdViTables::from_physical(0x4000_0000, 0x5000_0000, 0x5000_2000).unwrap();
    assert_eq!(t.device_table_register(), 0x4000_01ff);
    assert_eq!(t.command_buffer_register(), 0x0900_0000_5000_0000);
    assert!(AmdViTables::from_physical(0x4000_1000, 0x5000_0000, 0x5000_2000).is_none());
}
#[test] fn translation_requires_coherent_completion_engine() {
    let required = CONTROL_COMMAND_ENABLE | CONTROL_EVENT_ENABLE | CONTROL_COMPLETION_ENABLE | CONTROL_COHERENT_ENABLE;
    assert_eq!(required & CONTROL_COMPLETION_ENABLE, CONTROL_COMPLETION_ENABLE);
    assert_eq!(required & CONTROL_COHERENT_ENABLE, CONTROL_COHERENT_ENABLE);
}
#[test] fn remap_enable_bits_preserve_the_ga_then_xt_hardware_dependency() {
    assert_eq!(remap_enable_bits(AmdViIrMode::Legacy), 0);
    assert_eq!(remap_enable_bits(AmdViIrMode::Extended), 1 << 17);
    assert_eq!(remap_enable_bits(AmdViIrMode::ExtendedXt), (1 << 17) | (1 << 50));
}
#[test] fn rollback_clears_only_bootstrap_owned_enable_bits() {
    let live = CONTROL_COMMAND_ENABLE | CONTROL_EVENT_ENABLE | CONTROL_COMPLETION_ENABLE | CONTROL_COHERENT_ENABLE | CONTROL_IOMMU_ENABLE | (1 << 19);
    let disabled = live & !(CONTROL_COMMAND_ENABLE | CONTROL_EVENT_ENABLE | CONTROL_COMPLETION_ENABLE | CONTROL_IOMMU_ENABLE);
    assert_eq!(disabled, CONTROL_COHERENT_ENABLE | (1 << 19));
}
#[test] fn firmware_quiesce_order_preserves_the_required_sequence() {
    assert_eq!(FIRMWARE_QUIESCE_ORDER, [CONTROL_COMMAND_ENABLE, CONTROL_EVENT_INTERRUPT_ENABLE, CONTROL_EVENT_ENABLE,
        CONTROL_GA_LOG_ENABLE, CONTROL_GA_INTERRUPT_ENABLE, CONTROL_PPR_LOG_ENABLE, CONTROL_PPR_INTERRUPT_ENABLE,
        CONTROL_IOMMU_ENABLE, CONTROL_IRT_CACHE_DISABLE]);
}
#[test] fn device_table_entries_preserve_the_32_byte_hardware_layout() {
    assert_eq!(core::mem::size_of::<AmdViDte>(), 32); assert_eq!(AmdViDte::blocked().words(), [0; 4]);
    assert_eq!(AmdViDte::passthrough(7).words()[1], 7);
    let dte = AmdViDte::paging(0x1234_5000, 4, 9).unwrap();
    assert_eq!(dte.words()[0] & DTE_ROOT_MASK, 0x1234_5000); assert_eq!(dte.words()[1], 9);
    assert!(AmdViDte::paging(0x1234_5001, 4, 9).is_none()); assert_eq!(AmdViTables::dte_byte_offset(0x1234), 0x1234 * 32);
}
#[test] fn invalidation_commands_preserve_the_16_byte_ring_layout() {
    assert_eq!(AmdViCommand::invalidate_dte(0x1234).words(), [0x1234, 0x2000_0000, 0, 0]);
    assert_eq!(AmdViCommand::invalidate_irt(0x1234).words(), [0x1234, 0x5000_0000, 0, 0]);
    assert_eq!(core::mem::size_of::<AmdViCommand>(), 16);
}
#[test] fn completion_and_page_invalidation_preserve_hardware_layout() {
    let command = AmdViCommand::completion_wait(0x1234_5678_9000, 7).unwrap();
    assert_eq!(command.words(), [0x5678_9001, 0x1000_1234, 7, 0]);
    let one = AmdViCommand::invalidate_iova_pages(0x1234, 0x2000, 0x2000, false).unwrap();
    assert_eq!(one.words(), [0, 0x3000_1234, 0x2000, 0]);
    let range = AmdViCommand::invalidate_iova_pages(7, 0x4000, 0x9000, true).unwrap();
    assert_eq!(range.words(), [0, 0x3000_0007, 0x7003, 0]);
}
