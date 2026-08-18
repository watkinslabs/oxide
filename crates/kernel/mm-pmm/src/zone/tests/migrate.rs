use crate::zone::*;

#[test]
fn mobility_flags_select_the_matching_free_list_class() {
    assert_eq!(gfp_migratetype(0), Ok(MigrateType::Unmovable));
    assert_eq!(gfp_migratetype(GFP_MOVABLE), Ok(MigrateType::Movable));
    assert_eq!(gfp_migratetype(GFP_RECLAIMABLE), Ok(MigrateType::Reclaimable));
    assert_eq!(gfp_migratetype(GFP_MOVABLE | GFP_RECLAIMABLE), Err(GfpError));
}

#[test]
fn every_mobility_class_has_the_fragmentation_avoiding_fallback_order() {
    assert_eq!(MigrateType::Unmovable.fallbacks(), [MigrateType::Reclaimable, MigrateType::Movable]);
    assert_eq!(MigrateType::Movable.fallbacks(), [MigrateType::Reclaimable, MigrateType::Unmovable]);
    assert_eq!(MigrateType::Reclaimable.fallbacks(), [MigrateType::Unmovable, MigrateType::Movable]);
}
