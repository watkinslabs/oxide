use super::*;
use crate::types::VfsError;

#[test]
fn charge_tracks_usage_and_hard_limits() {
    let qs = DquotSet::new();
    let id = QuotaId::project(7);
    qs.set_limits(id, DquotLimits {
        space: QuotaLimit::hard(100),
        reserved_space: QuotaLimit::unlimited(),
        inodes: QuotaLimit::hard(2),
    });
    let dq = qs.charge(id, DquotUsage::inode(40, 0)).unwrap();
    assert_eq!(dq.usage(), DquotUsage::inode(40, 0));
    assert_eq!(qs.charge(id, DquotUsage::inode(61, 0)).err(), Some(VfsError::Edquot));
    assert_eq!(dq.usage(), DquotUsage::inode(40, 0));
}

#[test]
fn transfer_moves_project_usage_between_dquots() {
    let old = Dquot::new(QuotaId::project(10));
    let new = Dquot::new(QuotaId::project(11));
    let usage = DquotUsage::inode(4096, 512);
    old.charge(usage).unwrap();
    dquot_transfer(usage, &[DquotTransferSlot::project(old.as_ref(), new.as_ref())]).unwrap();
    assert_eq!(old.usage(), DquotUsage::zero());
    assert_eq!(new.usage(), usage);
}

#[test]
fn transfer_checks_destination_before_debiting_source() {
    let old = Dquot::new(QuotaId::project(10));
    let new = Dquot::with_limits(QuotaId::project(11), DquotLimits {
        space: QuotaLimit::hard(1000),
        reserved_space: QuotaLimit::unlimited(),
        inodes: QuotaLimit::unlimited(),
    });
    let usage = DquotUsage::inode(4096, 0);
    old.charge(usage).unwrap();
    assert_eq!(
        dquot_transfer(usage, &[DquotTransferSlot::project(old.as_ref(), new.as_ref())]),
        Err(VfsError::Edquot)
    );
    assert_eq!(old.usage(), usage);
    assert_eq!(new.usage(), DquotUsage::zero());
}

#[test]
fn transfer_rejects_undercharged_source_without_partial_update() {
    let old = Dquot::new(QuotaId::project(10));
    let new = Dquot::new(QuotaId::project(11));
    let usage = DquotUsage::inode(4096, 0);
    assert_eq!(
        dquot_transfer(usage, &[DquotTransferSlot::project(old.as_ref(), new.as_ref())]),
        Err(VfsError::Einval)
    );
    assert_eq!(old.usage(), DquotUsage::zero());
    assert_eq!(new.usage(), DquotUsage::zero());
}

#[test]
fn transfer_rollback_restores_old_usage_after_limit_lowered() {
    let old = Dquot::new(QuotaId::project(10));
    let new = Dquot::new(QuotaId::project(11));
    let usage = DquotUsage::inode(4096, 0);
    old.charge(usage).unwrap();
    dquot_transfer(usage, &[DquotTransferSlot::project(old.as_ref(), new.as_ref())]).unwrap();
    old.set_limits(DquotLimits {
        space: QuotaLimit::hard(1024),
        reserved_space: QuotaLimit::unlimited(),
        inodes: QuotaLimit::unlimited(),
    });

    super::transfer::rollback_transferred_usage(&[DquotTransferSlot::project(old.as_ref(), new.as_ref())], usage).unwrap();

    assert_eq!(old.usage(), usage);
    assert_eq!(new.usage(), DquotUsage::zero());
}

#[test]
fn transfer_rejects_mismatched_slot_classes() {
    let old = Dquot::new(QuotaId::project(10));
    let new = Dquot::new(QuotaId::user(10));
    old.charge(DquotUsage::inode(1, 0)).unwrap();
    assert_eq!(
        dquot_transfer(DquotUsage::inode(1, 0), &[DquotTransferSlot::new(old.as_ref(), new.as_ref())]),
        Err(VfsError::Einval)
    );
}

#[test]
fn dquot_fake_tracks_linux_no_limits_rule() {
    let dq = Dquot::new(QuotaId::user(1000));
    assert!(dq.is_fake());

    dq.set_dqblk(MemDqblk { dqb_curspace: 4096, dqb_rsvspace: 512, ..MemDqblk::new() });
    assert!(dq.is_fake());

    dq.set_dqblk(MemDqblk { dqb_bhardlimit: 8192, ..MemDqblk::new() });
    assert!(!dq.is_fake());

    dq.set_dqblk_masked(MemDqblk { dqb_bhardlimit: 0, ..MemDqblk::new() }, DQB_SPC_HARD, MemDqinfo::default(), 0).unwrap();
    assert!(dq.is_fake());
}
