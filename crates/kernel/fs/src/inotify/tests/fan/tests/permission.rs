use super::*;

#[cfg(test)]
pub(crate) fn audit_rule_bytes(ty: u8, pad: u8, len: u16, rule: u32, subj: u32, obj: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = ty;
    b[1] = pad;
    b[2..4].copy_from_slice(&len.to_le_bytes());
    b[4..8].copy_from_slice(&rule.to_le_bytes());
    b[8..12].copy_from_slice(&subj.to_le_bytes());
    b[12..16].copy_from_slice(&obj.to_le_bytes());
    b
}

/// A `fanotify_response` followed by raw info bytes, written as one call.
/// # C: O(info.len())
#[cfg(test)]
pub(crate) fn respond_with_rule(g: &InotifyData, fd: i32, response: u32, info: &[u8])
    -> vfs::KResult<usize> {
    let mut w = Vec::new();
    w.extend_from_slice(&fd.to_le_bytes());
    w.extend_from_slice(&response.to_le_bytes());
    w.extend_from_slice(info);
    g.write(0, &w)
}

/// An accessor that abandoned the wait (killed mid-syscall) must not be
/// "resumed" by a verdict that arrives afterwards — it is already gone, and the
/// response is discarded rather than published.
#[test]
fn a_verdict_for_an_abandoned_access_is_discarded() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9701);
    let st = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let fd = read_one_perm(&g);
    st.cancel();
    assert_eq!(respond(&g, fd, FAN_DENY), Ok(8), "the daemon's write still succeeds");
    assert_eq!(st.answered(), None, "but nothing is published to the dead accessor");
}

// Closing a group auto-allows still-pending perm events so a dead listener
// never wedges a blocked accessor.
#[test]
fn perm_release_auto_allows() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xA001);
    let st = queue_perm(&g, &ino, FAN_OPEN_PERM);
    g.on_release();
    assert_eq!(st.answered(), Some(FAN_ALLOW));
}

/// Closing with events outstanding must answer BOTH the ones a reader already
/// handed to the daemon and the ones still queued. Only answering one list
/// leaves the other set of accessors parked forever.
#[test]
fn release_answers_both_reported_and_still_queued_events() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xA101);
    let reported = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let _fd = read_one_perm(&g);                       // moves it to the pending list
    let queued = queue_perm(&g, &ino, crate::inotify::types::FAN_ACCESS_PERM); // still in the queue
    g.on_release();
    assert_eq!(reported.answered(), Some(FAN_ALLOW));
    assert_eq!(queued.answered(), Some(FAN_ALLOW));
}

/// After release the group queues nothing more, so an access arriving during
/// teardown is not parked on a group that will never answer.
#[test]
fn a_closed_group_queues_no_further_events() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xA201);
    g.on_release();
    let st = Arc::new(crate::inotify::types::PermState::new());
    assert!(g.queue_perm_event(perm_event(&ino, FAN_OPEN_PERM, st)).is_none());
    assert!(g.events.lock().is_empty());
}

// FAN_OPEN_EXEC_PERM execve-gate cycle (D56). perm_marks_present() is the boot
// fast-path gate the execve hook checks first: false with no perm mark armed
// (execve skips the resolve entirely), true once a FAN_OPEN_EXEC_PERM mark is
// installed. Single test: it is the sole mutator of the global
// PERM_MARK_COUNT, so the gate assertions are race-free.
#[test]
fn open_exec_perm_gate_cycle() {
    let _notify = crate::inotify::test_claim::claim_notify();
    // No perm marks armed by us yet → execve gate stays inert.
    assert!(!perm_marks_present());

    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xC001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(),
               FAN_OPEN_EXEC_PERM, true, false, 0);
    // A FAN_*_PERM mark is now armed → execve gate engages its resolve+check.
    assert!(perm_marks_present());

    let denied = queue_perm(&g, &ino, FAN_OPEN_EXEC_PERM);
    let fd = read_one_perm(&g);
    assert_eq!(respond(&g, fd, FAN_DENY), Ok(8));
    assert_eq!(denied.answered(), Some(FAN_DENY));

    let allowed = queue_perm(&g, &ino, FAN_OPEN_EXEC_PERM);
    let fd2 = read_one_perm(&g);
    assert_eq!(respond(&g, fd2, FAN_ALLOW), Ok(8));
    assert_eq!(allowed.answered(), Some(FAN_ALLOW));

    // Retire the mark → gate goes inert again (PERM_MARK_COUNT back to 0).
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(),
               FAN_OPEN_EXEC_PERM, false, false, 0);
    assert!(!perm_marks_present());
}

/// One permission-event record for `obj`, with fresh shared state. # C: O(1)
pub(crate) fn perm_event(obj: &InodeRef, mask: u32, st: Arc<crate::inotify::types::PermState>)
    -> crate::inotify::types::Event {
    crate::inotify::types::Event {
        wd: -1, mask, cookie: 0, name: Vec::new(), obj: Some(obj.clone()), pid: 0,
        perm: Some(st), ..Default::default()
    }
}

/// Queue a permission event on `g` and hand back the state an accessor would
/// park on. # C: O(1)
pub(crate) fn queue_perm(g: &Arc<InotifyData>, obj: &InodeRef, mask: u32)
    -> Arc<crate::inotify::types::PermState> {
    let st = Arc::new(crate::inotify::types::PermState::new());
    g.queue_perm_event(perm_event(obj, mask, st.clone())).expect("queued");
    st
}

/// Drain one 24-byte metadata record and return the descriptor it carried.
/// # C: O(1)
pub(crate) fn read_one_perm(g: &InotifyData) -> i32 {
    let mut buf = [0u8; 24];
    assert_eq!(g.read_fanotify(&mut buf).unwrap(), 24);
    i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]])
}

/// Write one `struct fanotify_response`. # C: O(1)
pub(crate) fn respond(g: &InotifyData, fd: i32, response: u32) -> vfs::KResult<usize> {
    let mut r = [0u8; 8];
    r[0..4].copy_from_slice(&fd.to_le_bytes());
    r[4..8].copy_from_slice(&response.to_le_bytes());
    g.write(0, &r)
}

// fanotify_init flag validation: unknown bits, the impossible class 0xc, and
// FAN_REPORT_NAME without FAN_REPORT_DIR_FID are all EINVAL.
#[test]
fn init_flag_validation() {
    let _notify = crate::inotify::test_claim::claim_notify();
    assert_eq!(validate_fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK), 0);
    assert_eq!(validate_fanotify_init(FAN_CLASS_CONTENT), 0);
    assert_ne!(validate_fanotify_init(0x8000_0000), 0);                 // unknown bit
    assert_ne!(validate_fanotify_init(FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT), 0); // 0xc
    assert_ne!(validate_fanotify_init(FAN_REPORT_NAME), 0);             // NAME w/o DIR_FID
    assert_eq!(validate_fanotify_init(FAN_REPORT_NAME | FAN_REPORT_DIR_FID), 0);
}

/// A throwaway superblock so an inode has a real cache to be evicted FROM.
/// Eviction is what `FAN_MARK_EVICTABLE` is about, and it cannot be observed on
/// a free-standing inode. # C: O(1)
#[cfg(test)]
fn mk_sb(s_dev: u64) -> Arc<vfs::SuperBlock> {
    struct T;
    impl vfs::superblock::FileSystemType for T {
        fn name(&self) -> &str { "markfs" }
        fn mount(&self, _s: Option<&str>, _o: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
            Err(vfs::VfsError::Enodev)
        }
    }
    struct O;
    impl vfs::superblock::SuperOps for O {
        fn statfs(&self) -> vfs::KResult<vfs::superblock::SbStatFs> {
            Ok(vfs::superblock::SbStatFs { f_bsize: 4096, ..Default::default() })
        }
    }
    vfs::SuperBlock::new(Arc::new(T), Arc::new(O), 0x6d61_726b, s_dev, 4096,
                         alloc::string::String::from("markfs"), Arc::new(()))
}

/// A link-less inode resident in `sb`'s cache, born with one reference.
/// # C: O(1)
#[cfg(test)]
fn cached_inode(sb: &Arc<vfs::SuperBlock>, ino: u64) -> InodeRef {
    sb.iget(ino, || InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(InotifyFileOps))
        .sb(Arc::downgrade(sb)).nlink(0).build())
}

/// `FAN_MARK_EVICTABLE` means "do not hold the object in memory". The mark
/// takes no reference on the inode, so the last other reference going evicts
/// it, and the mark goes with it — a watcher must re-establish such a mark.
///
/// Modelling the flag as a stored bool made it meaningless: an ORDINARY mark
/// held no reference either, so both kinds survived eviction identically and
/// the object was free to be reclaimed and its number reused underneath the
/// mark. The distinction is now the reference itself, so the two cannot
/// disagree.
#[test]
fn an_evictable_mark_takes_no_reference_and_leaves_with_the_inode() {
    let _notify = crate::inotify::test_claim::claim_notify();
    vfs::set_inode_evict_hook(crate::inotify::marks::evict_inode_marks);
    let g = InotifyData::new_fanotify(0);
    let sb = mk_sb(0xE001);
    let ino = cached_inode(&sb, 0xE001);
    crate::inotify::syscalls::apply_inode_mark(&g, &ino, FAN_OPEN, true, false,
                     crate::inotify::validate::FAN_MARK_EVICTABLE);
    fire_self(&ino, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN], "armed before eviction");
    assert_eq!(ino.i_count(), 1, "an evictable mark took no reference");
    sb.iput(ino.clone());
    drop(ino);
    assert!(sb.ilookup(0xE001).is_none(), "the inode left the cache");
    assert!(g.watches.lock().is_empty(), "and the mark left with it");
}

/// A mark WITHOUT the flag holds a reference on its inode, which is what keeps
/// the object — and therefore the mark's identity — alive. Dropping every
/// other reference does not evict it.
#[test]
fn an_ordinary_mark_holds_its_inode_resident() {
    let _notify = crate::inotify::test_claim::claim_notify();
    vfs::set_inode_evict_hook(crate::inotify::marks::evict_inode_marks);
    let g = InotifyData::new_fanotify(0);
    let sb = mk_sb(0xE101);
    let ino = cached_inode(&sb, 0xE101);
    crate::inotify::syscalls::apply_inode_mark(&g, &ino, FAN_OPEN, true, false, 0);
    assert_eq!(ino.i_count(), 2, "the mark took a reference of its own");
    sb.iput(ino.clone());
    drop(ino);
    let still = sb.ilookup(0xE101).expect("the mark keeps the inode resident");
    assert_eq!(still.i_count(), 1, "exactly the mark's reference remains");
    fire_self(&still, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN]);
}

/// Retiring the mark gives the reference back, and the inode is then free to
/// be evicted. Without the release a watcher that adds and removes marks in a
/// loop pins every inode it ever touched.
#[test]
fn retiring_a_mark_releases_the_inode_it_held() {
    let _notify = crate::inotify::test_claim::claim_notify();
    vfs::set_inode_evict_hook(crate::inotify::marks::evict_inode_marks);
    let g = InotifyData::new_fanotify(0);
    let sb = mk_sb(0xE201);
    let ino = cached_inode(&sb, 0xE201);
    crate::inotify::syscalls::apply_inode_mark(&g, &ino, FAN_OPEN, true, false, 0);
    sb.iput(ino.clone());
    drop(ino);
    crate::inotify::syscalls::apply_inode_mark(&g, &sb.ilookup(0xE201).unwrap(), FAN_OPEN, false, false, 0);
    assert!(g.watches.lock().is_empty(), "the mark is gone");
    assert!(sb.ilookup(0xE201).is_none(), "and so is the reference it held");
}

/// An `FAN_MARK_ADD` restates whether the mark pins its object, so turning an
/// ordinary mark evictable gives the reference back and turning an evictable
/// one ordinary takes a fresh reference.
#[test]
fn re_adding_a_mark_restates_whether_it_pins_its_object() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new_fanotify(0);
    let sb = mk_sb(0xE301);
    let ino = cached_inode(&sb, 0xE301);
    let evictable = crate::inotify::validate::FAN_MARK_EVICTABLE;
    crate::inotify::syscalls::apply_inode_mark(&g, &ino, FAN_OPEN, true, false, 0);
    assert_eq!(ino.i_count(), 2);
    crate::inotify::syscalls::apply_inode_mark(&g, &ino, FAN_MODIFY, true, false, evictable);
    assert_eq!(ino.i_count(), 1, "the mark gave its reference up");
    crate::inotify::syscalls::apply_inode_mark(&g, &ino, FAN_ACCESS, true, false, 0);
    assert_eq!(ino.i_count(), 2, "and took a fresh one back");
    drop(g);
    assert_eq!(ino.i_count(), 1, "the group dying releases it");
    sb.iput(ino.clone());
}

/// A `FAN_REPORT_PIDFD` group's read carries a pidfd info record after the
/// metadata, and `event_len` accounts for it — a record the size field did not
/// include would desynchronise the reader's record walk on the very first
/// event.
#[test]
fn a_pidfd_group_emits_a_pidfd_record() {
    let _notify = crate::inotify::test_claim::claim_notify();
    use crate::inotify::validate::FAN_REPORT_PIDFD;
    let g = InotifyData::new_fanotify(FAN_REPORT_PIDFD);
    let ino = mk_inode(FileType::Regular, 0xF001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN, true, false, 0);
    fire_self(&ino, FAN_OPEN);
    let mut buf = [0u8; 64];
    let n = g.read_fanotify(&mut buf).unwrap();
    assert_eq!(n, 24 + 8, "metadata plus one pidfd record");
    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 32,
               "event_len covers the info record");
    assert_eq!(buf[24], 4, "FAN_EVENT_INFO_TYPE_PIDFD");
    assert_eq!(u16::from_le_bytes([buf[26], buf[27]]), 8);
}

/// A fid-reporting group IS told the affected object was a directory; a legacy
/// fd-reporting group is not. Reporting it to a legacy group would set a bit
/// in `metadata.mask` that such a group's userspace never expects.
#[test]
fn only_a_fid_group_is_told_the_object_was_a_directory() {
    let _notify = crate::inotify::test_claim::claim_notify();
    use crate::inotify::validate::FAN_REPORT_FID;
    let legacy = InotifyData::new_fanotify(0);
    let fid = InotifyData::new_fanotify(FAN_REPORT_FID);
    let d = mk_inode(FileType::Directory, 0xF101);
    for g in [&legacy, &fid] {
        apply_mark(g, MarkScope::Inode, inode_key(&d), d.fsid(), FAN_OPEN | FAN_ONDIR, true, false, 0);
    }
    fire_self(&d, FAN_OPEN);
    assert_eq!(masks(&legacy), [FAN_OPEN], "legacy group: no FAN_ONDIR echoed back");
    assert_eq!(masks(&fid), [FAN_OPEN | FAN_ONDIR]);
}

// FLUSH drops only the marks of the selected scope, leaving other scopes intact.
#[test]
fn flush_is_scope_local() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xB001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN, true, false, 0);
    apply_mark(&g, MarkScope::Mount, 0, 0xB001, FAN_OPEN, true, false, 0);
    // Flush only the inode-scope marks by retaining non-inode.
    {
        let mut w = g.watches.lock();
        w.retain(|x| x.scope != MarkScope::Inode);
    }
    // The mount mark survives and still fires on the same superblock.
    fire_self(&ino, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN]);
}
