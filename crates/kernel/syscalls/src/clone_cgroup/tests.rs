use super::*;

fn task_with_cgroup_fd_flags(name: &str, tid: u32, flags: vfs::OpenFlags)
    -> (sched::Task, alloc::sync::Arc<vfs::FdTable>, i32, u64) {
    let (_fs, root) = cgroup::realize_tree();
    let cgid = cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap();
    let inode = root.lookup(name).unwrap();
    let file = vfs::File::new(alloc::sync::Arc::clone(&inode),
        vfs::Dentry::new_root(inode), flags);
    let fdt = alloc::sync::Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).unwrap();
    let task = sched::Task::new(tid, "clone-cgroup-fd",
        sched::SchedClass::Normal { weight: 1024 });
    // SAFETY: this unpublished test task has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(alloc::sync::Arc::clone(&fdt))); }
    (task, fdt, fd, cgid)
}

fn task_with_cgroup_fd(name: &str, tid: u32)
    -> (sched::Task, alloc::sync::Arc<vfs::FdTable>, i32, u64) {
    task_with_cgroup_fd_flags(name, tid, vfs::OpenFlags::O_RDONLY)
}

fn unprivileged(uid: u32) -> vfs::Cred {
    let mut cred = vfs::Cred::root();
    cred.uid = uid;
    cred.gid = uid;
    cred.cap_dac_override = false;
    cred.cap_dac_read_search = false;
    cred.cap_fowner = false;
    cred.cap_chown = false;
    cred.cap_fsetid = false;
    cred
}

#[test]
fn process_publication_inherits_canonical_parent_membership() {
    let _ = cgroup::realize_tree();
    let name = "b3320-publication-process";
    let cgid = cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap();
    let parent = 98_170u64;
    let child = 98_171u64;
    cgroup::attach_tid_into(cgid, parent).unwrap();
    let prepared = prepare_resolved(None, parent, false).unwrap();
    commit_new_task(prepared, child);
    assert_eq!(cgroup::cgroup_of(child), cgid);
    assert_eq!(cgroup::read_file(cgid, "cgroup.procs").unwrap(), b"98170\n98171\n");
    cgroup::on_exit(child, child);
    cgroup::on_exit(parent, parent);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn thread_publication_charges_canonical_process_membership() {
    let _ = cgroup::realize_tree();
    let name = "b3320-publication-thread";
    let cgid = cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap();
    let leader = 98_172u64;
    let thread = 98_173u64;
    cgroup::attach_tid_into(cgid, leader).unwrap();
    let prepared = prepare_resolved(None, leader, true).unwrap();
    commit_new_task(prepared, thread);
    assert_eq!(cgroup::cgroup_of(thread), cgid);
    assert_eq!(cgroup::read_file(cgid, "cgroup.threads").unwrap(), b"98172\n98173\n");
    cgroup::on_exit(thread, leader);
    cgroup::on_exit(leader, leader);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn invalid_explicit_group_cannot_reach_publication() {
    assert!(prepare_resolved(Some(u64::MAX), 98_170, false).is_err());
    assert_eq!(cgroup::cgroup_of(98_174), cgroup::ROOT_CGROUP);
}

#[test]
fn prepared_destination_is_pinned_across_rmdir() {
    let _ = cgroup::realize_tree();
    let name = "b3320-clone-cgroup-rmdir-pin";
    let cgid = cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap();
    let prepared = prepare_resolved(Some(cgid), 98_180, false).unwrap();
    let remover = std::thread::spawn(move || cgroup::rmdir_child(cgroup::ROOT_CGROUP, name));
    assert_eq!(remover.join().unwrap(), Err(vfs::VfsError::Ebusy));
    commit_new_task(prepared, 98_181);
    assert_eq!(cgroup::cgroup_of(98_181), cgid);
    cgroup::on_exit(98_181, 98_181);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn cgroup_fd_resolution_hands_off_an_independent_pin() {
    let name = "b3320-clone-cgroup-fd-pin";
    let (current, fdt, fd, cgid) = task_with_cgroup_fd(name, 98_185);
    let prepared = prepare_new_task(&current, Some(fd), 98_185, false).unwrap();
    assert_eq!(prepared.cgid(), cgid);
    fdt.close(fd).unwrap();
    assert_eq!(cgroup::rmdir_child(cgroup::ROOT_CGROUP, name), Err(vfs::VfsError::Ebusy));
    drop(prepared);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn opath_cgroup_directory_fd_is_accepted() {
    let name = "b3320-clone-cgroup-opath";
    let (current, _fdt, fd, cgid) = task_with_cgroup_fd_flags(
        name, 98_189, vfs::OpenFlags::O_PATH);
    let prepared = prepare_new_task(&current, Some(fd), 98_189, false).unwrap();
    assert_eq!(prepared.cgid(), cgid);
    drop(prepared);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn destination_procs_write_denial_cancels_the_pin_without_reserving() {
    let _ = cgroup::realize_tree();
    cgroup::write_file(cgroup::ROOT_CGROUP, "cgroup.subtree_control", "+pids").unwrap();
    let name = "b3320-clone-cgroup-dst-permission";
    let cgid = cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap();
    let error = prepare_resolved_as(Some(cgid), 98_190, false, &unprivileged(1_000))
        .err().unwrap();
    assert_eq!(error, -(syscall::errno::Errno::Eacces.as_i32() as i64));
    assert_eq!(cgroup::read_file(cgid, "pids.current").unwrap(), b"0\n");
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn destination_vet_runs_before_pids_reservation() {
    let _ = cgroup::realize_tree();
    cgroup::write_file(cgroup::ROOT_CGROUP, "cgroup.subtree_control", "+memory +pids").unwrap();
    let name = "b3320-clone-cgroup-dst-vet";
    let cgid = cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap();
    cgroup::write_file(cgid, "cgroup.subtree_control", "+memory").unwrap();
    let error = prepare_resolved_as(Some(cgid), 98_192, false, &vfs::Cred::root())
        .err().unwrap();
    assert_eq!(error, -(syscall::errno::Errno::Ebusy.as_i32() as i64));
    assert_eq!(cgroup::read_file(cgid, "pids.current").unwrap(), b"0\n");
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn common_ancestor_delegation_permission_is_required_before_reservation() {
    let _ = cgroup::realize_tree();
    cgroup::write_file(cgroup::ROOT_CGROUP, "cgroup.subtree_control", "+pids").unwrap();
    let boundary_name = "b3320-clone-cgroup-delegation";
    let boundary = cgroup::mkdir_child(cgroup::ROOT_CGROUP, boundary_name, 0, 0).unwrap();
    cgroup::write_file(boundary, "cgroup.subtree_control", "+pids").unwrap();
    let src = cgroup::mkdir_child(boundary, "src", 0, 0).unwrap();
    let dst = cgroup::mkdir_child(boundary, "dst", 0, 0).unwrap();
    let parent = 98_191u64;
    cgroup::attach_tid_into(src, parent).unwrap();
    cgroup::chown_file(dst, "cgroup.procs", 1_001, 1_001).unwrap();
    let cred = unprivileged(1_001);

    let denied = prepare_resolved_as(Some(dst), parent, false, &cred).err().unwrap();
    assert_eq!(denied, -(syscall::errno::Errno::Eacces.as_i32() as i64));
    assert_eq!(cgroup::read_file(dst, "pids.current").unwrap(), b"0\n");

    cgroup::chown_file(boundary, "cgroup.procs", 1_001, 1_001).unwrap();
    let admitted = prepare_resolved_as(Some(dst), parent, false, &cred).unwrap();
    assert_eq!(cgroup::read_file(dst, "pids.current").unwrap(), b"1\n",
        "positive control: both delegated write checks admit before publication");
    drop(admitted);
    cgroup::on_exit(parent, parent);
    cgroup::rmdir_child(boundary, "src").unwrap();
    cgroup::rmdir_child(boundary, "dst").unwrap();
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, boundary_name).unwrap();
}

#[test]
fn rmdir_between_fd_resolution_and_prepare_returns_enodev_cleanly() {
    let name = "b3320-clone-cgroup-resolve-rmdir";
    let (current, _fdt, fd, cgid) = task_with_cgroup_fd(name, 98_186);
    let result = prepare_new_task_with(&current, Some(fd), 98_186, false, || {
        cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
    });
    assert_eq!(result.err(), Some(-(syscall::errno::Errno::Enodev.as_i32() as i64)));
    assert!(!cgroup::node_exists(cgid));
}

#[test]
fn prepared_guard_cancels_on_prepublication_error_returns() {
    fn explicit(cgid: u64) -> Result<(), i64> {
        let _prepared = prepare_resolved(Some(cgid), 98_187, false)?;
        Err(-(syscall::errno::Errno::Enomem.as_i32() as i64))
    }
    fn question(cgid: u64) -> Result<(), i64> {
        let _prepared = prepare_resolved(Some(cgid), 98_188, false)?;
        Err::<(), _>(-(syscall::errno::Errno::Efault.as_i32() as i64))?;
        Ok(())
    }
    let _ = cgroup::realize_tree();
    cgroup::write_file(cgroup::ROOT_CGROUP, "cgroup.subtree_control", "+pids").unwrap();
    let name = "b3320-clone-cgroup-early-return";
    let cgid = cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap();
    cgroup::write_file(cgid, "pids.max", "1").unwrap();
    assert!(explicit(cgid).is_err());
    assert!(question(cgid).is_err());
    assert_eq!(cgroup::read_file(cgid, "pids.current").unwrap(), b"0\n");
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn concurrent_clones_cannot_share_the_last_pids_slot() {
    let _ = cgroup::realize_tree();
    cgroup::write_file(cgroup::ROOT_CGROUP, "cgroup.subtree_control", "+pids").unwrap();
    let name = "b3320-clone-cgroup-last-slot";
    let cgid = cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap();
    cgroup::write_file(cgid, "pids.max", "1").unwrap();
    let gate = alloc::sync::Arc::new(std::sync::Barrier::new(3));
    let mut workers = alloc::vec::Vec::new();
    for parent in [98_182u64, 98_183] {
        let gate = alloc::sync::Arc::clone(&gate);
        workers.push(std::thread::spawn(move || {
            gate.wait();
            prepare_resolved(Some(cgid), parent, false)
        }));
    }
    gate.wait();
    let mut admitted = None;
    let mut refused = 0;
    for worker in workers {
        match worker.join().unwrap() {
            Ok(prepared) => admitted = Some(prepared),
            Err(error) => {
                assert_eq!(error, -(syscall::errno::Errno::Eagain.as_i32() as i64));
                refused += 1;
            }
        }
    }
    assert!(admitted.is_some(), "one clone owns the final pids slot");
    assert_eq!(refused, 1, "the second concurrent clone is refused");
    drop(admitted);
    let cancelled = prepare_resolved(Some(cgid), 98_184, false).unwrap();
    drop(cancelled);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}
