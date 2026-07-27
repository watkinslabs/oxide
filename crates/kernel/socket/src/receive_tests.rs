use alloc::string::String;
use alloc::sync::Arc;

use super::*;

// Every test here exercises the process-global AF_UNIX in-flight/GC state.
// This lock existed but was taken ONLY by `discard_queued_cycle`, so the five
// siblings that touch the same global raced it — measured at 2/12 full-binary
// failures. Taken by every test now, with poison recovered so one genuine
// failure reports as one failure instead of cascading.
static SCM_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn regular_file(ino: u64) -> Arc<vfs::File> {
    let inode = vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Regular, 0o600),
        vfs::default_inode_ops(), vfs::default_file_ops()).build();
    let dentry = vfs::Dentry::new(None, String::from("scm-rights"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

fn socket_file(socket: Arc<net::sock::InetSocket>) -> Arc<vfs::File> {
    let inode = net::sock::make_inet_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, String::from("socket"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

fn queued_cycle() -> (Arc<net::UnixMsgPair>, Arc<vfs::File>, alloc::sync::Weak<vfs::File>, Arc<net::UnixPair>) {
    let cycle = net::UnixPair::new();
    let cycle_file = regular_file(0x8559);
    net::unix_sock::register_file(&cycle_file, &cycle.gc_node(net::UnixEnd::A));
    let weak = Arc::downgrade(&cycle_file);
    cycle.write_with_rights(net::UnixEnd::B, b"cycle",
        net::classify_files(alloc::vec![cycle_file.clone()])).unwrap();

    let root = net::UnixMsgPair::new();
    let root_file = regular_file(0x855a);
    net::unix_sock::register_file(&root_file, &root.gc_node(net::UnixEnd::B));
    root.send_with_rights(net::UnixEnd::A, b"root",
        net::classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    net::unix_sock::collect_scm_rights();
    assert!(weak.upgrade().is_some(), "queued external edge roots the cycle");
    (root, root_file, weak, cycle)
}

enum Discard { Capacity, Emfile, Fault }

fn discard_queued_cycle(mode: Discard) {
    let _serial = SCM_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (root, root_file, weak, cycle) = queued_cycle();
    let message = root.recv_msg(net::UnixEnd::B, 4).unwrap();
    let table = vfs::FdTable::new();
    let result = match mode {
        Discard::Capacity => install_received_fds(&table, 1, false, message.fds, 0,
            |_, _| unreachable!()),
        Discard::Emfile => install_received_fds(&table, 0, false, message.fds, 1,
            |_, _| Ok(())),
        Discard::Fault => install_received_fds(&table, 1, false, message.fds, 1,
            |_, _| Err(vfs::VfsError::Efault)),
    };
    assert!(result.truncated);
    assert_eq!(result.installed, 0);
    assert!(weak.upgrade().is_none(), "transfer completion collects the newly unrooted cycle");
    drop((root_file, cycle));
}

#[test]
fn receive_first_roots_passed_socket_through_fd_publication() {
    let _serial = SCM_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let socket = Arc::new(net::sock::InetSocket::new_unix());
    let file = socket_file(socket.clone());
    let table = vfs::FdTable::new();
    let result = install_received_fds(&table, 4, false, alloc::vec![file.clone()], 1,
        |index, fd| { assert_eq!((index, fd), (0, 0)); Ok(()) });
    assert_eq!(result, ReceiveFdResult { installed: 1, truncated: false, failure: None });

    drop(file);
    assert!(!socket.released.load(core::sync::atomic::Ordering::Acquire),
        "published descriptor retains the passed socket");
    table.close(0).unwrap();
    assert!(socket.released.load(core::sync::atomic::Ordering::Acquire),
        "final descriptor close releases the passed socket");
}

#[test]
fn zero_capacity_discards_complete_batch() {
    let _serial = SCM_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let first = regular_file(0x8550);
    let second = regular_file(0x8551);
    let table = vfs::FdTable::new();
    let result = install_received_fds(&table, 4, false,
        alloc::vec![first.clone(), second.clone()], 0, |_, _| unreachable!());

    assert_eq!(result, ReceiveFdResult { installed: 0, truncated: true, failure: None });
    assert_eq!(table.count(), 0);
    assert_eq!(Arc::strong_count(&first), 1);
    assert_eq!(Arc::strong_count(&second), 1);
}

#[test]
fn zero_capacity_collects_cycle_after_receive_transfer() {
    discard_queued_cycle(Discard::Capacity);
}

#[test]
fn emfile_collects_cycle_after_receive_transfer() {
    discard_queued_cycle(Discard::Emfile);
}

#[test]
fn copy_fault_collects_cycle_after_receive_transfer() {
    discard_queued_cycle(Discard::Fault);
}

#[test]
fn emfile_preserves_installed_prefix_and_discards_suffix() {
    let _serial = SCM_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let first = regular_file(0x8552);
    let second = regular_file(0x8553);
    let table = vfs::FdTable::new();
    let mut copied = alloc::vec::Vec::new();
    let result = install_received_fds(&table, 1, true,
        alloc::vec![first.clone(), second.clone()], 2,
        |index, fd| { copied.push((index, fd)); Ok(()) });

    assert_eq!(result, ReceiveFdResult { installed: 1, truncated: true,
        failure: Some(vfs::VfsError::Emfile) });
    assert_eq!(copied, [(0, 0)]);
    assert!(Arc::ptr_eq(&table.get(0).unwrap(), &first));
    assert_eq!(table.cloexec(0), Ok(true));
    assert_eq!(Arc::strong_count(&second), 1, "uninstallable suffix is discarded");
}

#[test]
fn copy_fault_rolls_back_current_reservation_only() {
    let _serial = SCM_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let first = regular_file(0x8554);
    let current = regular_file(0x8555);
    let suffix = regular_file(0x8556);
    let table = vfs::FdTable::new();
    let result = install_received_fds(&table, 4, false,
        alloc::vec![first.clone(), current.clone(), suffix.clone()], 3,
        |index, fd| if index == 1 {
            assert_eq!(fd, 1);
            Err(vfs::VfsError::Efault)
        } else { Ok(()) });

    assert_eq!(result, ReceiveFdResult { installed: 1, truncated: true,
        failure: Some(vfs::VfsError::Efault) });
    assert!(Arc::ptr_eq(&table.get(0).unwrap(), &first));
    assert_eq!(Arc::strong_count(&current), 1, "faulted file is discarded");
    assert_eq!(Arc::strong_count(&suffix), 1, "unvisited suffix is discarded");
    assert_eq!(table.alloc(regular_file(0x8557)).unwrap(), 1,
        "faulted reservation is reusable while prefix remains installed");
}

#[test]
fn peek_installs_duplicates_without_consuming_queued_rights() {
    let _serial = SCM_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let pair = net::UnixMsgPair::new();
    let file = regular_file(0x8558);
    pair.send_with_rights(net::UnixEnd::A, b"peek", net::classify_files(alloc::vec![file.clone()])).unwrap();
    let table = vfs::FdTable::new();

    for expected_fd in 0..2 {
        let (_, message, _) = pair.recv_msg_with(net::UnixEnd::B, 4, true,
            |_, rights, _, _| { assert_eq!(rights, 1); Ok::<_, ()>(()) }).unwrap().unwrap();
        let result = install_received_fds(&table, 4, false, message.fds, 1,
            |index, fd| { assert_eq!((index, fd), (0, expected_fd)); Ok(()) });
        assert_eq!(result.installed, 1);
        assert!(pair.has_msg(net::UnixEnd::B), "MSG_PEEK retains queued rights");
    }
    assert!(Arc::ptr_eq(&table.get(0).unwrap(), &file));
    assert!(Arc::ptr_eq(&table.get(1).unwrap(), &file));
    let message = pair.recv_msg(net::UnixEnd::B, 4).unwrap();
    assert_eq!(message.fds.len(), 1, "normal receive still consumes the queued right");
    assert!(!pair.has_msg(net::UnixEnd::B));
}
