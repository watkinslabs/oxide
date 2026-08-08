// The listener registry: the single owner of "which listener does this
// filter's recorded id name". A filter carries the id, so a chain copied onto
// a TSYNC'd thread or a forked child reaches the same object — and a filter
// whose listener has been closed must resolve to nothing at all.

use super::*;

#[test]
fn a_published_listener_resolves_by_the_id_its_filter_records() {
    let l = create(false);
    let found = lookup(l.id).expect("a published listener resolves");
    assert!(Arc::ptr_eq(&l, &found), "the same object, not a copy");
    // Two listeners never share an id, or one supervisor would answer for the
    // other's notifications.
    let other = create(false);
    assert_ne!(l.id, other.id);
    assert_eq!(lookup(other.id).map(|x| x.id), Some(other.id));
    detach(&l);
    detach(&other);
}

// Closing a listener is what makes its filter behave as a filter that never
// had one. Anything still queued is released with the no-supervisor answer,
// because nothing can ever reply to it again.
#[test]
fn a_detached_listener_resolves_to_nothing_and_releases_what_it_held() {
    let l = create(false);
    let id = l.id;
    let data = crate::seccomp::insn::SeccompData::default();
    let n = l.inner.lock().queue(1, data).expect("open listener accepts it");
    detach(&l);
    assert!(lookup(id).is_none(), "a closed listener is not reachable");
    let enosys = -(syscall::errno::Errno::Enosys.as_i32() as i32);
    assert_eq!(l.inner.lock().take_reply(n), Some((0, enosys, 0)));
    // Detaching twice is what a second close would do; it must not resurrect
    // the registry entry.
    detach(&l);
    assert!(lookup(id).is_none());
}

#[test]
fn notification_ids_are_unique_across_listeners() {
    let a = create(false);
    let b = create(false);
    let data = crate::seccomp::insn::SeccompData::default();
    let ia = a.inner.lock().queue(1, data).unwrap();
    let ib = b.inner.lock().queue(1, data).unwrap();
    assert_ne!(ia, ib);
    detach(&a);
    detach(&b);
}

#[test]
fn a_filter_installed_with_a_listener_carries_its_id_through_every_copy() {
    let l = create(false);
    let f = sched::seccomp_filter::SeccompFilter::with_listener(alloc::vec![1], 0, l.id);
    // A chain reaches a TSYNC'd thread and a forked child by value; the copy
    // must name the same listener or the child's notifications would go
    // nowhere.
    let copy = f.clone();
    assert_eq!(copy.listener, Some(l.id));
    assert_eq!(lookup(copy.listener.unwrap()).map(|x| x.id), Some(l.id));
    assert_eq!(sched::seccomp_filter::SeccompFilter::new(alloc::vec![1], 0).listener, None);
    detach(&l);
}

// The ioctl router recognises a listener by the state its inode owns, never
// by the command number: a foreign descriptor whose ioctl happens to use
// these numbers must fall through untouched, and a listener must answer even
// a command it does not know rather than letting it reach another handler.
#[test]
fn only_a_listener_descriptor_reaches_the_listener_ioctls() {
    let l = create(false);
    let inode = super::super::fd::make_listener_inode(l.clone());
    assert!(super::super::fd::is_listener_inode(&inode));
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("[seccomp notify]"),
                                  inode.clone());
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
    // An unknown command on a listener is answered here, not passed on.
    assert_eq!(super::super::handle_ioctl(&file, 0xdead_beef, 0),
               Some(-(syscall::errno::Errno::Einval.as_i32() as i64)));

    let plain_inode = vfs::InodeBuilder::new(2, vfs::mk_mode(vfs::FileType::Regular, 0o600),
        vfs::default_inode_ops(), vfs::default_file_ops()).build();
    assert!(!super::super::fd::is_listener_inode(&plain_inode));
    let plain_dentry = vfs::Dentry::new(None, alloc::string::String::from("f"),
                                        plain_inode.clone());
    let plain = vfs::File::new(plain_inode, plain_dentry, vfs::OpenFlags::empty());
    assert_eq!(super::super::handle_ioctl(&plain,
                   super::super::uapi::IOCTL_NOTIF_RECV as u64, 0), None,
               "a foreign descriptor is not routed into the listener handler");
    detach(&l);
}
