use super::*;

static TX_OPS: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());

fn tx_record(_owner: VsockOwner, frame: &[u8]) -> bool {
    let hdr = VsockHdr::decode(frame).expect("transmitted frame header");
    TX_OPS.lock().unwrap().push(hdr.op);
    true
}

fn child(owner: VsockOwner, port: u32, peer_port: u32) -> alloc::sync::Arc<VsockConn> {
    alloc::sync::Arc::new(VsockConn::new(
        owner, 3, port, 2, peer_port, VsockState::Connected))
}

#[test]
fn delayed_old_close_preserves_replacement_tuple() {
    with_vsock_state(|| {
        let old = child(owner(101), 20_101, 30_101);
        let replacement = child(owner(101), 20_101, 30_101);
        assert!(TABLE.insert(old.clone()));
        assert!(TABLE.remove_conn(&old));
        assert!(TABLE.insert(replacement.clone()));
        assert!(alloc::sync::Arc::ptr_eq(
            &TABLE.find(replacement.key()).expect("replacement published"), &replacement));

        close(&old);

        let current = TABLE.find(replacement.key()).expect("replacement survives old close");
        assert!(alloc::sync::Arc::ptr_eq(&current, &replacement));
        assert_eq!(*replacement.st.lock(), VsockState::Connected);
        close(&replacement);
    });
}

#[test]
fn concurrent_close_is_idempotent_and_removes_exact_record() {
    with_vsock_state(|| {
        let conn = child(owner(102), 20_102, 30_102);
        assert!(TABLE.insert(conn.clone()));
        let a = conn.clone();
        let b = conn.clone();
        let ta = std::thread::spawn(move || close(&a));
        let tb = std::thread::spawn(move || close(&b));
        ta.join().unwrap(); tb.join().unwrap();
        assert_eq!(*conn.st.lock(), VsockState::Closed);
        assert!(TABLE.find(conn.key()).is_none());
        close(&conn);
    });
}

#[test]
fn delayed_rx_cannot_reopen_closed_record() {
    with_driver(owner(106), 3, || {
        let conn = child(owner(106), 20_106, 30_106);
        assert!(TABLE.insert(conn.clone()));
        close(&conn);
        assert!(TABLE.insert(conn.clone()));
        let base = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 30_106, dst_port: 20_106,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_RESPONSE, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx_from(owner(106), &base, &[]);
        deliver_rx_from(owner(106), &VsockHdr {
            op: VIRTIO_VSOCK_OP_RW, len: 4, ..base
        }, b"late");
        deliver_rx_from(owner(106), &VsockHdr {
            op: VIRTIO_VSOCK_OP_SHUTDOWN, flags: VIRTIO_VSOCK_SHUTDOWN_SEND, ..base
        }, &[]);
        assert_eq!(*conn.st.lock(), VsockState::Closed);
        assert!(conn.rx.lock().is_empty());
        TABLE.remove_conn(&conn);
    });
}

#[test]
fn listener_removal_preserves_already_popped_child() {
    let table = VsockTable::new();
    let listener = table.add_listener(Some(owner(103)), 20_103).expect("listener registered");
    let conn = child(owner(103), 20_103, 30_103);
    assert!(table.publish_accept(owner(103), 20_103, conn.clone()));
    let accepted = table.pop_accept_exact(&listener).expect("child pending");
    assert!(alloc::sync::Arc::ptr_eq(&accepted, &conn));

    assert!(table.remove_listener_exact(&listener));

    assert_eq!(*accepted.st.lock(), VsockState::Connected);
    let current = table.find(accepted.key()).expect("accepted child remains published");
    assert!(alloc::sync::Arc::ptr_eq(&current, &accepted));
    assert!(table.remove_conn(&accepted));
}

#[test]
fn duplicate_listener_registration_is_rejected() {
    let table = VsockTable::new();
    let listener = table.add_listener(Some(owner(107)), 20_107)
        .expect("first listener registered");
    assert!(table.add_listener(Some(owner(107)), 20_107).is_none());
    let conn = child(owner(107), 20_107, 30_107);
    assert!(table.publish_accept(owner(107), 20_107, conn.clone()));
    assert!(table.pop_accept_peek_exact(&listener));
    assert!(table.remove_listener_exact(&listener));
    assert_eq!(*conn.st.lock(), VsockState::Closed);

    let replacement = table.add_listener(Some(owner(107)), 20_107)
        .expect("address reusable after exact removal");
    assert!(!alloc::sync::Arc::ptr_eq(&listener, &replacement));
    assert!(!table.pop_accept_peek_exact(&listener));
    assert!(table.remove_listener_exact(&replacement));
}

#[test]
fn duplicate_request_cannot_replace_live_tuple() {
    let table = VsockTable::new();
    let listener = table.add_listener(Some(owner(108)), 20_108)
        .expect("listener registered");
    let live = child(owner(108), 20_108, 30_108);
    let duplicate = child(owner(108), 20_108, 30_108);
    assert!(table.insert(live.clone()));
    assert!(!table.publish_accept(owner(108), 20_108, duplicate));
    assert!(!table.pop_accept_peek_exact(&listener));
    let current = table.find(live.key()).expect("live tuple preserved");
    assert!(alloc::sync::Arc::ptr_eq(&current, &live));
    assert_eq!(*live.st.lock(), VsockState::Connected);
    assert!(table.remove_conn(&live));
    assert!(table.remove_listener_exact(&listener));
}

#[test]
fn connect_start_reports_tuple_collision() {
    with_driver(owner(109), 3, || {
        let live = child(owner(109), 20_109, 30_109);
        assert!(TABLE.insert(live.clone()));
        assert!(matches!(connect_from_start(Some(owner(109)), Some(20_109), 2, 30_109),
            Err(NetError::Eaddrinuse)));
        let current = TABLE.find(live.key()).expect("live tuple preserved");
        assert!(alloc::sync::Arc::ptr_eq(&current, &live));
        TABLE.remove_conn(&live);
    });
}

#[test]
fn stale_listener_removal_cannot_drain_replacement_backlog() {
    let table = VsockTable::new();
    let old = table.add_listener(Some(owner(104)), 20_104).expect("old listener registered");
    let old_child = child(owner(104), 20_104, 30_104);
    assert!(table.publish_accept(owner(104), 20_104, old_child.clone()));
    assert!(table.remove_listener_exact(&old));
    assert_eq!(*old_child.st.lock(), VsockState::Closed);

    let replacement = table.add_listener(Some(owner(104)), 20_104)
        .expect("replacement listener registered");
    let replacement_child = child(owner(104), 20_104, 30_105);
    assert!(table.publish_accept(owner(104), 20_104, replacement_child.clone()));
    assert!(!table.remove_listener_exact(&old));

    assert!(table.pop_accept_exact(&old).is_none());
    let pending = table.pop_accept_exact(&replacement).expect("replacement child pending");
    assert!(alloc::sync::Arc::ptr_eq(&pending, &replacement_child));
    assert_eq!(*pending.st.lock(), VsockState::Connected);
    assert!(table.remove_conn(&pending));
    assert!(table.remove_listener_exact(&replacement));
}

#[test]
fn request_publication_linearizes_against_listener_removal() {
    for peer_port in 31_000..31_128 {
        let table = alloc::sync::Arc::new(VsockTable::new());
        let listener = table.add_listener(Some(owner(105)), 20_105)
            .expect("listener registered");
        let conn = child(owner(105), 20_105, peer_port);
        let barrier = alloc::sync::Arc::new(std::sync::Barrier::new(3));
        let publish_table = table.clone();
        let publish_conn = conn.clone();
        let publish_barrier = barrier.clone();
        let publish = std::thread::spawn(move || {
            publish_barrier.wait();
            publish_table.publish_accept(owner(105), 20_105, publish_conn)
        });
        let remove_table = table.clone();
        let remove_listener = listener.clone();
        let remove_barrier = barrier.clone();
        let remove = std::thread::spawn(move || {
            remove_barrier.wait();
            remove_table.remove_listener_exact(&remove_listener)
        });
        barrier.wait();
        let published = publish.join().unwrap();
        assert!(remove.join().unwrap());

        if published {
            assert_eq!(*conn.st.lock(), VsockState::Closed);
        } else {
            assert_eq!(*conn.st.lock(), VsockState::Connected);
        }
        assert!(table.find(conn.key()).is_none());
    }
}

#[test]
fn listener_removal_sends_terminal_frames_after_response() {
    with_vsock_state(|| {
        TX_OPS.lock().unwrap().clear();
        assert!(driver_install(owner(110), 3, tx_record, rx_noop));
        let listener = TABLE.add_listener(Some(owner(110)), 20_110)
            .expect("listener registered");
        let request = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 30_110, dst_port: 20_110,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx_from(owner(110), &request, &[]);
        assert!(TABLE.remove_listener_exact(&listener));
        assert_eq!(&*TX_OPS.lock().unwrap(), &[
            VIRTIO_VSOCK_OP_RESPONSE,
            VIRTIO_VSOCK_OP_SHUTDOWN,
            VIRTIO_VSOCK_OP_RST,
        ]);
        assert!(driver_uninstall(owner(110)));
    });
}

#[test]
fn response_never_follows_concurrent_terminal_teardown() {
    with_vsock_state(|| {
        assert!(driver_install(owner(111), 3, tx_record, rx_noop));
        for peer_port in 32_000..32_128 {
            TX_OPS.lock().unwrap().clear();
            let conn = child(owner(111), 20_111, peer_port);
            assert!(TABLE.insert(conn.clone()));
            let responding = conn.clone();
            let closing = conn.clone();
            let barrier = alloc::sync::Arc::new(std::sync::Barrier::new(3));
            let rb = barrier.clone();
            let response = std::thread::spawn(move || {
                rb.wait(); send_accept_response(&responding)
            });
            let cb = barrier.clone();
            let teardown = std::thread::spawn(move || {
                cb.wait(); close(&closing)
            });
            barrier.wait();
            let _ = response.join().unwrap();
            teardown.join().unwrap();
            let ops = TX_OPS.lock().unwrap();
            let terminal = ops.iter().position(|op| *op == VIRTIO_VSOCK_OP_SHUTDOWN);
            let response = ops.iter().position(|op| *op == VIRTIO_VSOCK_OP_RESPONSE);
            assert!(match (response, terminal) {
                (Some(response), Some(terminal)) => response < terminal,
                (None, Some(_)) => true,
                _ => false,
            });
        }
        assert!(driver_uninstall(owner(111)));
    });
}
