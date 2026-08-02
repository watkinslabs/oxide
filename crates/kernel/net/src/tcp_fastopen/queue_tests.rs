use super::*;
use super::super::keys::{Key, KEY_LEN};

fn ctx(seed: u8) -> KeyCtx { KeyCtx::new(Key::new([seed; KEY_LEN]), None) }

#[test]
fn a_fresh_queue_admits_no_fast_open_and_follows_its_namespaces_keys() {
    let q = FastOpenQueue::new();
    assert_eq!(q.max_qlen(), 0);
    assert_eq!(q.keys(), None);
}

#[test]
fn the_bound_is_clamped_by_somaxconn_the_way_a_listen_backlog_is() {
    assert_eq!(clamp_qlen(8, 4096), 8);
    assert_eq!(clamp_qlen(9000, 4096), 4096);
    assert_eq!(clamp_qlen(0, 4096), 0);
    // A lowered `somaxconn` bounds it just as tightly.
    assert_eq!(clamp_qlen(128, 16), 16);
}

#[test]
fn a_listener_key_overrides_the_namespaces_for_that_listener_alone() {
    let q = FastOpenQueue::new();
    q.set_keys(ctx(7));
    assert_eq!(q.keys(), Some(ctx(7)));
    // A second queue is unaffected: the key is this accept queue's.
    assert_eq!(FastOpenQueue::new().keys(), None);
    q.set_keys(ctx(9));
    assert_eq!(q.keys(), Some(ctx(9)));
}

#[test]
fn listen_sizes_the_queue_only_when_the_namespace_asked_it_to() {
    use super::super::flags::{TFO_DEFAULT, TFO_SERVER_ENABLE, TFO_SERVER_WO_SOCKOPT1};
    let both = TFO_SERVER_ENABLE | TFO_SERVER_WO_SOCKOPT1;
    // A namespace at the compiled default leaves the listener without a queue
    // and spends no entropy on keys nobody will mint from.
    let q = FastOpenQueue::new();
    assert!(!on_listen(TFO_DEFAULT, &q, 64, 4096));
    assert_eq!(q.max_qlen(), 0);
    // Either server bit alone is not enough.
    for bits in [TFO_SERVER_ENABLE, TFO_SERVER_WO_SOCKOPT1] {
        let q = FastOpenQueue::new();
        assert!(!on_listen(bits, &q, 64, 4096));
        assert_eq!(q.max_qlen(), 0);
    }
    // Both bits size it to the backlog and ask for the keys.
    let q = FastOpenQueue::new();
    assert!(on_listen(both, &q, 64, 4096));
    assert_eq!(q.max_qlen(), 64);
}

#[test]
fn the_automatic_size_is_clamped_by_somaxconn_the_way_the_backlog_is() {
    use super::super::flags::{TFO_SERVER_ENABLE, TFO_SERVER_WO_SOCKOPT1};
    let q = FastOpenQueue::new();
    assert!(on_listen(TFO_SERVER_ENABLE | TFO_SERVER_WO_SOCKOPT1, &q, 9000, 16));
    assert_eq!(q.max_qlen(), 16);
}

#[test]
fn a_bound_already_named_by_hand_survives_the_listen_that_follows_it() {
    use super::super::flags::{TFO_SERVER_ENABLE, TFO_SERVER_WO_SOCKOPT1};
    let q = FastOpenQueue::new();
    // What a `TCP_FASTOPEN` write in the closed state leaves behind.
    q.set_max_qlen(4);
    assert!(!on_listen(TFO_SERVER_ENABLE | TFO_SERVER_WO_SOCKOPT1, &q, 64, 4096));
    assert_eq!(q.max_qlen(), 4);
    // And nothing asks for a fresh key draw, because the queue was already live.
}
