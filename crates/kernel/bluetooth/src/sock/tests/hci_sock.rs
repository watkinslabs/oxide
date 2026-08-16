use super::*;
use crate::uapi::hci::{HCI_ACLDATA_PKT, HCI_EVENT_PKT};

fn exists(_d: u16) -> bool { true }
fn absent(_d: u16) -> bool { false }

#[test]
fn an_unknown_channel_is_refused() {
    for c in [5u16, 6, 0xffff] {
        assert!(!channel_known(c));
        assert_eq!(plan_bind(c, 0, true, exists), Err(Errno::Einval));
    }
}

// Raw and exclusive access reach the controller directly; the monitor sees
// every controller's traffic including another process's; the logging channel
// injects into that trace. The management channel is the one userspace binds
// unprivileged, and its own per-command trust screen decides what it may do.
#[test]
fn every_channel_but_the_management_one_requires_privilege() {
    for c in [HCI_CHANNEL_RAW, HCI_CHANNEL_USER, HCI_CHANNEL_MONITOR, HCI_CHANNEL_LOGGING] {
        assert!(channel_privileged(c), "channel {c}");
        assert_eq!(plan_bind(c, 0, false, exists), Err(Errno::Eperm), "channel {c}");
    }
    assert!(!channel_privileged(HCI_CHANNEL_CONTROL));
    assert!(plan_bind(HCI_CHANNEL_CONTROL, HCI_DEV_NONE, false, absent).is_ok());
}

// The privilege screen runs before the controller lookup, so an unprivileged
// caller naming a missing controller is told about the privilege, not the
// controller — otherwise the refusal leaks which controllers exist.
#[test]
fn the_privilege_screen_runs_before_the_controller_lookup() {
    assert_eq!(plan_bind(HCI_CHANNEL_RAW, 7, false, absent), Err(Errno::Eperm));
    assert_eq!(plan_bind(HCI_CHANNEL_RAW, 7, true, absent), Err(Errno::Enodev));
}

// The channel screen runs before the privilege one: a channel that does not
// exist is not a privileged one.
#[test]
fn the_channel_screen_runs_before_the_privilege_one() {
    assert_eq!(plan_bind(99, 0, false, exists), Err(Errno::Einval));
}

// A monitor bind must not fail because a controller happens to be absent: it
// is not bound to one.
#[test]
fn the_channels_that_name_no_controller_ignore_the_controller_lookup() {
    for c in [HCI_CHANNEL_MONITOR, HCI_CHANNEL_CONTROL, HCI_CHANNEL_LOGGING] {
        assert!(!channel_takes_device(c));
        let plan = plan_bind(c, 3, c != HCI_CHANNEL_CONTROL, absent).unwrap();
        assert_eq!(plan.dev, None, "channel {c}");
    }
}

// The raw channel accepts the no-controller index and stays attached to
// nothing; the exclusive channel does not, because there is nothing to take
// exclusive ownership of.
#[test]
fn the_no_controller_index_is_accepted_on_raw_and_refused_on_exclusive() {
    assert_eq!(plan_bind(HCI_CHANNEL_RAW, HCI_DEV_NONE, true, absent),
        Ok(BindPlan { channel: HCI_CHANNEL_RAW, dev: None }));
    assert_eq!(plan_bind(HCI_CHANNEL_USER, HCI_DEV_NONE, true, exists), Err(Errno::Einval));
}

#[test]
fn a_bound_controller_is_recorded() {
    assert_eq!(plan_bind(HCI_CHANNEL_RAW, 2, true, exists),
        Ok(BindPlan { channel: HCI_CHANNEL_RAW, dev: Some(2) }));
}

// Everything a socket may do depends on its channel, so changing it would
// carry one channel's traffic under another's permission screen.
#[test]
fn a_socket_cannot_be_rebound_to_another_channel() {
    let mut s = HciSocket::new();
    s.bind(plan_bind(HCI_CHANNEL_RAW, 0, true, exists).unwrap()).unwrap();
    assert_eq!(s.channel(), Some(HCI_CHANNEL_RAW));
    let monitor = plan_bind(HCI_CHANNEL_MONITOR, 0, true, exists).unwrap();
    assert_eq!(s.bind(monitor), Err(Errno::Einval));
    assert_eq!(s.channel(), Some(HCI_CHANNEL_RAW));
}

#[test]
fn an_unbound_socket_accepts_nothing() {
    let s = HciSocket::new();
    assert!(!s.accepts(0, HCI_EVENT_PKT, 0x0e));
}

// A socket attached to one controller must never see another's traffic,
// whatever its filter says.
#[test]
fn the_controller_screen_outranks_the_packet_filter() {
    let mut s = HciSocket::new();
    s.bind(plan_bind(HCI_CHANNEL_RAW, 1, true, exists).unwrap()).unwrap();
    s.filter = Filter::pass_all();
    assert!(s.accepts(1, HCI_EVENT_PKT, 0x0e));
    assert!(!s.accepts(0, HCI_EVENT_PKT, 0x0e));
    assert!(!s.accepts(2, HCI_ACLDATA_PKT, 0));
}

// A raw socket bound to no controller sees every controller, screened by its
// filter alone.
#[test]
fn a_raw_socket_bound_to_no_controller_sees_every_controller() {
    let mut s = HciSocket::new();
    s.bind(plan_bind(HCI_CHANNEL_RAW, HCI_DEV_NONE, true, absent).unwrap()).unwrap();
    s.filter = Filter::pass_all();
    for dev in 0..4u16 { assert!(s.accepts(dev, HCI_EVENT_PKT, 0x0e)); }
}

#[test]
fn a_fresh_socket_filter_passes_nothing_even_when_bound() {
    let mut s = HciSocket::new();
    s.bind(plan_bind(HCI_CHANNEL_RAW, 0, true, exists).unwrap()).unwrap();
    assert!(!s.accepts(0, HCI_EVENT_PKT, 0x0e));
}

// The monitor and management channels carry their own record framing and are
// not screened by the packet filter, which would otherwise silence them.
#[test]
fn the_record_framed_channels_are_not_screened_by_the_packet_filter() {
    for c in [HCI_CHANNEL_MONITOR, HCI_CHANNEL_CONTROL] {
        let mut s = HciSocket::new();
        s.bind(plan_bind(c, HCI_DEV_NONE, true, absent).unwrap()).unwrap();
        assert!(s.filter == Filter::new());
        assert!(s.accepts(0, HCI_EVENT_PKT, 0x0e), "channel {c}");
        assert!(s.accepts(9, HCI_ACLDATA_PKT, 0), "channel {c}");
    }
}

#[test]
fn a_reader_that_falls_behind_loses_the_oldest_frames() {
    let mut s = HciSocket::new();
    for n in 0..(RX_QUEUE_LIMIT + 2) { s.push(alloc::vec![n as u8]); }
    assert_eq!(s.dropped(), 2);
    assert_eq!(s.pop().unwrap(), alloc::vec![2u8]);
    assert!(s.readable());
}

#[test]
fn the_two_ancillary_options_default_off_and_set_independently() {
    let mut s = HciSocket::new();
    assert!(!s.data_dir && !s.time_stamp);
    s.data_dir = true;
    assert!(s.data_dir && !s.time_stamp);
}
