use alloc::vec::Vec;

use super::*;

fn text(v: &[u8]) -> &str { core::str::from_utf8(v).expect("record text is ASCII") }

/// A verdict with no justification still produces a record: "a daemon decided
/// this and would not say why" is what an auditor needs to see.
#[test]
fn a_verdict_without_a_justification_reports_unknown_trust() {
    let b = fanotify_body(2, None);
    assert_eq!(text(&b), "resp=2 fan_type=0 fan_info=0 subj_trust=2 obj_trust=2");
}

#[test]
fn a_verdict_with_a_rule_names_the_rule_in_hex_and_both_trust_values() {
    let b = fanotify_body(1, Some(FanotifyInfo { rule_number: 0x2a, subj_trust: 1, obj_trust: 0 }));
    assert_eq!(text(&b), "resp=1 fan_type=1 fan_info=2A subj_trust=1 obj_trust=0");
}

#[test]
fn a_zero_rule_number_still_renders_a_digit() {
    let b = fanotify_body(1, Some(FanotifyInfo::default()));
    assert_eq!(text(&b), "resp=1 fan_type=1 fan_info=0 subj_trust=0 obj_trust=0");
}

#[test]
fn a_syscall_filter_record_names_the_call_the_action_and_the_result() {
    let b = seccomp_body(SeccompEvent {
        tid: 91, signal: 31, action: 0x8000_0000, syscall: 59, arch: 0xc000_003e,
        ip: 0x7f00_1234, errno: 0,
    });
    assert_eq!(text(&b),
        "pid=91 sig=31 arch=c000003e syscall=59 ip=7f001234 code=80000000 res=0");
}

/// A tracer may rewrite the syscall number to a negative value to skip the
/// call; the record must carry that as a signed number.
#[test]
fn a_negative_syscall_number_renders_signed() {
    let b = seccomp_body(SeccompEvent { syscall: -1, ..SeccompEvent::default() });
    let s = text(&b);
    assert!(s.contains(" syscall=-1 "), "{s}");
}

/// Field order is ABI: a consumer parses by key, but a reordered body is the
/// tell that a field was renamed or lost.
#[test]
fn a_terminal_input_record_names_the_reader_the_device_and_the_bytes() {
    let b = tty_body(TTY_DESC_INPUT, actor(), crate::tty::Devno { major: 136, minor: 1 }, b"ls\n");
    assert_eq!(text(&b),
        "tty pid=531 uid=1000 auid=1000 ses=3 major=136 minor=1 comm=\"bash\" data=6C730A");
}

/// The injected-byte record differs from the buffered one only in its leading
/// description, so a consumer can tell typed input from input an ioctl pushed.
#[test]
fn an_injected_byte_record_carries_the_ioctl_description() {
    let b = tty_body(TTY_DESC_TIOCSTI, actor(), crate::tty::Devno { major: 4, minor: 64 }, b"A");
    assert_eq!(text(&b),
        "ioctl=TIOCSTI pid=531 uid=1000 auid=1000 ses=3 major=4 minor=64 comm=\"bash\" data=41");
}

/// Terminal input is raw bytes, so the data field is always hex — never quoted
/// and never able to choose its own framing.
#[test]
fn terminal_data_is_hex_whatever_it_contains() {
    let dev = crate::tty::Devno { major: 5, minor: 0 };
    let b = tty_body(TTY_DESC_INPUT, actor(), dev, b"a \"b\"\x7f");
    let s = text(&b);
    assert!(s.ends_with(" data=6120226222 7F".replace(' ', "").as_str()), "{s}");
    // An empty flush still writes the key, with no value after it.
    let e = tty_body(TTY_DESC_INPUT, actor(), dev, b"");
    assert!(text(&e).ends_with(" data="), "{}", text(&e));
}

/// A process names itself, so the command is encoded as untrusted: a comm
/// carrying a space or a quote must not be able to forge extra fields.
#[test]
fn a_command_name_that_could_split_a_field_is_hex_encoded() {
    let a = TtyActor { comm: b"a b", ..actor() };
    let b = tty_body(TTY_DESC_INPUT, a, crate::tty::Devno::default(), b"");
    assert!(text(&b).contains(" comm=612062 "), "{}", text(&b));
}

fn actor() -> TtyActor<'static> {
    TtyActor { pid: 531, uid: 1000, auid: 1000, ses: 3, comm: b"bash" }
}

#[test]
fn the_record_bodies_are_free_of_bytes_that_would_split_a_field() {
    for b in [fanotify_body(2, None), seccomp_body(SeccompEvent::default())] {
        let fields: Vec<&[u8]> = b.split(|c| *c == b' ').collect();
        assert!(fields.iter().all(|f| f.contains(&b'=')), "every field is a key=value pair");
    }
}
