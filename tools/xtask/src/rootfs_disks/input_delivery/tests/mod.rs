use super::core::*;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn probe_has_valid_shell_syntax_in_both_modes() {
    for mode in [Mode::Delivery, Mode::Rebind] {
        let mut child = Command::new("/bin/sh").arg("-n").stdin(Stdio::piped()).spawn().expect("spawn shell syntax check");
        child.stdin.as_mut().expect("shell stdin").write_all(probe_body(mode).as_bytes()).expect("write shell probe");
        assert!(child.wait().expect("wait for syntax check").success(), "{mode:?}");
    }
}

#[test]
fn probe_substitutes_every_placeholder() { for mode in [Mode::Delivery, Mode::Rebind] { assert!(!probe_body(mode).contains('@')); } }

#[test]
fn delivery_mode_asserts_every_event_class_and_skips_the_rebind_phase() {
    let body = probe_body(Mode::Delivery);
    for check in ["$phase-pointer-motion", "$phase-pointer-button", "$phase-pointer-sync", "$phase-keyboard-key", "$phase-tablet-absolute", "$phase-tablet-sync"] { assert!(body.contains(check), "missing assertion: {check}"); }
    assert!(body.contains("mode=delivery")); assert!(body.contains("observe first")); assert!(body.contains("if [ \"$mode\" = rebind ]")); assert!(body.contains("READY phase=%s")); assert!(body.contains("PASS mode=%s"));
}

#[test]
fn rebind_mode_reasserts_delivery_after_the_children_come_back() {
    let body = probe_body(Mode::Rebind);
    for check in ["mode=rebind", "/sys/bus/virtio/drivers/virtio-input", "$driver/unbind", "$driver/bind", "resolve rebound", "observe rebound"] { assert!(body.contains(check), "missing {check}"); }
}

#[test]
fn an_unclassified_node_dumps_the_sysfs_state_udev_classifies_from() {
    let body = probe_body(Mode::Rebind);
    for check in ["diagnose \"$1\"; fail \"$1-pointer-node\"", "readlink -f \"$class\"", "/device/capabilities/ev", "DIAG data="] { assert!(body.contains(check), "missing {check}"); }
}

#[test]
fn probe_claims_a_serial_line_rather_than_the_graphical_console() { let body = probe_body(Mode::Delivery); assert!(body.contains("for serial in /dev/ttyS0 /dev/ttyAMA0 /dev/console")); assert!(body.contains("exec > \"$serial\" 2>&1")); }

#[test]
fn record_geometry_matches_the_event_abi() { assert_eq!(EVENT_BYTES, 24); assert_eq!(EVENT_WORDS, 12); assert_eq!(EVENT_TYPE_WORD, 8); let body = probe_body(Mode::Delivery); assert!(body.contains("bs=24")); assert!(body.contains("r += 12")); assert!(body.contains("word[r + 8]")); }

#[test]
fn the_absolute_pointer_is_resolved_by_its_abs_capability_bitmap() { let body = probe_body(Mode::Delivery); for check in ["abs_node()", "/device/capabilities/abs", "tr -d ' 0'", "tablet=$(abs_node)", "$1-tablet-node", "$1-tablet-char"] { assert!(body.contains(check), "missing {check}"); } }

#[test]
fn both_pointer_kinds_are_captured_and_asserted_independently() { let body = probe_body(Mode::Delivery); assert!(body.contains("if=\"$tablet\" of=\"$work/tablet.bin\"")); assert!(body.contains("absolute=$(count_type \"$work/tablet.bin\" 3)")); assert!(body.contains("motion=$(count_type \"$work/pointer.bin\" 2)")); assert!(body.contains("kill \"$pointer_reader\" \"$keyboard_reader\" \"$tablet_reader\"")); assert_eq!(EV_ABS, 3); assert_eq!(EV_REL, 2); }

#[test]
fn buttons_are_asserted_across_both_pointer_nodes() { let body = probe_body(Mode::Delivery); assert!(body.contains("abs_button=$(count_type \"$work/tablet.bin\" 1)")); assert!(body.contains("buttons=$(( button + abs_button ))")); assert!(body.contains("[ \"$buttons\" -gt 0 ] || fail \"$phase-pointer-button\"")); assert!(body.contains("[ \"$motion\" -gt 0 ] || fail \"$phase-pointer-motion\"")); assert!(body.contains("[ \"$absolute\" -gt 0 ] || fail \"$phase-tablet-absolute\"")); }

#[test]
fn the_delivered_record_stream_is_transcribed_with_timestamps() { let body = probe_body(Mode::Delivery); for check in ["dump_records \"$phase-pointer\"", "dump_records \"$phase-tablet\"", "sec = word[r + 0] + word[r + 1] * 65536", "usec = word[r + 4] + word[r + 5] * 65536", "value = word[r + 10] + word[r + 11] * 65536", "if (value >= 2147483648) value -= 4294967296", "shown < 24"] { assert!(body.contains(check), "missing {check}"); } }

#[test]
fn capabilities_are_printed_unconditionally_on_every_resolve() { let body = probe_body(Mode::Rebind); assert!(body.contains("describe \"$1\"")); assert!(body.contains("caps phase=%s node=%s")); for a in ["capabilities/ev", "capabilities/rel", "capabilities/abs", "capabilities/key"] { assert!(body.contains(a), "missing {a}"); } }

#[test]
fn libinput_must_accept_both_pointers_before_the_window_opens() { let body = probe_body(Mode::Delivery); for check in ["libinput list-devices", "libinput_nodes_for \"$devices\" pointer", "for node in $pointer $tablet", "$1-libinput-pointer node=$node", "require_libinput_pointer \"$1\""] { assert!(body.contains(check), "missing {check}"); } }

#[test]
fn service_runs_after_udev_has_settled_the_input_nodes() { let service = service_body(); assert!(service.contains("After=systemd-udev-settle.service systemd-logind.service\n")); assert!(service.contains("ExecStart=/usr/local/bin/oxide-input-delivery\n")); assert!(service.contains("StandardOutput=journal+console\n")); assert_eq!(validate_arch("x86_64"), Ok(())); assert_eq!(validate_arch("aarch64"), Ok(())); assert_eq!(validate_arch("riscv64"), Err(EXIT_UNSUPPORTED_ARCH)); }
