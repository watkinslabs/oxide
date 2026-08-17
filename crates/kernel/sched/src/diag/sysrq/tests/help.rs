use crate::diag::sysrq::help::{render_help, HELP_MAX, HELP_PREFIX};
use crate::diag::sysrq::table::KEYS;

/// The line is BUILT, so its shape is pinned: one line, the prefix, then every
/// key. It is emitted as a single write because a line assembled by several
/// writes can be spliced by another CPU's output.
#[test]
fn the_rendered_list_is_one_line_naming_every_key() {
    let mut buf = [0u8; HELP_MAX];
    let n = render_help(&mut buf);
    let text = core::str::from_utf8(&buf[..n]).expect("ascii");
    assert_eq!(text,
        "[sysrq] keys: b=reboot c=crash l=backtrace-all-cpus o=poweroff \
p=registers t=tasks w=blocked-tasks");
    assert!(!text.contains('\n'), "the newline belongs to the emitter: {text}");
    assert!(text.starts_with(core::str::from_utf8(HELP_PREFIX).unwrap()));
}

/// The list is the whole table, with no consultation of the enable mask.
///
/// It used to be filtered, which reads as helpful and is not: a key the mask
/// refuses looks identical to a key that does not exist, on the machine whose
/// userspace has already stopped answering. The reference prints every
/// registered key on the unbound-key branch and reports a refusal per
/// keystroke instead — `perform` does the same.
#[test]
fn the_list_is_the_whole_table_whatever_the_mask_says() {
    let mut buf = [0u8; HELP_MAX];
    let n = render_help(&mut buf);
    let text = core::str::from_utf8(&buf[..n]).expect("ascii");
    for &(key, label) in KEYS {
        let mut want = [0u8; 32];
        want[0] = key;
        want[1] = b'=';
        want[2..2 + label.len()].copy_from_slice(label);
        let want = core::str::from_utf8(&want[..2 + label.len()]).unwrap();
        assert!(text.contains(want), "{want} is missing from the list");
    }
}

/// The buffer must hold the whole list. A key added without room would clip the
/// line rather than fail anywhere visible.
#[test]
fn the_render_buffer_holds_every_key() {
    let mut buf = [0u8; HELP_MAX];
    let n = render_help(&mut buf);
    assert!(n < HELP_MAX, "the list fills the buffer ({n} of {HELP_MAX}); it is being clipped");
}
