//! Mount option parsing, and that `show` round-trips through `parse`.

use super::{parse, show, Errors, Options};
use syscall::errno::Errno;

#[test]
fn defaults_are_errors_continue() {
    assert_eq!(Options::defaults().errors, Errors::Continue);
    assert_eq!(Options::default(), Options::defaults());
}

#[test]
fn errors_continue_is_accepted() {
    let o = parse(Options::defaults(), "errors=continue").unwrap();
    assert_eq!(o.errors, Errors::Continue);
}

#[test]
fn errors_panic_is_accepted() {
    let o = parse(Options::defaults(), "errors=panic").unwrap();
    assert_eq!(o.errors, Errors::Panic);
}

#[test]
fn ro_with_no_value_is_accepted_and_changes_nothing() {
    let o = parse(Options::defaults(), "ro").unwrap();
    assert_eq!(o, Options::defaults());
}

#[test]
fn threads_is_refused_this_build_cannot_honour_it() {
    assert_eq!(parse(Options::defaults(), "threads=4"), Err(Errno::Einval));
    assert_eq!(parse(Options::defaults(), "threads"), Err(Errno::Einval));
}

#[test]
fn unknown_key_is_einval() {
    assert_eq!(parse(Options::defaults(), "bogus=1"), Err(Errno::Einval));
}

#[test]
fn known_key_with_unrecognised_value_is_einval() {
    assert_eq!(parse(Options::defaults(), "errors=explode"), Err(Errno::Einval));
}

#[test]
fn empty_items_are_skipped() {
    let o = parse(Options::defaults(), " ,,errors=panic,, ").unwrap();
    assert_eq!(o.errors, Errors::Panic);
}

#[test]
fn comma_list_applies_every_item_left_to_right() {
    let o = parse(Options::defaults(), "errors=panic,errors=continue").unwrap();
    assert_eq!(o.errors, Errors::Continue);
}

#[test]
fn show_round_trips_through_parse() {
    for opts in [Options { errors: Errors::Continue }, Options { errors: Errors::Panic }] {
        let rendered = show(opts);
        // `show` prefixes with a comma, as a mount-option fragment does.
        let reparsed = parse(Options::defaults(), rendered.trim_start_matches(',')).unwrap();
        assert_eq!(reparsed, opts);
    }
}
