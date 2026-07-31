// Where a pattern sends the dump: a pathname, or a program with arguments.

use crate::coredump::pattern::{file_path, kind_of, pipe_argv, CoreKind};

use super::victim;

#[test]
fn the_first_character_chooses_the_destination() {
    assert_eq!(kind_of(b"core"), CoreKind::File);
    assert_eq!(kind_of(b"/var/crash/core"), CoreKind::File);
    assert_eq!(kind_of(b"|/usr/lib/systemd/systemd-coredump"), CoreKind::Pipe);
    assert_eq!(kind_of(b"@/run/systemd/coredump"), CoreKind::Socket);
    assert_eq!(kind_of(b""), CoreKind::File);
}

#[test]
fn a_relative_file_pattern_is_rooted() {
    // The dying process's working directory is not a dependable place to leave
    // a dump, so a bare name is resolved from the root.
    assert_eq!(file_path(b"core", &victim()), "/core");
    assert_eq!(file_path(b"core.%e.%p\n", &victim()), "/core.bash.42");
}

#[test]
fn an_absolute_file_pattern_is_kept() {
    assert_eq!(file_path(b"/var/crash/%e-%P", &victim()), "/var/crash/bash-4242");
}

#[test]
fn a_pattern_that_expands_to_nothing_falls_back_to_a_named_dump() {
    assert_eq!(file_path(b"", &victim()), "/core.42");
    assert_eq!(file_path(b"%z\n", &victim()), "/core.42");
}

#[test]
fn a_program_pattern_splits_into_a_program_and_arguments() {
    // The real Fedora pattern.
    let (argv, wants) = pipe_argv(
        b"|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n", &victim())
        .expect("a program pattern");
    assert!(!wants);
    assert_eq!(argv.len(), 8);
    assert_eq!(argv[0].as_slice(), b"/usr/lib/systemd/systemd-coredump");
    assert_eq!(argv[1].as_slice(), b"4242");
    assert_eq!(argv[2].as_slice(), b"1000");
    assert_eq!(argv[3].as_slice(), b"100");
    assert_eq!(argv[4].as_slice(), b"11");
    assert_eq!(argv[5].as_slice(), b"1700000000");
    assert_eq!(argv[6].as_slice(), b"18446744073709551615");
    assert_eq!(argv[7].as_slice(), b"oxide");
}

#[test]
fn splitting_happens_before_expansion() {
    // A command name containing a space must stay ONE argument: otherwise a
    // program could rename itself to inject an extra argument into the
    // reporter's command line.
    let mut cx = victim();
    cx.comm = b"two words".to_vec();
    let (argv, _) = pipe_argv(b"|/bin/reporter %e last", &cx).expect("a program pattern");
    assert_eq!(argv.len(), 3);
    assert_eq!(argv[1].as_slice(), b"two words");
    assert_eq!(argv[2].as_slice(), b"last");
}

#[test]
fn runs_of_separators_collapse() {
    let (argv, _) = pipe_argv(b"|/bin/reporter   a \t b \n", &victim()).expect("a program pattern");
    assert_eq!(argv.len(), 3);
    assert_eq!(argv[1].as_slice(), b"a");
    assert_eq!(argv[2].as_slice(), b"b");
}

#[test]
fn a_program_pattern_naming_nothing_runnable_is_refused() {
    // Refused, not turned into a file: the operator asked for a program.
    assert!(pipe_argv(b"|", &victim()).is_none());
    assert!(pipe_argv(b"|   ", &victim()).is_none());
    // A bare name has no search path to resolve against in a kernel helper.
    assert!(pipe_argv(b"|reporter", &victim()).is_none());
    assert!(pipe_argv(b"|%z arg", &victim()).is_none());
}

#[test]
fn a_file_pattern_is_not_a_program_pattern() {
    assert!(pipe_argv(b"/var/crash/core", &victim()).is_none());
    assert!(pipe_argv(b"@/run/systemd/coredump", &victim()).is_none());
}

#[test]
fn a_program_pattern_can_ask_for_a_process_descriptor() {
    let (argv, wants) = pipe_argv(b"|/usr/lib/systemd/systemd-coredump %F %P", &victim())
        .expect("a program pattern");
    assert!(wants);
    assert_eq!(argv[1].as_slice(), b"3");
    assert_eq!(argv[2].as_slice(), b"4242");
}
