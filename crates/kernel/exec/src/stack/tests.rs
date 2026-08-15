use aslr::ExecRnd;

use super::{plan_initial_stack, MAX_STACK_VECTOR};

const TOP: u64 = 0x7fff_ffff_0000;
const PAGE: u64 = 0x1000;

#[test]
fn initial_stack_plan_covers_only_the_bytes_the_writer_touches() {
    let argv: &[&[u8]] = &[b"/usr/lib/systemd/systemd", b"--system"];
    let envp: &[&[u8]] = &[b"LANG=C", b"TERM=vt100"];
    let p = plan_initial_stack(TOP, 8 << 20, argv, envp, &ExecRnd::default()).expect("plan");
    assert_eq!(p.sp & 0xf, 0);
    assert_eq!(p.write_top, TOP);
    assert!(p.write_len() < PAGE, "small vectors must not populate the stack rlimit");
    assert!(p.sp >= TOP - PAGE, "all written bytes must sit in the planned page");
}

#[test]
fn initial_stack_plan_spans_each_string_page_but_not_the_stack_limit() {
    let arg = [b'a'; 3500];
    let env = [b'e'; 1700];
    let argv: &[&[u8]] = &[&arg];
    let envp: &[&[u8]] = &[&env];
    let p = plan_initial_stack(TOP, 8 << 20, argv, envp, &ExecRnd::default()).expect("plan");
    assert!(p.write_len() > PAGE);
    assert!(p.write_len() < 3 * PAGE);
    assert!(p.sp >= TOP - 3 * PAGE);
}

#[test]
fn initial_stack_plan_refuses_a_vector_that_crosses_the_mapped_stack() {
    let arg = [b'a'; 3900];
    assert!(plan_initial_stack(TOP, PAGE, &[&arg], &[], &ExecRnd::default()).is_none());
}

#[test]
fn initial_stack_plan_rejects_a_vector_beyond_the_writer_capacity() {
    let argv = alloc::vec![b"x".as_slice(); MAX_STACK_VECTOR + 1];
    assert!(plan_initial_stack(TOP, 8 << 20, &argv, &[], &ExecRnd::default()).is_none());
}
