// `PERF_EVENT_IOC_SET_BPF` admission, attachment and release.
//
// Everything here is ungated: the decision is a pure function and the
// attachment is over a hosted-constructible event and program object, so the
// whole ladder runs under `cargo test -p fs`.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use security::bpf::uapi::{func_id, insn, prog_type};
use security::bpf::{make_bpf_prog_inode, prog_facts, ProgFacts};
use syscall::errno::Errno;

use super::*;
use super::super::counter::{SwSource, TaskCount};
use super::super::file::make_perf_event_inode;

fn facts(prog_type: u32, call_get_stack: bool) -> ProgFacts {
    ProgFacts { id: 1, prog_type, call_get_stack }
}

fn perf_event_prog() -> ProgFacts { facts(prog_type::PERF_EVENT, false) }

/// An event with the given attr bits and sample types, live enough to attach
/// to (a counting software event is what `perf_event_open` mints by default).
fn event(bits: u64, sample_type: u64) -> Arc<PerfEvent> {
    let attr = PerfAttr { bits, sample_type, ..PerfAttr::default() };
    PerfEvent::new(attr, SwSource::TaskCount(TaskCount::PageFaultsMin), None, 0, None)
}

fn plain_event() -> Arc<PerfEvent> { event(0, 0) }

/// `precise_ip` is a 2-bit field, not a flag: bit 16 alone is a nonzero
/// constraint, and the bit above it belongs to `mmap_data`.
#[test]
fn precise_ip_is_the_two_bit_field_at_its_own_offset() {
    assert_eq!(precise_ip(&PerfAttr::default()), 0);
    for level in 1..=3u64 {
        let a = PerfAttr { bits: level << attr_bit::PRECISE_IP, ..PerfAttr::default() };
        assert_eq!(precise_ip(&a), level as u8);
    }
    let mmap_data = PerfAttr { bits: 1 << attr_bit::MMAP_DATA, ..PerfAttr::default() };
    assert_eq!(precise_ip(&mmap_data), 0);
}

/// A program of the one type this arm runs is admitted on a plain event.
#[test]
fn a_perf_event_program_is_admitted() {
    assert_eq!(set_bpf_check(&PerfAttr::default(), false, false, perf_event_prog()), Ok(()));
}

/// Every other program type is refused, including the ones this kernel can
/// actually load — a socket filter or an LSM program has no business on a
/// counter's overflow.
#[test]
fn any_other_program_type_is_einval() {
    for t in [prog_type::SOCKET_FILTER, prog_type::CGROUP_SKB, prog_type::CGROUP_DEVICE,
              prog_type::LSM, prog_type::TRACING, prog_type::KPROBE, prog_type::TRACEPOINT] {
        assert_eq!(set_bpf_check(&PerfAttr::default(), false, false, facts(t, false)),
                   Err(Errno::Einval), "prog type {t}");
    }
}

/// A program cannot be replaced: the second attach is `-EEXIST`, which is a
/// distinct answer from the wrong-type refusal.
#[test]
fn a_second_program_is_eexist() {
    assert_eq!(set_bpf_check(&PerfAttr::default(), false, true, perf_event_prog()),
               Err(Errno::Eexist));
}

/// An event whose overflows already go to a kernel callback refuses a program
/// before either the already-attached test or the type test — so a caller
/// cannot tell an occupied breakpoint apart from a wrong-typed program by the
/// order the checks run in.
#[test]
fn a_kernel_counter_is_einval_before_every_other_rule() {
    assert_eq!(set_bpf_check(&PerfAttr::default(), true, true, perf_event_prog()),
               Err(Errno::Einval));
    assert_eq!(set_bpf_check(&PerfAttr::default(), true, false, facts(prog_type::LSM, false)),
               Err(Errno::Einval));
}

/// A stack-walking program on a precise event needs the full callchain
/// sampled: no `PERF_SAMPLE_CALLCHAIN`, or a callchain with either privilege
/// level excluded, is `-EPROTO` — its own errno, not `-EINVAL`.
#[test]
fn a_precise_event_without_a_full_callchain_refuses_a_stack_walker_with_eproto() {
    let prog = facts(prog_type::PERF_EVENT, true);
    let precise = 1 << attr_bit::PRECISE_IP;
    let no_callchain = PerfAttr { bits: precise, ..PerfAttr::default() };
    assert_eq!(set_bpf_check(&no_callchain, false, false, prog), Err(Errno::Eproto));
    for excluded in [attr_bit::EXCL_CALLCHAIN_KERNEL, attr_bit::EXCL_CALLCHAIN_USER] {
        let a = PerfAttr { bits: precise | (1 << excluded), sample_type: sample::CALLCHAIN,
                           ..PerfAttr::default() };
        assert_eq!(set_bpf_check(&a, false, false, prog), Err(Errno::Eproto), "bit {excluded}");
    }
    assert_eq!(Errno::Eproto.as_i32(), 71);
}

/// The same three ingredients each on their own are harmless: an imprecise
/// event, a program that walks no stack, or a full callchain all admit it.
#[test]
fn the_eproto_rule_needs_all_three_of_its_ingredients() {
    let walker = facts(prog_type::PERF_EVENT, true);
    let precise = 1 << attr_bit::PRECISE_IP;
    // Precise, walks the stack, full callchain sampled.
    let full = PerfAttr { bits: precise, sample_type: sample::CALLCHAIN, ..PerfAttr::default() };
    assert_eq!(set_bpf_check(&full, false, false, walker), Ok(()));
    // Not precise, so the unwinder is not constrained.
    let imprecise = PerfAttr::default();
    assert_eq!(set_bpf_check(&imprecise, false, false, walker), Ok(()));
    // Precise, but the program never walks a stack.
    let a = PerfAttr { bits: precise, ..PerfAttr::default() };
    assert_eq!(set_bpf_check(&a, false, false, perf_event_prog()), Ok(()));
}

/// The type check runs before the callchain rule, so a wrong-typed stack
/// walker is `-EINVAL` and never `-EPROTO`.
#[test]
fn the_type_check_precedes_the_callchain_rule() {
    let a = PerfAttr { bits: 1 << attr_bit::PRECISE_IP, ..PerfAttr::default() };
    assert_eq!(set_bpf_check(&a, false, false, facts(prog_type::KPROBE, true)),
               Err(Errno::Einval));
}

// ---- attachment, reference and release -----------------------------------

/// An attached program is readable back off the event's fd, which is what
/// `BPF_TASK_FD_QUERY` reads, and it is the same object that was attached.
#[test]
fn an_attached_program_is_visible_through_the_events_inode() {
    let ev = plain_event();
    let prog = make_bpf_prog_inode(prog_type::PERF_EVENT, Vec::new());
    let inode = make_perf_event_inode(Arc::clone(&ev));
    assert!(attached_prog(&inode).is_none());
    assert_eq!(attach(&ev, Arc::clone(&prog), prog_facts(&prog).unwrap()), Ok(()));
    let seen = attached_prog(&inode).expect("the event now carries a program");
    assert!(Arc::ptr_eq(&seen, &prog));
    assert_eq!(prog_facts(&seen).unwrap().prog_type, prog_type::PERF_EVENT);
}

/// The attachment holds a reference: the program outlives its own descriptor,
/// and only the event's teardown drops it (`perf_event_free_bpf_prog`).
#[test]
fn the_attachment_holds_a_reference_until_the_event_is_torn_down() {
    let prog = make_bpf_prog_inode(prog_type::PERF_EVENT, Vec::new());
    let held = Arc::strong_count(&prog);
    let ev = plain_event();
    assert_eq!(attach(&ev, Arc::clone(&prog), prog_facts(&prog).unwrap()), Ok(()));
    assert_eq!(Arc::strong_count(&prog), held + 1);
    drop(ev);
    assert_eq!(Arc::strong_count(&prog), held);
}

/// A refused attach takes no reference — the caller's is the only one left,
/// so the ioctl's error path releases the program exactly once.
#[test]
fn a_refused_attach_takes_no_reference() {
    let prog = make_bpf_prog_inode(prog_type::SOCKET_FILTER, Vec::new());
    let held = Arc::strong_count(&prog);
    let ev = plain_event();
    assert_eq!(attach(&ev, Arc::clone(&prog), prog_facts(&prog).unwrap()), Err(Errno::Einval));
    assert_eq!(Arc::strong_count(&prog), held);
    assert!(attached_prog(&make_perf_event_inode(ev)).is_none());
}

/// The second attach is refused and leaves the FIRST program in place — the
/// event is not left holding the loser, and the winner is not swapped out.
#[test]
fn a_refused_second_attach_leaves_the_first_program_attached() {
    let ev = plain_event();
    let first = make_bpf_prog_inode(prog_type::PERF_EVENT, Vec::new());
    let second = make_bpf_prog_inode(prog_type::PERF_EVENT, Vec::new());
    assert_eq!(attach(&ev, Arc::clone(&first), prog_facts(&first).unwrap()), Ok(()));
    let held = Arc::strong_count(&second);
    assert_eq!(attach(&ev, Arc::clone(&second), prog_facts(&second).unwrap()),
               Err(Errno::Eexist));
    assert_eq!(Arc::strong_count(&second), held);
    let seen = attached_prog(&make_perf_event_inode(Arc::clone(&ev))).unwrap();
    assert!(Arc::ptr_eq(&seen, &first));
}

/// A fork-inherited child event starts with no program of its own, so a
/// child never runs a program the parent's fd attached after the fork.
#[test]
fn an_inherited_child_event_carries_no_program() {
    let parent = plain_event();
    let prog = make_bpf_prog_inode(prog_type::PERF_EVENT, Vec::new());
    assert_eq!(attach(&parent, Arc::clone(&prog), prog_facts(&prog).unwrap()), Ok(()));
    let child = PerfEvent::new_inherited(&parent, 42, None);
    assert!(child.state.lock().prog.is_none());
}

/// A program whose bytecode calls neither stack helper does not carry the
/// flag, and one that calls either does — the property is derived from the
/// program, so no attach site keeps its own copy.
#[test]
fn the_stack_walking_flag_is_derived_from_the_bytecode() {
    fn call(helper: u32) -> Vec<u8> {
        let mut i = vec![0u8; 8];
        i[0] = insn::CALL;
        i[4..8].copy_from_slice(&helper.to_le_bytes());
        i
    }
    let plain = make_bpf_prog_inode(prog_type::PERF_EVENT, call(func_id::KTIME_GET_NS));
    assert!(!prog_facts(&plain).unwrap().call_get_stack);
    for helper in [func_id::GET_STACKID, func_id::GET_STACK] {
        let walker = make_bpf_prog_inode(prog_type::PERF_EVENT, call(helper));
        assert!(prog_facts(&walker).unwrap().call_get_stack, "helper {helper}");
    }
    // A pseudo call (nonzero `src_reg`) names another program, not a helper.
    let mut pseudo = call(func_id::GET_STACKID);
    pseudo[1] = 0x10;
    let other = make_bpf_prog_inode(prog_type::PERF_EVENT, pseudo);
    assert!(!prog_facts(&other).unwrap().call_get_stack);
}
