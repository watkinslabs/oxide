use super::*;

/// Type id of `bpf_lsm_file_open` in the published object: `int`, then the
/// hook's opaque argument struct, a pointer to it, the prototype, and the
/// stub. A program names this id as its attach target.
const FILE_OPEN_BTF_ID: u32 = 5;
/// Ids the walk above assigns to records that are not hook stubs.
const NON_STUB_IDS: [u32; 6] = [0, 1, 2, 3, 4, 6];

#[test] fn the_published_object_survives_this_kernels_own_parser() {
    assert!(published().is_some());
    assert!(parse(&build()).is_ok());
}

#[test] fn a_damaged_object_does_not_survive_that_parser() {
    // Positive control for the test above: the same acceptance check must
    // go red when the bytes stop being a well-formed object. Each mutation
    // breaks a different record of the header.
    let good = build();
    for at in [0, 4, 8, 12, 16, 20] {
        let mut bad = good.clone();
        bad[at] = bad[at].wrapping_add(1);
        assert!(parse(&bad).is_err(), "header byte {at} mutation was accepted");
    }
    let mut truncated = good.clone();
    truncated.pop();
    assert!(parse(&truncated).is_err());
}

#[test] fn the_hook_stub_id_resolves_to_its_hook() {
    assert_eq!(lsm_hook_by_btf_id(FILE_OPEN_BTF_ID), Some(Hook::FileOpen));
}

#[test] fn no_other_type_id_resolves_to_a_hook() {
    for id in NON_STUB_IDS {
        assert_eq!(lsm_hook_by_btf_id(id), None, "type id {id} resolved to a hook");
    }
    assert_eq!(lsm_hook_by_btf_id(u32::MAX), None);
}

#[test] fn the_stub_id_names_the_stub_function() {
    let btf = published().expect("kernel BTF");
    assert_eq!(btf.index.func_name(&btf.raw, FILE_OPEN_BTF_ID), Some(&b"bpf_lsm_file_open"[..]));
    // Non-function records carry names too; resolution must still refuse
    // them, otherwise the argument struct's name would be an attach target.
    for id in NON_STUB_IDS { assert_eq!(btf.index.func_name(&btf.raw, id), None); }
}

#[test] fn every_published_hook_has_exactly_one_resolvable_stub_id() {
    // Four records per single-argument hook plus the shared `int`, with
    // headroom so a hook gaining a stub id outside the scan fails loudly.
    let scan = 1..=(HOOKS.len() as u32 * 8 + 8);
    let btf = published().expect("kernel BTF");
    for (hook, spec) in HOOKS {
        let found: alloc::vec::Vec<u32> = scan.clone()
            .filter(|id| btf.index.func_name(&btf.raw, *id) == Some(spec.stub.as_bytes()))
            .collect();
        assert_eq!(found.len(), 1, "hook {hook:?} stub ids {found:?}");
        assert_eq!(lsm_hook_by_btf_id(found[0]), Some(*hook));
    }
}

#[test] fn the_object_is_stable_across_calls() {
    // Attach targets named by one load must mean the same thing at the
    // next; a rebuilt object with different ids would silently re-point
    // every already-loaded program.
    assert_eq!(build(), build());
    let first = published().expect("kernel BTF");
    let second = published().expect("kernel BTF");
    assert!(Arc::ptr_eq(&first, &second));
}

/// The served bytes ARE the resolved object: a reader that drained the
/// windowed accessor and a loader that resolved an attach target must be
/// looking at one blob, or a discovered id would name nothing.
#[test] fn draining_the_reader_reproduces_the_object_the_resolver_parses() {
    let len = published_len();
    assert!(len > 0);
    let mut served = alloc::vec::Vec::new();
    let mut window = [0u8; 7];
    loop {
        let n = published_read(served.len() as u64, &mut window);
        if n == 0 { break; }
        served.extend_from_slice(&window[..n]);
    }
    assert_eq!(served.len() as u64, len);
    assert_eq!(served, build());
    let index = parse(&served).expect("served object parses");
    assert_eq!(index.func_name(&served, FILE_OPEN_BTF_ID), Some(&b"bpf_lsm_file_open"[..]));
}

/// Positive control for the test above: an object that is NOT what the
/// resolver holds must fail that same check, so the equality is doing work.
#[test] fn a_reader_serving_shifted_bytes_would_be_caught() {
    let mut shifted = build();
    shifted.remove(0);
    assert_ne!(shifted, build());
    assert!(parse(&shifted).is_err());
}

/// Window arithmetic: a short buffer takes a prefix, an offset at the end
/// takes nothing, and an offset past it is not an error.
#[test] fn the_windowed_read_stops_at_the_end_of_the_object() {
    let len = published_len();
    let mut buf = [0u8; 16];
    assert_eq!(published_read(0, &mut buf), buf.len());
    assert_eq!(&buf[..2], &MAGIC.to_ne_bytes());
    assert_eq!(buf[2], VERSION);
    assert_eq!(published_read(len - 3, &mut buf), 3);
    assert_eq!(published_read(len, &mut buf), 0);
    assert_eq!(published_read(len + 4096, &mut buf), 0);
    assert_eq!(published_read(u64::MAX, &mut buf), 0);
    assert_eq!(published_read(0, &mut []), 0);
}

/// Iterator targets are named the same way hooks are, out of the same
/// object: exactly one type id per published target, and the two families
/// never answer to each other's ids.
#[test] fn every_iterator_target_has_exactly_one_resolvable_stub_id() {
    use super::super::super::iter::targets::TARGETS;
    let total = (HOOKS.len() + TARGETS.len()) as u32;
    let scan = 1..=(total * 8 + 8);
    let btf = published().expect("kernel BTF");
    for (target, spec) in TARGETS {
        let found: alloc::vec::Vec<u32> = scan.clone()
            .filter(|id| btf.index.func_name(&btf.raw, *id) == Some(spec.stub.as_bytes()))
            .collect();
        assert_eq!(found.len(), 1, "target {target:?} stub ids {found:?}");
        assert_eq!(iter_target_by_btf_id(found[0]), Some(*target));
        assert_eq!(lsm_hook_by_btf_id(found[0]), None, "an iterator id resolved to a hook");
    }
    assert_eq!(iter_target_by_btf_id(FILE_OPEN_BTF_ID), None);
    for id in NON_STUB_IDS { assert_eq!(iter_target_by_btf_id(id), None); }
}
