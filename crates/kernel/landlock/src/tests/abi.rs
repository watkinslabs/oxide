// Argument-admission contract for slots 444/445/446. Each case records a
// verified errno or ordering; a regression here changes what user space is
// told, which for a sandbox mechanism is a security-visible change.

use super::*;

fn attr_bytes(words: &[u64]) -> [u8; RULESET_ATTR_SIZE] {
    let mut b = [0u8; RULESET_ATTR_SIZE];
    for (i, w) in words.iter().enumerate() { b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes()); }
    b
}

#[test]
fn version_query_needs_null_attr_and_zero_size() {
    // Feature detection: programs call this first and disable sandboxing
    // entirely if it fails, so the shape of the query is load-bearing.
    assert_eq!(create_intent(0, 0, CREATE_RULESET_VERSION), Ok(CreateIntent::Version));
    assert_eq!(create_intent(0x1000, 0, CREATE_RULESET_VERSION), Err(Errno::Einval));
    assert_eq!(create_intent(0, 8, CREATE_RULESET_VERSION), Err(Errno::Einval));
}

#[test]
fn errata_query_is_separate_and_not_combinable() {
    assert_eq!(create_intent(0, 0, CREATE_RULESET_ERRATA), Ok(CreateIntent::Errata));
    // Both bits at once is not "version and errata"; it is invalid.
    assert_eq!(create_intent(0, 0, CREATE_RULESET_VERSION | CREATE_RULESET_ERRATA),
               Err(Errno::Einval));
}

#[test]
fn unknown_create_flag_is_rejected() {
    assert_eq!(create_intent(0, 0, 1 << 5), Err(Errno::Einval));
}

#[test]
fn zero_flags_means_build_a_ruleset() {
    assert_eq!(create_intent(0x1000, 8, 0), Ok(CreateIntent::Ruleset));
}

#[test]
fn the_reported_abi_version_matches_the_rights_actually_accepted() {
    // The version number is a promise about which rights are enforced. Raising
    // it past what is enforced silently disables a well-written caller's
    // sandbox, so every mask below must stop exactly where enforcement does.
    assert_eq!(ABI_VERSION, 6);
    // Device control is the last filesystem right of this level.
    assert_eq!(MASK_ACCESS_FS, (ACCESS_FS_IOCTL_DEV << 1) - 1);
    // Both scopes are enforced, so both are accepted.
    assert_eq!(MASK_SCOPE, (SCOPE_SIGNAL << 1) - 1);
    assert_eq!(MASK_SCOPE & SCOPE_ABSTRACT_UNIX_SOCKET, SCOPE_ABSTRACT_UNIX_SOCKET);
    // Stream ports only; datagram rights arrived later.
    assert_eq!(MASK_ACCESS_NET, (ACCESS_NET_CONNECT_TCP << 1) - 1);
    // Logging control and thread synchronisation both arrived later, so no
    // flag of either syscall is accepted.
    assert_eq!(MASK_RESTRICT_SELF, 0);
    assert_eq!(MASK_ADD_RULE, 0);
    assert_eq!(ERRATA, 0);
}

#[test]
fn a_right_from_a_later_abi_level_is_refused_rather_than_accepted_unenforced() {
    // The bit after the last enforced one: accepting it would hand back a
    // ruleset fd for a policy nothing implements.
    let later_fs = (LAST_ACCESS_FS << 1) as AccessMask;
    assert_eq!(RulesetAttr { handled_fs: later_fs, ..Default::default() }.validate(),
               Err(Errno::Einval));
    let later_net = (LAST_ACCESS_NET << 1) as AccessMask;
    assert_eq!(RulesetAttr { handled_net: later_net, ..Default::default() }.validate(),
               Err(Errno::Einval));
}

#[test]
fn null_attr_is_efault_before_any_size_check() {
    // A null pointer with a nonsense size still reports the pointer problem.
    assert_eq!(attr_buffer_ok(0, 0, RULESET_ATTR_MIN_SIZE), Err(Errno::Efault));
    assert_eq!(attr_buffer_ok(0, ATTR_MAX_SIZE + 1, RULESET_ATTR_MIN_SIZE), Err(Errno::Efault));
}

#[test]
fn too_small_is_einval_and_too_big_is_e2big() {
    assert_eq!(attr_buffer_ok(0x1000, 7, RULESET_ATTR_MIN_SIZE), Err(Errno::Einval));
    assert_eq!(attr_buffer_ok(0x1000, 8, RULESET_ATTR_MIN_SIZE), Ok(()));
    assert_eq!(attr_buffer_ok(0x1000, ATTR_MAX_SIZE, RULESET_ATTR_MIN_SIZE), Ok(()));
    assert_eq!(attr_buffer_ok(0x1000, ATTR_MAX_SIZE + 1, RULESET_ATTR_MIN_SIZE), Err(Errno::E2big));
}

#[test]
fn unknown_handled_bits_are_rejected_not_ignored() {
    // Ignoring an unknown right would leave the caller believing a right it
    // asked to filter is being filtered.
    let a = RulesetAttr { handled_fs: MASK_ACCESS_FS | (1 << 40), ..Default::default() };
    assert_eq!(a.validate(), Err(Errno::Einval));
    let a = RulesetAttr { handled_net: MASK_ACCESS_NET | (1 << 8), ..Default::default() };
    assert_eq!(a.validate(), Err(Errno::Einval));
    let a = RulesetAttr { scoped: MASK_SCOPE | (1 << 4), ..Default::default() };
    assert_eq!(a.validate(), Err(Errno::Einval));
}

#[test]
fn a_ruleset_that_handles_nothing_is_enomsg() {
    assert_eq!(RulesetAttr::default().validate(), Err(Errno::Enomsg));
    // Any one of the three masks is enough to make it meaningful.
    assert_eq!(RulesetAttr { handled_fs: ACCESS_FS_EXECUTE, ..Default::default() }.validate(), Ok(()));
    assert_eq!(RulesetAttr { handled_net: ACCESS_NET_BIND_TCP, ..Default::default() }.validate(), Ok(()));
    assert_eq!(RulesetAttr { scoped: SCOPE_SIGNAL, ..Default::default() }.validate(), Ok(()));
}

#[test]
fn attr_decodes_little_endian_words_in_order() {
    let b = attr_bytes(&[1, 2, 3]);
    let a = RulesetAttr::decode(&b);
    assert_eq!((a.handled_fs, a.handled_net, a.scoped), (1, 2, 3));
}

#[test]
fn a_short_attr_zero_extends_into_the_newer_members() {
    // An ABI-1 program passes 8 bytes; the network and scope masks must read as
    // zero rather than as whatever followed in its address space.
    let mut b = attr_bytes(&[ACCESS_FS_EXECUTE]);
    b[8..].fill(0);
    let a = RulesetAttr::decode(&b);
    assert_eq!(a.handled_fs, ACCESS_FS_EXECUTE);
    assert_eq!(a.handled_net, 0);
    assert_eq!(a.scoped, 0);
    assert_eq!(a.validate(), Ok(()));
}

#[test]
fn add_rule_accepts_no_flag() {
    assert_eq!(add_rule_flags_ok(0), Ok(()));
    assert_eq!(add_rule_flags_ok(1), Err(Errno::Einval));
    assert_eq!(add_rule_flags_ok(2), Err(Errno::Einval));
}

#[test]
fn an_empty_rule_is_enomsg() {
    assert_eq!(rule_access_ok(0, ACCESS_FS_EXECUTE), Err(Errno::Enomsg));
}

#[test]
fn a_rule_may_not_grant_what_the_ruleset_does_not_handle() {
    // The central invariant: a layer never grants a right it does not filter.
    assert_eq!(rule_access_ok(ACCESS_FS_WRITE_FILE, ACCESS_FS_READ_FILE), Err(Errno::Einval));
    assert_eq!(rule_access_ok(ACCESS_FS_READ_FILE, ACCESS_FS_READ_FILE), Ok(()));
    // Reparenting is filtered by default but must still be declared before a
    // rule may grant it.
    assert_eq!(rule_access_ok(ACCESS_FS_REFER, ACCESS_FS_READ_FILE), Err(Errno::Einval));
}

#[test]
fn enomsg_precedes_the_subset_check() {
    // An all-zero access is trivially a subset, so the order is observable only
    // through which error a caller with both problems receives.
    assert_eq!(rule_access_ok(0, 0), Err(Errno::Enomsg));
}

#[test]
fn a_port_rule_may_not_name_a_port_above_the_sixteen_bit_range() {
    assert_eq!(net_port_ok(0), Ok(()));
    assert_eq!(net_port_ok(PORT_MAX), Ok(()));
    assert_eq!(net_port_ok(PORT_MAX + 1), Err(Errno::Einval));
}

#[test]
fn a_rule_on_a_file_may_only_carry_file_rights() {
    assert_eq!(path_target_ok(false, ACCESS_FS_READ_FILE), Ok(()));
    assert_eq!(path_target_ok(false, ACCESS_FS_READ_DIR), Err(Errno::Einval));
    assert_eq!(path_target_ok(true, ACCESS_FS_READ_DIR), Ok(()));
    assert_eq!(path_target_ok(false, ACCESS_FILE), Ok(()));
}

#[test]
fn reparenting_is_filtered_even_when_undeclared() {
    assert_eq!(fs_layer_mask(0), ACCESS_FS_REFER);
    assert_eq!(fs_layer_mask(ACCESS_FS_READ_FILE), ACCESS_FS_READ_FILE | ACCESS_FS_REFER);
}

#[test]
fn a_stored_rule_also_grants_the_rights_its_layer_ignores() {
    // A layer that filters only reading must not appear to withhold writing.
    let a = absolute_access(ACCESS_FS_READ_FILE, ACCESS_FS_READ_FILE);
    assert_eq!(a & ACCESS_FS_WRITE_FILE, ACCESS_FS_WRITE_FILE);
    assert_eq!(a & ACCESS_FS_READ_FILE, ACCESS_FS_READ_FILE);
    // Reparenting is filtered by default, so it is not handed out for free.
    assert_eq!(a & ACCESS_FS_REFER, 0);
}

#[test]
fn enforcement_requires_no_new_privs_or_the_admin_capability() {
    // Without this an unprivileged thread could install a policy that a later
    // set-user-ID exec would still run under.
    assert_eq!(restrict_self_precheck(false, false, 0), Err(Errno::Eperm));
    assert_eq!(restrict_self_precheck(true, false, 0), Ok(()));
    assert_eq!(restrict_self_precheck(false, true, 0), Ok(()));
}

#[test]
fn the_permission_check_precedes_the_flag_check() {
    // A thread that may not sandbox itself learns that, not that its flags were
    // wrong; the reverse order would leak which flags a kernel supports.
    assert_eq!(restrict_self_precheck(false, false, 1 << 20), Err(Errno::Eperm));
    assert_eq!(restrict_self_precheck(true, false, 1 << 20), Err(Errno::Einval));
}

#[test]
fn a_flag_from_a_later_abi_level_is_refused() {
    // Accepting the thread-synchronisation bit without implementing it would
    // report success while sibling threads stayed unconfined.
    assert_eq!(restrict_self_precheck(true, false, 0), Ok(()));
    for bit in 0..8 {
        assert_eq!(restrict_self_precheck(true, false, 1 << bit), Err(Errno::Einval));
    }
}

#[test]
fn the_layer_stack_is_bounded() {
    assert_eq!(may_stack_layer(0), Ok(()));
    assert_eq!(may_stack_layer(MAX_NUM_LAYERS - 1), Ok(()));
    assert_eq!(may_stack_layer(MAX_NUM_LAYERS), Err(Errno::E2big));
}

#[test]
fn struct_sizes_match_the_published_layout() {
    assert_eq!(RULESET_ATTR_SIZE, 3 * 8);
    assert_eq!(PATH_BENEATH_ATTR_SIZE, 12);
    assert_eq!(NET_PORT_ATTR_SIZE, 16);
    assert_eq!(RULESET_ATTR_MIN_SIZE, 8);
}
