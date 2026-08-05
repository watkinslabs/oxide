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
    assert_eq!(TARGET_ABI_VERSION, 10);
    assert_eq!(ABI_VERSION, TARGET_ABI_VERSION);
    // Resolving a pathname socket is the last filesystem right of this level.
    assert_eq!(MASK_ACCESS_FS, (ACCESS_FS_RESOLVE_UNIX << 1) - 1);
    // Both scopes are enforced, so both are accepted.
    assert_eq!(MASK_SCOPE, (SCOPE_SIGNAL << 1) - 1);
    assert_eq!(MASK_SCOPE & SCOPE_ABSTRACT_UNIX_SOCKET, SCOPE_ABSTRACT_UNIX_SOCKET);
    // Datagram ports as well as stream ports.
    assert_eq!(MASK_ACCESS_NET, (ACCESS_NET_CONNECT_SEND_UDP << 1) - 1);
    // Logging control and thread synchronisation are both handled.
    assert_eq!(MASK_RESTRICT_SELF, (RESTRICT_SELF_TSYNC << 1) - 1);
    assert_eq!(MASK_ADD_RULE, ADD_RULE_QUIET);
    // Only the errata whose behaviour this kernel actually has.
    assert_eq!(ERRATA, ERRATUM_TCP_ONLY | ERRATUM_SAME_THREAD_GROUP_SIGNAL
               | ERRATUM_DISCONNECTED_HIERARCHY);
}

#[test]
fn the_security_spec_pins_the_same_landlock_target() {
    // The release string and the Landlock ABI are independent contracts. Keep
    // the human-facing target beside the security invariants, but make drift
    // from the runtime constant fail here instead of surviving as a stale
    // known-issue row.
    let spec = include_str!("../../../../../docs/27-security.md");
    let target = alloc::format!("Landlock target: ABI {TARGET_ABI_VERSION} (Linux 7.2 UAPI).");
    assert!(spec.lines().any(|line| line == target), "docs/27 Landlock target drifted");
    let tsync = "| 8 | `LANDLOCK_RESTRICT_SELF_TSYNC` | enforced; pseudo-signal task work, repeated clone discovery, and two commit barriers make the live thread group all-or-nothing |";
    assert!(spec.lines().any(|line| line == tsync),
            "ABI 10 cannot stay advertised while its cumulative ABI-8 TSYNC rung is open");
    let errata = "Oxide advertises errata 1 (TCP-only port rights), 2 (same-process signal scope), and 3 (disconnected directory hierarchy handling).";
    assert!(spec.lines().any(|line| line == errata),
            "erratum 3 cannot be reported while the security contract says it is open");
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
    let b = attr_bytes(&[1, 2, 3, 1, 2, 3]);
    let a = RulesetAttr::decode(&b);
    assert_eq!((a.handled_fs, a.handled_net, a.scoped), (1, 2, 3));
    assert_eq!((a.quiet_fs, a.quiet_net, a.quiet_scoped), (1, 2, 3));
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
fn add_rule_accepts_only_the_quiet_flag() {
    assert_eq!(add_rule_flags_ok(0), Ok(()));
    assert_eq!(add_rule_flags_ok(ADD_RULE_QUIET), Ok(()));
    assert_eq!(add_rule_flags_ok(ADD_RULE_QUIET | 2), Err(Errno::Einval));
    assert_eq!(add_rule_flags_ok(2), Err(Errno::Einval));
}

#[test]
fn an_empty_rule_is_enomsg() {
    assert_eq!(rule_access_ok(0, ACCESS_FS_EXECUTE, 0, 0), Err(Errno::Enomsg));
}

#[test]
fn a_rule_may_not_grant_what_the_ruleset_does_not_handle() {
    // The central invariant: a layer never grants a right it does not filter.
    assert_eq!(rule_access_ok(ACCESS_FS_WRITE_FILE, ACCESS_FS_READ_FILE, 0, 0), Err(Errno::Einval));
    assert_eq!(rule_access_ok(ACCESS_FS_READ_FILE, ACCESS_FS_READ_FILE, 0, 0), Ok(()));
    // Reparenting is filtered by default but must still be declared before a
    // rule may grant it.
    assert_eq!(rule_access_ok(ACCESS_FS_REFER, ACCESS_FS_READ_FILE, 0, 0), Err(Errno::Einval));
}

#[test]
fn enomsg_precedes_the_subset_check() {
    // An all-zero access is trivially a subset, so the order is observable only
    // through which error a caller with both problems receives.
    assert_eq!(rule_access_ok(0, 0, 0, 0), Err(Errno::Enomsg));
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
    assert_eq!(restrict_self_precheck(true, false, 1 << 4), Err(Errno::Einval));
}

#[test]
fn every_defined_restrict_flag_is_accepted() {
    assert_eq!(restrict_self_precheck(true, false, MASK_RESTRICT_SELF), Ok(()));
    assert_eq!(restrict_self_precheck(true, false, MASK_RESTRICT_SELF + 1), Err(Errno::Einval));
}

#[test]
fn only_a_pure_log_configuration_change_may_omit_a_ruleset() {
    assert!(restrict_plan(3, 0, false).needs_ruleset);
    assert!(restrict_plan(-1, 0, false).needs_ruleset);
    assert!(!restrict_plan(-1, RESTRICT_SELF_LOG_SUBDOMAINS_OFF, false).needs_ruleset);
    assert!(!restrict_plan(-1, RESTRICT_SELF_LOG_SUBDOMAINS_OFF | RESTRICT_SELF_TSYNC,
                           false).needs_ruleset);
    // Any other flag makes it a real enforcement, which needs a ruleset.
    assert!(restrict_plan(-1, RESTRICT_SELF_LOG_SUBDOMAINS_OFF | RESTRICT_SELF_LOG_NEW_EXEC_ON,
                          false).needs_ruleset);
    assert!(restrict_plan(3, RESTRICT_SELF_LOG_SUBDOMAINS_OFF, false).needs_ruleset);
}

#[test]
fn thread_synchronisation_carries_no_new_privs_to_the_siblings() {
    // Otherwise a sibling could gain privileges under a policy it never
    // installed, which is the exact scenario the permission gate exists for.
    assert!(restrict_plan(3, RESTRICT_SELF_TSYNC, true).propagate_no_new_privs);
    // A caller admitted by capability instead does not force it on siblings.
    assert!(!restrict_plan(3, RESTRICT_SELF_TSYNC, false).propagate_no_new_privs);
    // Without the flag nothing is propagated.
    assert!(!restrict_plan(3, 0, true).propagate_no_new_privs);
    assert!(!restrict_plan(3, 0, true).tsync);
    assert!(restrict_plan(3, RESTRICT_SELF_TSYNC, false).tsync);
}

#[test]
fn the_logging_flags_are_accepted_and_change_no_decision() {
    // They select which denials reach an audit log. There is no audit log, so
    // they are inert — but refusing them would break a caller that only wants
    // to quieten its own logs.
    for f in [RESTRICT_SELF_LOG_SAME_EXEC_OFF, RESTRICT_SELF_LOG_NEW_EXEC_ON,
              RESTRICT_SELF_LOG_SUBDOMAINS_OFF] {
        assert_eq!(restrict_self_precheck(true, false, f), Ok(()));
        assert!(restrict_plan(3, f, false).needs_ruleset);
        assert!(!restrict_plan(3, f, false).tsync);
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
    assert_eq!(RULESET_ATTR_SIZE, 6 * 8);
    assert_eq!(PATH_BENEATH_ATTR_SIZE, 12);
    assert_eq!(NET_PORT_ATTR_SIZE, 16);
    assert_eq!(RULESET_ATTR_MIN_SIZE, 8);
}

#[test]
fn a_quiet_mask_may_only_name_rights_the_ruleset_handles() {
    // Quieting a right the layer does not filter would describe a denial that
    // cannot happen, so it is refused rather than dropped.
    let a = RulesetAttr { handled_fs: ACCESS_FS_READ_FILE,
                          quiet_fs: ACCESS_FS_WRITE_FILE, ..Default::default() };
    assert_eq!(a.validate(), Err(Errno::Einval));
    let a = RulesetAttr { handled_net: ACCESS_NET_BIND_TCP,
                          quiet_net: ACCESS_NET_CONNECT_TCP, ..Default::default() };
    assert_eq!(a.validate(), Err(Errno::Einval));
    let a = RulesetAttr { scoped: SCOPE_SIGNAL,
                          quiet_scoped: SCOPE_ABSTRACT_UNIX_SOCKET, ..Default::default() };
    assert_eq!(a.validate(), Err(Errno::Einval));
    // A subset is accepted, including the whole handled mask.
    let a = RulesetAttr { handled_fs: ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE,
                          quiet_fs: ACCESS_FS_READ_FILE, ..Default::default() };
    assert_eq!(a.validate(), Ok(()));
}

#[test]
fn a_quiet_mask_carrying_an_unknown_bit_is_caught_by_the_subset_test() {
    // The handled masks are validated first, so an unknown quiet bit can never
    // be a subset of a valid handled mask.
    let a = RulesetAttr { handled_fs: ACCESS_FS_READ_FILE,
                          quiet_fs: 1 << 40, ..Default::default() };
    assert_eq!(a.validate(), Err(Errno::Einval));
}

#[test]
fn the_quiet_subset_check_precedes_the_empty_ruleset_answer() {
    // An all-zero handled mask with a quiet bit set is an argument error, not
    // an inert policy: the caller named something it cannot have meant.
    let a = RulesetAttr { quiet_fs: ACCESS_FS_READ_FILE, ..Default::default() };
    assert_eq!(a.validate(), Err(Errno::Einval));
}

#[test]
fn an_empty_rule_is_meaningful_once_it_carries_the_quiet_flag() {
    // Without a flag an empty rule grants nothing and is reported inert. With
    // the quiet flag it still marks its object, which is the reason to add it.
    assert_eq!(rule_access_ok(0, ACCESS_FS_READ_FILE, 0, ACCESS_FS_READ_FILE),
               Err(Errno::Enomsg));
    assert_eq!(rule_access_ok(0, ACCESS_FS_READ_FILE, ADD_RULE_QUIET, ACCESS_FS_READ_FILE),
               Ok(()));
}

#[test]
fn marking_a_rule_quiet_needs_a_ruleset_with_something_to_quiet() {
    // A quiet marking against an empty quiet mask can never suppress anything.
    assert_eq!(rule_access_ok(ACCESS_FS_READ_FILE, ACCESS_FS_READ_FILE, ADD_RULE_QUIET, 0),
               Err(Errno::Einval));
    assert_eq!(rule_access_ok(ACCESS_FS_READ_FILE, ACCESS_FS_READ_FILE,
                              ADD_RULE_QUIET, ACCESS_FS_READ_FILE), Ok(()));
}

#[test]
fn the_handled_subset_check_precedes_the_quiet_flag_check() {
    // A rule granting an unhandled right is an argument error whether or not
    // it also asks to be quiet; reporting the flag problem would hide it.
    assert_eq!(rule_access_ok(ACCESS_FS_WRITE_FILE, ACCESS_FS_READ_FILE, ADD_RULE_QUIET, 0),
               Err(Errno::Einval));
}

#[test]
fn the_rights_of_the_reported_abi_level_are_all_accepted() {
    // Each right this level added must be admitted, or a program that
    // feature-detected the version gets EINVAL for a right it was promised.
    for m in [ACCESS_FS_RESOLVE_UNIX] {
        assert_eq!(RulesetAttr { handled_fs: m, ..Default::default() }.validate(), Ok(()));
    }
    for m in [ACCESS_NET_BIND_UDP, ACCESS_NET_CONNECT_SEND_UDP] {
        assert_eq!(RulesetAttr { handled_net: m, ..Default::default() }.validate(), Ok(()));
    }
}

#[test]
fn resolving_a_pathname_socket_is_a_right_a_file_rule_may_carry() {
    // The right names a socket, which is not a directory, so a rule anchored on
    // the socket itself has to be admissible.
    assert_eq!(path_target_ok(false, ACCESS_FS_RESOLVE_UNIX), Ok(()));
}
