// The tmpfs option contract, stated as tests: what each key resolves to, and
// what each key REFUSES. The refusals are the half that used to be missing —
// every one of them was previously an accept-and-drop.

use alloc::vec::Vec;
use vfs::VfsError;

use super::limits::*;
use super::memparse::memparse;
use super::mpol::parse_mpol;
use super::opts::*;
use super::parse::{parse_opts, split_opts};

const PG: u64 = super::super::limits::PG as u64;
const ADMIN: MountCred = MountCred::KERNEL;

fn parse(data: &str) -> Result<TmpfsOpts, VfsError> { parse_opts(data, 0, ADMIN) }
fn parse_ram(data: &str, ram: u64) -> Result<TmpfsOpts, VfsError> { parse_opts(data, ram, ADMIN) }
fn refused(data: &str) -> bool { parse(data) == Err(VfsError::Einval) }

// ---- the string real mounts pass -------------------------------------------

#[test]
fn parses_the_systemd_run_user_string() {
    let o = parse("mode=0700,uid=979,gid=979,size=402886656,nr_inodes=819200").unwrap();
    assert_eq!((o.mode, o.uid, o.gid), (Some(0o700), Some(979), Some(979)));
    assert_eq!(o.resolve_blocks(1 << 20), 402_886_656 / PG);
    assert_eq!(o.resolve_inodes(1 << 20), 819_200);
}

#[test]
fn empty_data_leaves_every_default_in_place() {
    let o = parse("").unwrap();
    assert_eq!((o.mode, o.uid, o.gid), (None, None, None));
    assert_eq!(o.resolve_blocks(1234), 1234);
    assert_eq!(o.resolve_inodes(1234), 1234);
    assert!(!o.noswap);
    assert!(!o.full_inums(), "a mount that says nothing gets 32-bit-safe numbers");
}

// ---- sizes ------------------------------------------------------------------

#[test]
fn size_and_nr_blocks_are_one_ceiling_and_the_last_one_written_wins() {
    assert_eq!(parse("size=4096,nr_blocks=7").unwrap().resolve_blocks(99), 7);
    assert_eq!(parse("nr_blocks=7,size=8193").unwrap().resolve_blocks(99), 3);
}

#[test]
fn size_accepts_every_binary_suffix_and_rounds_up_to_a_page() {
    assert_eq!(parse("size=64m").unwrap().resolve_blocks(0), (64 << 20) / PG);
    assert_eq!(parse("size=2G").unwrap().resolve_blocks(0), (2u64 << 30) / PG);
    assert_eq!(parse("size=1t").unwrap().resolve_blocks(0), (1u64 << 40) / PG);
    assert_eq!(parse("size=4097").unwrap().resolve_blocks(0), 2);
    assert_eq!(parse("size=0x2000").unwrap().resolve_blocks(0), 2);
}

#[test]
fn a_percentage_size_is_a_share_of_ram() {
    assert_eq!(parse_ram("size=50%", 1000).unwrap().resolve_blocks(1), 500);
    assert_eq!(parse_ram("size=100%", 8).unwrap().resolve_blocks(1), 8);
}

/// Trailing text is the refusal that matters most: `size=64mb` used to mount a
/// DEFAULT-sized filesystem, because the parser took the 64m and threw the `b`
/// away. A mount asking for something the kernel cannot spell must fail.
#[test]
fn a_size_with_trailing_text_is_refused_not_truncated() {
    assert!(refused("size=64mb"));
    assert!(refused("size=10%%"));
    assert!(refused("size=twelve"));
    assert!(refused("nr_blocks=7x"));
    assert!(refused("nr_inodes=1 000"));
}

#[test]
fn a_ceiling_too_large_to_account_for_is_refused() {
    assert!(refused("nr_inodes=18446744073709551615"));
    assert!(refused("nr_blocks=0xffffffffffffffff"));
    assert!(parse("nr_blocks=0x7fffffffffffffff").is_ok());
}

// ---- shapes -----------------------------------------------------------------

#[test]
fn a_flag_given_a_value_and_a_value_given_none_are_both_refused() {
    assert!(refused("noswap=1"));
    assert!(refused("inode64=yes"));
    assert!(refused("size"));
    assert!(refused("mode"));
    assert!(refused("mpol"));
}

#[test]
fn mode_is_octal_and_masked_to_the_permission_bits() {
    assert_eq!(parse("mode=1777").unwrap().mode, Some(0o1777));
    assert_eq!(parse("mode=0700").unwrap().mode, Some(0o700));
    // 0o17777 carries a bit above the mask; the mask is what is kept.
    assert_eq!(parse("mode=17777").unwrap().mode, Some(0o7777));
    assert!(refused("mode=0o755"), "the option is octal already, not Rust source");
    assert!(refused("mode=799"), "9 is not an octal digit");
}

// ---- inode numbering --------------------------------------------------------

#[test]
fn inode32_and_inode64_are_the_two_answers_to_one_question() {
    assert_eq!(parse("inode64").unwrap().full_inums(), true);
    assert_eq!(parse("inode32").unwrap().full_inums(), false);
    // Last one written wins, as with every other pair.
    assert_eq!(parse("inode64,inode32").unwrap().full_inums(), false);
    assert_eq!(parse("inode32,inode64").unwrap().full_inums(), true);
}

// ---- swap -------------------------------------------------------------------

#[test]
fn noswap_is_recorded_for_a_privileged_mount() {
    assert!(parse("noswap").unwrap().noswap);
}

/// Turning swap off is a decision about machine-wide memory pressure, so a
/// mount made without the administrative capability, or from a user namespace,
/// may not make it.
#[test]
fn an_unprivileged_mount_may_not_turn_off_swap() {
    let unpriv = MountCred { in_init_userns: false, sys_admin: false };
    assert_eq!(parse_opts("noswap", 0, unpriv), Err(VfsError::Einval));
    let no_cap = MountCred { in_init_userns: true, sys_admin: false };
    assert_eq!(parse_opts("noswap", 0, no_cap), Err(VfsError::Einval));
    let no_ns = MountCred { in_init_userns: false, sys_admin: true };
    assert_eq!(parse_opts("noswap", 0, no_ns), Err(VfsError::Einval));
}

// ---- quota ------------------------------------------------------------------

#[test]
fn the_quota_flags_select_their_classes() {
    assert_eq!(parse("usrquota").unwrap().quota_types, QTYPE_MASK_USR);
    assert_eq!(parse("grpquota").unwrap().quota_types, QTYPE_MASK_GRP);
    assert_eq!(parse("quota").unwrap().quota_types, QTYPE_MASK_USR | QTYPE_MASK_GRP);
    assert_eq!(parse("usrquota,grpquota").unwrap().quota_types,
        QTYPE_MASK_USR | QTYPE_MASK_GRP);
}

#[test]
fn quota_is_not_available_to_an_unprivileged_namespace() {
    for k in ["quota", "usrquota", "grpquota"] {
        let unpriv = MountCred { in_init_userns: false, sys_admin: false };
        assert_eq!(parse_opts(k, 0, unpriv), Err(VfsError::Einval), "{k}");
    }
}

#[test]
fn the_four_hard_limits_are_read_with_suffixes() {
    let o = parse("usrquota_block_hardlimit=1g,usrquota_inode_hardlimit=100,\
                   grpquota_block_hardlimit=2m,grpquota_inode_hardlimit=7").unwrap();
    assert_eq!(o.qlimits, QuotaLimits {
        usr_block: 1 << 30, usr_inode: 100, grp_block: 2 << 20, grp_inode: 7 });
}

/// A limit of zero would deny the class everything, and a limit above the
/// representable maximum is not a limit at all. Both are refusals, not clamps.
#[test]
fn a_zero_or_oversized_hard_limit_is_refused() {
    for k in ["usrquota_block_hardlimit", "usrquota_inode_hardlimit",
              "grpquota_block_hardlimit", "grpquota_inode_hardlimit"] {
        assert!(refused(&alloc::format!("{k}=0")), "{k}=0");
        assert!(refused(&alloc::format!("{k}=0x8000000000000000")), "{k} over max");
        assert!(parse(&alloc::format!("{k}=0x7fffffffffffffff")).is_ok(), "{k} at max");
    }
    assert_eq!(QUOTA_MAX_SPC_LIMIT, i64::MAX as u64);
    assert_eq!(QUOTA_MAX_INO_LIMIT, i64::MAX as u64);
}

// ---- large folios -----------------------------------------------------------

/// `huge=` names an allocator this filesystem does not have. Every value but
/// "never" is therefore refused — the alternative is a mount whose
/// `/proc/mounts` line claims a policy that nothing applies.
#[test]
fn only_the_large_folio_policy_that_can_be_honoured_is_accepted() {
    assert_eq!(parse("huge=never").unwrap().huge, Some(HugeMode::Never));
    for v in ["always", "within_size", "advise"] {
        assert!(refused(&alloc::format!("huge={v}")), "huge={v}");
    }
    assert!(refused("huge=sometimes"));
}

// ---- case folding -----------------------------------------------------------

/// The instance's name encoding: both spellings of the option are accepted and
/// recorded, only a UTF-8 charset this kernel has a table for is a charset, and
/// strictness without an encoding describes nothing.
#[test]
fn the_encoding_option_records_what_it_accepts_and_refuses_the_rest() {
    let latest = parse_opts("casefold", 0, MountCred::KERNEL).expect("the bare flag");
    assert!(latest.casefold.is_some(), "the bare flag names the table's own version");
    assert!(!latest.strict_encoding);
    let named = parse_opts("casefold=utf8-12.1.0", 0, MountCred::KERNEL).expect("a named version");
    assert_eq!(named.casefold.as_deref(), Some("utf8-12.1.0"));
    let strict = parse_opts("casefold,strict_encoding", 0, MountCred::KERNEL).expect("strict");
    assert!(strict.strict_encoding);

    assert!(refused("casefold=latin1"), "only a UTF-8 charset has a table here");
    assert!(refused("casefold=utf8-99.0.0"), "a version newer than the table");
    assert!(refused("strict_encoding"), "strictness without an encoding is strict about nothing");
}

// ---- numa policy ------------------------------------------------------------

#[test]
fn a_memory_policy_that_names_this_machines_node_is_accepted() {
    // A preference with no node list is local allocation, not a refusal.
    for v in ["default", "local", "prefer", "prefer:0", "bind:0", "interleave", "interleave:0",
              "bind:0=static", "bind:0=relative", "prefer (many):0"] {
        assert!(parse(&alloc::format!("mpol={v}")).is_ok(), "mpol={v}");
    }
    // `default` is the ABSENCE of a policy, not a policy object.
    assert_eq!(parse("mpol=default").unwrap().mpol, Some(None));
    assert!(parse("mpol=bind:0").unwrap().mpol.unwrap().is_some());
}

#[test]
fn a_memory_policy_this_machine_cannot_satisfy_is_refused() {
    for v in ["bind:1", "bind:0-3", "bind", "local:0", "default:0",
              "prefer:0-1", "bind:0=sideways", "nosuchmode", "bind:", "bind:x"] {
        assert!(refused(&alloc::format!("mpol={v}")), "mpol={v}");
    }
}

/// A node list contains commas, and the option separator is a comma. The
/// tokeniser has to keep `mpol=bind:0,0` in one piece or the policy arrives
/// truncated and `0` arrives as a key.
#[test]
fn a_node_list_survives_the_option_separator() {
    let toks: Vec<&str> = split_opts("mpol=bind:0,0,size=64m,noswap").collect();
    assert_eq!(toks, ["mpol=bind:0,0", "size=64m", "noswap"]);
    let o = parse("mpol=bind:0,0,size=64m").unwrap();
    assert!(o.mpol.is_some());
    assert_eq!(o.resolve_blocks(0), (64 << 20) / PG);
}

// ---- the number reader ------------------------------------------------------

#[test]
fn memparse_reports_what_it_did_not_consume() {
    assert_eq!(memparse("4096"), (4096, ""));
    assert_eq!(memparse("64m"), (64 << 20, ""));
    assert_eq!(memparse("64mb"), (64 << 20, "b"));
    assert_eq!(memparse("10%"), (10, "%"));
    assert_eq!(memparse("0x10"), (16, ""));
    assert_eq!(memparse("010"), (8, ""), "a leading zero is octal");
    assert_eq!(memparse("abc"), (0, "abc"));
    assert_eq!(memparse(""), (0, ""));
}

#[test]
fn the_option_separators_are_the_ones_the_contract_names() {
    assert_eq!(OPT_SEP, ',');
    assert_eq!(OPT_ASSIGN, '=');
    assert_eq!(PERCENT_SUFFIX, '%');
    assert_eq!(PERCENT, 100);
    assert_eq!(BOGO_INODE_SIZE, 1024);
}

#[test]
fn a_key_this_parser_does_not_own_is_left_alone() {
    // Admission decides which keys EXIST; a key that reached here from
    // somewhere else must not fail the mount.
    let o = parse("smackfsroot=*,mode=1777").unwrap();
    assert_eq!(o.mode, Some(0o1777));
}

#[test]
fn parse_mpol_rejects_a_node_beyond_the_mask() {
    assert_eq!(parse_mpol("bind:64"), Err(VfsError::Einval));
    assert_eq!(parse_mpol("bind:99999999999"), Err(VfsError::Einval));
}
