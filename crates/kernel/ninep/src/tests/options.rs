// Mount-option parsing and the defaults it derives.

use crate::codec::Dialect;
use crate::err::NpError;
use crate::opts::*;
use crate::uapi::limits;

#[test]
fn defaults_match_the_protocol_and_the_common_mount() {
    let o = parse("hostshare", "").unwrap();
    assert_eq!(o.source, "hostshare");
    assert_eq!(o.trans, Trans::Virtio);
    assert_eq!(o.version, Dialect::DotL);
    assert_eq!(o.msize, limits::DEFAULT_MSIZE);
    assert_eq!(o.cache, cache_modes::NONE);
    assert_eq!(o.uname, DEFAULT_UNAME);
    assert_eq!(o.aname, "");
    assert_eq!(o.locktimeout_secs, DEFAULT_LOCK_TIMEOUT_SECS);
    assert_eq!(o.port, limits::FD_PORT);
}

#[test]
fn a_dotl_mount_defaults_to_client_side_permission_checks() {
    assert_eq!(parse("t", "").unwrap().access, Access::Client);
    // A dialect with no numeric owners cannot enforce locally, so the default
    // there is server-side.
    assert_eq!(parse("t", "version=9P2000").unwrap().access, Access::User);
    assert_eq!(parse("t", "version=9P2000.u").unwrap().access, Access::User);
}

#[test]
fn an_explicit_access_choice_is_not_overridden_by_the_dialect_default() {
    assert_eq!(parse("t", "access=user").unwrap().access, Access::User);
    assert_eq!(parse("t", "access=any").unwrap().access, Access::Any);
    assert_eq!(parse("t", "access=1000").unwrap().access, Access::Single(1000));
}

#[test]
fn client_side_checking_is_refused_on_a_dialect_that_cannot_support_it() {
    // Enforcing against fields the dialect does not report would deny or grant
    // on values that were never sent.
    let o = parse("t", "version=9P2000,access=client").unwrap();
    assert_eq!(o.access, Access::User);
    let o = parse("t", "version=9P2000.u,access=client").unwrap();
    assert_eq!(o.access, Access::User);
    let o = parse("t", "version=9P2000.L,access=client").unwrap();
    assert_eq!(o.access, Access::Client);
}

#[test]
fn posix_acls_need_both_the_dialect_and_client_side_checking() {
    assert!(parse("t", "posixacl").unwrap().posixacl);
    assert!(!parse("t", "posixacl,access=user").unwrap().posixacl);
    assert!(!parse("t", "posixacl,version=9P2000.u").unwrap().posixacl);
}

#[test]
fn cache_modes_are_bit_sets_not_ordinals() {
    let none = parse("t", "cache=none").unwrap();
    assert!(!none.caches_data() && !none.caches_meta() && !none.allows_writeback());
    let ra = parse("t", "cache=readahead").unwrap();
    assert!(ra.caches_data() && !ra.allows_writeback() && !ra.caches_meta());
    let mm = parse("t", "cache=mmap").unwrap();
    assert!(mm.caches_data() && mm.allows_writeback() && !mm.caches_meta());
    let lo = parse("t", "cache=loose").unwrap();
    assert!(lo.caches_data() && lo.caches_meta() && lo.allows_writeback() && lo.is_loose());
    let fs = parse("t", "cache=fscache").unwrap();
    assert!(fs.is_loose() && fs.cache & cache_bits::FSCACHE != 0);
}

#[test]
fn an_unknown_cache_word_is_an_error_not_a_silent_downgrade() {
    // Mounting uncached when the caller asked for writeback turns a
    // performance option into a correctness surprise they cannot see.
    assert!(parse("t", "cache=writeback").is_err());
    assert!(parse("t", "cache=").is_err());
}

#[test]
fn a_loose_mount_expires_negative_names_on_its_own() {
    // Nothing revalidates under `loose`, so without an expiry a file created on
    // the server never becomes visible to this mount.
    assert_eq!(parse("t", "cache=loose").unwrap().negtimeout_ms, LOOSE_NEG_TIMEOUT_MS);
    assert_eq!(parse("t", "cache=loose,negtimeout=500").unwrap().negtimeout_ms, 500);
    assert_eq!(parse("t", "cache=none").unwrap().negtimeout_ms, 0);
}

#[test]
fn a_frame_size_below_the_protocol_floor_is_refused() {
    assert!(parse("t", "msize=4096").is_ok());
    assert!(parse("t", "msize=4095").is_err());
    assert!(parse("t", "msize=0").is_err());
    assert!(parse("t", "msize=2147483648").is_err());
    assert_eq!(parse("t", "msize=65536").unwrap().msize, 65536);
}

#[test]
fn an_fd_transport_needs_both_descriptors() {
    // One descriptor can read or write but not both, and the mount would wedge
    // on its first reply.
    assert!(parse("", "trans=fd,rfdno=3,wfdno=4").is_ok());
    assert!(parse("", "trans=fd,rfdno=3").is_err());
    assert!(parse("", "trans=fd,wfdno=4").is_err());
    let o = parse("", "trans=fd,rfdno=3,wfdno=4").unwrap();
    assert_eq!((o.rfdno, o.wfdno), (Some(3), Some(4)));
}

#[test]
fn a_transport_that_needs_a_source_refuses_an_empty_one() {
    assert!(parse("", "trans=virtio").is_err());
    assert!(parse("", "trans=tcp").is_err());
    assert!(parse("host", "trans=tcp").is_ok());
}

#[test]
fn transports_round_trip_their_names() {
    for t in [Trans::Virtio, Trans::Fd, Trans::Tcp, Trans::Unix] {
        assert_eq!(Trans::parse(t.as_str()), Some(t));
    }
    assert_eq!(Trans::parse("rdma"), None);
    assert!(parse("t", "trans=rdma").is_err());
}

#[test]
fn an_unknown_option_is_ignored_but_a_bad_value_is_not() {
    // Mount helpers pass options this code has never heard of.
    assert!(parse("t", "somethingelse=1,msize=8192").is_ok());
    assert_eq!(parse("t", "somethingelse=1,msize=8192").unwrap().msize, 8192);
    // A known option with an unparseable value is the caller's error.
    assert!(parse("t", "msize=abc").is_err());
    assert!(parse("t", "dfltuid=-1").is_err());
    assert!(parse("t", "port=0").is_err());
    assert!(parse("t", "port=70000").is_err());
    assert!(parse("t", "locktimeout=0").is_err());
}

#[test]
fn the_debug_option_is_hexadecimal() {
    assert_eq!(parse("t", "debug=0x1f").unwrap().debug, 0x1f);
    assert_eq!(parse("t", "debug=1f").unwrap().debug, 0x1f);
}

#[test]
fn noextend_forces_the_legacy_dialect() {
    assert_eq!(parse("t", "noextend").unwrap().version, Dialect::Legacy);
}

#[test]
fn the_boolean_flags_land_where_they_are_named() {
    let o = parse("t", "nodevmap,directio,noxattr,ignoreqv,privport").unwrap();
    assert!(o.nodev && o.directio && o.noxattr && o.ignoreqv && o.privport);
    let o = parse("t", "").unwrap();
    assert!(!o.nodev && !o.directio && !o.noxattr && !o.ignoreqv && !o.privport);
}

#[test]
fn the_rendered_option_tail_names_what_a_mount_table_needs() {
    let o = parse("myshare", "msize=65536,cache=loose,aname=/export,uname=root").unwrap();
    let s = o.show();
    assert!(s.contains("trans=virtio"));
    assert!(s.contains("version=9P2000.L"));
    assert!(s.contains("msize=65536"));
    assert!(s.contains("cache=loose"));
    assert!(s.contains("aname=/export"));
    assert!(s.contains("uname=root"));
    assert!(s.contains("access=client"));
}

#[test]
fn parse_errors_are_typed_as_invalid_argument() {
    assert_eq!(parse("t", "msize=1").unwrap_err(), NpError::Server(22));
    assert_eq!(parse("", "trans=fd").unwrap_err(), NpError::Server(92));
}
