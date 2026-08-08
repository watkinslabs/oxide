//! `SOL_NETLINK` option probes on an `AF_NETLINK`/`NETLINK_ROUTE` socket.

use crate::record::{errname, out, result};
use crate::sock::{getopt_raw, netlink_fd, priv_pair, scalar_get, scalar_set_get, setopt_raw, SENTINEL};
use crate::uapi;
use std::os::raw::c_void;

/// Unprivileged boolean flags: get-before-set (default), set 1 + get, set 0 +
/// get. Each is a fresh socket so no flag's default depends on another test's
/// ordering. # C: O(1)
pub fn probe_flags() {
    let cases: [(&str, i32); 6] = [
        ("pktinfo", uapi::NETLINK_PKTINFO),
        ("broadcast_error", uapi::NETLINK_BROADCAST_ERROR),
        ("no_enobufs", uapi::NETLINK_NO_ENOBUFS),
        ("cap_ack", uapi::NETLINK_CAP_ACK),
        ("ext_ack", uapi::NETLINK_EXT_ACK),
        ("get_strict_chk", uapi::NETLINK_GET_STRICT_CHK),
    ];
    for (name, optname) in cases { flag_case("netlink_flag", name, optname); }
}

/// `NETLINK_LISTEN_ALL_NSID` requires `CAP_NET_BROADCAST`, run under both
/// privilege levels so the capability ladder is in the diff. # C: O(1)
pub fn probe_listen_all_nsid() {
    priv_pair(|tag| flag_case("netlink_flag_priv", &format!("listen_all_nsid_{tag}"), uapi::NETLINK_LISTEN_ALL_NSID));
}

fn flag_case(area: &str, name: &str, optname: i32) {
    let fd = netlink_fd();
    let (drc, derr, dlen, dval) = scalar_get(fd, libc::SOL_NETLINK, optname);
    let (s1rc, s1err, g1rc, g1err, g1len, g1val) = scalar_set_get(fd, libc::SOL_NETLINK, optname, 1);
    let (s0rc, s0err, g0rc, g0err, g0len, g0val) = scalar_set_get(fd, libc::SOL_NETLINK, optname, 0);
    out(area, name, &format!(
        "default_rc={drc}|default_errno={}|default_len={dlen}|default_value={dval}|\
set1_rc={s1rc}|set1_errno={}|get1_rc={g1rc}|get1_errno={}|get1_len={g1len}|get1_value={g1val}|\
set0_rc={s0rc}|set0_errno={}|get0_rc={g0rc}|get0_errno={}|get0_len={g0len}|get0_value={g0val}",
        errname(derr), errname(s1err), errname(g1err), errname(s0err), errname(g0err)));
    // SAFETY: fd is a valid descriptor this function opened; close(2) on it
    // is always safe once no further use is pending.
    unsafe { libc::close(fd); }
}

/// `NETLINK_ADD_MEMBERSHIP`/`NETLINK_DROP_MEMBERSHIP` require `CAP_NET_ADMIN`
/// — run every case (valid group, group 0, out-of-range group) under both
/// privilege levels. # C: O(1)
pub fn probe_membership() {
    priv_pair(|tag| membership_case(tag, "valid", uapi::MEMBERSHIP_GROUPS[0]));
    priv_pair(|tag| membership_case(tag, "zero", 0));
    priv_pair(|tag| membership_case(tag, "out_of_range", uapi::GROUP_OUT_OF_RANGE));
}

fn membership_case(tag: &str, case: &str, group: i32) {
    let fd = netlink_fd();
    let (arc, aerr) = setopt_raw(fd, libc::SOL_NETLINK, uapi::NETLINK_ADD_MEMBERSHIP,
        &group as *const i32 as *const c_void, 4);
    let (drc, derr) = setopt_raw(fd, libc::SOL_NETLINK, uapi::NETLINK_DROP_MEMBERSHIP,
        &group as *const i32 as *const c_void, 4);
    out("netlink_membership", &format!("{case}_{tag}"), &format!(
        "add_rc={arc}|add_errno={}|drop_rc={drc}|drop_errno={}",
        errname(aerr), errname(derr)));
    // SAFETY: fd is a valid descriptor opened above.
    unsafe { libc::close(fd); }
}

/// `NETLINK_LIST_MEMBERSHIPS` at buffer sizes that stop mid-word (0,1,3,5,7)
/// and on a word boundary (4,8), against a socket with a known, fixed
/// membership set — so the copied bytes are a deterministic function of
/// `uapi::MEMBERSHIP_GROUPS`, not of anything host-specific. Runs as root:
/// membership itself needs `CAP_NET_ADMIN`. # C: O(1)
pub fn probe_list_memberships() {
    let fd = netlink_fd();
    for g in uapi::MEMBERSHIP_GROUPS {
        setopt_raw(fd, libc::SOL_NETLINK, uapi::NETLINK_ADD_MEMBERSHIP, &g as *const i32 as *const c_void, 4);
    }
    for len in [0u32, 1, 3, 4, 5, 7, 8] { list_memberships_case(fd, len); }
    // SAFETY: fd is a valid descriptor opened above.
    unsafe { libc::close(fd); }
}

fn list_memberships_case(fd: i32, requested_len: u32) {
    let mut buf = [SENTINEL; 16];
    let (rc, err, returned_len) = getopt_raw(fd, libc::SOL_NETLINK, uapi::NETLINK_LIST_MEMBERSHIPS,
        buf.as_mut_ptr() as *mut c_void, requested_len);
    let visible = requested_len.min(buf.len() as u32) as usize;
    let hex: String = buf[..visible].iter().map(|b| format!("{b:02x}")).collect();
    out("netlink_list_memberships", &format!("len_{requested_len}"), &format!(
        "rc={rc}|errno={}|requested_len={requested_len}|returned_optlen={returned_len}|bytes={hex}",
        errname(err)));
}

/// Error-ordering probes: negative `optlen`, `optlen` shorter than an `int`,
/// NULL `optval`, an unknown option number, and a wrong `level`. Run for both
/// `setsockopt` and `getsockopt` against `SOL_NETLINK`. # C: O(1)
pub fn probe_errors() {
    let fd = netlink_fd();
    let val: i32 = 1;
    let vp = &val as *const i32 as *const c_void;

    let (rc, err) = setopt_raw(fd, libc::SOL_NETLINK, uapi::NETLINK_EXT_ACK, vp, (-1i32) as u32);
    result("netlink_errors", "set_optlen_negative", rc, err);

    let (rc, err) = setopt_raw(fd, libc::SOL_NETLINK, uapi::NETLINK_EXT_ACK, vp, 1);
    result("netlink_errors", "set_optlen_short", rc, err);

    let (rc, err) = setopt_raw(fd, libc::SOL_NETLINK, uapi::NETLINK_EXT_ACK, std::ptr::null(), 4);
    result("netlink_errors", "set_optval_null", rc, err);

    let (rc, err) = setopt_raw(fd, libc::SOL_NETLINK, uapi::UNKNOWN_OPTION, vp, 4);
    result("netlink_errors", "set_unknown_option", rc, err);

    let (rc, err) = setopt_raw(fd, libc::SOL_SOCKET + 9999, uapi::NETLINK_EXT_ACK, vp, 4);
    result("netlink_errors", "set_wrong_level", rc, err);

    let mut got: i32 = 0;
    let gp = &mut got as *mut i32 as *mut c_void;
    let (rc, err, _) = getopt_raw(fd, libc::SOL_NETLINK, uapi::NETLINK_EXT_ACK, gp, (-1i32) as u32);
    result("netlink_errors", "get_optlen_negative", rc, err);

    let (rc, err, _) = getopt_raw(fd, libc::SOL_NETLINK, uapi::NETLINK_EXT_ACK, std::ptr::null_mut(), 4);
    result("netlink_errors", "get_optval_null", rc, err);

    let (rc, err, _) = getopt_raw(fd, libc::SOL_NETLINK, uapi::UNKNOWN_OPTION, gp, 4);
    result("netlink_errors", "get_unknown_option", rc, err);

    let (rc, err, _) = getopt_raw(fd, libc::SOL_SOCKET + 9999, uapi::NETLINK_EXT_ACK, gp, 4);
    result("netlink_errors", "get_wrong_level", rc, err);

    // SAFETY: fd is a valid descriptor opened above.
    unsafe { libc::close(fd); }
}
