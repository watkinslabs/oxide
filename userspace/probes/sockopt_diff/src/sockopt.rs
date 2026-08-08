//! `SOL_SOCKET` option probes run on the same `AF_NETLINK`/`NETLINK_ROUTE`
//! fd — the level is generic core-socket code, but this proves it against a
//! netlink socket specifically since nothing else in the tree does.

use crate::record::{errname, out};
use crate::sock::{getopt_raw, netlink_fd, priv_pair, scalar_get, scalar_set_get, setopt_raw, SENTINEL};
use std::os::raw::c_void;

/// Plain set-then-get boolean/int options with no privilege requirement and
/// no derived/machine-specific value. # C: O(1)
pub fn probe_scalars() {
    let cases: [(&str, i32, i32); 11] = [
        ("passcred", libc::SO_PASSCRED, 1),
        ("passsec", libc::SO_PASSSEC, 1),
        ("timestamp", libc::SO_TIMESTAMP, 1),
        ("timestampns", libc::SO_TIMESTAMPNS, 1),
        ("timestamping", libc::SO_TIMESTAMPING, 0),
        ("rcvlowat", libc::SO_RCVLOWAT, 1),
        ("busy_poll", libc::SO_BUSY_POLL, 0),
        ("reuseaddr", libc::SO_REUSEADDR, 1),
        ("priority_low", libc::SO_PRIORITY, 2),
        ("sndbuf", libc::SO_SNDBUF, 8192),
        ("rcvbuf", libc::SO_RCVBUF, 8192),
    ];
    for (name, optname, val) in cases { scalar_case("sockopt_scalar", name, optname, val); }
}

fn scalar_case(area: &str, name: &str, optname: i32, val: i32) {
    let fd = netlink_fd();
    let (srcv, serr, grc, gerr, glen, gval) = scalar_set_get(fd, libc::SOL_SOCKET, optname, val);
    out(area, name, &format!(
        "set_val={val}|set_rc={srcv}|set_errno={}|get_rc={grc}|get_errno={}|get_len={glen}|get_value={gval}",
        errname(serr), errname(gerr)));
    // SAFETY: fd is a valid descriptor opened above.
    unsafe { libc::close(fd); }
}

/// `SO_MARK`, `SO_*BUFFORCE`, and `SO_PRIORITY` above the unprivileged
/// ceiling all require `CAP_NET_ADMIN` — run under both privilege levels.
/// # C: O(1)
pub fn probe_priv_scalars() {
    priv_pair(|tag| scalar_case("sockopt_priv", &format!("mark_{tag}"), libc::SO_MARK, 42));
    priv_pair(|tag| scalar_case("sockopt_priv", &format!("sndbufforce_{tag}"), libc::SO_SNDBUFFORCE, 65536));
    priv_pair(|tag| scalar_case("sockopt_priv", &format!("rcvbufforce_{tag}"), libc::SO_RCVBUFFORCE, 65536));
    priv_pair(|tag| scalar_case("sockopt_priv", &format!("priority_high_{tag}"), libc::SO_PRIORITY, 9999));
}

/// `SO_RCVTIMEO`/`SO_SNDTIMEO`: valid, negative seconds, out-of-range
/// microseconds. # C: O(1)
pub fn probe_timeo() {
    for (opt_name, optname) in [("rcvtimeo", libc::SO_RCVTIMEO), ("sndtimeo", libc::SO_SNDTIMEO)] {
        timeo_case(opt_name, optname, "valid", 1, 0);
        timeo_case(opt_name, optname, "negative_sec", -1, 0);
        timeo_case(opt_name, optname, "usec_out_of_range", 0, 2_000_000);
    }
}

fn timeo_case(opt_name: &str, optname: i32, case: &str, sec: i64, usec: i64) {
    let fd = netlink_fd();
    let tv = libc::timeval { tv_sec: sec as libc::time_t, tv_usec: usec as libc::suseconds_t };
    let sz = std::mem::size_of::<libc::timeval>() as u32;
    let (src, serr) = setopt_raw(fd, libc::SOL_SOCKET, optname, &tv as *const _ as *const c_void, sz);
    let mut got = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let (grc, gerr, glen) = getopt_raw(fd, libc::SOL_SOCKET, optname, &mut got as *mut _ as *mut c_void, sz);
    out("sockopt_timeo", &format!("{opt_name}_{case}"), &format!(
        "set_sec={sec}|set_usec={usec}|set_rc={src}|set_errno={}|get_rc={grc}|get_errno={}|get_len={glen}|get_sec={}|get_usec={}",
        errname(serr), errname(gerr), got.tv_sec, got.tv_usec));
    // SAFETY: fd is a valid descriptor opened above.
    unsafe { libc::close(fd); }
}

/// `SO_LINGER`: set `(onoff=1, linger=5)` then get it back. # C: O(1)
pub fn probe_linger() {
    let fd = netlink_fd();
    let want = libc::linger { l_onoff: 1, l_linger: 5 };
    let sz = std::mem::size_of::<libc::linger>() as u32;
    let (src, serr) = setopt_raw(fd, libc::SOL_SOCKET, libc::SO_LINGER, &want as *const _ as *const c_void, sz);
    let mut got = libc::linger { l_onoff: 0, l_linger: 0 };
    let (grc, gerr, glen) = getopt_raw(fd, libc::SOL_SOCKET, libc::SO_LINGER, &mut got as *mut _ as *mut c_void, sz);
    out("sockopt_linger", "onoff1_linger5", &format!(
        "set_rc={src}|set_errno={}|get_rc={grc}|get_errno={}|get_len={glen}|onoff={}|linger={}",
        errname(serr), errname(gerr), got.l_onoff, got.l_linger));
    // SAFETY: fd is a valid descriptor opened above.
    unsafe { libc::close(fd); }
}

/// Read-only options: `SO_TYPE`, `SO_DOMAIN`, `SO_PROTOCOL`, `SO_ACCEPTCONN`,
/// `SO_ERROR`. Each is get-only in Linux, plus one wrongful `set` attempt to
/// record its errno on this fd, and each value is stable across hosts (type
/// of socket / af / protocol / listen-state are all determined solely by how
/// this probe opened the socket, and `SO_ERROR` clears to 0 on a fresh fd).
/// # C: O(1)
pub fn probe_readonly() {
    let cases: [(&str, i32); 5] = [
        ("type", libc::SO_TYPE),
        ("domain", libc::SO_DOMAIN),
        ("protocol", libc::SO_PROTOCOL),
        ("acceptconn", libc::SO_ACCEPTCONN),
        ("error", libc::SO_ERROR),
    ];
    for (name, optname) in cases {
        let fd = netlink_fd();
        let (src, serr) = setopt_raw(fd, libc::SOL_SOCKET, optname, &0i32 as *const i32 as *const c_void, 4);
        let (grc, gerr, glen, gval) = scalar_get(fd, libc::SOL_SOCKET, optname);
        out("sockopt_readonly", name, &format!(
            "set_rc={src}|set_errno={}|get_rc={grc}|get_errno={}|get_len={glen}|value={gval}",
            errname(serr), errname(gerr)));
        // SAFETY: fd is a valid descriptor opened above.
        unsafe { libc::close(fd); }
    }
}

/// `SO_BINDTODEVICE` against `lo`, which exists in both the host and guest
/// environments and whose NAME (not ifindex) is what this records. Requires
/// `CAP_NET_RAW`; runs as root only, alongside the other root-context probes.
/// # C: O(1)
pub fn probe_bindtodevice() {
    let fd = netlink_fd();
    let name = b"lo\0";
    let (src, serr) = setopt_raw(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE,
        name.as_ptr() as *const c_void, (name.len() - 1) as u32);
    let mut buf = [SENTINEL; 16];
    let (grc, gerr, glen) = getopt_raw(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE,
        buf.as_mut_ptr() as *mut c_void, buf.len() as u32);
    let text = String::from_utf8_lossy(buf.split(|b| *b == 0).next().unwrap_or(&[]));
    out("sockopt_bindtodevice", "lo", &format!(
        "set_rc={src}|set_errno={}|get_rc={grc}|get_errno={}|get_len={glen}|name={text}",
        errname(serr), errname(gerr)));
    // SAFETY: fd is a valid descriptor opened above.
    unsafe { libc::close(fd); }
}

/// `SO_COOKIE`/`SO_NETNS_COOKIE`: machine- and instance-specific, so only
/// `rc`/`errno`/"non-zero" are recorded, never the raw value (task
/// determinism rule). # C: O(1)
pub fn probe_cookies() {
    for (name, optname) in [("so_cookie", libc::SO_COOKIE), ("so_netns_cookie", libc::SO_NETNS_COOKIE)] {
        let fd = netlink_fd();
        let mut got: u64 = 0;
        let (rc, err, len) = getopt_raw(fd, libc::SOL_SOCKET, optname, &mut got as *mut u64 as *mut c_void, 8);
        out("sockopt_cookie", name, &format!(
            "rc={rc}|errno={}|len={len}|nonzero={}", errname(err), got != 0));
        // SAFETY: fd is a valid descriptor opened above.
        unsafe { libc::close(fd); }
    }
}

/// Truncating reads: a short buffer on `SO_LINGER` (8-byte value, 4-byte
/// buffer) proves truncation, not `EINVAL`; an oversized `optlen` on
/// `SO_TYPE` proves the kernel shrinks `optlen` to the value's real size
/// rather than zero-padding to what was offered. # C: O(1)
pub fn probe_len_edges() {
    let fd = netlink_fd();
    let want = libc::linger { l_onoff: 1, l_linger: 7 };
    setopt_raw(fd, libc::SOL_SOCKET, libc::SO_LINGER, &want as *const _ as *const c_void,
        std::mem::size_of::<libc::linger>() as u32);
    let mut short_buf = [SENTINEL; 4];
    let (rc, err, len) = getopt_raw(fd, libc::SOL_SOCKET, libc::SO_LINGER,
        short_buf.as_mut_ptr() as *mut c_void, 4);
    let hex: String = short_buf.iter().map(|b| format!("{b:02x}")).collect();
    out("sockopt_len", "linger_short_buffer", &format!(
        "rc={rc}|errno={}|requested_len=4|returned_optlen={len}|bytes={hex}", errname(err)));

    let mut oversized = [SENTINEL; 64];
    let (rc, err, len) = getopt_raw(fd, libc::SOL_SOCKET, libc::SO_TYPE,
        oversized.as_mut_ptr() as *mut c_void, oversized.len() as u32);
    out("sockopt_len", "type_oversized_optlen", &format!(
        "rc={rc}|errno={}|requested_len={}|returned_optlen={len}", errname(err), oversized.len()));
    // SAFETY: fd is a valid descriptor opened above.
    unsafe { libc::close(fd); }
}
