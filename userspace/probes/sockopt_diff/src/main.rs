//! `setsockopt`/`getsockopt` differential probe for `SOL_NETLINK` and
//! `SOL_SOCKET`-on-a-netlink-fd: the level pair nothing else in the tree
//! exercises (`af_packet_diff` covers `SOL_PACKET`;
//! `glibc_conformance/t_{set,get}sockopt.c` covers neither level).
//!
//! Rust, not C like `af_packet_diff`/`wait_diff`: both the host oracle and
//! the guest build target `*-unknown-linux-gnu` through the same compiler
//! (`rootfs_disks::probe_cargo`), so the "same source, same compiler is the
//! oracle" reasoning those two probes are C for applies here to Rust too.
//!
//! Output is `area|test|detail` records, diffed byte-for-byte against a real
//! Linux run of this exact binary by `tools/boot-smoke-sockopt-diff.sh`. No
//! record may carry a timestamp, pid, address, pointer value, or interface
//! name that could differ between host and guest — see each module's
//! comments for how a given case avoids that.

mod netlink;
mod record;
mod sock;
mod sockopt;
mod uapi;

use record::out;

fn main() {
    out("meta", "format", "sockopt_diff=1");

    netlink::probe_flags();
    netlink::probe_listen_all_nsid();
    netlink::probe_membership();
    netlink::probe_list_memberships();
    netlink::probe_errors();

    sockopt::probe_scalars();
    sockopt::probe_priv_scalars();
    sockopt::probe_timeo();
    sockopt::probe_linger();
    sockopt::probe_readonly();
    sockopt::probe_bindtodevice();
    sockopt::probe_cookies();
    sockopt::probe_len_edges();

    out("meta", "complete", "status=DONE");
}
