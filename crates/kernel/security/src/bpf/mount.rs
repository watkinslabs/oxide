use syscall::errno::Errno;

use super::uapi;

/// Delegation masks owned by one bpffs mount and copied into each token it
/// creates. # C: O(1) storage
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfDelegation {
    pub allowed_cmds: u64,
    pub allowed_maps: u64,
    pub allowed_progs: u64,
    pub allowed_attachs: u64,
}

/// Parse bpffs's four colon-separated delegation values. Linux accepts enum
/// names and numeric masks; unknown names are refused rather than becoming a
/// silently broader token. # C: O(len(data))
pub fn parse_mount_delegation(data: &str) -> Result<BpfDelegation, Errno> {
    let mut out = BpfDelegation::default();
    for item in data.split(',') {
        let (key, value) = match item.split_once('=') { Some(v) => v, None => continue };
        let slot = match key {
            "delegate_cmds" => &mut out.allowed_cmds,
            "delegate_maps" => &mut out.allowed_maps,
            "delegate_progs" => &mut out.allowed_progs,
            "delegate_attachs" => &mut out.allowed_attachs,
            _ => continue,
        };
        for word in value.split(':') {
            *slot |= match word {
                "any" => u64::MAX,
                _ => parse_word(key, word).ok_or(Errno::Einval)?,
            };
        }
    }
    Ok(out)
}

fn parse_word(key: &str, word: &str) -> Option<u64> {
    if let Some(v) = word.strip_prefix("0x") {
        return u64::from_str_radix(v, 16).ok();
    }
    if word.bytes().all(|b| b.is_ascii_digit()) {
        return word.parse().ok();
    }
    let n = match key {
        "delegate_cmds" => match word {
            "MAP_CREATE" => uapi::cmd::MAP_CREATE,
            "PROG_LOAD" => uapi::cmd::PROG_LOAD,
            "BTF_LOAD" => uapi::cmd::BTF_LOAD,
            "TOKEN_CREATE" => uapi::cmd::TOKEN_CREATE,
            _ => return None,
        },
        "delegate_maps" => match word {
            "HASH" => uapi::map_type::HASH,
            "ARRAY" => uapi::map_type::ARRAY,
            "LPM_TRIE" => uapi::map_type::LPM_TRIE,
            "REUSEPORT_SOCKARRAY" => uapi::map_type::REUSEPORT_SOCKARRAY,
            _ => return None,
        },
        "delegate_progs" => match word {
            "SOCKET_FILTER" => uapi::prog_type::SOCKET_FILTER,
            "CGROUP_SKB" => uapi::prog_type::CGROUP_SKB,
            "CGROUP_DEVICE" => uapi::prog_type::CGROUP_DEVICE,
            "CGROUP_SOCK_ADDR" => uapi::prog_type::CGROUP_SOCK_ADDR,
            "RAW_TRACEPOINT" => uapi::prog_type::RAW_TRACEPOINT,
            "TRACING" => uapi::prog_type::TRACING,
            "LSM" => uapi::prog_type::LSM,
            _ => return None,
        },
        "delegate_attachs" => match word {
            "CGROUP_INET_INGRESS" => uapi::attach_type::CGROUP_INET_INGRESS,
            "CGROUP_INET_EGRESS" => uapi::attach_type::CGROUP_INET_EGRESS,
            "CGROUP_DEVICE" => uapi::attach_type::CGROUP_DEVICE,
            "CGROUP_INET4_BIND" => uapi::attach_type::CGROUP_INET4_BIND,
            "CGROUP_INET6_BIND" => uapi::attach_type::CGROUP_INET6_BIND,
            "LSM_MAC" => uapi::attach_type::LSM_MAC,
            _ => return None,
        },
        _ => return None,
    };
    Some(1u64 << n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numeric_masks_accumulate_per_mount_field() {
        let got = parse_mount_delegation(
            "delegate_cmds=MAP_CREATE:0x20,delegate_maps=HASH:ARRAY,delegate_progs=SOCKET_FILTER,delegate_attachs=any",
        ).unwrap();
        assert_eq!(got.allowed_cmds, (1u64 << uapi::cmd::MAP_CREATE) | 0x20);
        assert_eq!(got.allowed_maps, (1u64 << uapi::map_type::HASH) | (1u64 << uapi::map_type::ARRAY));
        assert_eq!(got.allowed_progs, 1u64 << uapi::prog_type::SOCKET_FILTER);
        assert_eq!(got.allowed_attachs, u64::MAX);
    }

    #[test]
    fn unknown_names_and_malformed_values_are_refused() {
        assert_eq!(parse_mount_delegation("delegate_cmds=NO_SUCH_COMMAND"), Err(Errno::Einval));
        assert_eq!(parse_mount_delegation("delegate_maps=0x"), Err(Errno::Einval));
    }
}
