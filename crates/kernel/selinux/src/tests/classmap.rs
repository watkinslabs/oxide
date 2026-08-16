use super::*;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

#[test]
fn class_values_are_one_based_and_dense() {
    assert!(class_def(0).is_none(), "class zero is the absence of a class");
    for (i, def) in SECCLASS_MAP.iter().enumerate() {
        let value = i as u16 + 1;
        assert_eq!(class_def(value).map(|d| d.name), Some(def.name));
        assert_eq!(class_by_name(def.name), Some(value));
    }
    assert!(class_def(SECCLASS_MAP.len() as u16 + 1).is_none());
}

#[test]
fn the_first_classes_hold_the_positions_other_tables_assume() {
    assert_eq!(class_by_name("security"), Some(1));
    assert_eq!(class_by_name("process"), Some(2));
    assert_eq!(class_by_name("file"), Some(7));
    assert_eq!(class_by_name("dir"), Some(8));
}

#[test]
fn class_names_are_unique() {
    let names: BTreeSet<&str> = SECCLASS_MAP.iter().map(|c| c.name).collect();
    assert_eq!(names.len(), SECCLASS_MAP.len(), "a duplicate name makes lookup ambiguous");
}

#[test]
fn no_class_exceeds_the_thirty_two_permission_limit() {
    for def in SECCLASS_MAP {
        let n = perm_count(def);
        assert!(n <= 32, "class {} declares {n} permissions", def.name);
    }
}

#[test]
fn permission_names_are_unique_within_a_class() {
    for def in SECCLASS_MAP {
        let names: Vec<&str> = perm_names(def).collect();
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len(),
                   "class {} repeats a permission name", def.name);
    }
}

#[test]
fn the_shared_file_permissions_occupy_the_same_bits_in_every_file_class() {
    let base: Vec<u32> = ["read", "write", "open", "execute"].iter()
        .map(|p| perm_bit(class_by_name("file").unwrap(), p).unwrap()).collect();
    for name in ["lnk_file", "chr_file", "blk_file", "sock_file", "fifo_file",
                 "dir", "anon_inode", "memfd_file"] {
        let c = class_by_name(name).unwrap();
        let got: Vec<u32> = ["read", "write", "open", "execute"].iter()
            .map(|p| perm_bit(c, p).unwrap()).collect();
        assert_eq!(got, base, "class {name} moved a shared permission's bit");
    }
}

#[test]
fn the_shared_socket_permissions_occupy_the_same_bits_in_every_socket_class() {
    let base: Vec<u32> = ["bind", "connect", "listen", "accept", "name_bind"].iter()
        .map(|p| perm_bit(class_by_name("socket").unwrap(), p).unwrap()).collect();
    for name in ["tcp_socket", "udp_socket", "unix_stream_socket",
                 "unix_dgram_socket", "netlink_route_socket", "sctp_socket"] {
        let c = class_by_name(name).unwrap();
        let got: Vec<u32> = ["bind", "connect", "listen", "accept", "name_bind"].iter()
            .map(|p| perm_bit(c, p).unwrap()).collect();
        assert_eq!(got, base, "class {name} moved a shared permission's bit");
    }
}

#[test]
fn class_specific_permissions_follow_the_shared_group() {
    let file = class_by_name("file").unwrap();
    let dir = class_by_name("dir").unwrap();
    let shared = perm_count(class_def(file).unwrap()) - 2;
    assert_eq!(perm_index(class_def(file).unwrap(), "execute_no_trans"),
               Some(shared as u32));
    assert_eq!(perm_index(class_def(dir).unwrap(), "add_name"), Some(shared as u32),
               "both classes append after the same shared prefix");
    assert!(perm_bit(file, "add_name").is_none(), "add_name is a directory permission");
    assert!(perm_bit(dir, "execute_no_trans").is_none());
}

#[test]
fn the_capability_class_orders_permissions_by_capability_number() {
    let cap = class_by_name("capability").unwrap();
    for (i, name) in ["chown", "dac_override", "dac_read_search", "fowner"]
        .iter().enumerate()
    {
        assert_eq!(perm_bit(cap, name), Some(1u32 << i), "{name}");
    }
    assert_eq!(perm_bit(cap, "setfcap"), Some(1u32 << 31),
               "the first capability class fills all thirty-two bits");
    assert_eq!(perm_count(class_def(cap).unwrap()), 32);
}

#[test]
fn the_user_namespace_capability_classes_mirror_the_ordinary_ones() {
    for (a, b) in [("capability", "cap_userns"), ("capability2", "cap2_userns")] {
        let (ca, cb) = (class_by_name(a).unwrap(), class_by_name(b).unwrap());
        let na: Vec<&str> = perm_names(class_def(ca).unwrap()).collect();
        let nb: Vec<&str> = perm_names(class_def(cb).unwrap()).collect();
        assert_eq!(na, nb, "{a} and {b} must share a permission ordering");
    }
}

#[test]
fn the_ipc_classes_share_their_prefix_and_append_their_own() {
    let ipc = class_by_name("ipc").unwrap();
    let msgq = class_by_name("msgq").unwrap();
    let shm = class_by_name("shm").unwrap();
    for name in ["create", "destroy", "unix_write"] {
        assert_eq!(perm_bit(msgq, name), perm_bit(ipc, name), "{name}");
        assert_eq!(perm_bit(shm, name), perm_bit(ipc, name), "{name}");
    }
    assert_eq!(perm_index(class_def(msgq).unwrap(), "enqueue"), Some(9));
    assert_eq!(perm_index(class_def(shm).unwrap(), "lock"), Some(9));
}

#[test]
fn a_permission_the_class_does_not_declare_has_no_bit() {
    let file = class_by_name("file").unwrap();
    assert!(perm_bit(file, "nonexistent").is_none());
    assert!(perm_bit(file, "").is_none());
    assert!(perm_bit(0, "read").is_none(), "class zero has no permissions");
    assert!(perm_bit(u16::MAX, "read").is_none());
}

#[test]
fn every_declared_permission_resolves_to_a_distinct_bit() {
    for (i, def) in SECCLASS_MAP.iter().enumerate() {
        let class = i as u16 + 1;
        let mut seen = 0u32;
        for name in perm_names(def) {
            let bit = perm_bit(class, name).unwrap_or_else(|| panic!("{}:{name}", def.name));
            assert_eq!(bit & seen, 0, "{}:{name} reuses a bit", def.name);
            seen |= bit;
        }
        assert_eq!(seen.count_ones() as usize, perm_count(def));
    }
}

#[test]
fn the_process_class_declares_the_transition_permissions_the_engine_requires() {
    let p = class_by_name("process").unwrap();
    assert!(perm_bit(p, "transition").is_some());
    assert!(perm_bit(p, "dyntransition").is_some());
    assert_eq!(perm_bit(p, "fork"), Some(1), "fork is the first process permission");
}

#[test]
fn every_socket_named_class_actually_carries_the_socket_permissions() {
    for def in SECCLASS_MAP.iter().filter(|d| d.name.ends_with("socket")) {
        let names: Vec<&str> = perm_names(def).collect();
        for p in ["bind", "connect", "sendto", "recvfrom"] {
            assert!(names.contains(&p), "class {} lacks {p}", def.name);
        }
    }
}
