use super::*;

const REG: u32 = 0o100644;
const DIR: u32 = 0o040755;
const LNK: u32 = 0o120777;
const CHR: u32 = 0o020666;
const BLK: u32 = 0o060660;
const FIFO: u32 = 0o010644;
const SOCK: u32 = 0o140666;

fn class(name: &str) -> u16 { class_by_name(name).expect(name) }

#[test]
fn every_file_type_maps_to_its_own_class() {
    assert_eq!(inode_class(REG), Some(class("file")));
    assert_eq!(inode_class(DIR), Some(class("dir")));
    assert_eq!(inode_class(LNK), Some(class("lnk_file")));
    assert_eq!(inode_class(CHR), Some(class("chr_file")));
    assert_eq!(inode_class(BLK), Some(class("blk_file")));
    assert_eq!(inode_class(FIFO), Some(class("fifo_file")));
    assert_eq!(inode_class(SOCK), Some(class("sock_file")));
}

#[test]
fn a_device_node_is_not_a_regular_file() {
    assert_ne!(inode_class(CHR), inode_class(REG),
               "collapsing these would consult another class's rules");
    assert_ne!(inode_class(BLK), inode_class(CHR));
}

#[test]
fn a_mode_with_no_type_bits_is_an_anonymous_inode() {
    assert_eq!(inode_class(0o644), Some(class("anon_inode")));
}

#[test]
fn a_read_mask_asks_only_for_read() {
    let av = mask_to_av(REG, MAY_READ);
    assert_eq!(av, selinux::uapi::classmap::perm_bit(class("file"), "read").unwrap());
}

#[test]
fn append_is_asked_for_instead_of_write_not_as_well() {
    let file = class("file");
    let append = selinux::uapi::classmap::perm_bit(file, "append").unwrap();
    let write = selinux::uapi::classmap::perm_bit(file, "write").unwrap();
    let av = mask_to_av(REG, MAY_WRITE | MAY_APPEND);
    assert_eq!(av & append, append);
    assert_eq!(av & write, 0,
               "demanding write of an append-only domain refuses every append");
}

#[test]
fn a_plain_write_mask_asks_for_write() {
    let file = class("file");
    assert_eq!(mask_to_av(REG, MAY_WRITE),
               selinux::uapi::classmap::perm_bit(file, "write").unwrap());
}

#[test]
fn a_directory_maps_execute_to_search() {
    let dir = class("dir");
    let search = selinux::uapi::classmap::perm_bit(dir, "search").unwrap();
    assert_eq!(mask_to_av(DIR, MAY_EXEC), search);
    assert_ne!(search, selinux::uapi::classmap::perm_bit(dir, "execute").unwrap_or(0));
}

#[test]
fn a_directory_has_no_append_and_takes_write_for_both() {
    let dir = class("dir");
    let write = selinux::uapi::classmap::perm_bit(dir, "write").unwrap();
    assert_eq!(mask_to_av(DIR, MAY_WRITE), write);
    assert_eq!(mask_to_av(DIR, MAY_APPEND), 0, "a directory is never appended to");
}

#[test]
fn an_empty_mask_asks_for_nothing() {
    for mode in [REG, DIR, LNK, CHR] { assert_eq!(mask_to_av(mode, 0), 0); }
}

#[test]
fn a_combined_mask_asks_for_every_named_permission() {
    let file = class("file");
    let av = mask_to_av(REG, MAY_READ | MAY_WRITE | MAY_EXEC);
    for p in ["read", "write", "execute"] {
        let bit = selinux::uapi::classmap::perm_bit(file, p).unwrap();
        assert_eq!(av & bit, bit, "{p} missing");
    }
}

#[test]
fn the_named_initial_sids_are_distinct_and_nonzero() {
    let sids = [unlabeled_sid(), kernel_sid(), init_sid(), security_sid()];
    for s in sids { assert_ne!(s, 0, "sid zero is the absence of a label"); }
    for i in 0..sids.len() {
        for j in i + 1..sids.len() { assert_ne!(sids[i], sids[j]); }
    }
}

#[test]
fn the_extended_attribute_name_is_in_the_security_namespace() {
    assert!(XATTR_NAME_SELINUX.starts_with("security."),
            "a label outside the security namespace would be writable without privilege");
}
