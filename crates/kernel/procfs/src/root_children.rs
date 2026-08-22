//! Static registry-backed children held directly by the `/proc` root.

use alloc::collections::BTreeMap;
use alloc::string::String;
use vfs::InodeRef;

/// Insert the registry directories that `/proc` must expose in its own child
/// map. A registry-only directory resolves by name but is absent from readdir.
/// # C: O(1)
pub(crate) fn insert(children: &mut BTreeMap<String, InodeRef>) {
    use alloc::string::ToString;

    let reg = crate::reg::proc_reg();
    reg.ensure_dir_path("sys");
    reg.ensure_dir_path("net");
    children.insert("sys".to_string(), reg.lookup_path("sys").unwrap());
    children.insert("net".to_string(), reg.lookup_path("net").unwrap());
    children.insert("fs".to_string(), crate::fs_dir::proc_fs_inode());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_root_holds_every_registry_backed_static_directory() {
        let mut children = BTreeMap::new();
        insert(&mut children);

        assert_eq!(children.keys().map(String::as_str).collect::<alloc::vec::Vec<_>>(),
                   ["fs", "net", "sys"]);
    }
}
