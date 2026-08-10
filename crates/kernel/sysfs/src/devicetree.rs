// `/sys/firmware/fdt` and `/sys/firmware/devicetree/base` — the two ways
// userspace reads this machine's device tree.
//
// `fdt` is the raw blob, byte for byte, and is what `kexec -l` reads to build
// the device tree it hands the next kernel; without it an arm64 kexec fails
// before it ever reaches the syscall. `devicetree/base` is the same tree
// unflattened into directories and property files, which is the older ABI and
// is what `/proc/device-tree` points at.
//
// The path/name decisions live in `fdt::of_tree` and the layout below is
// planned before anything is registered, so a malformed blob publishes no tree
// rather than half of one — a partial device tree reads to userspace as a
// machine that genuinely lacks those nodes.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use fdt::of_tree::{export_tree, OfEntry};
use fdt::DtbError;

use crate::{ids, make_body_inode_perm, register, register_dir};

use fdt::uapi::{OF_PROP_MODE, OF_RAW_MODE, OF_SECURE_PROP_MODE, OF_SYSFS_KSET, OF_SYSFS_RAW};

/// One planned sysfs entry: a node directory, or an attribute file with the
/// exact body and permission it will be registered with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DtEntry {
    Dir { path: String },
    Attr { path: String, body: Vec<u8>, perm: u16 },
}

#[cfg(test)]
impl DtEntry {
    fn path(&self) -> &str {
        match self { DtEntry::Dir { path } => path, DtEntry::Attr { path, .. } => path }
    }
}

/// Full `/sys/firmware` layout for `blob`, in registration order: the raw
/// attribute, the kset directory, then the unflattened tree. `Err` when the
/// blob does not walk — the caller registers nothing in that case.
/// # C: O(struct_block_size * max_children)
pub(crate) fn plan(blob: &[u8]) -> Result<Vec<DtEntry>, DtbError> {
    let mut out: Vec<DtEntry> = Vec::new();
    out.push(DtEntry::Attr {
        path: OF_SYSFS_RAW.to_string(), body: Vec::from(blob), perm: OF_RAW_MODE,
    });
    out.push(DtEntry::Dir { path: OF_SYSFS_KSET.to_string() });
    let mut tree: Vec<DtEntry> = Vec::new();
    export_tree(blob, OF_SYSFS_KSET, |e| tree.push(match e {
        OfEntry::Dir { path } => DtEntry::Dir { path },
        // A withheld property still exists, with a size of zero: the file's
        // presence is part of the tree's shape, its contents are not.
        OfEntry::Prop { path, data, secure } => DtEntry::Attr {
            path,
            body: if secure { Vec::new() } else { Vec::from(data) },
            perm: if secure { OF_SECURE_PROP_MODE } else { OF_PROP_MODE },
        },
    }))?;
    out.extend(tree);
    Ok(out)
}

/// Publish the retained device tree. No-op on a platform that has none (every
/// x86_64 boot, and any arm64 firmware that describes itself with ACPI only).
/// # C: O(struct_block_size * max_children)
pub fn init() {
    let Some(blob) = firmware::fdt::blob() else { return; };
    let Ok(entries) = plan(blob) else { return; };
    let mut ino = ids::OF_ATTR_BASE;
    for e in entries {
        match e {
            DtEntry::Dir { path } => register_dir(&path),
            DtEntry::Attr { path, body, perm } => {
                register(&path, make_body_inode_perm(body, ino, perm));
                ino += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use fdt::uapi::OF_SYSFS_BASE;

    /// Every planned path, in order.
    fn paths(blob: &[u8]) -> Vec<String> {
        plan(blob).expect("plan").iter().map(|e| String::from(e.path())).collect()
    }

    #[test]
    fn the_raw_blob_is_published_whole_and_root_only() {
        let blob = fdt::fixture::virt_like();
        let p = plan(&blob).expect("plan");
        match &p[0] {
            DtEntry::Attr { path, body, perm } => {
                assert_eq!(path, OF_SYSFS_RAW);
                assert_eq!(body.as_slice(), blob.as_slice(), "kexec reads this byte for byte");
                assert_eq!(*perm, 0o400);
            }
            other => panic!("first entry must be the raw blob, got {other:?}"),
        }
    }

    #[test]
    fn the_unflattened_tree_is_rooted_at_base() {
        let blob = fdt::fixture::virt_like();
        let ps = paths(&blob);
        assert!(ps.contains(&OF_SYSFS_KSET.to_string()));
        assert!(ps.contains(&OF_SYSFS_BASE.to_string()));
        assert!(ps.contains(&format!("{OF_SYSFS_BASE}/chosen/bootargs")));
        assert!(ps.contains(&format!("{OF_SYSFS_BASE}/cpus/cpu@0/reg")));
    }

    #[test]
    fn property_files_carry_the_raw_bytes_and_are_world_readable() {
        let blob = fdt::fixture::virt_like();
        let want = format!("{OF_SYSFS_BASE}/memory@40000000/reg");
        let e = plan(&blob).expect("plan").into_iter().find(|e| e.path() == want).expect("reg");
        match e {
            DtEntry::Attr { body, perm, .. } => {
                let mut expect = Vec::new();
                expect.extend_from_slice(&0x4000_0000u64.to_be_bytes());
                expect.extend_from_slice(&0x8000_0000u64.to_be_bytes());
                assert_eq!(body, expect);
                assert_eq!(perm, 0o444);
            }
            other => panic!("expected an attribute, got {other:?}"),
        }
    }

    #[test]
    fn a_security_property_is_present_but_empty_and_root_only() {
        let mut f = fdt::fixture::Fdt::new();
        let blob = f.begin("").prop("security-key", b"hunter2").end().finish();
        let want = format!("{OF_SYSFS_BASE}/security-key");
        let e = plan(&blob).expect("plan").into_iter().find(|e| e.path() == want).expect("prop");
        match e {
            DtEntry::Attr { body, perm, .. } => {
                assert!(body.is_empty(), "the value is withheld, not published");
                assert_eq!(perm, 0o400);
            }
            other => panic!("expected an attribute, got {other:?}"),
        }
    }

    #[test]
    fn a_parent_directory_is_always_planned_before_its_contents() {
        let blob = fdt::fixture::virt_like();
        let ps = paths(&blob);
        for (i, p) in ps.iter().enumerate() {
            if p == OF_SYSFS_RAW || p == OF_SYSFS_KSET { continue; }
            let parent = p.rsplit_once('/').expect("absolute path").0;
            assert!(ps[..i].iter().any(|q| q == parent), "{p} planned before {parent}");
        }
    }

    #[test]
    fn every_planned_path_is_unique() {
        let blob = fdt::fixture::virt_like();
        let mut ps = paths(&blob);
        let n = ps.len();
        ps.sort();
        ps.dedup();
        assert_eq!(ps.len(), n);
    }

    /// A blob that does not walk must plan nothing at all: `init` registers the
    /// plan or registers nothing, so a partial tree can never be published.
    #[test]
    fn a_malformed_blob_plans_nothing() {
        assert!(plan(b"this is not a device tree").is_err());
        let mut blob = fdt::fixture::virt_like();
        let n = blob.len();
        blob[n / 2] = 0xff; // corrupt the middle of the struct/strings area
        // Either it still walks (the byte was inert) or it fails — but it must
        // never return a plan containing a path outside the tree.
        if let Ok(p) = plan(&blob) {
            for e in p { assert!(e.path().starts_with("/sys/firmware/"), "{}", e.path()); }
        }
    }
}
