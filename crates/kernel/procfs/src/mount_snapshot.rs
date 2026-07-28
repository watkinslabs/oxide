use alloc::string::String;
use alloc::vec::Vec;

use vfs::mntns::MntNamespaceRef;

pub(crate) type MountSnapshotBuilder = fn(&MntNamespaceRef, Option<&str>) -> Vec<u8>;

pub(crate) struct OpenMountSnapshot {
    namespace: MntNamespaceRef,
    root_prefix: Option<String>,
    /// `false` until the first `refresh`. Linux `seq_open` allocates the
    /// `seq_file` and its private state but renders NOTHING; the first `read()`
    /// runs `->start/->show`. Rendering at open instead made every
    /// open+read-at-0 (what a `/proc/self/mountinfo` re-parse is) pay for TWO
    /// full renders, and systemd re-parses after every mount operation while
    /// setting up a sandboxed unit (B1475).
    built: bool,
    data_seen: u64,
    poll_seen: u64,
    data: Vec<u8>,
}

impl OpenMountSnapshot {
    pub(crate) fn new(namespace: MntNamespaceRef, root_prefix: Option<String>) -> Self {
        let seq = vfs::mntns::ns_seq(namespace.id());
        Self { namespace, root_prefix, built: false, data_seen: seq, poll_seen: seq, data: Vec::new() }
    }

    pub(crate) fn refresh(&mut self, force: bool, build: MountSnapshotBuilder) {
        let seq = vfs::mntns::ns_seq(self.namespace.id());
        if self.built && !force && seq == self.data_seen { return; }
        self.data = build(&self.namespace, self.root_prefix.as_deref());
        self.data_seen = seq;
        self.built = true;
    }

    pub(crate) fn data(&self) -> &[u8] { &self.data }

    pub(crate) fn poll_mask(&mut self) -> u32 {
        let seq = vfs::mntns::ns_seq(self.namespace.id());
        let changed = seq != self.poll_seen;
        self.poll_seen = seq;
        if changed { vfs::POLL_IN | vfs::POLL_PRI | vfs::POLL_ERR } else { vfs::POLL_IN }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    fn namespace_id(namespace: &MntNamespaceRef, _root_prefix: Option<&str>) -> Vec<u8> {
        namespace.id().to_le_bytes().to_vec()
    }

    #[test]
    fn open_snapshot_pins_exact_mount_namespace_until_final_drop() {
        let user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
        let target_namespace = vfs::mntns::allocate(user.clone()).unwrap();
        let switched_namespace = vfs::mntns::allocate(user).unwrap();
        let target_id = target_namespace.id();
        let switched_id = switched_namespace.id();
        let mut open = OpenMountSnapshot::new(Arc::clone(&target_namespace), None);

        drop(target_namespace);
        assert!(vfs::mntns::ns_by_id(target_id).is_some(), "open state pins target namespace");
        assert_eq!(open.poll_mask(), vfs::POLL_IN, "unchanged pinned namespace is readable");
        vfs::mntns::bump_gen(target_id);
        assert_eq!(open.poll_mask(), vfs::POLL_IN | vfs::POLL_PRI | vfs::POLL_ERR,
            "poll observes changes in pinned namespace");
        open.refresh(true, namespace_id);
        assert_eq!(open.data(), target_id.to_le_bytes(), "refresh stays on open-time namespace");
        assert_ne!(open.data(), switched_id.to_le_bytes(), "task namespace switch cannot retarget open state");
        vfs::mntns::bump_gen(switched_id);
        assert_eq!(open.poll_mask(), vfs::POLL_IN, "switched namespace changes do not retarget poll");

        let generation = vfs::mntns::mount_generation();
        drop(open);
        assert!(vfs::mntns::ns_by_id(target_id).is_none(), "final open-state drop releases namespace");
        assert_eq!(vfs::mntns::mount_generation(), generation + 1, "VFS performs final namespace reap");
        assert!(vfs::mntns::ns_by_id(switched_id).is_some(), "target reap does not affect switched namespace");
        drop(switched_namespace);
    }
}
