// The mutable object behind a ruleset file descriptor: exactly one policy
// layer, still under construction. It is never consulted by an access check —
// enforcement reads a `Domain`, which is snapshotted from a ruleset at the
// moment it is enforced. That split is what makes a rule added after
// enforcement unable to widen an already-installed sandbox.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::abi;
use crate::uapi::*;

/// A hierarchy rule: `allowed` rights at `inode` and everything beneath it.
/// The inode is the key, so the same directory reached through a bind mount is
/// the same rule target.
#[derive(Clone)]
pub struct FsRule {
    pub inode:   InodeRef,
    pub allowed: AccessMask,
}

/// A port rule: `allowed` network actions on `port`.
#[derive(Clone, Copy)]
pub struct NetRule {
    pub port:    u16,
    pub allowed: AccessMask,
}

#[derive(Default)]
struct Rules {
    fs:  Vec<FsRule>,
    net: Vec<NetRule>,
}

/// One policy layer under construction.
pub struct Ruleset {
    pub handled_fs:  AccessMask,
    pub handled_net: AccessMask,
    pub scoped:      AccessMask,
    rules: Spinlock<Rules, TaskListClass>,
}

impl Ruleset {
    /// # C: O(1)
    pub fn new(attr: &abi::RulesetAttr) -> Arc<Self> {
        Arc::new(Self {
            handled_fs: attr.handled_fs, handled_net: attr.handled_net, scoped: attr.scoped,
            rules: Spinlock::new(Rules::default()),
        })
    }

    /// Rights this layer filters, including the ones denied by default.
    /// # C: O(1)
    pub fn fs_mask(&self) -> AccessMask { abi::fs_layer_mask(self.handled_fs) }

    /// Admit and store a hierarchy rule. `is_dir` describes the rule target.
    /// # C: O(1)
    pub fn add_fs(&self, inode: InodeRef, is_dir: bool, allowed: AccessMask) -> Result<(), Errno> {
        abi::rule_access_ok(allowed, self.handled_fs)?;
        abi::path_target_ok(is_dir, allowed)?;
        let allowed = abi::absolute_access(allowed, self.handled_fs);
        self.rules.lock().fs.push(FsRule { inode, allowed });
        Ok(())
    }

    /// Admit and store a port rule.
    /// # C: O(1)
    pub fn add_net(&self, port: u64, allowed: AccessMask) -> Result<(), Errno> {
        abi::rule_access_ok(allowed, self.handled_net)?;
        abi::net_port_ok(port)?;
        self.rules.lock().net.push(NetRule { port: port as u16, allowed });
        Ok(())
    }

    /// Copy the rules out for a snapshot.
    /// # C: O(N_rules)
    pub fn snapshot(&self) -> (Vec<FsRule>, Vec<NetRule>) {
        let g = self.rules.lock();
        (g.fs.clone(), g.net.clone())
    }

    /// # C: O(1)
    pub fn num_fs_rules(&self) -> usize { self.rules.lock().fs.len() }
    /// # C: O(1)
    pub fn num_net_rules(&self) -> usize { self.rules.lock().net.len() }
}
