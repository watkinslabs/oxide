// The write-then-read-back query nodes.
//
// A caller writes its request and reads the answer back from THE SAME open
// file description. The answer therefore belongs to the description, not to
// the inode: two callers querying at once each read their own answer, and a
// node that recomputed on read would have nothing to recompute from.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, Ordering};

use sync::{SecurityPolicy as LockClass, Spinlock};
use vfs::file::File;
use vfs::file_ops::FileOps;
use vfs::inode::InodeBuilder;
use vfs::inode_ops::mk_mode;
use vfs::{FileType, InodeRef, KResult, VfsError};

use crate::format::request::{parse_access_request, parse_context_request, parse_create_request};
use crate::format::response::access_response;
use crate::format::scalar::request_text;
use crate::ops::{NewContext, PolicyOps};
use crate::server::with_ops;

use super::plumb::{copy_out, ctl_inode_ops, slice_at};

/// Permission validating a context is checked against.
pub const PERM_CHECK_CONTEXT: &str = "check_context";
/// Permission computing a decision is checked against.
pub const PERM_COMPUTE_AV: &str = "compute_av";
/// Permission computing a created object's context is checked against.
pub const PERM_COMPUTE_CREATE: &str = "compute_create";
/// Permission computing a relabel is checked against.
pub const PERM_COMPUTE_RELABEL: &str = "compute_relabel";
/// Permission computing a member's context is checked against.
pub const PERM_COMPUTE_MEMBER: &str = "compute_member";

/// Mode of a transaction node.
const TRANSACTION_MODE: u16 = 0o666;

/// Answer of the compatibility user node.
///
/// The node is retained so a caller that opens it still finds it; the reply
/// is fixed because the question it once asked — which contexts a user may
/// take — is answered from the policy by the caller itself now.
const USER_RESPONSE: &str = "0";

/// Which question a transaction node asks.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TxKind {
    /// Validate and canonicalise a context.
    Context,
    /// Compute a decision.
    Access,
    /// Compute a created object's context.
    Create,
    /// Compute a relabelled object's context.
    Relabel,
    /// Compute a member's context.
    Member,
    /// Compatibility node.
    User,
}

/// Answer one request. # C: O(request)
///
/// The permission gate runs BEFORE the request is parsed, so a caller with no
/// permission learns nothing about which requests would have been well
/// formed.
pub fn transact(ops: &mut dyn PolicyOps, kind: TxKind, body: &[u8]) -> KResult<String> {
    if let Some(permission) = required_permission(kind) { ops.check(permission)?; }
    let text = request_text(body)?;
    match kind {
        TxKind::User => Ok(USER_RESPONSE.to_string()),
        TxKind::Context => {
            let context = parse_context_request(text)?;
            ops.canonical_context(&context)
        }
        TxKind::Access => {
            let r = parse_access_request(text)?;
            let avd = ops.compute_av(&r.scontext, &r.tcontext, r.class)?;
            Ok(access_response(&avd))
        }
        TxKind::Create => {
            let r = parse_create_request(text)?;
            ops.new_context(NewContext::Create, &r.scontext, &r.tcontext, r.class,
                            r.name.as_deref())
        }
        TxKind::Relabel | TxKind::Member => {
            let r = parse_access_request(text)?;
            let which = if kind == TxKind::Relabel { NewContext::Relabel } else { NewContext::Member };
            ops.new_context(which, &r.scontext, &r.tcontext, r.class, None)
        }
    }
}

/// Permission one transaction is gated on, if any. # C: O(1)
pub const fn required_permission(kind: TxKind) -> Option<&'static str> {
    match kind {
        TxKind::Context => Some(PERM_CHECK_CONTEXT),
        TxKind::Access => Some(PERM_COMPUTE_AV),
        TxKind::Create => Some(PERM_COMPUTE_CREATE),
        TxKind::Relabel => Some(PERM_COMPUTE_RELABEL),
        TxKind::Member => Some(PERM_COMPUTE_MEMBER),
        TxKind::User => None,
    }
}

/// Answers held for the open descriptions that computed them.
static ANSWERS: Spinlock<BTreeMap<u64, Vec<u8>>, LockClass> = Spinlock::new(BTreeMap::new());

/// Next description token; zero means "this description has no answer".
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Backend state of a transaction node: which question it asks.
struct Transaction { kind: TxKind }

/// File operations of a transaction node.
struct TransactionOps;

impl FileOps for TransactionOps {
    /// # C: O(1)
    ///
    /// The request and the answer share one description and one cursor:
    /// userspace writes the request and reads the answer back with no seek in
    /// between. A write that moved the cursor would leave the read starting
    /// past the answer, so it would copy out nothing — and a zero-length read
    /// is not an error to the caller, it is an EMPTY CONTEXT, which is then
    /// handed to a `setcon`/`setfilecon` that rightly refuses it.
    fn write_advances_pos(&self) -> bool { false }

    /// # C: O(answer)
    /// The answer is taken under the lock and written out after it is
    /// dropped: `buf` is caller memory and touching it can take a demand fault
    /// that sleeps, which under a spinlock is a scheduling violation.
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let token = file.private_data();
        if token == 0 { return Ok(0); }
        let staged = {
            let answers = ANSWERS.lock();
            answers.get(&token).map(|answer| slice_at(answer, off, buf.len()))
        };
        match staged {
            Some(answer) => Ok(copy_out(&answer, 0, buf)),
            None => Ok(0),
        }
    }

    /// # C: O(request)
    fn write_file(&self, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        let kind = file.inode().private::<Transaction>().ok_or(VfsError::Einval)?.kind;
        let answer = with_ops(|o| transact(o, kind, buf))?;
        let token = match file.private_data() {
            0 => { let t = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
                   file.set_private_data(t); t }
            t => t,
        };
        ANSWERS.lock().insert(token, answer.into_bytes());
        Ok(buf.len())
    }

    /// # C: O(log descriptions)
    fn on_release_file(&self, file: &File) {
        let token = file.private_data();
        if token != 0 { ANSWERS.lock().remove(&token); }
    }
}

/// Build one transaction node. # C: O(1)
pub fn make_transaction(kind: TxKind) -> InodeRef {
    InodeBuilder::new(crate::root::alloc_ino(), mk_mode(FileType::Regular, TRANSACTION_MODE),
                      ctl_inode_ops(), Arc::new(TransactionOps))
        .fsid(crate::root::SELINUXFS_FSID)
        .private(Arc::new(Transaction { kind }))
        .build()
}

/// Name of each transaction node and the question it asks. # C: O(1)
pub const TRANSACTION_NODES: [(&str, TxKind); 6] = [
    ("context", TxKind::Context),
    ("access", TxKind::Access),
    ("create", TxKind::Create),
    ("relabel", TxKind::Relabel),
    ("member", TxKind::Member),
    ("user", TxKind::User),
];

/// Answers currently held, for a test that a release frees one. # C: O(1)
pub fn held_answers() -> usize { ANSWERS.lock().len() }

#[cfg(test)]
#[path = "../tests/transaction.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/transaction_file.rs"]
mod file_tests;
