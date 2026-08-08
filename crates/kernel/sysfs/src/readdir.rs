// Entry collection for sysfs's synthetic directories.
//
// Every sysfs directory is synthesised from a LIVE registry snapshot, so its
// cursor must be a per-entry NAME cookie (`vfs::readdir_cookie`), never an
// ordinal index into that snapshot. `getdents` is paginated: a disk/netdev/
// module registered or removed between two calls shifts every later ordinal, so
// the listing duplicates or skips entries, and a `seekdir(3)` cookie taken
// before the mutation names a different entry after it. A name cookie is
// derived from the entry alone and survives its neighbours changing.
//
// Second invariant owned here: a name whose object vanished between the
// snapshot and the `lookup` that resolves its ino is NOT listed. `d_ino == 0`
// is how a filesystem marks a DELETED placeholder entry, so emitting a live
// entry with ino 0 reports it to userspace as already unlinked.

use alloc::string::String;
use alloc::vec::Vec;

use vfs::{CookieEntry, DirContext, FileType, Inode, KResult};

/// One directory's entries, accumulated under the shared cookie contract.
pub(crate) struct DirEntries<'a> {
    inode: &'a Inode,
    out: Vec<CookieEntry>,
}

impl<'a> DirEntries<'a> {
    /// # C: O(1)
    pub(crate) fn new(inode: &'a Inode) -> Self { Self { inode, out: Vec::new() } }

    /// Resolve `name`'s live ino through this directory's own `lookup` and take
    /// the entry. A failed lookup DROPS the entry — the object vanished, and
    /// the alternative (`d_ino == 0`) means "deleted placeholder" to userspace.
    /// # C: O(lookup)
    pub(crate) fn push(&mut self, name: &str, d_type: FileType) {
        let Ok(child) = self.inode.lookup(name) else { return };
        self.out.push(CookieEntry::new(String::from(name), child.ino(), d_type));
    }

    /// Order by cookie and emit everything at or after `ctx.pos`. # C: O(N log N)
    pub(crate) fn emit(mut self, ctx: &mut DirContext) -> KResult<()> {
        vfs::emit_by_cookie(&mut self.out, ctx)
    }
}

/// Emit a fixed `(name, type)` entry table. # C: O(N log N)
pub(crate) fn emit_table(inode: &Inode, ctx: &mut DirContext,
                         entries: &[(&str, FileType)]) -> KResult<()> {
    let mut es = DirEntries::new(inode);
    for (name, d_type) in entries.iter() { es.push(name, *d_type); }
    es.emit(ctx)
}

#[cfg(test)]
mod tests;

/// Emit `names`, every one of the same type. # C: O(N log N)
pub(crate) fn emit_names<'n>(inode: &Inode, ctx: &mut DirContext,
                             names: impl Iterator<Item = &'n str>,
                             d_type: FileType) -> KResult<()> {
    let mut es = DirEntries::new(inode);
    for name in names { es.push(name, d_type); }
    es.emit(ctx)
}
