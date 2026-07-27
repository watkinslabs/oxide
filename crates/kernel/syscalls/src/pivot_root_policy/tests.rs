use super::*;

fn e(errno: Errno) -> i64 { -(errno.as_i32() as i64) }

struct Fake {
    lookups: alloc::vec::Vec<Arg>,
    lookup_err: alloc::vec::Vec<(Arg, Errno)>,
    may_mount: bool,
    commit_err: Option<Errno>,
    committed: bool,
}

impl Fake {
    fn new() -> Self {
        Fake { lookups: alloc::vec::Vec::new(), lookup_err: alloc::vec::Vec::new(),
            may_mount: true, commit_err: None, committed: false }
    }
}

impl PivotOps for Fake {
    fn lookup_directory(&mut self, arg: Arg) -> Result<(), i64> {
        self.lookups.push(arg);
        for (a, err) in self.lookup_err.iter() { if *a == arg { return Err(e(*err)); } }
        Ok(())
    }
    fn may_mount(&mut self) -> bool { self.may_mount }
    fn commit(&mut self) -> Result<(), i64> {
        self.committed = true;
        match self.commit_err { Some(err) => Err(e(err)), None => Ok(()) }
    }
}

#[test]
fn a_clean_call_resolves_both_paths_then_commits() {
    let mut f = Fake::new();
    assert_eq!(pivot_root(&mut f), Ok(()));
    assert_eq!(f.lookups, alloc::vec![Arg::NewRoot, Arg::PutOld]);
    assert!(f.committed);
}

#[test]
fn new_root_is_resolved_before_put_old_is_looked_at() {
    let mut f = Fake::new();
    f.lookup_err.push((Arg::NewRoot, Errno::Enotdir));
    f.lookup_err.push((Arg::PutOld, Errno::Enoent));
    assert_eq!(pivot_root(&mut f), Err(e(Errno::Enotdir)));
    assert_eq!(f.lookups, alloc::vec![Arg::NewRoot], "put_old must not be resolved");
    assert!(!f.committed);
}

#[test]
fn a_bad_put_old_reports_its_own_errno() {
    let mut f = Fake::new();
    f.lookup_err.push((Arg::PutOld, Errno::Enoent));
    assert_eq!(pivot_root(&mut f), Err(e(Errno::Enoent)));
    assert_eq!(f.lookups, alloc::vec![Arg::NewRoot, Arg::PutOld]);
    assert!(!f.committed);
}

#[test]
fn lookup_errors_outrank_the_capability_check() {
    // Linux resolves both pathnames in the syscall wrapper and only then calls
    // path_pivot_root(), whose first act is may_mount(). An unprivileged caller
    // naming a nonexistent directory therefore sees ENOENT, never EPERM — and
    // EPERM tells it to retry with privilege it may already hold.
    for err in [Errno::Enoent, Errno::Enotdir, Errno::Eloop, Errno::Eacces,
        Errno::Enametoolong, Errno::Efault]
    {
        let mut f = Fake::new();
        f.may_mount = false;
        f.lookup_err.push((Arg::NewRoot, err));
        assert_eq!(pivot_root(&mut f), Err(e(err)));
        assert!(!f.committed);
    }
}

#[test]
fn eperm_precedes_every_mount_tree_check() {
    let mut f = Fake::new();
    f.may_mount = false;
    f.commit_err = Some(Errno::Einval);
    assert_eq!(pivot_root(&mut f), Err(e(Errno::Eperm)));
    assert!(!f.committed, "an unprivileged caller must not reach the mount tree");
}

#[test]
fn the_mount_tree_errno_is_reported_verbatim() {
    // EBUSY, ENOENT and EINVAL are all reachable from path_pivot_root and mean
    // different things; collapsing them to EINVAL was the pre-F739 behaviour.
    for err in [Errno::Ebusy, Errno::Enoent, Errno::Einval] {
        let mut f = Fake::new();
        f.commit_err = Some(err);
        assert_eq!(pivot_root(&mut f), Err(e(err)));
    }
}
