//! Where an `O_CREAT` open lands when its final component is a dangling symlink.
//!
//! A create whose last component is a symlink does not create the symlink's
//! name — it follows the link and creates what the link points at. The
//! reference reaches this by re-entering the path walk on the trailing link, so
//! `/etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf` is writable by
//! `> /etc/resolv.conf` even when the target does not exist yet. Creating at the
//! link's own name instead fails `EEXIST`, because that name is taken by the
//! link — and `EEXIST` is only ever correct for `O_EXCL`.
//!
//! Ungated on purpose: the syscall slot that uses this is target-gated, where a
//! `#[cfg(test)]` block compiles away in silence (`08§7`).

extern crate alloc;
use alloc::string::String;

/// Trailing-symlink hops one create may follow before it is a loop. Matches the
/// walk's own budget, so a chain the walk would resolve is not rejected here.
pub const MAX_CREATE_LINK_HOPS: u32 = vfs::MAX_SYMLINK_DEPTH;

/// What an `O_CREAT` does when its final component is an existing symlink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalLink {
    /// Follow the link and create what it points at.
    Follow,
    /// `O_EXCL`: the name is taken by the link, and that is the whole point of
    /// the flag. Reported as `EEXIST`.
    Exists,
    /// `O_NOFOLLOW` without `O_EXCL`: the link is not followed, so the open
    /// lands on the link itself, which is not an openable file. Reported as
    /// `ELOOP`, not `EEXIST` — the name resolved, it just resolved to a link.
    Loop,
}

/// Which of the three an open asks for. `O_EXCL` outranks `O_NOFOLLOW`: the
/// reference rejects an existing final component before it ever weighs whether
/// the component may be followed. # C: O(1)
pub fn final_symlink_action(o_excl: bool, o_nofollow: bool) -> FinalLink {
    if o_excl { FinalLink::Exists }
    else if o_nofollow { FinalLink::Loop }
    else { FinalLink::Follow }
}

/// The path an `O_CREAT` retries at after its final component resolved to a
/// symlink holding `target`.
///
/// An absolute target replaces the path outright. A relative one is taken from
/// the directory holding the link, not from the caller's working directory, so
/// the retry stays anchored where the link lives. The result is fed back to the
/// same directory descriptor and the same resolve scope as the original call —
/// re-rooting it at a rendered mount path would discard the bind-mount, chroot
/// and `RESOLVE_*` identity the first walk was performed under.
/// # C: O(len)
pub fn next_create_path(original: &str, target: &str) -> String {
    if target.starts_with('/') { return String::from(target); }
    match original.rfind('/') {
        // `dir/link` → `dir/<target>`. The root case keeps its leading slash.
        Some(0) => {
            let mut out = String::from("/");
            out.push_str(target);
            out
        }
        Some(cut) => {
            let mut out = String::from(&original[..cut]);
            out.push('/');
            out.push_str(target);
            out
        }
        // A bare name resolved against a directory descriptor: the link's
        // directory IS that descriptor, so the target rides it unchanged.
        None => String::from(target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_target_replaces_the_whole_path() {
        assert_eq!(next_create_path("/etc/resolv.conf", "/run/systemd/resolve/stub.conf"),
            "/run/systemd/resolve/stub.conf");
        assert_eq!(next_create_path("rel/link", "/abs"), "/abs");
    }

    #[test]
    fn a_relative_target_is_taken_from_the_directory_holding_the_link() {
        // The real case: Fedora ships this link and nothing could write it.
        assert_eq!(next_create_path("/etc/resolv.conf", "../run/systemd/resolve/stub.conf"),
            "/etc/../run/systemd/resolve/stub.conf");
        assert_eq!(next_create_path("/etc/a/b", "c"), "/etc/a/c");
    }

    #[test]
    fn a_link_directly_under_the_root_keeps_the_roots_slash() {
        assert_eq!(next_create_path("/link", "target"), "/target");
        assert_eq!(next_create_path("/link", "../target"), "/../target");
    }

    #[test]
    fn a_bare_name_stays_relative_to_the_directory_descriptor_it_came_from() {
        assert_eq!(next_create_path("link", "target"), "target");
        assert_eq!(next_create_path("link", "sub/target"), "sub/target");
    }

    #[test]
    fn o_excl_outranks_o_nofollow_on_a_final_symlink() {
        assert_eq!(final_symlink_action(true, true), FinalLink::Exists);
        assert_eq!(final_symlink_action(true, false), FinalLink::Exists);
    }

    #[test]
    fn o_nofollow_alone_lands_on_the_link_itself_which_is_not_openable() {
        assert_eq!(final_symlink_action(false, true), FinalLink::Loop);
    }

    #[test]
    fn a_plain_create_follows_the_link() {
        assert_eq!(final_symlink_action(false, false), FinalLink::Follow);
    }

    #[test]
    fn the_hop_budget_matches_the_walks_own_symlink_budget() {
        assert_eq!(MAX_CREATE_LINK_HOPS, vfs::MAX_SYMLINK_DEPTH);
        assert!(MAX_CREATE_LINK_HOPS > 0);
    }
}
