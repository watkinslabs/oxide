#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use super::lookup::{mount_dentry, resolve_path};

pub use super::lookup::mount_dentry;

/// # C: O(components)
pub fn d_delete_path(abs: &str) {
    drop_cached_child(abs);
}

/// # C: O(components)
pub fn d_drop_path(abs: &str) {
    drop_cached_child(abs);
}

fn split_parent_name(abs: &str) -> Option<(&str, &str)> {
    let trimmed = abs.trim_end_matches('/');
    if trimmed.is_empty() { return None; }
    let (parent, name) = match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => return None,
    };
    if name.is_empty() { return None; }
    Some((parent, name))
}

fn drop_cached_child(abs: &str) {
    let Some((parent, name)) = split_parent_name(abs) else { return; };
    if let Some(pd) = resolve_path(parent, false).map(|p| p.dentry) {
        match pd.cached_child(name).or_else(|| vfs::d_lookup(&pd, name)) {
            Some(child) => vfs::d_drop(&child),
            None => pd.forget_child(name),
        }
    }
}

/// # C: O(subtree)
pub fn d_invalidate_path(abs: &str) {
    let Some((parent, name)) = split_parent_name(abs) else { return; };
    if let Some(pd) = resolve_path(parent, false).map(|p| p.dentry) {
        match pd.cached_child(name).or_else(|| vfs::d_lookup(&pd, name)) {
            Some(child) => vfs::d_invalidate(&child),
            None => pd.forget_child(name),
        }
    }
}

/// # C: O(components)
pub fn d_move_path(from_abs: &str, to_abs: &str) {
    let (Some((fp, fname)), Some((tp, tname))) = (split_parent_name(from_abs), split_parent_name(to_abs))
    else {
        drop_cached_child(from_abs);
        drop_cached_child(to_abs);
        return;
    };
    let from_pd = resolve_path(fp, false).map(|p| p.dentry);
    let to_pd = resolve_path(tp, false).map(|p| p.dentry);
    let (Some(from_pd), Some(to_pd)) = (from_pd, to_pd) else {
        drop_cached_child(from_abs);
        drop_cached_child(to_abs);
        return;
    };
    if let Some(old) = to_pd.cached_child(tname).or_else(|| vfs::d_lookup(&to_pd, tname)) {
        vfs::d_drop(&old);
    }
    match from_pd.cached_child(fname).or_else(|| vfs::d_lookup(&from_pd, fname)) {
        Some(child) => vfs::d_move(&child, &to_pd, tname),
        None => from_pd.forget_child(fname),
    }
}
