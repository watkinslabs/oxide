// Mount-data string → `TmpfsOpts`. One key at a time, in the reference's
// order, with the reference's refusals.
//
// The rule this module exists to enforce: an option is either ACTED ON or
// REFUSED. There is no third answer. A key accepted and dropped is a lie to
// whoever wrote it — `mount -o noswap` that still swaps, `mount -o size=64mb`
// (note the `b`) that silently becomes a default-sized mount. Both were real
// behaviours here before this file.

use vfs::{KResult, VfsError};

use super::limits::*;
use super::memparse::{memparse, parse_mode, parse_u32};
use super::mpol::parse_mpol;
use super::opts::*;

const KEY_GID: &str = "gid";
const KEY_HUGE: &str = "huge";
const KEY_MODE: &str = "mode";
const KEY_MPOL: &str = "mpol";
const KEY_NR_BLOCKS: &str = "nr_blocks";
const KEY_NR_INODES: &str = "nr_inodes";
const KEY_SIZE: &str = "size";
const KEY_UID: &str = "uid";
const KEY_INODE32: &str = "inode32";
const KEY_INODE64: &str = "inode64";
const KEY_NOSWAP: &str = "noswap";
const KEY_QUOTA: &str = "quota";
const KEY_USRQUOTA: &str = "usrquota";
const KEY_GRPQUOTA: &str = "grpquota";
const KEY_USRQUOTA_BLOCK: &str = "usrquota_block_hardlimit";
const KEY_USRQUOTA_INODE: &str = "usrquota_inode_hardlimit";
const KEY_GRPQUOTA_BLOCK: &str = "grpquota_block_hardlimit";
const KEY_GRPQUOTA_INODE: &str = "grpquota_inode_hardlimit";
const KEY_CASEFOLD: &str = "casefold";
const KEY_STRICT_ENCODING: &str = "strict_encoding";

/// Split a mount-data string into option tokens.
///
/// The separator is a comma that is NOT followed by a digit. A plain split on
/// every comma would cut `mpol=bind:0,1` in half and leave `1` as a key
/// nothing recognises, which is why the node-list case has to be part of the
/// tokeniser rather than of the `mpol` handler.
/// # C: O(len)
pub(crate) fn split_opts(data: &str) -> impl Iterator<Item = &str> {
    let mut rest = data;
    core::iter::from_fn(move || {
        if rest.is_empty() { return None; }
        let bytes = rest.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == OPT_SEP as u8 && !bytes.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
                let tok = &rest[..i];
                rest = &rest[i + 1..];
                return Some(tok);
            }
            i += 1;
        }
        let tok = rest;
        rest = "";
        Some(tok)
    }).filter(|t| !t.is_empty())
}

/// A value option was written with no value, or a flag option with one.
/// # C: O(1)
fn wrong_shape() -> VfsError { VfsError::Einval }

/// Read the value of a key that requires one. # C: O(1)
fn need_value<'a>(val: Option<&'a str>) -> KResult<&'a str> { val.ok_or_else(wrong_shape) }

/// Reject a value on a key that takes none. # C: O(1)
fn need_flag(val: Option<&str>) -> KResult<()> {
    if val.is_some() { return Err(wrong_shape()); }
    Ok(())
}

/// A number that must consume its whole value, with binary suffixes allowed.
/// # C: O(len)
fn whole_number(val: &str) -> KResult<u64> {
    let (n, rest) = memparse(val);
    if !rest.is_empty() { return Err(VfsError::Einval); }
    Ok(n)
}

/// A quota hard limit: a whole number, non-zero, at or below `max`. Zero is
/// refused rather than treated as "no limit" — a mount writing `=0` is asking
/// for something, and the something it would get is a class that can allocate
/// nothing.
/// # C: O(len)
fn quota_limit(val: &str, max: u64) -> KResult<u64> {
    let n = whole_number(val)?;
    if n == 0 || n > max { return Err(VfsError::Einval); }
    Ok(n)
}

/// Parse `size=`: bytes, or a percentage of RAM, resolved to a PAGE ceiling.
/// # C: O(len)
fn parse_size_blocks(val: &str, total_ram_pages: u64) -> KResult<u64> {
    let (n, rest) = memparse(val);
    let bytes = match rest.strip_prefix(PERCENT_SUFFIX) {
        Some(after) => {
            if !after.is_empty() { return Err(VfsError::Einval); }
            n.saturating_mul(PG_BYTES)
                .saturating_mul(total_ram_pages) / PERCENT
        }
        None => {
            if !rest.is_empty() { return Err(VfsError::Einval); }
            n
        }
    };
    Ok(bytes.div_ceil(PG_BYTES))
}

/// Page size in bytes, as the option arithmetic sees it.
const PG_BYTES: u64 = super::super::limits::PG as u64;

/// Parse a whole tmpfs mount-data string.
///
/// `cred` decides the privileged options; `total_ram_pages` resolves a
/// percentage `size=`. Nothing is half-applied: the first refusal ends the
/// parse and the mount fails with it.
/// # C: O(len(data))
pub(crate) fn parse_opts(data: &str, total_ram_pages: u64, cred: MountCred) -> KResult<TmpfsOpts> {
    let mut o = TmpfsOpts::default();
    for tok in split_opts(data) {
        let (key, val) = match tok.split_once(OPT_ASSIGN) {
            Some((k, v)) => (k, Some(v)),
            None => (tok, None),
        };
        parse_one(&mut o, key, val, total_ram_pages, cred)?;
    }
    Ok(o)
}

/// Consume one option token. An unknown key is not this module's to refuse —
/// admission (`params.rs`) already decided which keys exist, and a mount whose
/// key list came from elsewhere (a security module's own option) must not fail
/// here.
/// # C: O(len(tok))
fn parse_one(o: &mut TmpfsOpts, key: &str, val: Option<&str>, total_ram_pages: u64,
             cred: MountCred) -> KResult<()> {
    match key {
        KEY_SIZE => o.blocks = Some(parse_size_blocks(need_value(val)?, total_ram_pages)?),
        KEY_NR_BLOCKS => {
            let n = whole_number(need_value(val)?)?;
            if n > MAX_NR_BLOCKS { return Err(VfsError::Einval); }
            o.blocks = Some(n);
        }
        KEY_NR_INODES => {
            let n = whole_number(need_value(val)?)?;
            if n > TmpfsOpts::max_inodes() { return Err(VfsError::Einval); }
            o.inodes = Some(n);
        }
        KEY_MODE => o.mode = Some(parse_mode(need_value(val)?).ok_or(VfsError::Einval)?),
        KEY_UID => o.uid = Some(parse_u32(need_value(val)?).ok_or(VfsError::Einval)?),
        KEY_GID => o.gid = Some(parse_u32(need_value(val)?).ok_or(VfsError::Einval)?),
        KEY_HUGE => {
            let mode = HugeMode::from_name(need_value(val)?).ok_or(VfsError::Einval)?;
            // A large-folio policy other than "never" asks for an allocator
            // this filesystem does not have. Refusing is the answer a kernel
            // without large-folio support gives; storing it would make
            // `/proc/mounts` claim a policy nothing applies.
            if mode != HugeMode::Never { return Err(VfsError::Einval); }
            o.huge = Some(mode);
        }
        KEY_MPOL => o.mpol = Some(parse_mpol(need_value(val)?)?),
        KEY_INODE32 => { need_flag(val)?; o.full_inums = Some(false); }
        KEY_INODE64 => { need_flag(val)?; o.full_inums = Some(true); }
        KEY_NOSWAP => {
            need_flag(val)?;
            // Turning off swap is an administrative decision about machine-wide
            // memory pressure, so an unprivileged mount may not make it.
            if !cred.in_init_userns || !cred.sys_admin { return Err(VfsError::Einval); }
            o.noswap = true;
        }
        KEY_QUOTA => { need_flag(val)?; quota_for(o, cred, QTYPE_MASK_USR | QTYPE_MASK_GRP)?; }
        KEY_USRQUOTA => { need_flag(val)?; quota_for(o, cred, QTYPE_MASK_USR)?; }
        KEY_GRPQUOTA => { need_flag(val)?; quota_for(o, cred, QTYPE_MASK_GRP)?; }
        KEY_USRQUOTA_BLOCK =>
            o.qlimits.usr_block = quota_limit(need_value(val)?, QUOTA_MAX_SPC_LIMIT)?,
        KEY_USRQUOTA_INODE =>
            o.qlimits.usr_inode = quota_limit(need_value(val)?, QUOTA_MAX_INO_LIMIT)?,
        KEY_GRPQUOTA_BLOCK =>
            o.qlimits.grp_block = quota_limit(need_value(val)?, QUOTA_MAX_SPC_LIMIT)?,
        KEY_GRPQUOTA_INODE =>
            o.qlimits.grp_inode = quota_limit(need_value(val)?, QUOTA_MAX_INO_LIMIT)?,
        // Case-insensitive lookup needs a Unicode case-folding table to
        // compare names with, and there is none here. A kernel built without
        // one refuses both spellings rather than mounting a filesystem whose
        // names would compare case-SENSITIVELY under a `casefold` mount.
        KEY_CASEFOLD => {
            if let Some(v) = val {
                if !v.starts_with(CASEFOLD_UTF8_PREFIX) { return Err(VfsError::Einval); }
            }
            return Err(VfsError::Einval);
        }
        KEY_STRICT_ENCODING => { need_flag(val)?; return Err(VfsError::Einval); }
        _ => {}
    }
    Ok(())
}

/// Record a quota class request. Quota state is per-machine bookkeeping an
/// unprivileged namespace may not create. # C: O(1)
fn quota_for(o: &mut TmpfsOpts, cred: MountCred, types: u32) -> KResult<()> {
    if !cred.in_init_userns { return Err(VfsError::Einval); }
    o.quota_types |= types;
    Ok(())
}
