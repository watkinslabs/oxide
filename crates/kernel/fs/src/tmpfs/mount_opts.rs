// tmpfs mount-option parsing (Linux `shmem_parse_options` subset).
//
// `mount("tmpfs", target, "tmpfs", flags, data)` carries a comma-separated
// option string in `data`. systemd-user-runtime-dir mounts the per-user
// runtime dir with `mode=0700,uid=979,gid=979,size=<bytes>,nr_inodes=<n>`
// (util-linux/systemd `mount-util.c`); the ROOT inode's owner/mode come from
// these options, and pam_systemd/`systemd --user` require /run/user/UID to be
// mode 0700 owned by the target uid/gid. Before this parser the option string
// was dropped, so every tmpfs mounted root:root 0755 with half-RAM limits —
// a real-Linux divergence. We honour the keys Linux tmpfs accepts and that the
// boot userspace actually passes; unknown keys are ignored (accept-and-noop)
// rather than EINVAL so a future SMACK `smackfsroot=*` or `noswap` does not
// regress the mount.

/// Parsed tmpfs `-o` options. `None` fields mean "not specified — use the
/// Linux default" (half-RAM blocks/inodes, root inode mode 0755 owned by 0:0).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct TmpfsOpts {
    /// `mode=` — root-inode permission bits (octal in the option string).
    pub mode: Option<u16>,
    /// `uid=` — root-inode owner uid.
    pub uid: Option<u32>,
    /// `gid=` — root-inode owner gid.
    pub gid: Option<u32>,
    /// `size=` — max bytes for data pages (accepts k/m/g/K/M/G suffix, or a
    /// trailing `%` meaning percent of RAM). Mutually exclusive with
    /// `nr_blocks`: parsing keeps only the last supplied block limit.
    pub size_bytes: Option<u64>,
    /// `nr_blocks=` — max data pages, directly (no byte→page conversion).
    pub nr_blocks: Option<u64>,
    /// `nr_inodes=` — max inode count.
    pub nr_inodes: Option<u64>,
}

/// Parse a decimal (or 0x-hex) unsigned value, returning `None` on any garbage
/// so a malformed option is ignored rather than mis-charged. # C: O(len)
fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if s.is_empty() { return None; }
    s.parse::<u64>().ok()
}

/// Parse `mode=` — Linux tmpfs reads it as OCTAL (e.g. `0700`), masked to the
/// 07777 permission/setid bits. # C: O(len)
fn parse_mode(s: &str) -> Option<u16> {
    let s = s.trim().trim_start_matches("0o");
    u32::from_str_radix(s, 8).ok().map(|m| (m & 0o7777) as u16)
}

/// Parse a `size=` value: bytes with an optional single-letter binary suffix
/// (k/m/g = 1024^n, matching `mount(8)`'s `size=`), or a trailing `%` giving a
/// percentage that the accountant resolves against total RAM. Returns the size
/// in BYTES (percent is encoded by the caller via `size_percent`). # C: O(len)
fn parse_size(s: &str) -> Option<SizeVal> {
    let s = s.trim();
    if let Some(pct) = s.strip_suffix('%') {
        return parse_u64(pct).map(SizeVal::Percent);
    }
    let (num, mult): (&str, u64) = match s.as_bytes().last().copied() {
        Some(b'k') | Some(b'K') => (&s[..s.len() - 1], 1 << 10),
        Some(b'm') | Some(b'M') => (&s[..s.len() - 1], 1 << 20),
        Some(b'g') | Some(b'G') => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    parse_u64(num).map(|n| SizeVal::Bytes(n.saturating_mul(mult)))
}

/// A `size=` value, either absolute bytes or a percent of RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SizeVal {
    Bytes(u64),
    Percent(u64),
}

impl TmpfsOpts {
    /// Parse the comma-separated `data` option string. Empty/`None`-equivalent
    /// input yields all-default options. Unknown keys and bare flags
    /// (`noswap`, `smackfsroot=*`, …) are ignored. # C: O(len)
    pub(super) fn parse(data: &str, total_ram_pages: u64) -> Self {
        let mut o = TmpfsOpts::default();
        for tok in data.split(',') {
            let tok = tok.trim();
            if tok.is_empty() { continue; }
            let (key, val) = match tok.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue, // bare flag (e.g. `noswap`) — nothing to charge
            };
            match key {
                "mode" => o.mode = parse_mode(val).or(o.mode),
                "uid" => o.uid = parse_u64(val).map(|v| v as u32).or(o.uid),
                "gid" => o.gid = parse_u64(val).map(|v| v as u32).or(o.gid),
                "nr_inodes" => o.nr_inodes = parse_u64(val).or(o.nr_inodes),
                "nr_blocks" => {
                    if let Some(blocks) = parse_u64(val) {
                        o.nr_blocks = Some(blocks);
                        o.size_bytes = None;
                    }
                }
                "size" => {
                    match parse_size(val) {
                        Some(SizeVal::Bytes(b)) => {
                            o.size_bytes = Some(b);
                            o.nr_blocks = None;
                        }
                        // Percent → bytes via total RAM (page-granular is fine;
                        // convert pages back to bytes so `resolve_blocks` shares
                        // one byte→page round-up path).
                        Some(SizeVal::Percent(p)) => {
                            let pages = total_ram_pages.saturating_mul(p) / 100;
                            o.size_bytes = Some(pages.saturating_mul(super::limits::PG as u64));
                            o.nr_blocks = None;
                        }
                        None => {}
                    }
                }
                _ => {} // unknown key — accept-and-ignore (no EINVAL regression)
            }
        }
        o
    }

    /// Resolve the block cap (in pages) from `size=`/`nr_blocks=`, falling back
    /// to `default_pages` (Linux half-RAM) when neither is given. `size` (bytes)
    /// is rounded UP to whole pages. # C: O(1)
    pub(super) fn resolve_blocks(&self, default_pages: u64) -> u64 {
        if let Some(b) = self.size_bytes {
            let pg = super::limits::PG as u64;
            return b.div_ceil(pg);
        }
        self.nr_blocks.unwrap_or(default_pages)
    }

    /// Resolve the inode cap from `nr_inodes=`, else `default_inodes`. # C: O(1)
    pub(super) fn resolve_inodes(&self, default_inodes: u64) -> u64 {
        self.nr_inodes.unwrap_or(default_inodes)
    }
}
