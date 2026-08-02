// devpts mount options — Linux `fs/devpts/inode.c` `struct pts_mount_opts`,
// `devpts_param_specs`, `devpts_parse_param`, `devpts_show_options`.
//
// systemd mounts `/dev/pts -o gid=5,mode=620,ptmxmode=000` on every boot, so
// these are not exotic: ignoring them gives every pty slave the wrong owner and
// the wrong mode, and leaves `/dev/ptmx` at whatever mode the node was born
// with. `mode=620` (`rw--w----`) with `gid=5` (tty) is what lets `write(1)` and
// `wall(1)` reach another user's terminal and nothing else; a slave left 0600
// root:root silently breaks that, and one left world-writable is worse.
//
// No target gate: every value here decides a permission on a device node.

extern crate alloc;
use alloc::string::String;

/// `S_IALLUGO` — the caller-settable half of a mode. Both `mode=` and
/// `ptmxmode=` are masked with it, so a mount cannot smuggle a file-type bit
/// into a node's mode.
const S_IALLUGO: u16 = 0o7777;

/// Linux `DEVPTS_DEFAULT_MODE`: a slave nobody asked about is owner-only.
pub const DEFAULT_MODE: u16 = 0o600;
/// Linux `DEVPTS_DEFAULT_PTMX_MODE`: the `ptmx` node is unreachable by mode
/// until a mount says otherwise — access normally comes via `/dev/ptmx`.
pub const DEFAULT_PTMX_MODE: u16 = 0o000;
/// Linux `NR_UNIX98_PTY_MAX` (`1 << MINORBITS`): the absolute pty ceiling, and
/// the value `max=` may not exceed.
pub const NR_UNIX98_PTY_MAX: u32 = 1 << 20;

/// One devpts mount's options (Linux `struct pts_mount_opts`).
///
/// `uid`/`gid` are `Option` rather than a value plus a `setuid`/`setgid` flag:
/// the flag pair exists in the reference only because C has no option type, and
/// it is read exactly as "was this given" — at slave creation (fall back to the
/// creator's fsuid/fsgid) and in `show_options` (print only if given).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtsMountOpts {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: u16,
    pub ptmxmode: u16,
    pub max: u32,
}

impl Default for PtsMountOpts {
    /// What an option-less `mount -t devpts` produces. # C: O(1)
    fn default() -> Self {
        PtsMountOpts {
            uid: None, gid: None,
            mode: DEFAULT_MODE, ptmxmode: DEFAULT_PTMX_MODE, max: NR_UNIX98_PTY_MAX,
        }
    }
}

impl PtsMountOpts {
    /// The owner a slave node gets, given the creating task's fs credentials
    /// (Linux `devpts_pty_new`: `opts->setuid ? opts->uid : current_fsuid()`).
    /// # C: O(1)
    pub fn slave_owner(&self, fsuid: u32, fsgid: u32) -> (u32, u32) {
        (self.uid.unwrap_or(fsuid), self.gid.unwrap_or(fsgid))
    }

    /// Is `index` within this mount's pty ceiling? Linux allocates the index
    /// with `ida_alloc_max(.., opts->max - 1)`, so `max` is a COUNT and the
    /// highest usable index is one below it. # C: O(1)
    pub fn index_permitted(&self, index: u32) -> bool { index < self.max }
}

/// Parse one `key=value` (or bare `key`) devpts option.
///
/// `newinstance` is accepted and does nothing, exactly as the reference keeps
/// it: it selected a private instance before every devpts mount became one, and
/// refusing it now would break old userspace that still passes it.
/// # C: O(len)
pub fn apply_param(opts: &mut PtsMountOpts, key: &str, value: Option<&str>) -> Result<(), ()> {
    match (key, value) {
        ("uid", Some(v))       => opts.uid = Some(parse_dec(v)?),
        ("gid", Some(v))       => opts.gid = Some(parse_dec(v)?),
        // `fsparam_u32oct`: the value is OCTAL, so `mode=620` is 0o620. Read as
        // decimal it would be 0o1154 — the setuid bit plus a wrong mode.
        ("mode", Some(v))      => opts.mode = (parse_oct(v)? as u16) & S_IALLUGO,
        ("ptmxmode", Some(v))  => opts.ptmxmode = (parse_oct(v)? as u16) & S_IALLUGO,
        ("max", Some(v))       => {
            let m = parse_dec(v)?;
            // Linux: `if (result.uint_32 > NR_UNIX98_PTY_MAX) return invalf(fc,
            // "max out of range")`.
            if m > NR_UNIX98_PTY_MAX { return Err(()); }
            opts.max = m;
        }
        ("newinstance", None)  => {}
        // A value where a flag belongs, or a flag where a value belongs, is as
        // wrong as an unknown key: `-o newinstance=1` and `-o mode` are both
        // refused by the reference's spec before any value is looked at.
        _ => return Err(()),
    }
    Ok(())
}

fn parse_dec(v: &str) -> Result<u32, ()> {
    if v.is_empty() { return Err(()); }
    v.parse::<u32>().map_err(|_| ())
}

fn parse_oct(v: &str) -> Result<u32, ()> {
    if v.is_empty() { return Err(()); }
    u32::from_str_radix(v, 8).map_err(|_| ())
}

/// Render for `/proc/mounts` (Linux `devpts_show_options`): `uid`/`gid` only
/// when given, `mode`/`ptmxmode` always and in octal, `max` only when it is
/// below the absolute ceiling. # C: O(1)
pub fn show_options(opts: &PtsMountOpts) -> String {
    let mut s = String::new();
    if let Some(u) = opts.uid { s.push_str(",uid="); push_dec(&mut s, u); }
    if let Some(g) = opts.gid { s.push_str(",gid="); push_dec(&mut s, g); }
    s.push_str(",mode=");     push_oct3(&mut s, opts.mode);
    s.push_str(",ptmxmode="); push_oct3(&mut s, opts.ptmxmode);
    if opts.max < NR_UNIX98_PTY_MAX { s.push_str(",max="); push_dec(&mut s, opts.max); }
    s
}

fn push_dec(s: &mut String, mut v: u32) {
    if v == 0 { s.push('0'); return; }
    let mut buf = [0u8; 10];
    let mut n = 0;
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    while n > 0 { n -= 1; s.push(buf[n] as char); }
}

/// `%03o` — three octal digits minimum, as the reference prints them, so
/// `mode=020` does not render as `mode=20` and read back as a different value.
fn push_oct3(s: &mut String, v: u16) {
    let mut buf = [0u8; 6];
    let mut n = 0;
    let mut x = v;
    while x > 0 { buf[n] = b'0' + (x % 8) as u8; x /= 8; n += 1; }
    while n < 3 { buf[n] = b'0'; n += 1; }
    while n > 0 { n -= 1; s.push(buf[n] as char); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(data: &str) -> Result<PtsMountOpts, ()> {
        let mut o = PtsMountOpts::default();
        for piece in data.split(',') {
            if piece.is_empty() { continue; }
            match piece.find('=') {
                None => apply_param(&mut o, piece, None)?,
                Some(i) => apply_param(&mut o, &piece[..i], Some(&piece[i + 1..]))?,
            }
        }
        Ok(o)
    }

    /// The line systemd passes on every boot. Getting `mode` right is the whole
    /// point: read as decimal, 620 would be 0o1154 — setuid plus a wrong mode.
    #[test]
    fn the_option_string_every_boot_passes_is_parsed_the_way_the_reference_reads_it() {
        let o = parse("gid=5,mode=620,ptmxmode=000").expect("systemd's devpts line");
        assert_eq!(o.gid, Some(5));
        assert_eq!(o.mode, 0o620, "mode is OCTAL");
        assert_eq!(o.ptmxmode, 0o000);
        assert_eq!(o.uid, None, "uid was not given, so it is not set");
    }

    #[test]
    fn an_option_less_mount_is_owner_only_slaves_and_an_unreachable_ptmx() {
        let o = PtsMountOpts::default();
        assert_eq!(o.mode, 0o600);
        assert_eq!(o.ptmxmode, 0o000);
        assert_eq!(o.max, NR_UNIX98_PTY_MAX);
    }

    /// Not given ⇒ the creating task's fs credentials; given ⇒ the mount's.
    #[test]
    fn slave_ownership_falls_back_to_the_creator_only_when_the_mount_did_not_say() {
        let d = PtsMountOpts::default();
        assert_eq!(d.slave_owner(1000, 1000), (1000, 1000));

        let o = parse("gid=5").expect("gid");
        assert_eq!(o.slave_owner(1000, 1000), (1000, 5), "gid= wins, uid still the creator's");

        let o = parse("uid=0,gid=5").expect("both");
        assert_eq!(o.slave_owner(1000, 1000), (0, 5));
    }

    /// `uid=0`/`gid=0` are real values, not "unset" — the bug an
    /// Option-less-with-sentinel encoding invites.
    #[test]
    fn a_zero_uid_or_gid_is_a_value_and_not_an_absence() {
        let o = parse("uid=0,gid=0").expect("root-owned slaves");
        assert_eq!((o.uid, o.gid), (Some(0), Some(0)));
        assert_eq!(o.slave_owner(1000, 1000), (0, 0));
        assert!(show_options(&o).contains(",uid=0"), "and it is shown");
    }

    #[test]
    fn a_mode_cannot_smuggle_a_file_type_bit_past_the_mask() {
        let o = parse("mode=170777").expect("masked, not refused");
        assert_eq!(o.mode, 0o777 | 0o0000, "S_IALLUGO keeps only the low 12 bits");
        assert_eq!(o.mode & !0o7777, 0);
    }

    #[test]
    fn max_is_a_count_so_the_highest_usable_index_is_one_below_it() {
        let o = parse("max=4").expect("max");
        assert_eq!(o.max, 4);
        assert!(o.index_permitted(3));
        assert!(!o.index_permitted(4), "ida_alloc_max(.., max - 1)");
    }

    #[test]
    fn max_above_the_absolute_ceiling_is_refused() {
        assert_eq!(parse(&alloc::format!("max={}", NR_UNIX98_PTY_MAX + 1)), Err(()));
        assert!(parse(&alloc::format!("max={}", NR_UNIX98_PTY_MAX)).is_ok(), "the ceiling itself is fine");
    }

    /// Kept because the reference keeps it: old userspace still passes it and a
    /// refusal would fail the mount.
    #[test]
    fn newinstance_is_accepted_and_does_nothing() {
        assert_eq!(parse("newinstance"), Ok(PtsMountOpts::default()));
        assert_eq!(parse("newinstance=1"), Err(()), "but it takes no value");
    }

    #[test]
    fn a_value_taking_option_given_as_a_bare_flag_is_refused() {
        for k in ["uid", "gid", "mode", "ptmxmode", "max"] {
            assert_eq!(parse(k), Err(()), "-o {k} needs a value");
        }
    }

    #[test]
    fn an_unknown_key_or_an_unparseable_value_is_refused() {
        for bad in ["bogus", "bogus=1", "mode=", "mode=9", "mode=abc", "uid=-1", "uid=x", "max="] {
            assert_eq!(parse(bad), Err(()), "{bad} must not parse");
        }
        // 8 and 9 are not octal digits: `mode=800` is a typo, not 0o800.
        assert_eq!(parse("mode=800"), Err(()));
    }

    /// The blob path, which is what `mount -t devpts -o ...` actually takes:
    /// the options are in the DATA string, never in the pinned-parameter slice.
    #[test]
    fn the_mount_option_blob_becomes_the_mounts_options() {
        let o = opts_for_mount("gid=5,mode=620,ptmxmode=000", &[]).expect("systemd's line");
        assert_eq!((o.gid, o.mode, o.ptmxmode), (Some(5), 0o620, 0o000));
        assert_eq!(opts_for_mount("", &[]), Ok(PtsMountOpts::default()));
        assert!(opts_for_mount("newinstance", &[]).is_ok(), "a bare flag in the blob");
        assert!(opts_for_mount("mode=9", &[]).is_err(), "a bad value fails the mount");
        assert!(opts_for_mount("", &[vfs::fs::FsParameter::string("mode", "620")]).is_err(),
            "the pinned slice is not an option source for devpts");
    }

    /// The table and the parse must agree — a name in one and not the other is
    /// how an option becomes accepted-and-ignored.
    #[test]
    fn every_declared_parameter_is_one_the_parse_consumes() {
        for spec in DEVPTS_PARAMS {
            let probe = match spec.name {
                "uid" | "gid" => "0",
                "max" => "16",
                "mode" | "ptmxmode" => "600",
                "newinstance" => "",
                other => panic!("undeclared-but-listed parameter {other}"),
            };
            let blob = if probe.is_empty() { alloc::string::String::from(spec.name) }
                       else { alloc::format!("{}={}", spec.name, probe) };
            assert!(opts_for_mount(&blob, &[]).is_ok(), "{} is declared but refused", spec.name);
        }
        assert_eq!(DEVPTS_PARAMS.len(), 6, "a new parameter needs a case here and an enforcement site");
    }

    /// What is shown is what parses back — a remount of the displayed line
    /// reproduces the same mount.
    #[test]
    fn the_shown_options_round_trip() {
        assert_eq!(show_options(&PtsMountOpts::default()), ",mode=600,ptmxmode=000");
        let o = parse("gid=5,mode=620,ptmxmode=000").expect("parse");
        assert_eq!(show_options(&o), ",gid=5,mode=620,ptmxmode=000");
        assert_eq!(parse(show_options(&o).trim_start_matches(',')), Ok(o));

        let o = parse("uid=0,gid=5,mode=20,ptmxmode=666,max=16").expect("parse");
        assert_eq!(show_options(&o), ",uid=0,gid=5,mode=020,ptmxmode=666,max=16",
            "modes print with three digits so they read back as the same value");
        assert_eq!(parse(show_options(&o).trim_start_matches(',')), Ok(o));
    }
}

/// `devpts_param_specs` (Linux `fs/devpts/inode.c`). Every name here is
/// enforced: `uid`/`gid`/`mode` land on each slave node, `ptmxmode` on the
/// instance `ptmx` node, `max` bounds index allocation, and `newinstance` is
/// the reference's own accepted no-op.
pub static DEVPTS_PARAMS: &[vfs::fs::FsParamSpec] = &[
    vfs::fs::FsParamSpec::value("gid",      vfs::fs::FsParamType::U32),
    vfs::fs::FsParamSpec::value("max",      vfs::fs::FsParamType::U32),
    vfs::fs::FsParamSpec::value("mode",     vfs::fs::FsParamType::U32Oct),
    vfs::fs::FsParamSpec::flag("newinstance"),
    vfs::fs::FsParamSpec::value("ptmxmode", vfs::fs::FsParamType::U32Oct),
    vfs::fs::FsParamSpec::value("uid",      vfs::fs::FsParamType::U32),
];

/// Build one mount's options from the `mount(2)` option BLOB.
///
/// The blob is where `mount(2)` puts them; a constructor's parameter slice
/// carries only values that are pinned open files, which devpts has none of.
/// Split with the VFS's own splitter so `a,b=c,` means one thing in this tree.
/// # C: O(len data)
pub fn opts_for_mount(data: &str, pinned: &[vfs::fs::FsParameter])
    -> Result<PtsMountOpts, vfs::VfsError>
{
    if !pinned.is_empty() { return Err(vfs::VfsError::Einval); }
    let mut opts = PtsMountOpts::default();
    for p in vfs::fs::split_monolithic(data) {
        let value = match &p.value {
            vfs::fs::FsValue::String(s) => Some(s.as_str()),
            vfs::fs::FsValue::Flag => None,
            _ => return Err(vfs::VfsError::Einval),
        };
        apply_param(&mut opts, p.key.as_str(), value).map_err(|_| vfs::VfsError::Einval)?;
    }
    Ok(opts)
}
