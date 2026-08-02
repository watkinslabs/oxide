// Per-MOUNT procfs identity and the decisions it drives — Linux `struct
// proc_fs_info` (`include/linux/proc_fs.h`), which lives in `sb->s_fs_info` and
// is built fresh by `proc_fill_super` for every superblock.
//
// The point of the struct is that these answers belong to the MOUNT, not to the
// process asking. Two `mount -t proc` calls with different `hidepid=` must give
// different answers for the same reader, which is impossible while every mount
// shares one root inode and every decision is re-derived from the caller.
//
// No target gate: `hidepid=` and `subset=` are confinement decisions userspace
// relies on, so every rung is hosted-testable.

extern crate alloc;
use alloc::string::String;

/// `hidepid=` (Linux `enum proc_hidepid`). The numeric values ARE the ABI —
/// `mount -o hidepid=2` is the spelling most userspace uses — so they are fixed
/// here rather than derived from declaration order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum HidePid {
    /// Everybody may read every `/proc/<pid>` directory.
    Off = 0,
    /// Directories are visible but their contents are not readable by others.
    NoAccess = 1,
    /// Directories of other users are not even visible.
    Invisible = 2,
    /// Only processes the reader could ptrace are visible at all.
    NotPtraceable = 4,
}

/// `subset=pid` (Linux `enum proc_pidonly`): hide every non-process entry, so a
/// container sees process directories and nothing else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidOnly { Off, On }

/// The mount's own identity. Held by the root inode this mount built and
/// published in the superblock's private slot, which is where the reference
/// keeps it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcFsInfo {
    /// `gid=`: a member of this group is exempt from `hidepid` (Linux
    /// `pid_gid`, consulted through `in_group_p`).
    pub pid_gid: Option<u32>,
    pub hide_pid: HidePid,
    pub pidonly: PidOnly,
}

impl Default for ProcFsInfo {
    /// What an option-less `mount -t proc` produces: everything visible, which
    /// is the reference's default and what every existing mount gets.
    fn default() -> Self {
        ProcFsInfo { pid_gid: None, hide_pid: HidePid::Off, pidonly: PidOnly::Off }
    }
}

/// Parse a `hidepid=` value. Accepts the four numeric values and the four
/// names, exactly as the reference does — a name spelling is not a convenience
/// we add, it is what `proc_parse_hidepid_param` accepts, and userspace uses
/// both. Any other value is rejected rather than defaulted: silently taking a
/// misspelled `hidepid` as "off" hands back the confinement the caller asked
/// for and did not get. # C: O(len)
pub fn parse_hidepid(value: &str) -> Result<HidePid, ()> {
    match value {
        "0" | "off"        => Ok(HidePid::Off),
        "1" | "noaccess"   => Ok(HidePid::NoAccess),
        "2" | "invisible"  => Ok(HidePid::Invisible),
        "4" | "ptraceable" => Ok(HidePid::NotPtraceable),
        _ => Err(()),
    }
}

/// Parse a `subset=` value. The reference accepts exactly `pid`, and treats an
/// EMPTY value as "no subset" rather than an error. # C: O(len)
pub fn parse_subset(value: &str) -> Result<PidOnly, ()> {
    match value {
        ""    => Ok(PidOnly::Off),
        "pid" => Ok(PidOnly::On),
        _     => Err(()),
    }
}

/// `proc_fs_parameters` (Linux `fs/proc/root.c`). `pidns=` is deliberately
/// absent: it names a pid-namespace file to mount against, and this kernel
/// derives a mount's namespace from the mounting task rather than from a file,
/// so declaring it would claim a selector nothing reads. Every name listed here
/// is enforced below.
pub static PROC_PARAMS: &[vfs::fs::FsParamSpec] = &[
    vfs::fs::FsParamSpec::value("gid",     vfs::fs::FsParamType::U32),
    vfs::fs::FsParamSpec::value("hidepid", vfs::fs::FsParamType::String),
    vfs::fs::FsParamSpec::value("subset",  vfs::fs::FsParamType::String),
];

/// Build one mount's identity from its parameters. An unparseable VALUE is
/// `EINVAL` — admission has already accepted the key and its shape, so this is
/// the rung that judges what the value says. # C: O(params)
pub fn info_from_params(params: &[vfs::fs::FsParameter]) -> Result<ProcFsInfo, vfs::VfsError> {
    let mut info = ProcFsInfo::default();
    for p in params {
        let text = match &p.value {
            vfs::fs::FsValue::String(s) => s.as_str(),
            // A bare `-o hidepid` names no value. The reference's spec marks all
            // three as value-taking, so admission refuses the flag form before
            // it reaches here; this arm keeps the parse total.
            _ => return Err(vfs::VfsError::Einval),
        };
        match p.key.as_str() {
            "gid"     => info.pid_gid = Some(text.parse::<u32>().map_err(|_| vfs::VfsError::Einval)?),
            "hidepid" => info.hide_pid = parse_hidepid(text).map_err(|_| vfs::VfsError::Einval)?,
            "subset"  => info.pidonly = parse_subset(text).map_err(|_| vfs::VfsError::Einval)?,
            // Admission rejects an unknown key before the constructor runs, so
            // reaching here means the table and this parse disagree.
            _ => return Err(vfs::VfsError::Einval),
        }
    }
    Ok(info)
}

/// The identity a mount gets, from the two things a filesystem constructor is
/// handed: the option BLOB and the pinned-file parameters.
///
/// Which of the two carries the options is the whole content of this function,
/// and it is not obvious: `mount(2)` puts them in the blob, while the parameter
/// slice holds only values that are pinned open files (`FSCONFIG_SET_FD`).
/// procfs declares no file-valued parameter, so the slice is always empty for
/// it and reading that slice instead of the blob silently drops every option —
/// which is exactly what shipped until a guest probe showed `meminfo` inside a
/// `subset=pid` mount while every hosted test passed.
/// # C: O(len data)
pub fn info_for_mount(data: &str, pinned: &[vfs::fs::FsParameter])
    -> Result<ProcFsInfo, vfs::VfsError>
{
    // A pinned file-valued parameter can only have come from a key procfs does
    // not declare, so admission already refused it; treat its presence as the
    // contradiction it is rather than ignoring it.
    if !pinned.is_empty() { return Err(vfs::VfsError::Einval); }
    info_from_params(&vfs::fs::split_monolithic(data))
}

/// Render the mount's options for `/proc/mounts` — only the ones that were set,
/// in the reference's spelling, so a remount round-trips. # C: O(1)
pub fn show_options(info: &ProcFsInfo) -> String {
    let mut s = String::new();
    if let Some(g) = info.pid_gid {
        s.push_str(",gid=");
        push_u32(&mut s, g);
    }
    match info.hide_pid {
        HidePid::Off           => {}
        HidePid::NoAccess      => s.push_str(",hidepid=noaccess"),
        HidePid::Invisible     => s.push_str(",hidepid=invisible"),
        HidePid::NotPtraceable => s.push_str(",hidepid=ptraceable"),
    }
    if info.pidonly == PidOnly::On { s.push_str(",subset=pid"); }
    s
}

fn push_u32(s: &mut String, mut v: u32) {
    if v == 0 { s.push('0'); return; }
    let mut buf = [0u8; 10];
    let mut n = 0;
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    while n > 0 { n -= 1; s.push(buf[n] as char); }
}

/// What the reader is permitted to know about one process, given the mount's
/// `hidepid` and who is asking (Linux `has_pid_permissions`).
///
/// `min` is the threshold the CALL SITE cares about: the reference passes
/// `Invisible` where the question is "may this appear in a directory listing"
/// and `NoAccess` where it is "may this be opened". Both collapse to the same
/// ladder, which is why it is one function.
///
/// `in_pid_group` is `in_group_p(pid_gid)` for the reader; `may_ptrace` is
/// `ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)`. Both are supplied by
/// the caller so this stays a pure decision — the two live sources are the
/// running task's credentials and the ptrace policy, neither of which a hosted
/// test can produce. # C: O(1)
pub fn has_pid_permissions(info: &ProcFsInfo, min: HidePid,
                           in_pid_group: bool, may_ptrace: bool) -> bool {
    // `ptraceable` is absolute: the group exemption does not apply, because the
    // whole point of that mode is that visibility follows ptrace and nothing
    // else.
    if info.hide_pid == HidePid::NotPtraceable { return may_ptrace; }
    if (info.hide_pid as u8) < (min as u8) { return true; }
    if in_pid_group { return true; }
    may_ptrace
}

/// May a non-process entry (`/proc/meminfo`, `/proc/sys`, …) be resolved or
/// listed on this mount? `subset=pid` removes them all — the reference answers
/// `ENOENT` from `proc_lookup` and emits nothing from `proc_readdir`.
/// # C: O(1)
pub fn static_entries_visible(info: &ProcFsInfo) -> bool { info.pidonly == PidOnly::Off }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_hidepid_spelling_the_reference_accepts_is_accepted_here() {
        for (num, name, want) in [
            ("0", "off",        HidePid::Off),
            ("1", "noaccess",   HidePid::NoAccess),
            ("2", "invisible",  HidePid::Invisible),
            ("4", "ptraceable", HidePid::NotPtraceable),
        ] {
            assert_eq!(parse_hidepid(num),  Ok(want), "numeric {num}");
            assert_eq!(parse_hidepid(name), Ok(want), "name {name}");
        }
    }

    /// 3 is NOT a hidepid value — the enum skips it, and a mount naming it must
    /// fail rather than round down to `invisible`.
    #[test]
    fn a_value_outside_the_set_is_refused_rather_than_defaulted() {
        for bad in ["3", "5", "", "yes", "invisble", "OFF", "0x2", " 2"] {
            assert_eq!(parse_hidepid(bad), Err(()), "{bad} must not parse");
        }
    }

    #[test]
    fn subset_accepts_pid_and_the_empty_value_and_nothing_else() {
        assert_eq!(parse_subset("pid"), Ok(PidOnly::On));
        assert_eq!(parse_subset(""),    Ok(PidOnly::Off));
        for bad in ["pids", "PID", "all", "0"] {
            assert_eq!(parse_subset(bad), Err(()), "{bad} must not parse");
        }
    }

    #[test]
    fn an_option_less_mount_hides_nothing() {
        let d = ProcFsInfo::default();
        assert!(static_entries_visible(&d));
        assert!(has_pid_permissions(&d, HidePid::Invisible, false, false),
            "hidepid=off must not depend on ptrace or group membership");
        assert!(has_pid_permissions(&d, HidePid::NoAccess, false, false));
    }

    /// The threshold is what separates "listed" from "readable": at
    /// `hidepid=noaccess` a foreign process still APPEARS (min=Invisible is
    /// above the setting) but cannot be OPENED (min=NoAccess is not).
    #[test]
    fn noaccess_hides_contents_while_leaving_the_directory_visible() {
        let i = ProcFsInfo { hide_pid: HidePid::NoAccess, ..Default::default() };
        assert!(has_pid_permissions(&i, HidePid::Invisible, false, false),
            "still listed");
        assert!(!has_pid_permissions(&i, HidePid::NoAccess, false, false),
            "but not readable");
    }

    #[test]
    fn invisible_removes_the_directory_from_a_listing_too() {
        let i = ProcFsInfo { hide_pid: HidePid::Invisible, ..Default::default() };
        assert!(!has_pid_permissions(&i, HidePid::Invisible, false, false));
        assert!(!has_pid_permissions(&i, HidePid::NoAccess, false, false));
    }

    #[test]
    fn the_pid_group_is_exempt_from_hidepid_but_ptraceable_is_absolute() {
        let inv = ProcFsInfo { hide_pid: HidePid::Invisible, pid_gid: Some(42), ..Default::default() };
        assert!(has_pid_permissions(&inv, HidePid::Invisible, true, false),
            "a member of gid= sees everything under hidepid=invisible");

        let ptr = ProcFsInfo { hide_pid: HidePid::NotPtraceable, pid_gid: Some(42), ..Default::default() };
        assert!(!has_pid_permissions(&ptr, HidePid::Invisible, true, false),
            "hidepid=ptraceable follows ptrace ALONE — the group exemption does not apply");
        assert!(has_pid_permissions(&ptr, HidePid::Invisible, false, true));
    }

    /// Whatever the mode, a reader that could ptrace the target may see it —
    /// the last rung of the ladder.
    #[test]
    fn ptrace_access_is_the_final_rung_for_every_mode() {
        for mode in [HidePid::NoAccess, HidePid::Invisible, HidePid::NotPtraceable] {
            let i = ProcFsInfo { hide_pid: mode, ..Default::default() };
            assert!(has_pid_permissions(&i, HidePid::NoAccess, false, true), "{mode:?}");
        }
    }

    #[test]
    fn subset_pid_removes_the_static_entries() {
        let i = ProcFsInfo { pidonly: PidOnly::On, ..Default::default() };
        assert!(!static_entries_visible(&i));
    }

    /// The table and the parse must agree: every key the table admits is a key
    /// the parse handles, and nothing else is admitted. A key in one and not the
    /// other is how an option becomes accepted-and-ignored.
    #[test]
    fn every_declared_parameter_is_one_the_parse_consumes() {
        for spec in PROC_PARAMS {
            let probe = match spec.name {
                "gid"     => "0",
                "hidepid" => "off",
                "subset"  => "pid",
                other     => panic!("undeclared-but-listed parameter {other}"),
            };
            assert!(info_from_params(&[vfs::fs::FsParameter::string(spec.name, probe)]).is_ok(),
                "{} is declared but the parse refuses it", spec.name);
        }
        assert_eq!(PROC_PARAMS.len(), 3, "a new parameter needs a case here and an enforcement site");
    }

    /// The wiring bug itself, pinned: the options are in the BLOB, and the
    /// parameter slice is not an option source. Reading the slice was what made
    /// `mount -o subset=pid` succeed and confine nothing.
    #[test]
    fn a_mounts_options_come_from_the_blob_and_never_from_the_pinned_slice() {
        assert_eq!(info_for_mount("subset=pid", &[]).map(|i| i.pidonly), Ok(PidOnly::On),
            "the blob is where mount(2) puts them");
        // The shape that shipped: options ONLY in the slice. procfs declares no
        // file-valued parameter, so this cannot be a real mount — and it must
        // not quietly produce a default-confinement mount either.
        assert!(info_for_mount("", &[vfs::fs::FsParameter::string("subset", "pid")]).is_err(),
            "a pinned parameter is not an option source for procfs");
        assert_eq!(info_for_mount("", &[]), Ok(ProcFsInfo::default()));
    }

    /// THE path `mount -t proc -o subset=pid` actually takes. The constructor
    /// receives the option BLOB; its parameter slice carries only pinned open
    /// files, which procfs has none of. Reading that slice instead of the blob
    /// made every option silently do nothing — hosted tests of
    /// `info_from_params` all passed while the guest showed `meminfo` inside a
    /// `subset=pid` mount. This case is the blob.
    #[test]
    fn the_mount_option_blob_becomes_the_mounts_identity() {
        let info = info_from_params(&vfs::fs::split_monolithic("subset=pid"))
            .expect("the option string a container runtime passes");
        assert_eq!(info.pidonly, PidOnly::On);

        let info = info_from_params(&vfs::fs::split_monolithic("hidepid=invisible,gid=1000"))
            .expect("two options in one blob");
        assert_eq!(info, ProcFsInfo { pid_gid: Some(1000), hide_pid: HidePid::Invisible, pidonly: PidOnly::Off });

        assert_eq!(info_from_params(&vfs::fs::split_monolithic("")), Ok(ProcFsInfo::default()),
            "an option-less mount passes an empty blob");
        assert!(info_from_params(&vfs::fs::split_monolithic("hidepid=3")).is_err(),
            "a bad value in the blob fails the mount");
    }

    #[test]
    fn parameters_become_the_mounts_identity() {
        let info = info_from_params(&[
            vfs::fs::FsParameter::string("hidepid", "2"),
            vfs::fs::FsParameter::string("subset", "pid"),
            vfs::fs::FsParameter::string("gid", "1000"),
        ]).expect("all three are valid");
        assert_eq!(info, ProcFsInfo { pid_gid: Some(1000), hide_pid: HidePid::Invisible, pidonly: PidOnly::On });
    }

    /// A value the reference rejects must fail the MOUNT, not silently leave the
    /// default in place — that is the difference between a confinement refused
    /// and a confinement believed-in but absent.
    #[test]
    fn an_unparseable_value_fails_the_mount() {
        for p in [
            vfs::fs::FsParameter::string("hidepid", "3"),
            vfs::fs::FsParameter::string("subset", "all"),
            vfs::fs::FsParameter::string("gid", "root"),
            vfs::fs::FsParameter::flag("hidepid"),
        ] {
            assert_eq!(info_from_params(&[p.clone()]).err(), Some(vfs::VfsError::Einval), "{:?}", p.key);
        }
    }

    #[test]
    fn an_option_less_mount_parses_to_the_default() {
        assert_eq!(info_from_params(&[]), Ok(ProcFsInfo::default()));
    }

    #[test]
    fn only_the_options_that_were_set_are_shown_and_they_round_trip() {
        assert_eq!(show_options(&ProcFsInfo::default()), "");
        let i = ProcFsInfo { pid_gid: Some(0), hide_pid: HidePid::Invisible, pidonly: PidOnly::On };
        assert_eq!(show_options(&i), ",gid=0,hidepid=invisible,subset=pid");
        let i = ProcFsInfo { pid_gid: Some(1234), hide_pid: HidePid::NotPtraceable, pidonly: PidOnly::Off };
        assert_eq!(show_options(&i), ",gid=1234,hidepid=ptraceable");
        // The rendered spellings are the ones the parser accepts.
        assert_eq!(parse_hidepid("invisible"), Ok(HidePid::Invisible));
        assert_eq!(parse_hidepid("ptraceable"), Ok(HidePid::NotPtraceable));
    }
}
