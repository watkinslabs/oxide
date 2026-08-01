// fsconfig(2) 431: the command set and the argument-admission switch of
// `fs/fsopen.c` `SYSCALL_DEFINE5(fsconfig)`. Linux validates `_key`, `_value`
// and `aux` per command BEFORE it touches the context fd, and every command has
// a different rule — `SET_FLAG` wants no value and `aux == 0`, `SET_BINARY`
// wants `0 < aux <= 1 MiB`, `SET_PATH*` wants `AT_FDCWD` or a non-negative
// dirfd, `SET_FD` wants no value and a non-negative fd, the `CMD_*` trio wants
// none of the three, and an unrecognised command is EOPNOTSUPP (not EINVAL).
//
// Ungated on purpose: `431_fsconfig.rs` is `#![cfg(target_os = "oxide-kernel")]`
// so a `#[cfg(test)]` block inside it compiles out silently (docs/53, CLAUDE.md
// phantom-test rule). The admission ladder is the decision worth testing.

use syscall::errno::Errno;

/// `FSCONFIG_*` (`include/uapi/linux/mount.h`).
pub const FSCONFIG_SET_FLAG:        u64 = 0;
pub const FSCONFIG_SET_STRING:      u64 = 1;
pub const FSCONFIG_SET_BINARY:      u64 = 2;
pub const FSCONFIG_SET_PATH:        u64 = 3;
pub const FSCONFIG_SET_PATH_EMPTY:  u64 = 4;
pub const FSCONFIG_SET_FD:          u64 = 5;
pub const FSCONFIG_CMD_CREATE:      u64 = 6;
pub const FSCONFIG_CMD_RECONFIGURE: u64 = 7;
pub const FSCONFIG_CMD_CREATE_EXCL: u64 = 8;

/// `strndup_user(_key, 256)` (`fs/fsopen.c`).
pub const KEY_MAX: usize = 256;
/// `strndup_user(_value, 256)` for `FSCONFIG_SET_STRING`.
pub const VALUE_MAX: usize = 256;
/// `aux > 1024 * 1024` rejects an oversized `FSCONFIG_SET_BINARY` blob.
pub const BINARY_MAX: i32 = 1024 * 1024;
/// `AT_FDCWD` — the one negative dirfd `FSCONFIG_SET_PATH*` accepts.
pub const AT_FDCWD: i32 = -100;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsconfigCmd {
    SetFlag,
    SetString,
    SetBinary,
    SetPath,
    SetPathEmpty,
    SetFd,
    CmdCreate,
    CmdCreateExcl,
    CmdReconfigure,
}

impl FsconfigCmd {
    /// Commands carrying a parameter key — everything but the `CMD_*` trio, for
    /// which Linux requires `_key == NULL`. # C: O(1)
    pub fn takes_key(self) -> bool {
        !matches!(self, FsconfigCmd::CmdCreate | FsconfigCmd::CmdCreateExcl | FsconfigCmd::CmdReconfigure)
    }

    /// # C: O(1)
    pub fn value_kind(self) -> ValueKind {
        match self {
            FsconfigCmd::SetString    => ValueKind::Str,
            FsconfigCmd::SetBinary    => ValueKind::Blob,
            FsconfigCmd::SetPath      => ValueKind::Path { empty_ok: false },
            FsconfigCmd::SetPathEmpty => ValueKind::Path { empty_ok: true },
            _ => ValueKind::None,
        }
    }
}

/// Value shape the command reads out of `_value`, so the slot file copies in
/// the right way without re-deriving it from the command number. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ValueKind {
    /// `_value` must be NULL: `SET_FLAG`, `SET_FD`, the `CMD_*` trio.
    None,
    /// NUL-terminated string, `VALUE_MAX` bound.
    Str,
    /// Pathname, empty permitted for `SET_PATH_EMPTY` (`LOOKUP_EMPTY`).
    Path { empty_ok: bool },
    /// Blob of `aux` bytes.
    Blob,
}

/// `SYSCALL_DEFINE5(fsconfig)` prologue: `fd < 0` → EINVAL, then the per-command
/// `_key`/`_value`/`aux` switch, then EOPNOTSUPP for an unknown command. `key`
/// and `value` are the raw user pointers (0 == NULL); `aux` is Linux's signed
/// `int aux`. # C: O(1)
pub fn classify(fd: i32, cmd: u64, key: u64, value: u64, aux: i32) -> Result<FsconfigCmd, Errno> {
    if fd < 0 { return Err(Errno::Einval); }
    match cmd {
        FSCONFIG_SET_FLAG => {
            if key == 0 || value != 0 || aux != 0 { return Err(Errno::Einval); }
            Ok(FsconfigCmd::SetFlag)
        }
        FSCONFIG_SET_STRING => {
            if key == 0 || value == 0 || aux != 0 { return Err(Errno::Einval); }
            Ok(FsconfigCmd::SetString)
        }
        FSCONFIG_SET_BINARY => {
            if key == 0 || value == 0 || aux <= 0 || aux > BINARY_MAX { return Err(Errno::Einval); }
            Ok(FsconfigCmd::SetBinary)
        }
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            if key == 0 || value == 0 || (aux != AT_FDCWD && aux < 0) { return Err(Errno::Einval); }
            Ok(if cmd == FSCONFIG_SET_PATH { FsconfigCmd::SetPath } else { FsconfigCmd::SetPathEmpty })
        }
        FSCONFIG_SET_FD => {
            if key == 0 || value != 0 || aux < 0 { return Err(Errno::Einval); }
            Ok(FsconfigCmd::SetFd)
        }
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL | FSCONFIG_CMD_RECONFIGURE => {
            if key != 0 || value != 0 || aux != 0 { return Err(Errno::Einval); }
            Ok(match cmd {
                FSCONFIG_CMD_CREATE      => FsconfigCmd::CmdCreate,
                FSCONFIG_CMD_CREATE_EXCL => FsconfigCmd::CmdCreateExcl,
                _                        => FsconfigCmd::CmdReconfigure,
            })
        }
        _ => Err(Errno::Eopnotsupp),
    }
}

/// `strndup_user(p, n)` (`mm/util.c`) applied to bytes already copied in.
/// `bytes` is what a NUL-stopping bounded read produced, so it is `n` bytes long
/// exactly when no terminator was found inside the bound — Linux's `length > n`
/// rejection. The distinction matters: a silent `n`-byte prefix would turn an
/// over-long option name into a DIFFERENT, possibly valid, option name.
/// Non-UTF-8 is the same EINVAL the key/value readers report. # C: O(n)
pub fn strndup_admit(bytes: &[u8], n: usize) -> Result<&str, Errno> {
    if bytes.len() >= n { return Err(Errno::Einval); }
    core::str::from_utf8(bytes).map_err(|_| Errno::Einval)
}

/// `getname_flags(_value, lookup_flags)` for the `SET_PATH` pair: `LOOKUP_EMPTY`
/// is set only by `FSCONFIG_SET_PATH_EMPTY`, and without it an empty pathname is
/// ENOENT — the same rule `AT_EMPTY_PATH` follows everywhere else. # C: O(1)
pub fn admit_path_value(value: &str, empty_ok: bool) -> Result<(), Errno> {
    if value.is_empty() && !empty_ok { return Err(Errno::Enoent); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: u64 = 0x1000;
    const VAL: u64 = 0x2000;

    #[test]
    fn context_fd_must_be_non_negative_before_the_command_switch() {
        // `if (fd < 0) return -EINVAL;` precedes the switch, so even a bogus
        // command reports EINVAL rather than EOPNOTSUPP.
        assert_eq!(classify(-1, FSCONFIG_SET_FLAG, KEY, 0, 0), Err(Errno::Einval));
        assert_eq!(classify(-1, 999, KEY, 0, 0), Err(Errno::Einval));
    }

    #[test]
    fn unknown_command_is_eopnotsupp_not_einval() {
        assert_eq!(classify(3, 9, 0, 0, 0), Err(Errno::Eopnotsupp));
        assert_eq!(classify(3, u64::MAX, 0, 0, 0), Err(Errno::Eopnotsupp));
    }

    #[test]
    fn set_fd_wants_key_no_value_and_a_non_negative_aux_fd() {
        // `case FSCONFIG_SET_FD: if (!_key || _value || aux < 0) return -EINVAL;`
        assert_eq!(classify(3, FSCONFIG_SET_FD, KEY, 0, 0), Ok(FsconfigCmd::SetFd));
        assert_eq!(classify(3, FSCONFIG_SET_FD, KEY, 0, 7), Ok(FsconfigCmd::SetFd));
        assert_eq!(classify(3, FSCONFIG_SET_FD, 0, 0, 7), Err(Errno::Einval));
        assert_eq!(classify(3, FSCONFIG_SET_FD, KEY, VAL, 7), Err(Errno::Einval));
        assert_eq!(classify(3, FSCONFIG_SET_FD, KEY, 0, -1), Err(Errno::Einval));
        assert_eq!(classify(3, FSCONFIG_SET_FD, KEY, 0, AT_FDCWD), Err(Errno::Einval));
    }

    #[test]
    fn set_fd_carries_a_key_and_reads_no_user_value() {
        assert!(FsconfigCmd::SetFd.takes_key());
        assert_eq!(FsconfigCmd::SetFd.value_kind(), ValueKind::None);
    }

    #[test]
    fn set_flag_and_set_string_disagree_only_about_the_value_pointer() {
        assert_eq!(classify(3, FSCONFIG_SET_FLAG, KEY, 0, 0), Ok(FsconfigCmd::SetFlag));
        assert_eq!(classify(3, FSCONFIG_SET_FLAG, KEY, VAL, 0), Err(Errno::Einval));
        assert_eq!(classify(3, FSCONFIG_SET_STRING, KEY, VAL, 0), Ok(FsconfigCmd::SetString));
        assert_eq!(classify(3, FSCONFIG_SET_STRING, KEY, 0, 0), Err(Errno::Einval));
        // Both reject a non-zero aux.
        assert_eq!(classify(3, FSCONFIG_SET_FLAG, KEY, 0, 1), Err(Errno::Einval));
        assert_eq!(classify(3, FSCONFIG_SET_STRING, KEY, VAL, 1), Err(Errno::Einval));
    }

    #[test]
    fn set_binary_bounds_aux_to_one_mib() {
        assert_eq!(classify(3, FSCONFIG_SET_BINARY, KEY, VAL, 1), Ok(FsconfigCmd::SetBinary));
        assert_eq!(classify(3, FSCONFIG_SET_BINARY, KEY, VAL, BINARY_MAX), Ok(FsconfigCmd::SetBinary));
        assert_eq!(classify(3, FSCONFIG_SET_BINARY, KEY, VAL, 0), Err(Errno::Einval));
        assert_eq!(classify(3, FSCONFIG_SET_BINARY, KEY, VAL, BINARY_MAX + 1), Err(Errno::Einval));
    }

    #[test]
    fn set_path_accepts_at_fdcwd_but_no_other_negative_dirfd() {
        assert_eq!(classify(3, FSCONFIG_SET_PATH, KEY, VAL, AT_FDCWD), Ok(FsconfigCmd::SetPath));
        assert_eq!(classify(3, FSCONFIG_SET_PATH_EMPTY, KEY, VAL, 4), Ok(FsconfigCmd::SetPathEmpty));
        assert_eq!(classify(3, FSCONFIG_SET_PATH, KEY, VAL, -2), Err(Errno::Einval));
        assert_eq!(FsconfigCmd::SetPath.value_kind(), ValueKind::Path { empty_ok: false });
        assert_eq!(FsconfigCmd::SetPathEmpty.value_kind(), ValueKind::Path { empty_ok: true });
    }

    #[test]
    fn cmd_trio_takes_neither_key_value_nor_aux() {
        for (c, want) in [
            (FSCONFIG_CMD_CREATE, FsconfigCmd::CmdCreate),
            (FSCONFIG_CMD_CREATE_EXCL, FsconfigCmd::CmdCreateExcl),
            (FSCONFIG_CMD_RECONFIGURE, FsconfigCmd::CmdReconfigure),
        ] {
            assert_eq!(classify(3, c, 0, 0, 0), Ok(want));
            assert_eq!(classify(3, c, KEY, 0, 0), Err(Errno::Einval));
            assert_eq!(classify(3, c, 0, VAL, 0), Err(Errno::Einval));
            assert_eq!(classify(3, c, 0, 0, 1), Err(Errno::Einval));
            assert!(!want.takes_key());
        }
    }

    // An over-long key is EINVAL, not a truncated prefix: `strndup_user(_key,
    // 256)` accepts at most 255 characters plus the terminator.
    #[test]
    fn a_key_that_does_not_terminate_inside_the_bound_is_einval() {
        let long = [b'k'; KEY_MAX];
        assert_eq!(strndup_admit(&long, KEY_MAX), Err(Errno::Einval));
        let just_fits = [b'k'; KEY_MAX - 1];
        assert_eq!(strndup_admit(&just_fits, KEY_MAX), Ok(core::str::from_utf8(&just_fits).unwrap()));
    }

    #[test]
    fn an_empty_value_is_accepted_and_non_utf8_is_einval() {
        assert_eq!(strndup_admit(b"", VALUE_MAX), Ok(""));
        assert_eq!(strndup_admit(b"ro", VALUE_MAX), Ok("ro"));
        assert_eq!(strndup_admit(&[0xffu8, 0xfe], VALUE_MAX), Err(Errno::Einval));
    }

    // `FSCONFIG_SET_PATH` has no LOOKUP_EMPTY, so "" is ENOENT; only the
    // _EMPTY variant admits it.
    #[test]
    fn an_empty_path_is_enoent_unless_the_command_is_the_empty_variant() {
        assert_eq!(admit_path_value("", false), Err(Errno::Enoent));
        assert_eq!(admit_path_value("", true), Ok(()));
        assert_eq!(admit_path_value("/dev/sda", false), Ok(()));
        assert_eq!(admit_path_value("/dev/sda", true), Ok(()));
    }
}
