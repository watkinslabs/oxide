// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
use syscall::errno::Errno;

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[path = "../src/179_quotactl/abi.rs"]
mod abi;
#[path = "../src/179_quotactl/cmd.rs"]
mod cmd;

#[repr(C)]
struct TestIfDqblk {
    dqb_bhardlimit: u64,
    dqb_bsoftlimit: u64,
    dqb_curspace:   u64,
    dqb_ihardlimit: u64,
    dqb_isoftlimit: u64,
    dqb_curinodes:  u64,
    dqb_btime:      u64,
    dqb_itime:      u64,
    dqb_valid:      u32,
}

#[repr(C)]
struct TestIfDqinfo {
    dqi_bgrace: u64,
    dqi_igrace: u64,
    dqi_flags:  u32,
    dqi_valid:  u32,
}

#[test]
fn classic_setquota_ignores_unknown_dqb_valid_bits_hosted() {
    let dq = TestIfDqblk {
        dqb_bhardlimit: 0,
        dqb_bsoftlimit: 0,
        dqb_curspace:   0,
        dqb_ihardlimit: 0,
        dqb_isoftlimit: 0,
        dqb_curinodes:  0,
        dqb_btime:      0,
        dqb_itime:      0,
        dqb_valid:      (1 << 1) | (1 << 31),
    };
    let dq = abi::read_dqblk(&dq as *const _ as u64).expect("unknown dqb_valid bits are ignored");
    assert_eq!(abi::if_dqblk_fieldmask(dq.dqb_valid), vfs::DQB_SPACE);
}

#[test]
fn classic_setinfo_copyin_preserves_xfs_only_info_valid_bits_hosted() {
    let info = TestIfDqinfo {
        dqi_bgrace: 0,
        dqi_igrace: 0,
        dqi_flags:  0,
        dqi_valid:  vfs::IIF_RT_BGRACE,
    };
    let info = abi::read_dqinfo(&info as *const _ as u64).expect("copyin succeeds before support/valid checks");
    assert_eq!(info.dqi_valid, vfs::IIF_RT_BGRACE);
    assert!(!abi::dqinfo_classic_valid(info));
}

#[test]
fn classic_setquota_valid_bits_translate_to_vfs_fieldmask_hosted() {
    let valid = (1 << 0) | (1 << 1) | (1 << 4);
    let mask = abi::if_dqblk_fieldmask(valid);
    assert_eq!(mask & vfs::DQB_SPC_HARD, vfs::DQB_SPC_HARD);
    assert_eq!(mask & vfs::DQB_SPC_SOFT, vfs::DQB_SPC_SOFT);
    assert_eq!(mask & vfs::DQB_SPACE, vfs::DQB_SPACE);
    assert_eq!(mask & vfs::DQB_SPC_TIMER, vfs::DQB_SPC_TIMER);
    assert_eq!(mask & vfs::DQB_INO_HARD, 0);
}

#[test]
fn quotactl_command_type_validation_runs_hosted() {
    assert!(cmd::quotactl_cmd_type_valid(cmd::qcmd(cmd::Q_SYNC, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_type_valid(cmd::qcmd(cmd::Q_GETQUOTA, cmd::GRPQUOTA)));
    assert!(cmd::quotactl_cmd_type_valid(cmd::qcmd(cmd::Q_SETQUOTA, cmd::PRJQUOTA)));
    assert!(!cmd::quotactl_cmd_type_valid(cmd::qcmd(cmd::Q_SYNC, cmd::MAXQUOTAS)));
}

#[test]
fn quotactl_write_classification_runs_hosted() {
    assert!(!cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_SYNC, cmd::USRQUOTA)));
    assert!(!cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_GETFMT, cmd::USRQUOTA)));
    assert!(!cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_GETINFO, cmd::USRQUOTA)));

    assert!(cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_GETQUOTA, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_GETNEXTQUOTA, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_SETQUOTA, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_SETINFO, cmd::USRQUOTA)));

    assert!(!cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_XGETQSTAT, cmd::USRQUOTA)));
    assert!(!cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_XGETQSTATV, cmd::USRQUOTA)));
    assert!(!cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_XGETQUOTA, cmd::USRQUOTA)));
    assert!(!cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_XGETNEXTQUOTA, cmd::USRQUOTA)));
    assert!(!cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_XQUOTASYNC, cmd::USRQUOTA)));

    assert!(cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_XQUOTAON, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_XQUOTAOFF, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_XQUOTARM, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_write(cmd::qcmd(cmd::Q_XSETQLIM, cmd::USRQUOTA)));
}

#[test]
fn quotactl_onoff_classification_runs_hosted() {
    assert!(cmd::quotactl_cmd_onoff(cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_onoff(cmd::qcmd(cmd::Q_QUOTAOFF, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_onoff(cmd::qcmd(cmd::Q_XQUOTAON, cmd::USRQUOTA)));
    assert!(cmd::quotactl_cmd_onoff(cmd::qcmd(cmd::Q_XQUOTAOFF, cmd::USRQUOTA)));
    assert!(!cmd::quotactl_cmd_onoff(cmd::qcmd(cmd::Q_SETQUOTA, cmd::USRQUOTA)));
    assert!(!cmd::quotactl_cmd_onoff(cmd::qcmd(cmd::Q_XSETQLIM, cmd::USRQUOTA)));
}
