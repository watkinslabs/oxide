// Quota types (quotactl UAPI).
pub const USRQUOTA: u64 = 0;
pub const GRPQUOTA: u64 = 1;
pub const PRJQUOTA: u64 = 2;
pub const MAXQUOTAS: u64 = 3;

// Q_* subcommands — values AFTER the `>> 8` decode; carry the 0x800000 prefix
// that Linux's QCMD macro OR-folds into the packed cmd (quotactl UAPI).
pub const Q_SYNC: u64 = 0x800001;
pub const Q_QUOTAON: u64 = 0x800002;
pub const Q_QUOTAOFF: u64 = 0x800003;
pub const Q_GETFMT: u64 = 0x800004;
pub const Q_GETINFO: u64 = 0x800005;
pub const Q_SETINFO: u64 = 0x800006;
pub const Q_GETQUOTA: u64 = 0x800007;
pub const Q_SETQUOTA: u64 = 0x800008;
pub const Q_GETNEXTQUOTA: u64 = 0x800009;

pub const Q_XQUOTAON:      u64 = 0x5801;
pub const Q_XQUOTAOFF:     u64 = 0x5802;
pub const Q_XGETQUOTA:     u64 = 0x5803;
pub const Q_XSETQLIM:      u64 = 0x5804;
pub const Q_XGETQSTAT:     u64 = 0x5805;
pub const Q_XQUOTARM:      u64 = 0x5806;
pub const Q_XQUOTASYNC:    u64 = 0x5807;
pub const Q_XGETQSTATV:    u64 = 0x5808;
pub const Q_XGETNEXTQUOTA: u64 = 0x5809;

// cmd packing: subcmd in the high bits, qtype in the low byte.
pub(super) const QTYPE_MASK: u64 = 0xff;
pub const SUBCMD_SHIFT: u32 = 8;

/// Pack a Linux quotactl command. # C: O(1)
pub fn qcmd(subcmd: u64, qtype: u64) -> u64 { (subcmd << SUBCMD_SHIFT) | qtype }

/// True iff the packed quotactl command names a Linux quota type. # C: O(1)
pub fn quotactl_cmd_type_valid(cmd: u64) -> bool { (cmd & QTYPE_MASK) < MAXQUOTAS }

/// Linux `quotactl_cmd_write`: commands outside this read-only set need a
/// writable mount in `quotactl_fd`. # C: O(1)
pub fn quotactl_cmd_write(cmd: u64) -> bool {
    let subcmd = cmd >> SUBCMD_SHIFT;
    !matches!(subcmd, Q_GETFMT | Q_GETINFO | Q_SYNC
        | Q_XGETQSTAT | Q_XGETQSTATV | Q_XGETQUOTA | Q_XGETNEXTQUOTA | Q_XQUOTASYNC)
}

/// True iff Linux runs this command under exclusive `s_umount`. # C: O(1)
pub fn quotactl_cmd_onoff(cmd: u64) -> bool {
    matches!(cmd >> SUBCMD_SHIFT, Q_QUOTAON | Q_QUOTAOFF | Q_XQUOTAON | Q_XQUOTAOFF)
}
