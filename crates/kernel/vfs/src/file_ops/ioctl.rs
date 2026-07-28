// `unlocked_ioctl` request/reply shapes for [`super::FileOps::unlocked_ioctl`].
// Pure ABI-adjacent data: the usercopy stays in the syscall layer, so a backend
// sees an already-decoded command and returns an already-typed payload.

/// Int-valued Linux `unlocked_ioctl` queue queries whose copy_to_user remains
/// owned by the syscall ABI layer. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IoctlIntCmd {
    /// `FIONREAD` / `SIOCINQ` — readable bytes or next datagram length.
    Fionread,
    /// `SIOCOUTQ` / `TIOCOUTQ` — protocol-defined outgoing queued bytes.
    Siocoutq,
    /// `SIOCOUTQNSD` — TCP bytes not yet handed to transmission.
    Siocoutqnsd,
    /// `SIOCATMARK` — whether the next TCP stream byte is the urgent mark.
    Siocatmark,
}

/// Linux `file_operations->unlocked_ioctl` operations whose usercopy remains
/// in the syscall ABI layer. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileIoctlCmd {
    /// `EXT4_IOC_GETVERSION` / legacy `FS_IOC_GETVERSION`.
    GetVersion,
    /// Pre-copyin admission for `EXT4_IOC_SETVERSION`.
    SetVersionPrepare,
    /// `EXT4_IOC_SETVERSION` / legacy `FS_IOC_SETVERSION`.
    SetVersion(u32),
    /// `FS_IOC_GETFSLABEL` on filesystem-specific `f_op->unlocked_ioctl`.
    GetFsLabel,
    /// Pre-copyin admission for `FS_IOC_SETFSLABEL`; carries CAP_SYS_ADMIN.
    SetFsLabelPrepare(bool),
    /// `FS_IOC_SETFSLABEL`: exact ext4 16-byte on-disk label payload.
    SetFsLabel([u8; 16]),
    /// Pre-copyin admission for `FITRIM`; carries CAP_SYS_ADMIN.
    FitTrimPrepare(bool),
    /// `FITRIM`: filesystem trim request after ABI-layer usercopy.
    FitTrim { start: u64, len: u64, minlen: u64 },
}

/// Return payload for [`FileOps::unlocked_ioctl`]. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileIoctlReply {
    /// ioctl succeeded without a scalar payload.
    Done,
    /// ioctl returned a 32-bit scalar copied by the ABI layer.
    U32(u32),
    /// ioctl returned an ext4 label buffer including the trailing NUL byte.
    Label([u8; 17]),
}
