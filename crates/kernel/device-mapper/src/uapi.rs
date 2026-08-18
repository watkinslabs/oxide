//! Device-mapper UAPI: the numbers `dmsetup` and LVM speak. Numbers only —
//! no policy, no dispatch (`52§5` rule 22).

/// Directory under `/dev` that mapped devices are published in.
pub const DM_DIR: &str = "mapper";
/// Node inside `DM_DIR` that carries the whole control ioctl surface.
pub const DM_CONTROL_NODE: &str = "control";
/// Longest target-type name a table entry may name.
pub const DM_MAX_TYPE_NAME: usize = 16;
/// Size of the fixed name field, including its terminator.
pub const DM_NAME_LEN: usize = 128;
/// Size of the fixed uuid field, including its terminator.
pub const DM_UUID_LEN: usize = 129;

/// Interface version reported by `DM_VERSION` and stamped into every reply.
pub const DM_VERSION_MAJOR: u32 = 4;
/// Minor half of the reported interface version.
pub const DM_VERSION_MINOR: u32 = 50;
/// Patch half of the reported interface version.
pub const DM_VERSION_PATCHLEVEL: u32 = 0;

/// Control-device ioctl type byte.
pub const DM_IOCTL: u32 = 0xfd;

/// Misc minor of `/dev/mapper/control`.
pub const MISC_MAPPER_CONTROL_MINOR: u32 = 236;

/// Sectors are the device-mapper unit of address throughout, never bytes.
pub const SECTOR_SHIFT: u32 = 9;
/// Bytes in one device-mapper sector.
pub const SECTOR_BYTES: u64 = 1 << SECTOR_SHIFT;

// Command ordinals. The order is the ABI: a client compiled against an older
// header sends the same ordinal for the same command.
/// Report the interface version and nothing else.
pub const DM_VERSION_CMD: u32 = 0;
/// Remove every mapped device.
pub const DM_REMOVE_ALL_CMD: u32 = 1;
/// Enumerate mapped devices.
pub const DM_LIST_DEVICES_CMD: u32 = 2;
/// Create a device with neither table slot filled.
pub const DM_DEV_CREATE_CMD: u32 = 3;
/// Remove one device and destroy its tables.
pub const DM_DEV_REMOVE_CMD: u32 = 4;
/// Rename a device, or set its uuid when none was supplied.
pub const DM_DEV_RENAME_CMD: u32 = 5;
/// Suspend or resume, selected by `DM_SUSPEND_FLAG`.
pub const DM_DEV_SUSPEND_CMD: u32 = 6;
/// Report the device's status without its table.
pub const DM_DEV_STATUS_CMD: u32 = 7;
/// Block until the device's event counter passes the supplied value.
pub const DM_DEV_WAIT_CMD: u32 = 8;
/// Load a table into the inactive slot.
pub const DM_TABLE_LOAD_CMD: u32 = 9;
/// Discard whatever sits in the inactive slot.
pub const DM_TABLE_CLEAR_CMD: u32 = 10;
/// Report the set of devices the active table depends on.
pub const DM_TABLE_DEPS_CMD: u32 = 11;
/// Report per-target status or the table itself.
pub const DM_TABLE_STATUS_CMD: u32 = 12;
/// Enumerate registered target types and their versions.
pub const DM_LIST_VERSIONS_CMD: u32 = 13;
/// Deliver a message to the target covering a sector.
pub const DM_TARGET_MSG_CMD: u32 = 14;
/// Set the CHS geometry reported for the device.
pub const DM_DEV_SET_GEOMETRY_CMD: u32 = 15;
/// Arm the device's poll notification.
pub const DM_DEV_ARM_POLL_CMD: u32 = 16;
/// Report the version of one named target type.
pub const DM_GET_TARGET_VERSION_CMD: u32 = 17;
/// Probe the paths of a multipath device (issued on the block node).
pub const DM_MPATH_PROBE_PATHS_CMD: u32 = 18;

/// Highest control-node command ordinal this interface answers.
pub const DM_CMD_LAST: u32 = DM_GET_TARGET_VERSION_CMD;

/// Wire size of [`DmIoctl`], and therefore the size field of every command
/// number. Asserted against the struct below so the two cannot drift.
pub const DM_IOCTL_STRUCT_SIZE: u32 = 312;

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

/// Encode one `_IOWR(DM_IOCTL, nr, struct dm_ioctl)` command number.
/// # C: O(1)
pub const fn dm_cmd(nr: u32) -> u32 {
    ((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT)
        | (DM_IOCTL_STRUCT_SIZE << IOC_SIZESHIFT)
        | (DM_IOCTL << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
}

/// Command ordinal carried by an ioctl request word, whatever its size and
/// direction bits say. Linux dispatches on the ordinal alone, so a client
/// compiled against a header whose struct grew still reaches its command.
/// # C: O(1)
pub const fn cmd_nr(request: u32) -> u32 { (request >> IOC_NRSHIFT) & ((1 << IOC_NRBITS) - 1) }

/// Type byte carried by an ioctl request word. # C: O(1)
pub const fn cmd_type(request: u32) -> u32 { (request >> IOC_TYPESHIFT) & ((1 << IOC_TYPEBITS) - 1) }

/// Payload size the client compiled against, from its request word. # C: O(1)
pub const fn cmd_size(request: u32) -> u32 { (request >> IOC_SIZESHIFT) & ((1 << IOC_SIZEBITS) - 1) }

/// `DM_VERSION` command number.
pub const DM_VERSION: u32 = dm_cmd(DM_VERSION_CMD);
/// `DM_REMOVE_ALL` command number.
pub const DM_REMOVE_ALL: u32 = dm_cmd(DM_REMOVE_ALL_CMD);
/// `DM_LIST_DEVICES` command number.
pub const DM_LIST_DEVICES: u32 = dm_cmd(DM_LIST_DEVICES_CMD);
/// `DM_DEV_CREATE` command number.
pub const DM_DEV_CREATE: u32 = dm_cmd(DM_DEV_CREATE_CMD);
/// `DM_DEV_REMOVE` command number.
pub const DM_DEV_REMOVE: u32 = dm_cmd(DM_DEV_REMOVE_CMD);
/// `DM_DEV_RENAME` command number.
pub const DM_DEV_RENAME: u32 = dm_cmd(DM_DEV_RENAME_CMD);
/// `DM_DEV_SUSPEND` command number.
pub const DM_DEV_SUSPEND: u32 = dm_cmd(DM_DEV_SUSPEND_CMD);
/// `DM_DEV_STATUS` command number.
pub const DM_DEV_STATUS: u32 = dm_cmd(DM_DEV_STATUS_CMD);
/// `DM_DEV_WAIT` command number.
pub const DM_DEV_WAIT: u32 = dm_cmd(DM_DEV_WAIT_CMD);
/// `DM_DEV_ARM_POLL` command number.
pub const DM_DEV_ARM_POLL: u32 = dm_cmd(DM_DEV_ARM_POLL_CMD);
/// `DM_TABLE_LOAD` command number.
pub const DM_TABLE_LOAD: u32 = dm_cmd(DM_TABLE_LOAD_CMD);
/// `DM_TABLE_CLEAR` command number.
pub const DM_TABLE_CLEAR: u32 = dm_cmd(DM_TABLE_CLEAR_CMD);
/// `DM_TABLE_DEPS` command number.
pub const DM_TABLE_DEPS: u32 = dm_cmd(DM_TABLE_DEPS_CMD);
/// `DM_TABLE_STATUS` command number.
pub const DM_TABLE_STATUS: u32 = dm_cmd(DM_TABLE_STATUS_CMD);
/// `DM_LIST_VERSIONS` command number.
pub const DM_LIST_VERSIONS: u32 = dm_cmd(DM_LIST_VERSIONS_CMD);
/// `DM_GET_TARGET_VERSION` command number.
pub const DM_GET_TARGET_VERSION: u32 = dm_cmd(DM_GET_TARGET_VERSION_CMD);
/// `DM_TARGET_MSG` command number.
pub const DM_TARGET_MSG: u32 = dm_cmd(DM_TARGET_MSG_CMD);
/// `DM_DEV_SET_GEOMETRY` command number.
pub const DM_DEV_SET_GEOMETRY: u32 = dm_cmd(DM_DEV_SET_GEOMETRY_CMD);

// Flag word bits. In/out direction noted where it is not both.
/// Device carries no writable mapping. In/out.
pub const DM_READONLY_FLAG: u32 = 1 << 0;
/// Suspend rather than resume; on output, the device is suspended. In/out.
pub const DM_SUSPEND_FLAG: u32 = 1 << 1;
/// Caller chose the minor number in `dev` rather than taking any free one. In.
pub const DM_PERSISTENT_DEV_FLAG: u32 = 1 << 3;
/// Report the table rather than per-target status. In.
pub const DM_STATUS_TABLE_FLAG: u32 = 1 << 4;
/// The active table slot is filled. Out.
pub const DM_ACTIVE_PRESENT_FLAG: u32 = 1 << 5;
/// The inactive table slot is filled. Out.
pub const DM_INACTIVE_PRESENT_FLAG: u32 = 1 << 6;
/// The supplied buffer could not hold the whole reply. Out.
pub const DM_BUFFER_FULL_FLAG: u32 = 1 << 8;
/// Retained for clients that still set it; the kernel ignores it. In.
pub const DM_SKIP_BDGET_FLAG: u32 = 1 << 9;
/// Suspend without freezing any filesystem mounted on the device. In.
pub const DM_SKIP_LOCKFS_FLAG: u32 = 1 << 10;
/// Suspend without flushing queued I/O; deferred I/O is failed instead. In.
pub const DM_NOFLUSH_FLAG: u32 = 1 << 11;
/// Report on the inactive table instead of the live one. In.
pub const DM_QUERY_INACTIVE_TABLE_FLAG: u32 = 1 << 12;
/// A uevent was generated the caller may need to wait for. Out.
pub const DM_UEVENT_GENERATED_FLAG: u32 = 1 << 13;
/// Rename sets the uuid rather than the name. In.
pub const DM_UUID_FLAG: u32 = 1 << 14;
/// Wipe every buffer after use; set when a key crosses the boundary. In.
pub const DM_SECURE_DATA_FLAG: u32 = 1 << 15;
/// A message produced output data. Out.
pub const DM_DATA_OUT_FLAG: u32 = 1 << 16;
/// Remove when the last opener closes rather than refusing a busy device. In/out.
pub const DM_DEFERRED_REMOVE: u32 = 1 << 17;
/// The device is suspended by the kernel rather than by a caller. Out.
pub const DM_INTERNAL_SUSPEND_FLAG: u32 = 1 << 18;
/// Return the raw table text an integrity measurement would cover. In.
pub const DM_IMA_MEASUREMENT_FLAG: u32 = 1 << 19;

/// Flags cleared out of every incoming header before the command runs. Three
/// of them are outputs the kernel sets, so a caller asserting them would be
/// claiming a result it has not been given. `DM_SECURE_DATA_FLAG` is cleared
/// with them because the reply must not tell the caller its own request was
/// secure — the kernel decides that per command.
pub const CLEARED_ON_ENTRY_FLAGS: u32 = DM_BUFFER_FULL_FLAG
    | DM_UEVENT_GENERATED_FLAG
    | DM_SECURE_DATA_FLAG
    | DM_DATA_OUT_FLAG;

/// This entry's uuid follows its name, aligned up to eight bytes.
pub const DM_NAME_LIST_FLAG_HAS_UUID: u32 = 1;
/// This entry has no uuid; nothing follows its name.
pub const DM_NAME_LIST_FLAG_DOESNT_HAVE_UUID: u32 = 2;

/// Header at the start of every device-mapper ioctl payload.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DmIoctl {
    /// Interface version the client compiled against; overwritten on reply.
    pub version: [u32; 3],
    /// Total payload size including this header.
    pub data_size: u32,
    /// Offset from the start of this header to the variable-length payload.
    pub data_start: u32,
    /// Number of `DmTargetSpec` records in the payload.
    pub target_count: u32,
    /// Open file descriptions holding the device. Out.
    pub open_count: i32,
    /// Flag word.
    pub flags: u32,
    /// Event counter on output; an event number or a udev cookie on input.
    pub event_nr: u32,
    /// Unused; present so `dev` lands on its natural alignment.
    pub padding: u32,
    /// Packed device number of the mapped device.
    pub dev: u64,
    /// NUL-terminated device name.
    pub name: [u8; DM_NAME_LEN],
    /// NUL-terminated device uuid.
    pub uuid: [u8; DM_UUID_LEN],
    /// Padding that a short payload may also use for data.
    pub data: [u8; 7],
}

const _: () = assert!(core::mem::size_of::<DmIoctl>() == DM_IOCTL_STRUCT_SIZE as usize);

impl Default for DmIoctl {
    /// A zeroed header stamped with this interface's version. # C: O(1)
    fn default() -> Self {
        Self {
            version: [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCHLEVEL],
            data_size: 0, data_start: 0, target_count: 0, open_count: 0,
            flags: 0, event_nr: 0, padding: 0, dev: 0,
            name: [0; DM_NAME_LEN], uuid: [0; DM_UUID_LEN], data: [0; 7],
        }
    }
}

/// One table entry on the wire. The target's parameter string follows this
/// record as NUL-terminated text, padded so the next record stays aligned.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DmTargetSpec {
    /// First sector of the device this target covers.
    pub sector_start: u64,
    /// Length of the covered range, in sectors.
    pub length: u64,
    /// Set by the kernel on a read; ignored on a load.
    pub status: i32,
    /// On a load, bytes from THIS record to the next; on a status read, bytes
    /// from the FIRST record to the next. The two senses are not the same and
    /// a reader that assumes one of them mis-parses the other direction.
    pub next: u32,
    /// NUL-padded target-type name.
    pub target_type: [u8; DM_MAX_TYPE_NAME],
}

const _: () = assert!(core::mem::size_of::<DmTargetSpec>() == 40);

/// Header of the `DM_TABLE_DEPS` reply; `count` packed device numbers follow.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct DmTargetDeps {
    /// Number of device numbers that follow.
    pub count: u32,
    /// Unused.
    pub padding: u32,
}

/// Header of one `DM_LIST_DEVICES` entry; a NUL-terminated name follows, then
/// — aligned up to eight bytes — an event number, a flag word, and a uuid.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct DmNameList {
    /// Packed device number of this entry.
    pub dev: u64,
    /// Offset from the start of THIS record to the next, or zero at the end.
    pub next: u32,
}

/// Header of one `DM_LIST_VERSIONS` entry; a NUL-terminated name follows.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct DmTargetVersions {
    /// Offset from the start of this record to the next, or zero at the end.
    pub next: u32,
    /// The target type's own three-part version.
    pub version: [u32; 3],
}

/// Header of a `DM_TARGET_MSG` payload; the message text follows.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct DmTargetMsg {
    /// Sector selecting which target of the table receives the message.
    pub sector: u64,
}

/// Most targets one table may hold.
pub const DM_MAX_TARGETS: u32 = 1_048_576;
/// Longest parameter string one target line may carry.
pub const DM_MAX_TARGET_PARAMS: u32 = 1024;

/// Smallest payload a command may declare: the header up to its trailing
/// `data` field, which is where a variable-length reply starts.
pub const DM_MIN_DATA_SIZE: u32 = 305;

const _: () = assert!(DM_MIN_DATA_SIZE as usize == core::mem::offset_of!(DmIoctl, data));

/// Round `n` up to the next multiple of eight — the alignment every
/// variable-length record in this ABI starts on. # C: O(1)
pub const fn align8(n: usize) -> usize { (n + 7) & !7 }
