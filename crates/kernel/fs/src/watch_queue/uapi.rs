// Watch-queue UAPI: record layout, notification types, filter limits and the
// two ioctl numbers. Numbers only.

/// `pipe2` flag selecting a notification pipe. It IS `O_EXCL` — the flag has
/// no meaning to `pipe2` otherwise, so the value is reused rather than a new
/// bit being spent.
pub const O_NOTIFICATION_PIPE: u32 = vfs::OpenFlags::O_EXCL.bits();

/// `IOC_WATCH_QUEUE_SET_SIZE` — set the queue depth in notes.
pub const IOC_WATCH_QUEUE_SET_SIZE: u64 = 0x5760;
/// `IOC_WATCH_QUEUE_SET_FILTER` — install or remove the filter.
pub const IOC_WATCH_QUEUE_SET_FILTER: u64 = 0x5761;

/// Record types.
pub const WATCH_TYPE_META: u32 = 0;
pub const WATCH_TYPE_KEY_NOTIFY: u32 = 1;
/// One past the last defined type; a filter naming anything at or above this
/// is IGNORED rather than rejected, so a program built against a later kernel
/// still runs here.
pub const WATCH_TYPE_NR: u32 = 2;

/// `WATCH_TYPE_META` subtypes.
pub const WATCH_META_REMOVAL_NOTIFICATION: u32 = 0;
pub const WATCH_META_LOSS_NOTIFICATION: u32 = 1;

/// Key-change subtypes (`enum key_notification_subtype`).
pub const NOTIFY_KEY_INSTANTIATED: u32 = 0;
pub const NOTIFY_KEY_UPDATED: u32 = 1;
pub const NOTIFY_KEY_LINKED: u32 = 2;
pub const NOTIFY_KEY_UNLINKED: u32 = 3;
pub const NOTIFY_KEY_CLEARED: u32 = 4;
pub const NOTIFY_KEY_REVOKED: u32 = 5;
pub const NOTIFY_KEY_INVALIDATED: u32 = 6;
pub const NOTIFY_KEY_SETATTR: u32 = 7;

/// `struct watch_notification` — `type:24`, `subtype:8`, then `info`.
pub const WATCH_HEADER_SIZE: usize = 8;
/// `struct key_notification` — the header plus the key serial and one word of
/// per-subtype auxiliary data.
pub const KEY_NOTIFICATION_SIZE: usize = 16;
/// `struct watch_notification_removal` — the header plus the object id.
pub const WATCH_REMOVAL_SIZE: usize = 16;
/// Bit position of `subtype` inside the first word; `type` occupies the low 24.
pub const WATCH_SUBTYPE_SHIFT: u32 = 24;
pub const WATCH_TYPE_MASK: u32 = 0x00ff_ffff;

/// `info` field layout: the record length in bytes, the watchpoint id the
/// caller chose, and type-specific bits above them.
pub const WATCH_INFO_LENGTH: u32 = 0x0000_007f;
pub const WATCH_INFO_ID: u32 = 0x0000_ff00;
pub const WATCH_INFO_ID_SHIFT: u32 = 8;
pub const WATCH_INFO_TYPE_INFO: u32 = 0xffff_0000;

/// Largest watchpoint id `KEYCTL_WATCH_KEY` accepts; `-1` removes a watch and
/// anything else outside `0..=255` is EINVAL.
pub const WATCH_ID_MAX: i32 = 0xff;
/// The watch id that removes rather than adds.
pub const WATCH_ID_REMOVE: i32 = -1;

/// Note size and queue-depth limits. A note is a fixed slot, so the depth a
/// caller asks for is rounded UP to a whole page of them.
pub const WATCH_QUEUE_NOTE_SIZE: usize = 128;
pub const WATCH_QUEUE_NOTES_PER_PAGE: usize = 4096 / WATCH_QUEUE_NOTE_SIZE;
pub const WATCH_QUEUE_MAX_NOTES: usize = 512;

/// `struct watch_notification_filter`: a count, a reserved word, then that
/// many type filters.
pub const WATCH_FILTER_HEADER_SIZE: usize = 8;
pub const WATCH_FILTER_NR_OFFSET: usize = 0;
pub const WATCH_FILTER_RESERVED_OFFSET: usize = 4;
/// `struct watch_notification_type_filter`: type, info filter, info mask, and
/// a 256-bit subtype bitmap.
pub const WATCH_TYPE_FILTER_SIZE: usize = 44;
pub const WATCH_TYPE_FILTER_TYPE_OFFSET: usize = 0;
pub const WATCH_TYPE_FILTER_INFO_FILTER_OFFSET: usize = 4;
pub const WATCH_TYPE_FILTER_INFO_MASK_OFFSET: usize = 8;
pub const WATCH_TYPE_FILTER_SUBTYPE_OFFSET: usize = 12;
pub const WATCH_TYPE_FILTER_SUBTYPE_WORDS: usize = 8;
/// Most type filters one call may install.
pub const WATCH_FILTER_MAX: u32 = 16;
