// Linux keyring UAPI constants — `include/uapi/linux/keyctl.h` and
// `include/linux/key.h`. Numbers only; every policy decision lives in
// `perm.rs` / `ops/`.

/// Special (negative) keyring ids (`uapi/linux/keyctl.h`).
pub const KEY_SPEC_THREAD_KEYRING:       i32 = -1;
pub const KEY_SPEC_PROCESS_KEYRING:      i32 = -2;
pub const KEY_SPEC_SESSION_KEYRING:      i32 = -3;
pub const KEY_SPEC_USER_KEYRING:         i32 = -4;
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
pub const KEY_SPEC_GROUP_KEYRING:        i32 = -6;
pub const KEY_SPEC_REQKEY_AUTH_KEY:      i32 = -7;
pub const KEY_SPEC_REQUESTOR_KEYRING:    i32 = -8;

/// `keyctl(2)` operation codes.
pub const KEYCTL_GET_KEYRING_ID:       u64 = 0;
pub const KEYCTL_JOIN_SESSION_KEYRING: u64 = 1;
pub const KEYCTL_UPDATE:               u64 = 2;
pub const KEYCTL_REVOKE:               u64 = 3;
pub const KEYCTL_CHOWN:                u64 = 4;
pub const KEYCTL_SETPERM:              u64 = 5;
pub const KEYCTL_DESCRIBE:             u64 = 6;
pub const KEYCTL_CLEAR:                u64 = 7;
pub const KEYCTL_LINK:                 u64 = 8;
pub const KEYCTL_UNLINK:               u64 = 9;
pub const KEYCTL_SEARCH:               u64 = 10;
pub const KEYCTL_READ:                 u64 = 11;
pub const KEYCTL_INSTANTIATE:          u64 = 12;
pub const KEYCTL_NEGATE:               u64 = 13;
pub const KEYCTL_SET_REQKEY_KEYRING:   u64 = 14;
pub const KEYCTL_SET_TIMEOUT:          u64 = 15;
pub const KEYCTL_ASSUME_AUTHORITY:     u64 = 16;
pub const KEYCTL_GET_SECURITY:         u64 = 17;
pub const KEYCTL_SESSION_TO_PARENT:    u64 = 18;
pub const KEYCTL_REJECT:               u64 = 19;
pub const KEYCTL_INSTANTIATE_IOV:      u64 = 20;
pub const KEYCTL_INVALIDATE:           u64 = 21;
pub const KEYCTL_GET_PERSISTENT:       u64 = 22;
pub const KEYCTL_DH_COMPUTE:           u64 = 23;
pub const KEYCTL_PKEY_QUERY:           u64 = 24;
pub const KEYCTL_PKEY_ENCRYPT:         u64 = 25;
pub const KEYCTL_PKEY_DECRYPT:         u64 = 26;
pub const KEYCTL_PKEY_SIGN:            u64 = 27;
pub const KEYCTL_PKEY_VERIFY:          u64 = 28;
pub const KEYCTL_RESTRICT_KEYRING:     u64 = 29;
pub const KEYCTL_MOVE:                 u64 = 30;
pub const KEYCTL_CAPABILITIES:         u64 = 31;
pub const KEYCTL_WATCH_KEY:            u64 = 32;

/// `KEYCTL_MOVE` flag: fail with EEXIST rather than overwrite.
pub const KEYCTL_MOVE_EXCL: u32 = 0x0000_0001;

/// `KEYCTL_SET_REQKEY_KEYRING` settings (`cred->jit_keyring`).
pub const KEY_REQKEY_DEFL_NO_CHANGE:            i32 = -1;
pub const KEY_REQKEY_DEFL_DEFAULT:              i32 = 0;
pub const KEY_REQKEY_DEFL_THREAD_KEYRING:       i32 = 1;
pub const KEY_REQKEY_DEFL_PROCESS_KEYRING:      i32 = 2;
pub const KEY_REQKEY_DEFL_SESSION_KEYRING:      i32 = 3;
pub const KEY_REQKEY_DEFL_USER_KEYRING:         i32 = 4;
pub const KEY_REQKEY_DEFL_USER_SESSION_KEYRING: i32 = 5;
pub const KEY_REQKEY_DEFL_GROUP_KEYRING:        i32 = 6;
pub const KEY_REQKEY_DEFL_REQUESTOR_KEYRING:    i32 = 7;

/// `KEY_NEED_*` need bits (`include/linux/key.h`), expressed as the
/// other-byte mask `key_task_permission` selects.
pub const KEY_NEED_VIEW:    u32 = 0x01;
pub const KEY_NEED_READ:    u32 = 0x02;
pub const KEY_NEED_WRITE:   u32 = 0x04;
pub const KEY_NEED_SEARCH:  u32 = 0x08;
pub const KEY_NEED_LINK:    u32 = 0x10;
pub const KEY_NEED_SETATTR: u32 = 0x20;

/// `key->perm` byte layout: possessor(31:24) / user(23:16) / group(15:8) /
/// other(7:0), six meaningful bits each.
pub const KEY_PERM_BYTE_MASK: u32 = 0x3f;
pub const KEY_PERM_POS_SHIFT: u32 = 24;
pub const KEY_PERM_USR_SHIFT: u32 = 16;
pub const KEY_PERM_GRP_SHIFT: u32 = 8;
pub const KEY_PERM_OTH_SHIFT: u32 = 0;

pub const KEY_POS_ALL: u32 = KEY_PERM_BYTE_MASK << KEY_PERM_POS_SHIFT;
pub const KEY_USR_ALL: u32 = KEY_PERM_BYTE_MASK << KEY_PERM_USR_SHIFT;
pub const KEY_GRP_ALL: u32 = KEY_PERM_BYTE_MASK << KEY_PERM_GRP_SHIFT;
pub const KEY_OTH_ALL: u32 = KEY_PERM_BYTE_MASK << KEY_PERM_OTH_SHIFT;
/// Every bit `keyctl_setperm_key` accepts; anything else is EINVAL.
pub const KEY_PERM_VALID: u32 = KEY_POS_ALL | KEY_USR_ALL | KEY_GRP_ALL | KEY_OTH_ALL;

pub const KEY_POS_VIEW:    u32 = KEY_NEED_VIEW    << KEY_PERM_POS_SHIFT;
pub const KEY_POS_READ:    u32 = KEY_NEED_READ    << KEY_PERM_POS_SHIFT;
pub const KEY_POS_WRITE:   u32 = KEY_NEED_WRITE   << KEY_PERM_POS_SHIFT;
pub const KEY_POS_SEARCH:  u32 = KEY_NEED_SEARCH  << KEY_PERM_POS_SHIFT;
pub const KEY_POS_LINK:    u32 = KEY_NEED_LINK    << KEY_PERM_POS_SHIFT;
pub const KEY_POS_SETATTR: u32 = KEY_NEED_SETATTR << KEY_PERM_POS_SHIFT;
pub const KEY_USR_VIEW:    u32 = KEY_NEED_VIEW    << KEY_PERM_USR_SHIFT;
pub const KEY_USR_READ:    u32 = KEY_NEED_READ    << KEY_PERM_USR_SHIFT;
pub const KEY_USR_LINK:    u32 = KEY_NEED_LINK    << KEY_PERM_USR_SHIFT;

/// `install_thread_keyring_to_cred` / `install_process_keyring_to_cred`
/// (`security/keys/process_keys.c`): `KEY_POS_ALL | KEY_USR_VIEW`.
pub const THREAD_KEYRING_PERM: u32 = KEY_POS_ALL | KEY_USR_VIEW;
/// `install_session_keyring_to_cred`: adds `KEY_USR_READ`.
pub const SESSION_KEYRING_PERM: u32 = KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ;
/// `keyctl_join_session_keyring` on a named ring: adds `KEY_USR_LINK`.
pub const NAMED_SESSION_KEYRING_PERM: u32 = KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_LINK;
/// `look_up_user_keyrings`: `(KEY_POS_ALL & ~KEY_POS_SETATTR) | KEY_USR_ALL`.
pub const USER_KEYRING_PERM: u32 = (KEY_POS_ALL & !KEY_POS_SETATTR) | KEY_USR_ALL;

/// `KEYCTL_CAPABILITIES` byte 0/1 bits (`uapi/linux/keyctl.h`).
pub const KEYCTL_CAPS0_CAPABILITIES:      u8 = 0x01;
pub const KEYCTL_CAPS0_PERSISTENT_KEYRINGS: u8 = 0x02;
pub const KEYCTL_CAPS0_DIFFIE_HELLMAN:    u8 = 0x04;
pub const KEYCTL_CAPS0_PUBLIC_KEY:        u8 = 0x08;
pub const KEYCTL_CAPS0_BIG_KEY:           u8 = 0x10;
pub const KEYCTL_CAPS0_INVALIDATE:        u8 = 0x20;
pub const KEYCTL_CAPS0_RESTRICT_KEYRING:  u8 = 0x40;
pub const KEYCTL_CAPS0_MOVE:              u8 = 0x80;
pub const KEYCTL_CAPS1_NS_KEYRING_NAME:   u8 = 0x01;
pub const KEYCTL_CAPS1_NS_KEY_TAG:        u8 = 0x02;
pub const KEYCTL_CAPS1_NOTIFICATIONS:     u8 = 0x04;

/// `keyrings_capabilities[]` for this kernel: persistent keyrings, the
/// `big_key` type, `KEYCTL_INVALIDATE`, `KEYCTL_RESTRICT_KEYRING` and
/// `KEYCTL_MOVE` are implemented and advertised. The Diffie-Hellman, public-key
/// and key-notification bits stay clear because those command families are not
/// implemented — the advertised bits and the commands' answers must agree, or a
/// caller that probes capabilities before use is told to expect a facility that
/// is not there.
pub const KEYRINGS_CAPABILITIES: [u8; 2] = [
    KEYCTL_CAPS0_CAPABILITIES
        | KEYCTL_CAPS0_PERSISTENT_KEYRINGS
        | KEYCTL_CAPS0_BIG_KEY
        | KEYCTL_CAPS0_INVALIDATE
        | KEYCTL_CAPS0_RESTRICT_KEYRING
        | KEYCTL_CAPS0_MOVE,
    KEYCTL_CAPS1_NS_KEYRING_NAME | KEYCTL_CAPS1_NS_KEY_TAG,
];

/// `key_get_type_from_user` buffer size (`char type[32]`).
pub const KEY_TYPE_MAX: usize = 32;
/// `KEY_MAX_DESC_SIZE` (`security/keys/internal.h`).
pub const KEY_MAX_DESC_SIZE: usize = 4096;
/// `SYSCALL_DEFINE5(add_key)`: `plen > 1024 * 1024 - 1` is EINVAL.
pub const KEY_MAX_PAYLOAD: u64 = 1024 * 1024 - 1;
/// `strndup_user(_callout_info, PAGE_SIZE)` in `request_key`.
pub const KEY_CALLOUT_MAX: usize = 4096;
/// `keyctl_update_key` bounds its payload at one page, NOT at the 1 MiB
/// `add_key` accepts — a longer update payload is EINVAL before any copy.
pub const KEYCTL_UPDATE_MAX_PAYLOAD: u64 = 4096;
/// `KEYCTL_READ` on a keyring hands back an array of 4-byte serials, so a
/// buffer length that is not a multiple of that is EINVAL.
pub const KEY_SERIAL_SIZE: u64 = 4;

/// Per-uid key quota defaults, settable through `/proc/sys/kernel/keys/`:
/// `key_quota_maxkeys` / `key_quota_maxbytes` for an ordinary uid and
/// `key_quota_root_maxkeys` / `key_quota_root_maxbytes` for uid 0. Crossing
/// either ceiling is EDQUOT.
pub const KEY_QUOTA_MAXKEYS:       u64 = 200;
pub const KEY_QUOTA_MAXBYTES:      u64 = 20_000;
pub const KEY_QUOTA_ROOT_MAXKEYS:  u64 = 1_000_000;
pub const KEY_QUOTA_ROOT_MAXBYTES: u64 = 25_000_000;
/// The uid the root quota ceilings apply to.
pub const ROOT_UID: u32 = 0;

/// Linux `INVALID_GID` as seen through `from_kgid_munged`: the user/user-session
/// keyrings are allocated with no group, so their group perm byte never applies.
pub const GID_INVALID: u32 = u32::MAX;

/// First serial handed out. Serials climb from here so no real key collides
/// with the (removed) legacy sentinel `1`.
pub const FIRST_SERIAL: i32 = 0x1000_0000;

/// `enum key_state`. A key is UNINSTANTIATED until something fills its payload
/// in; a NEGATIVE key carries `-errno` in the same field, which is the error
/// every later lookup of it hands back. `key_read_state` is consulted BEFORE
/// `key_validate`, so a negative key that has also expired still reports its
/// stored error rather than EKEYEXPIRED.
pub const KEY_IS_UNINSTANTIATED: i32 = 0;
pub const KEY_IS_POSITIVE:       i32 = 1;

/// `key_negative_timeout` — seconds a key negated by a failed upcall lives
/// before it expires, so a miss is not re-upcalled on every request.
pub const KEY_NEGATIVE_TIMEOUT: u64 = 60;

/// `MAX_ERRNO`. `KEYCTL_REJECT` accepts `1..MAX_ERRNO` minus the restart
/// pseudo-errnos below, which are kernel-internal and never visible to a
/// requester.
pub const MAX_ERRNO: u32 = 4095;
pub const ERESTARTSYS_NR:            u32 = 512;
pub const ERESTARTNOINTR_NR:         u32 = 513;
pub const ERESTARTNOHAND_NR:         u32 = 514;
pub const ERESTART_RESTARTBLOCK_NR:  u32 = 516;

/// `UIO_MAXIOV` — the `KEYCTL_INSTANTIATE_IOV` segment-count ceiling.
pub const UIO_MAXIOV: u64 = 1024;

/// The instantiation authorisation token's type name. The leading `.` is what
/// keeps it out of userspace's reach: `key_get_type_from_user` refuses a
/// `.`-prefixed type name with EPERM.
pub const REQKEY_AUTH_TYPE: &str = ".request_key_auth";

/// `.request_key_auth` perm: the holder (possessor) may view, read the callout
/// info, find it by search and link it; the owner gets VIEW alone.
pub const REQKEY_AUTH_PERM: u32 = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH | KEY_POS_LINK | KEY_USR_VIEW;

/// The per-request session keyring `call_sbin_request_key` builds for the
/// helper: `keyring_alloc(..., KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ, ...)`.
pub const REQKEY_HELPER_KEYRING_PERM: u32 = KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ;

/// `.persistent_register` and each `_persistent.<uid>` keyring:
/// `(KEY_POS_ALL & ~KEY_POS_SETATTR) | KEY_USR_VIEW | KEY_USR_READ`.
pub const PERSISTENT_KEYRING_PERM: u32 = (KEY_POS_ALL & !KEY_POS_SETATTR) | KEY_USR_VIEW | KEY_USR_READ;
/// `persistent_keyring_expiry` — three days of non-use, refreshed by every
/// successful `KEYCTL_GET_PERSISTENT`.
pub const PERSISTENT_KEYRING_EXPIRY: u64 = 3 * 24 * 3600;
/// The register holding every per-uid persistent keyring, and the prefix each
/// of those carries. Both are kernel-internal names.
pub const PERSISTENT_REGISTER_NAME: &str = ".persistent_register";
pub const PERSISTENT_PREFIX: &str = "_persistent.";

/// `/sbin/request-key` and the environment it is given.
pub const SBIN_REQUEST_KEY: &[u8] = b"/sbin/request-key";
/// `rka->op` for the `request_key(2)` construction path (`char op[8]`).
pub const REQKEY_OP_CREATE: &str = "create";
/// `char op[8]` — the auth record's operation name is truncated to fit.
pub const REQKEY_OP_MAX: usize = 7;
