//! System V IPC tunables and ABI numbers. Values track Linux
//! `include/uapi/linux/{ipc,sem,msg}.h` exactly — a smaller cap here is a
//! visible behaviour change (`E2BIG`/`EINVAL` where Linux succeeds), so these
//! are the real Linux defaults, not convenience numbers.

/// `IPC_PRIVATE` — `key` that always creates a fresh object.
pub const IPC_PRIVATE: i32 = 0;

/// `ipc.h` flag bits carried in `semflg` / `msgflg` / `shmflg`.
pub const IPC_CREAT:  i32 = 0o1000;
pub const IPC_EXCL:   i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;

/// Low 9 bits of a `*flg` are the permission mode (`S_IRWXUGO`).
pub const S_IRWXUGO: u32 = 0o777;
/// `ipcperms()` request modes.
pub const S_IRUGO: i32 = 0o444;
pub const S_IWUGO: i32 = 0o222;
/// Only the low 3 bits of the folded request mask are meaningful.
pub const IPC_PERM_BITS: u32 = 0o7;

/// `ipc.h` control commands common to every object class.
pub const IPC_RMID: i32 = 0;
pub const IPC_SET:  i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;

/// `sem.h` control commands.
pub const GETPID:  i32 = 11;
pub const GETVAL:  i32 = 12;
pub const GETALL:  i32 = 13;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const SETVAL:  i32 = 16;
pub const SETALL:  i32 = 17;
pub const SEM_STAT:     i32 = 18;
pub const SEM_INFO:     i32 = 19;
pub const SEM_STAT_ANY: i32 = 20;

/// `sembuf.sem_flg` bit requesting an exit-time adjustment (`ipc/sem.c`).
pub const SEM_UNDO: i16 = 0o10000;

/// `msg.h` control commands.
pub const MSG_STAT:     i32 = 11;
pub const MSG_INFO:     i32 = 12;
pub const MSG_STAT_ANY: i32 = 13;

/// `msgrcv` flag bits (`include/uapi/linux/msg.h`).
pub const MSG_NOERROR: i32 = 0o10000;
pub const MSG_EXCEPT:  i32 = 0o20000;
pub const MSG_COPY:    i32 = 0o40000;

/// `include/uapi/linux/sem.h` defaults.
pub const SEMMNI: usize = 32_000;
pub const SEMMSL: usize = 32_000;
pub const SEMMNS: usize = SEMMNI * SEMMSL;
pub const SEMOPM: usize = 500;
pub const SEMVMX: i32   = 32_767;
pub const SEMAEM: i32   = SEMVMX;
pub const SEMUME: usize = SEMOPM;
pub const SEMMNU: usize = SEMMNS;
pub const SEMMAP: usize = SEMMNS;
pub const SEMUSZ: usize = 20;

/// `include/uapi/linux/msg.h` defaults.
pub const MSGMNI: usize = 32_000;
pub const MSGMAX: usize = 8_192;
pub const MSGMNB: usize = 16_384;
pub const MSGSSZ: usize = 16;
pub const MSGPOOL: usize = MSGMNI * MSGMNB / 1024;
pub const MSGTQL: usize = MSGMNB;
pub const MSGMAP: usize = MSGMNB;
/// `MSGSEG` saturates at `0xffff` per the uapi header's ternary.
pub const MSGSEG: u16 = {
    let raw = MSGPOOL * 1024 / MSGSSZ;
    if raw <= 0xffff { raw as u16 } else { 0xffff }
};

/// `ipc/util.h` `IPCMNI_SHIFT` — `id = seq << IPCMNI_SHIFT | idx`. The
/// registries here hand out ids through this same encoding so a stale id from
/// a removed-then-recreated object fails `EINVAL` exactly as Linux's
/// `ipc_checkid` makes it fail.
pub const IPCMNI_SHIFT: u32 = 15;
pub const IPCMNI: usize = 1 << IPCMNI_SHIFT;
pub const IPCMNI_IDX_MASK: i32 = (1 << IPCMNI_SHIFT) - 1;
