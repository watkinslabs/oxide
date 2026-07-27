//! Linux `msgctl_info` — `struct msginfo` for `IPC_INFO` / `MSG_INFO`.

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use crate::sysv::limits::{MSGMAP, MSGMAX, MSGMNB, MSGMNI, MSGPOOL, MSGSEG, MSGSSZ, MSGTQL, MSG_INFO};
use crate::sysv::msg::model;
use crate::sysv::uapi::{
    put_i32, put_u16, MSGINFO_BYTES, MSGINFO_MSGMAP_OFF, MSGINFO_MSGMAX_OFF, MSGINFO_MSGMNB_OFF,
    MSGINFO_MSGMNI_OFF, MSGINFO_MSGPOOL_OFF, MSGINFO_MSGSEG_OFF, MSGINFO_MSGSSZ_OFF,
    MSGINFO_MSGTQL_OFF,
};
use crate::sysv::user;

/// Linux `min_t(int, ..., INT_MAX)` on the per-namespace totals. # C: O(1)
fn clamp(v: u64) -> i32 { if v > i32::MAX as u64 { i32::MAX } else { v as i32 } }

/// Linux `msgctl_info`. Returns the namespace's highest live index, or `0`
/// when the namespace holds no queues. `msqid` is unused: Linux validates it
/// only through the `msqid < 0` gate in `ksys_msgctl`.
/// # C: O(N_queues)
pub fn msgctl_info(ns: NamespaceId, cmd: i32, buf: u64) -> Result<i64, Errno> {
    let mut out = [0u8; MSGINFO_BYTES];
    put_i32(&mut out, MSGINFO_MSGMNI_OFF, MSGMNI as i32);
    put_i32(&mut out, MSGINFO_MSGMAX_OFF, MSGMAX as i32);
    put_i32(&mut out, MSGINFO_MSGMNB_OFF, MSGMNB as i32);
    put_i32(&mut out, MSGINFO_MSGSSZ_OFF, MSGSSZ as i32);
    put_u16(&mut out, MSGINFO_MSGSEG_OFF, MSGSEG);
    let (in_use, hdrs, bytes, max_idx) = model::info_counters(ns);
    if cmd == MSG_INFO {
        put_i32(&mut out, MSGINFO_MSGPOOL_OFF, clamp(in_use as u64));
        put_i32(&mut out, MSGINFO_MSGMAP_OFF, clamp(hdrs));
        put_i32(&mut out, MSGINFO_MSGTQL_OFF, clamp(bytes));
    } else {
        put_i32(&mut out, MSGINFO_MSGPOOL_OFF, MSGPOOL as i32);
        put_i32(&mut out, MSGINFO_MSGMAP_OFF, MSGMAP as i32);
        put_i32(&mut out, MSGINFO_MSGTQL_OFF, MSGTQL as i32);
    }
    user::write_bytes(buf, &out)?;
    Ok(if max_idx < 0 { 0 } else { max_idx })
}
