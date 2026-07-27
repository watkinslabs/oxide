//! Linux `convert_mode` / `testmsg` / `find_msg` (`ipc/msg.c`) — the `msgtyp`
//! selection rules, kept pure so the hosted tests drive them directly instead
//! of through a park that a `cargo test` build has no scheduler for.

use alloc::collections::VecDeque;

use super::model::Msg;
use crate::sysv::limits::{MSG_COPY, MSG_EXCEPT};

/// Linux's `SEARCH_*` modes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Search {
    /// `SEARCH_ANY` — first message, whatever its type.
    Any,
    /// `SEARCH_EQUAL` — `m_type == msgtyp`.
    Equal,
    /// `SEARCH_NOTEQUAL` — `m_type != msgtyp` (`MSG_EXCEPT`).
    NotEqual,
    /// `SEARCH_LESSEQUAL` — lowest `m_type <= msgtyp`.
    LessEqual,
    /// `SEARCH_NUMBER` — `msgtyp` is a queue index (`MSG_COPY`).
    Number,
}

/// Linux `convert_mode`, returning the mode alongside the possibly-rewritten
/// `msgtyp`. `LONG_MIN` maps to `LONG_MAX` because negating it is undefined.
/// # C: O(1)
pub fn convert_mode(msgtyp: i64, msgflg: i32) -> (Search, i64) {
    if (msgflg & MSG_COPY) != 0 { return (Search::Number, msgtyp); }
    if msgtyp == 0 { return (Search::Any, msgtyp); }
    if msgtyp < 0 {
        let bound = if msgtyp == i64::MIN { i64::MAX } else { -msgtyp };
        return (Search::LessEqual, bound);
    }
    if (msgflg & MSG_EXCEPT) != 0 { return (Search::NotEqual, msgtyp); }
    (Search::Equal, msgtyp)
}

/// Linux `testmsg`. # C: O(1)
pub fn testmsg(mtype: i64, msgtyp: i64, mode: Search) -> bool {
    match mode {
        Search::Any | Search::Number => true,
        Search::LessEqual => mtype <= msgtyp,
        Search::Equal => mtype == msgtyp,
        Search::NotEqual => mtype != msgtyp,
    }
}

/// Linux `find_msg` — the index of the selected message, or `None` when the
/// queue holds no match (Linux's `ERR_PTR(-EAGAIN)` sentinel).
///
/// `LessEqual` is deliberately NOT "first match": each accepted candidate whose
/// type is not `1` narrows `msgtyp` to `m_type - 1` and the scan continues, so
/// the result is the LOWEST qualifying type, and among equal types the FIRST in
/// FIFO order (a later message of the same type can no longer pass the narrowed
/// bound). A type of `1` is the floor and returns immediately.
/// # C: O(N_msgs)
pub fn find_msg(msgs: &VecDeque<Msg>, msgtyp: &mut i64, mode: Search) -> Option<usize> {
    /// Linux's `msg->m_type != 1` floor: nothing can undercut the lowest legal
    /// message type, so the scan stops there.
    const LOWEST_MTYPE: i64 = 1;
    let mut found = None;
    let mut count: i64 = 0;
    for (i, m) in msgs.iter().enumerate() {
        if !testmsg(m.mtype, *msgtyp, mode) { continue; }
        if mode == Search::LessEqual && m.mtype != LOWEST_MTYPE {
            *msgtyp = m.mtype - 1;
            found = Some(i);
        } else if mode == Search::Number {
            if *msgtyp == count { return Some(i); }
        } else {
            return Some(i);
        }
        count += 1;
    }
    found
}
