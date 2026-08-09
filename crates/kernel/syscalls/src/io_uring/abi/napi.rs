// `IORING_REGISTER_NAPI` / `IORING_UNREGISTER_NAPI` — the wire struct, the
// admission ladder and the busy-poll window a wait honours.
//
// Busy-polling means the waiter drives the device receive path itself for a
// bounded window instead of parking and waiting for the interrupt: it trades
// CPU for latency. What it drives is the device poll list `net::backlog::napi`
// owns — the same routines the NET_RX bottom half runs — so registering here
// changes WHEN those routines run, never who owns them.
//
// Two tracking modes, exactly as in the reference. `STATIC` polls the queue
// identifiers the ring was explicitly told about; `DYNAMIC` polls the ones the
// ring learned from the sockets its own requests touched. Either way the
// identifier list is the gate: an empty list busy-polls nothing, which is what
// a system whose receive path records no queue identifier correctly does.

use syscall::errno::Errno;

/// `sizeof(struct io_uring_napi)` — {busy_poll_to u32, prefer_busy_poll u8,
/// opcode u8, pad[2] u8, op_param u32, resv u32}.
pub const NAPI_BYTES: u64 = 16;

/// `IO_URING_NAPI_REGISTER_OP` — set the busy-poll window and tracking mode.
pub const IO_URING_NAPI_REGISTER_OP: u8 = 0;
/// `IO_URING_NAPI_STATIC_ADD_ID` — add one queue identifier to the list.
pub const IO_URING_NAPI_STATIC_ADD_ID: u8 = 1;
/// `IO_URING_NAPI_STATIC_DEL_ID` — remove one queue identifier.
pub const IO_URING_NAPI_STATIC_DEL_ID: u8 = 2;

/// `IO_URING_NAPI_TRACKING_DYNAMIC` — the ring learns identifiers from the
/// sockets its requests touch.
pub const IO_URING_NAPI_TRACKING_DYNAMIC: u32 = 0;
/// `IO_URING_NAPI_TRACKING_STATIC` — the ring is told its identifiers.
pub const IO_URING_NAPI_TRACKING_STATIC: u32 = 1;
/// `IO_URING_NAPI_TRACKING_INACTIVE` — no busy-polling. The initial mode.
pub const IO_URING_NAPI_TRACKING_INACTIVE: u32 = 255;

/// Busy-poll window ceiling, microseconds. A request past it is CLAMPED, not
/// refused — the reference caps spin time at 10 ms rather than letting a
/// caller pin a CPU for as long as it likes.
pub const NAPI_BUSY_POLL_MAX_US: u32 = 10_000;

/// Nanoseconds per microsecond — the window is stated in microseconds and
/// held in nanoseconds.
pub const NSEC_PER_USEC: u64 = 1_000;

/// Smallest valid queue identifier; everything below is reserved. Taken from
/// the socket layer that assigns them, so the two cannot disagree.
pub use net::sock_opts::sol_socket::MIN_NAPI_ID;

/// `struct io_uring_napi`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Napi {
    pub busy_poll_to: u32,
    pub prefer_busy_poll: u8,
    pub opcode: u8,
    pub pad: [u8; 2],
    pub op_param: u32,
    pub resv: u32,
}

impl Napi {
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; NAPI_BYTES as usize]) -> Self {
        Self {
            busy_poll_to: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            prefer_busy_poll: b[4], opcode: b[5], pad: [b[6], b[7]],
            op_param: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            resv: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        }
    }

    /// # C: O(1)
    pub fn to_bytes(&self) -> [u8; NAPI_BYTES as usize] {
        let mut b = [0u8; NAPI_BYTES as usize];
        b[0..4].copy_from_slice(&self.busy_poll_to.to_le_bytes());
        b[4] = self.prefer_busy_poll;
        b[5] = self.opcode;
        b[6] = self.pad[0];
        b[7] = self.pad[1];
        b[8..12].copy_from_slice(&self.op_param.to_le_bytes());
        b[12..16].copy_from_slice(&self.resv.to_le_bytes());
        b
    }
}

/// The ring's busy-poll settings, as they are reported back to the caller on
/// every register and unregister. The reference writes these out BEFORE it
/// acts on the request, so even a refused request tells the caller what the
/// ring was doing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NapiState {
    /// Busy-poll window, nanoseconds. Zero = no busy-polling.
    pub busy_poll_dt_ns: u64,
    pub prefer_busy_poll: bool,
    pub track_mode: u32,
}

impl NapiState {
    /// A ring that has registered nothing: no window, and the mode that means
    /// "do not busy-poll". # C: O(1)
    pub fn inactive() -> Self {
        Self { busy_poll_dt_ns: 0, prefer_busy_poll: false, track_mode: IO_URING_NAPI_TRACKING_INACTIVE }
    }

    /// The current settings in the wire form, for the write-back.
    /// `op_param` carries the tracking mode on the way out. # C: O(1)
    pub fn to_wire(&self) -> Napi {
        Napi {
            busy_poll_to: (self.busy_poll_dt_ns / NSEC_PER_USEC) as u32,
            prefer_busy_poll: self.prefer_busy_poll as u8,
            opcode: 0, pad: [0; 2],
            op_param: self.track_mode,
            resv: 0,
        }
    }
}

/// What a `IORING_REGISTER_NAPI` request asks the ring to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NapiAction {
    /// Replace the window, the preference and the tracking mode, and drop
    /// every identifier the old mode collected.
    SetMode(NapiState),
    /// Add one identifier to the static list.
    AddId(u32),
    /// Remove one identifier from the static list.
    DelId(u32),
}

/// Reserved fields must be zero. Checked before the write-back, so a caller
/// that passed garbage learns that rather than having the ring's settings
/// copied over its garbage. # C: O(1)
pub fn admit_napi(n: &Napi) -> Result<(), Errno> {
    if n.pad != [0, 0] || n.resv != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Which action a validated request selects, given the tracking mode the ring
/// is in NOW. The two identifier opcodes are only meaningful under static
/// tracking: under dynamic tracking the list is the ring's own to maintain,
/// so editing it by hand is `EINVAL`. # C: O(1)
pub fn napi_action(n: &Napi, cur: &NapiState) -> Result<NapiAction, Errno> {
    match n.opcode {
        IO_URING_NAPI_REGISTER_OP => {
            match n.op_param {
                IO_URING_NAPI_TRACKING_DYNAMIC | IO_URING_NAPI_TRACKING_STATIC => {}
                _ => return Err(Errno::Einval),
            }
            // Clamped rather than refused: the ceiling exists to bound how
            // long one waiter may hold a CPU, not to police the argument.
            let us = core::cmp::min(NAPI_BUSY_POLL_MAX_US, n.busy_poll_to);
            Ok(NapiAction::SetMode(NapiState {
                busy_poll_dt_ns: us as u64 * NSEC_PER_USEC,
                prefer_busy_poll: n.prefer_busy_poll != 0,
                track_mode: n.op_param,
            }))
        }
        IO_URING_NAPI_STATIC_ADD_ID => {
            if cur.track_mode != IO_URING_NAPI_TRACKING_STATIC { return Err(Errno::Einval); }
            Ok(NapiAction::AddId(n.op_param))
        }
        IO_URING_NAPI_STATIC_DEL_ID => {
            if cur.track_mode != IO_URING_NAPI_TRACKING_STATIC { return Err(Errno::Einval); }
            Ok(NapiAction::DelId(n.op_param))
        }
        _ => Err(Errno::Einval),
    }
}

/// Whether a queue identifier may enter the list at all. # C: O(1)
pub fn napi_id_valid(id: u32) -> bool { id >= MIN_NAPI_ID }

/// Add `id` to `ids`. `EINVAL` for a reserved identifier, `EEXIST` for one
/// already tracked — a silent success there would hide a caller adding the
/// same queue twice. # C: O(N_ids)
pub fn add_id(ids: &mut alloc::vec::Vec<u32>, id: u32) -> Result<(), Errno> {
    if !napi_id_valid(id) { return Err(Errno::Einval); }
    if ids.contains(&id) { return Err(Errno::Eexist); }
    ids.push(id);
    Ok(())
}

/// Remove `id`. `EINVAL` for a reserved identifier, `ENOENT` for one that was
/// never tracked. # C: O(N_ids)
pub fn del_id(ids: &mut alloc::vec::Vec<u32>, id: u32) -> Result<(), Errno> {
    if !napi_id_valid(id) { return Err(Errno::Einval); }
    let Some(at) = ids.iter().position(|&e| e == id) else { return Err(Errno::Enoent) };
    ids.remove(at);
    Ok(())
}

/// Whether a wait should busy-poll before it parks.
///
/// Both tracking modes drive the SAME identifier list, so an empty list polls
/// nothing whichever mode is set — and a ring whose window is zero has asked
/// not to spin at all. # C: O(1)
pub fn busy_poll_wanted(st: &NapiState, n_ids: usize) -> bool {
    if st.busy_poll_dt_ns == 0 || n_ids == 0 { return false; }
    matches!(st.track_mode, IO_URING_NAPI_TRACKING_STATIC | IO_URING_NAPI_TRACKING_DYNAMIC)
}

/// How long a wait may busy-poll: its own window, never past the deadline it
/// already has. Spinning past the timeout would turn a timed wait into a
/// longer one. # C: O(1)
pub fn busy_poll_until(now: u64, st: &NapiState, deadline: u64) -> u64 {
    let end = now.saturating_add(st.busy_poll_dt_ns);
    if deadline != 0 && deadline < end { deadline } else { end }
}

#[cfg(test)]
#[path = "napi/tests.rs"]
mod tests;
