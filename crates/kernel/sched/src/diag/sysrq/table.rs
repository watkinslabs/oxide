// The key table: what one letter means. No global state, so it is checkable
// without a machine to press a key on.

/// A decoded magic-SysRq command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// `c` — crash the machine deliberately. The point of the key: it produces
    /// a panic at a moment of the operator's choosing, which is what a staged
    /// crash kernel is waiting for.
    Crash,
    /// `b` — restart immediately, without syncing or unmounting.
    Reboot,
    /// `o` — power the machine off.
    PowerOff,
    /// `t` — every task's state.
    ShowTasks,
    /// `w` — the tasks in uninterruptible sleep.
    ShowBlocked,
    /// `l` — a backtrace from every active CPU.
    ShowBacktraceAllCpus,
    /// `p` — this CPU's registers. Rendered here as its heartbeat, which is
    /// the per-CPU state this kernel actually retains.
    ShowRegisters,
    /// `h` — the key list.
    Help,
    /// A key with no command bound to it. Carried rather than collapsed into
    /// `Help` so a caller can tell "not a command" from "asked for the list".
    Unbound(u8),
}

/// Decode one key. Case is significant and every command is lower-case, so an
/// upper-case letter is unbound rather than quietly the same command.
/// # C: O(1)
pub fn decode(key: u8) -> Cmd {
    match key {
        b'c' => Cmd::Crash,
        b'b' => Cmd::Reboot,
        b'o' => Cmd::PowerOff,
        b't' => Cmd::ShowTasks,
        b'w' => Cmd::ShowBlocked,
        b'l' => Cmd::ShowBacktraceAllCpus,
        b'p' => Cmd::ShowRegisters,
        b'h' => Cmd::Help,
        other => Cmd::Unbound(other),
    }
}

/// Every bound key and the word the help line names it by, in key order.
pub const KEYS: &[(u8, &[u8])] = &[
    (b'b', b"reboot"),
    (b'c', b"crash"),
    (b'l', b"backtrace-all-cpus"),
    (b'o', b"poweroff"),
    (b'p', b"registers"),
    (b't', b"tasks"),
    (b'w', b"blocked-tasks"),
];
