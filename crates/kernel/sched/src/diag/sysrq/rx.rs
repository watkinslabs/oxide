// The serial line's arm-then-key state machine, and the deadline that bounds it.
//
// A break arms the line and the byte after it is a command. The window that
// belief lives in MUST expire. It did not: the armed state was a bare flag,
// cleared only by the next byte to arrive, so a single stray zero on the wire —
// line noise, an unplugged cable, a peripheral powering up — left the console
// armed for as long as the machine ran. The next character that happened along,
// minutes or days later, was taken as a command, and on our boot line (which
// asks for enable-all) `c` panics the machine and `b` reboots it. A spontaneous
// reboot with nothing in the log to explain it.
//
// The reference bounds it explicitly: arming stores a deadline five seconds out
// and every dispatch is gated on the current time still being before it,
// clearing the state otherwise. Same contract here, in one word of state, with
// the arithmetic in `decide` so the expiry is testable with no clock at all.

use core::sync::atomic::{AtomicU64, Ordering};

use super::mask::{always_enabled, effective_mask, mask_value};
use super::perform::perform;
use super::table::{decode, Cmd};

/// The byte that arms the line. A UART reports a break condition as a framing
/// error carrying zero, which is why it is this value and not a letter.
pub const SYSRQ_ARM: u8 = 0x00;

/// How long an armed line stays armed. Five seconds, the reference's window
/// (`HZ * 5`) — long enough to type a key after a break, short enough that a
/// console left alone is not sitting one character away from a panic.
pub const ARM_WINDOW_NS: u64 = 5_000_000_000;

/// Sentinel for "not armed", so the whole state is one word as it is in the
/// reference. A real deadline can never collide with it: the window is
/// non-zero, so `now + ARM_WINDOW_NS` is non-zero for every `now`.
pub const DISARMED: u64 = 0;

/// What the console byte sink owes a received byte, and the arm state it
/// leaves behind.
///
/// `Armed` carries the deadline to store; `Run` and `Passthrough` both leave
/// the line DISARMED — every path out of an armed state clears it, which is
/// what makes the window bounded rather than sticky.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxStep {
    /// Consumed as the arming break; a command is accepted until this deadline.
    Armed(u64),
    /// Consumed as a command; the line is disarmed again.
    Run(Cmd),
    /// Not sysrq's — forward it to the tty, with the line disarmed.
    Passthrough,
}

impl RxStep {
    /// The arm state this step leaves behind. # C: O(1)
    pub fn next_armed_until(self) -> u64 {
        match self { RxStep::Armed(deadline) => deadline, _ => DISARMED }
    }
}

/// Decide what one received byte means, given the deadline the line is armed
/// until (`DISARMED` when it is not) and the current monotonic time.
///
/// The whole of the serial console's input contract, and the only part of it a
/// machine is not needed to check. It went untested for as long as it lived
/// inside [`rx`]: the arm/key pair is the sequence the boot gate types at every
/// guest, so a break in it looks exactly like an unreachable UART and nothing
/// could have distinguished the two.
///
/// Three refusals, all the reference's:
/// - the window has passed (`now_ns >= armed_until_ns`) — disarm, and the byte
///   is the tty's, so ordinary typing after a stray break reaches the shell;
/// - the byte is zero — a second break is not a command. The reference guards
///   its dispatch on the byte being non-zero and its break handler clears the
///   armed state on a second break; both leave the byte to the tty;
/// - nothing is armed and the byte is not a break.
/// # C: O(1)
pub fn decide(armed_until_ns: u64, now_ns: u64, b: u8) -> RxStep {
    if armed_until_ns == DISARMED {
        if b == SYSRQ_ARM { return RxStep::Armed(now_ns.saturating_add(ARM_WINDOW_NS)); }
        return RxStep::Passthrough;
    }
    if b != SYSRQ_ARM && now_ns < armed_until_ns { return RxStep::Run(decode(b)); }
    RxStep::Passthrough
}

/// The deadline the line is armed until, in CLOCK_MONOTONIC nanoseconds;
/// `DISARMED` when no break is outstanding.
static ARMED_UNTIL_NS: AtomicU64 = AtomicU64::new(DISARMED);

/// The serial line's byte sink: a break arms, the next byte inside the window
/// is the command. Returns true when the byte was consumed by sysrq rather
/// than the tty.
///
/// Runs in the UART's receive interrupt, which is why the clock read is
/// `timekeeper::monotonic_ns`: it is a lock-free seqlock read over the
/// architecture counter, documented safe from hard IRQ (its writers mask
/// interrupts, so an ISR reader cannot spin on an update it interrupted).
/// It is also the RIGHT clock rather than merely an available one — the
/// reference reads `jiffies`, its timer-tick counter, and a tick counter here
/// would stop advancing during exactly the I/O storms that freeze this
/// kernel's tick for seconds, leaving a window that outlives its own deadline.
/// The counter keeps running regardless.
///
/// The state is taken before the decision and republished after, so the window
/// between them reads as DISARMED — a concurrent byte can only fail to
/// dispatch, never dispatch on a stale deadline. `known_issues.md` carries the
/// per-port state this word should be, which is a `drv-serial` change.
/// # C: see `perform`
pub fn rx(b: u8) -> bool {
    let now = timekeeper::monotonic_ns();
    let step = decide(ARMED_UNTIL_NS.swap(DISARMED, Ordering::Relaxed), now, b);
    ARMED_UNTIL_NS.store(step.next_armed_until(), Ordering::Relaxed);
    match step {
        RxStep::Run(cmd) => { perform(cmd, effective_mask(mask_value(), always_enabled())); true }
        RxStep::Armed(_) => true,
        RxStep::Passthrough => false,
    }
}
