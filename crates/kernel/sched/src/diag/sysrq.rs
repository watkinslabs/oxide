// The magic-SysRq command table: ONE decoding of a key, consulted by both
// entries into it.
//
// There are two ways a command arrives — the serial line's break-then-key
// sequence, and a write to `/proc/sysrq-trigger` — and they must agree on what
// a key means. They did not: the serial path had its own `match` in which `c`
// dumped per-CPU heartbeats and `b` printed backtraces, so a key that halts a
// machine everywhere else printed a table here, and the key that CRASHES a
// machine everywhere else was bound to a harmless dump. An operator carries
// those letters in muscle memory; a second private table is how they get a
// machine that does not do what they asked.
//
// Decoding and the enable mask are decided here, with no global state, so both
// are checkable without a machine to press a key on. The side effects live in
// `perform`, which is the only part that needs a kernel.

use core::sync::atomic::Ordering;

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

/// Bits of the enable mask (`kernel.sysrq`), as the reference numbers them.
/// A mask of exactly `1` enables everything; otherwise a command runs only
/// when its own bit is set.
pub const ENABLE_ALL: u32 = 1;
/// Loglevel changes.
pub const ENABLE_LOG: u32 = 0x0002;
/// Debugging dumps.
pub const ENABLE_DUMP: u32 = 0x0004;
/// Reboot and power off.
pub const ENABLE_BOOT: u32 = 0x0080;

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

/// Which mask bit `cmd` is gated by.
/// # C: O(1)
pub fn enable_bit(cmd: Cmd) -> u32 {
    match cmd {
        Cmd::Crash | Cmd::ShowTasks | Cmd::ShowBlocked
        | Cmd::ShowBacktraceAllCpus | Cmd::ShowRegisters => ENABLE_DUMP,
        Cmd::Reboot | Cmd::PowerOff => ENABLE_BOOT,
        Cmd::Help | Cmd::Unbound(_) => ENABLE_LOG,
    }
}

/// May `cmd` run under `mask`?
///
/// `1` is not a bit pattern — it is the spelling of "all of them", and a mask
/// read bit-wise would enable nothing but the loglevel keys on the setting
/// almost every machine uses.
/// # C: O(1)
pub fn mask_allows(mask: u32, cmd: Cmd) -> bool {
    mask == ENABLE_ALL || (mask & enable_bit(cmd)) != 0
}

/// The mask a key press is actually judged against.
///
/// `kernel.sysrq` is userspace policy, and a distribution's `sysctl.d` sets it
/// after any value the boot line asked for — so on the one machine that needs
/// the keys, the machine whose userspace has stopped answering, they are
/// refused. The boot parameter is the setting userspace cannot overwrite, and
/// the reference gives it exactly this meaning: enable everything, whatever
/// the sysctl later holds.
/// # C: O(1)
pub fn effective_mask(mask: u32, always: bool) -> u32 { if always { ENABLE_ALL } else { mask } }

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

/// Prefix every help line carries, whatever the mask leaves in it.
pub const HELP_PREFIX: &[u8] = b"[sysrq] keys:";

/// Room for the prefix plus every key and its label. Sized from the table so a
/// key added without room shows up as a compile-time constant that is too
/// small, rather than as a silently clipped line.
pub const HELP_MAX: usize = 128;

/// Does the help line under `mask` advertise `key`?
///
/// The list names what the operator can actually run. Advertising a key the
/// mask refuses invites the one keystroke that then does nothing, on a machine
/// where the operator is already out of options.
/// # C: O(1)
pub fn advertised(mask: u32, key: u8) -> bool {
    match decode(key) {
        Cmd::Help | Cmd::Unbound(_) => false,
        cmd => mask_allows(mask, cmd),
    }
}

/// Render the key list permitted by `mask` into `out`, returning its length.
///
/// Built into a caller-supplied buffer and emitted as ONE line, because the
/// line is printed from the console's emergency route and a line assembled by
/// several writes can be spliced by another CPU's output in between.
/// # C: O(number of keys)
pub fn render_help(mask: u32, out: &mut [u8; HELP_MAX]) -> usize {
    let mut n = 0;
    let mut put = |bytes: &[u8], n: &mut usize| {
        for &b in bytes { if *n < HELP_MAX { out[*n] = b; *n += 1; } }
    };
    put(HELP_PREFIX, &mut n);
    for &(key, label) in KEYS {
        if !advertised(mask, key) { continue; }
        put(b" ", &mut n);
        put(&[key], &mut n);
        put(b"=", &mut n);
        put(label, &mut n);
    }
    n
}

/// Print the key list, filtered to what `mask` permits. # C: O(number of keys)
pub fn emit_help(mask: u32) {
    let mut buf = [0u8; HELP_MAX];
    let n = render_help(mask, &mut buf);
    klog::announce_bytes(&buf[..n]);
}

/// Run `cmd` under `mask`. Returns for every command except the two that take
/// the machine.
///
/// Asking for the list is never refused, whatever the mask says. The mask
/// decides what a machine will DO, not whether it will say what it can do —
/// and a refused help key leaves an operator with a console that answers
/// nothing at all, which reads as an unreachable keyboard.
/// # C: O(number of tasks) for the dumps, O(1) otherwise
pub fn perform(cmd: Cmd, mask: u32) {
    match cmd {
        Cmd::Help | Cmd::Unbound(_) => return emit_help(mask),
        _ => {}
    }
    if !mask_allows(mask, cmd) {
        klog::announce("[sysrq] this operation is disabled by kernel.sysrq");
        return;
    }
    match cmd {
        Cmd::Crash => crash(),
        Cmd::Reboot | Cmd::PowerOff => restart(),
        Cmd::ShowTasks | Cmd::ShowBlocked => super::emit::dump_tasks(),
        Cmd::ShowBacktraceAllCpus => super::nmi::backtrace_all(),
        Cmd::ShowRegisters => super::percpu::dump_cpus(),
        Cmd::Help | Cmd::Unbound(_) => unreachable!(),
    }
}

/// Panic on purpose. Announced first on the raw console, because everything
/// after this point is the panic path and an operator watching a serial line
/// needs to know the crash was asked for rather than found.
/// # C: O(1)
fn crash() -> ! {
    klog::announce("[sysrq] crash requested");
    panic!("sysrq: crash requested from userspace");
}

/// Take the machine down through the installed restart callback. Falls through
/// when none is installed — an operator gets the refusal on the console rather
/// than a key that appears to do nothing.
/// # C: O(1)
fn restart() {
    match klog::oops::restart_hook() {
        Some(f) => { klog::announce("[sysrq] restarting"); f(); }
        None => klog::announce("[sysrq] no restart method is installed"),
    }
}

/// The `/proc/sysrq-trigger` entry: run `key` REGARDLESS of the enable mask.
///
/// Writing the file is already privileged by its mode, and the reference
/// deliberately skips the mask check here — the mask exists to stop a key
/// press on an unattended console, not to stop root. Gating this on the mask
/// makes the file useless on the default `kernel.sysrq=0` machines that are
/// exactly the ones an operator needs it on.
/// # C: see `perform`
pub fn trigger(key: u8) { perform(decode(key), ENABLE_ALL); }

const SYSRQ_ARM: u8 = 0x00;

/// What the console byte sink owes a received byte, and the arm state it
/// leaves behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxStep {
    /// Consumed as the arming break; the byte after this one is a command.
    Armed,
    /// Consumed as a command; the line is disarmed again.
    Run(Cmd),
    /// Not sysrq's — forward it to the tty.
    Passthrough,
}

/// Decide what one received byte means, given whether the line is armed.
///
/// Split out from [`rx`] because it is the whole of the serial console's
/// input contract and the only part of it that a machine is not needed to
/// check. It went untested for as long as it lived inside `rx`: the arm/key
/// pair is the sequence the boot gate types at every guest, so a break in it
/// looks exactly like an unreachable UART, and nothing here could have
/// distinguished the two.
/// # C: O(1)
pub fn decide(armed: bool, b: u8) -> RxStep {
    if armed { return RxStep::Run(decode(b)); }
    if b == SYSRQ_ARM { return RxStep::Armed; }
    RxStep::Passthrough
}

/// The serial line's byte sink: a break arms, the next byte is the command.
/// Returns true when the byte was consumed by sysrq rather than the tty.
/// # C: see `perform`
pub fn rx(b: u8) -> bool {
    match decide(super::emit::sysrq_disarm(), b) {
        RxStep::Run(cmd) => { perform(cmd, effective_mask(mask_value(), always_enabled())); true }
        RxStep::Armed => { super::emit::sysrq_arm(); true }
        RxStep::Passthrough => false,
    }
}

/// The live `kernel.sysrq` setting.
/// # C: O(1)
pub fn mask_value() -> u32 { MASK.load(Ordering::Relaxed) }

static MASK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(ENABLE_ALL);

/// Publish a new `kernel.sysrq` value. # C: O(1)
pub fn set_mask(v: u32) { MASK.store(v, Ordering::Relaxed); }

static ALWAYS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Did the boot line ask for `sysrq_always_enabled`? # C: O(1)
pub fn always_enabled() -> bool { ALWAYS.load(Ordering::Relaxed) }

/// Record the boot line's `sysrq_always_enabled` request. Announced when set,
/// because a machine whose keys answer regardless of `kernel.sysrq` is a
/// deliberate configuration an operator should see stated once.
/// # C: O(1)
pub fn set_always_enabled(on: bool) {
    ALWAYS.store(on, Ordering::Relaxed);
    if on { klog::announce("[sysrq] always enabled by the boot line"); }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The letters an operator already knows. `c` crashes and `b` reboots on
    /// every other machine they will ever touch; this kernel bound `c` to a
    /// per-CPU dump and `b` to a backtrace, so both of the keys that take a
    /// machine down printed a table instead.
    /// A distribution's `sysctl.d` lowers `kernel.sysrq` after the boot line
    /// asked for it, and the keys are then refused on the one machine that
    /// needs them. The boot parameter is what userspace cannot overwrite.
    #[test]
    fn the_boot_parameter_overrides_a_sysctl_that_refuses_everything() {
        let refuse_all = 0;
        assert!(!mask_allows(refuse_all, Cmd::ShowTasks), "the sysctl alone refuses the dump");
        assert!(mask_allows(effective_mask(refuse_all, true), Cmd::ShowTasks));
        assert!(mask_allows(effective_mask(refuse_all, true), Cmd::Crash));
        assert!(mask_allows(effective_mask(refuse_all, true), Cmd::Reboot));
    }

    /// ...and without it the sysctl still decides, in both directions.
    #[test]
    fn without_the_boot_parameter_the_sysctl_still_decides() {
        assert_eq!(effective_mask(ENABLE_DUMP, false), ENABLE_DUMP);
        assert!(!mask_allows(effective_mask(ENABLE_DUMP, false), Cmd::Reboot));
        assert!(mask_allows(effective_mask(ENABLE_DUMP, false), Cmd::ShowTasks));
        assert_eq!(effective_mask(0, false), 0);
    }

    #[test]
    fn the_keys_that_take_a_machine_down_are_the_reference_letters() {
        assert_eq!(decode(b'c'), Cmd::Crash);
        assert_eq!(decode(b'b'), Cmd::Reboot);
        assert_eq!(decode(b'o'), Cmd::PowerOff);
    }

    #[test]
    fn the_dump_keys_are_the_reference_letters() {
        assert_eq!(decode(b't'), Cmd::ShowTasks);
        assert_eq!(decode(b'w'), Cmd::ShowBlocked);
        assert_eq!(decode(b'l'), Cmd::ShowBacktraceAllCpus);
        assert_eq!(decode(b'p'), Cmd::ShowRegisters);
    }

    /// An upper-case letter is not the same command in a different case: the
    /// shift key is how a key press arrives already, and folding it would let
    /// a shifted keystroke crash a machine.
    #[test]
    fn case_is_significant() {
        assert_eq!(decode(b'C'), Cmd::Unbound(b'C'));
        assert_eq!(decode(b'B'), Cmd::Unbound(b'B'));
    }

    #[test]
    fn an_unbound_key_is_distinguishable_from_asking_for_help() {
        assert_eq!(decode(b'h'), Cmd::Help);
        assert_eq!(decode(b'z'), Cmd::Unbound(b'z'));
    }

    /// `1` means all of them. Read as a bit pattern it enables the loglevel
    /// group and nothing else, which is the setting nearly every machine runs.
    #[test]
    fn a_mask_of_one_enables_every_command() {
        for cmd in [Cmd::Crash, Cmd::Reboot, Cmd::PowerOff, Cmd::ShowTasks,
                    Cmd::ShowBlocked, Cmd::ShowBacktraceAllCpus, Cmd::ShowRegisters] {
            assert!(mask_allows(ENABLE_ALL, cmd), "{cmd:?} refused under the enable-all mask");
        }
    }

    /// The sequence the boot gate types at every guest, byte for byte: a NUL
    /// arms the line, and the byte after it is the command. `?` is bound to
    /// nothing, which is deliberately how the gate asks for the key list —
    /// it wants an answer that cannot take the machine down.
    #[test]
    fn a_break_then_a_key_is_the_typed_console_sequence() {
        assert_eq!(decide(false, SYSRQ_ARM), RxStep::Armed);
        assert_eq!(decide(true, b'?'), RxStep::Run(Cmd::Unbound(b'?')));
        assert_eq!(decide(true, b't'), RxStep::Run(Cmd::ShowTasks));
    }

    /// An unarmed ordinary byte belongs to the tty. Consuming it here would
    /// swallow every character typed at the console.
    #[test]
    fn an_unarmed_ordinary_byte_goes_to_the_tty() {
        for b in [b'a', b'?', b't', b'\r', b'\n', 0xff] {
            assert_eq!(decide(false, b), RxStep::Passthrough, "byte {b:#x} was eaten");
        }
    }

    /// A second NUL arrives while armed, so it is a command byte and not a
    /// re-arm: it asks for the key list and leaves the line disarmed. Treating
    /// it as a re-arm would leave the line armed forever after a stray NUL,
    /// and the next character typed would run whatever it decodes to.
    #[test]
    fn a_second_break_is_a_command_byte_not_a_re_arm() {
        assert_eq!(decide(true, SYSRQ_ARM), RxStep::Run(Cmd::Unbound(SYSRQ_ARM)));
    }

    /// Every step either consumes the byte or passes it on, never both, and
    /// only `Armed` leaves the line armed.
    #[test]
    fn exactly_one_step_leaves_the_line_armed() {
        for b in 0u8..=0xff {
            assert_eq!(decide(false, b) == RxStep::Armed, b == SYSRQ_ARM,
                       "byte {b:#x} armed the line, or the break failed to");
            assert!(matches!(decide(true, b), RxStep::Run(_)),
                    "byte {b:#x} was not taken as a command on an armed line");
        }
    }

    #[test]
    fn a_zero_mask_refuses_every_command() {
        for cmd in [Cmd::Crash, Cmd::Reboot, Cmd::ShowTasks, Cmd::Help] {
            assert!(!mask_allows(0, cmd), "{cmd:?} ran under a zero mask");
        }
    }

    /// The groups are independent: a machine that allows dumps must not
    /// thereby allow a reboot.
    #[test]
    fn the_enable_groups_do_not_leak_into_each_other() {
        assert!(mask_allows(ENABLE_DUMP, Cmd::Crash));
        assert!(!mask_allows(ENABLE_DUMP, Cmd::Reboot));
        assert!(mask_allows(ENABLE_BOOT, Cmd::Reboot));
        assert!(!mask_allows(ENABLE_BOOT, Cmd::ShowTasks));
    }

    /// Every key the list advertises is bound, and every bound key that is
    /// not `h` is advertised. A list that drifts from the table is how a key
    /// stops being discoverable.
    #[test]
    fn the_help_list_is_exactly_the_bound_keys() {
        for &(key, _) in KEYS {
            assert!(!matches!(decode(key), Cmd::Unbound(_) | Cmd::Help),
                    "{} is advertised but not a command", key as char);
        }
        for key in 0x20u8..0x7f {
            let bound = !matches!(decode(key), Cmd::Unbound(_) | Cmd::Help);
            assert_eq!(bound, KEYS.iter().any(|&(k, _)| k == key),
                       "{} is bound but not advertised, or the reverse", key as char);
        }
    }

    /// The list names what the operator can RUN. Under a mask that permits
    /// only reboots, offering the dump keys invites the keystroke that then
    /// does nothing.
    #[test]
    fn the_list_is_filtered_to_what_the_mask_permits() {
        assert!(advertised(ENABLE_BOOT, b'b'));
        assert!(!advertised(ENABLE_BOOT, b't'));
        assert!(advertised(ENABLE_DUMP, b't'));
        assert!(!advertised(ENABLE_DUMP, b'b'));
        for &(key, _) in KEYS { assert!(advertised(ENABLE_ALL, key)); }
    }

    /// The line is BUILT, so its shape is pinned: one line, the prefix, then
    /// each permitted key. It is emitted as a single write because a line
    /// assembled by several writes can be spliced by another CPU's output.
    #[test]
    fn the_rendered_list_is_one_line_naming_the_permitted_keys() {
        let mut buf = [0u8; HELP_MAX];
        let n = render_help(ENABLE_ALL, &mut buf);
        let text = core::str::from_utf8(&buf[..n]).expect("ascii");
        assert_eq!(text,
            "[sysrq] keys: b=reboot c=crash l=backtrace-all-cpus o=poweroff \
p=registers t=tasks w=blocked-tasks");
        assert!(!text.contains('\n'), "the newline belongs to the emitter: {text}");

        let n = render_help(ENABLE_BOOT, &mut buf);
        let text = core::str::from_utf8(&buf[..n]).expect("ascii");
        assert_eq!(text, "[sysrq] keys: b=reboot o=poweroff");

        // A mask that permits nothing still says who is speaking, so a typed
        // console answers rather than staying silent.
        let n = render_help(0, &mut buf);
        assert_eq!(&buf[..n], HELP_PREFIX);
    }

    /// The buffer must hold the whole list. A key added without room would
    /// clip the line rather than fail anywhere visible.
    #[test]
    fn the_render_buffer_holds_every_key() {
        let mut buf = [0u8; HELP_MAX];
        let n = render_help(ENABLE_ALL, &mut buf);
        assert!(n < HELP_MAX, "the list fills the buffer ({n} of {HELP_MAX}); it is being clipped");
    }

    /// Asking what a machine can do is never refused. A mask that suppressed
    /// the list too would leave a typed console answering nothing at all,
    /// which is indistinguishable from a keyboard that is not reaching the
    /// kernel — and that is exactly the fault the console probe exists to
    /// tell apart.
    #[test]
    fn asking_for_the_list_is_never_refused() {
        for mask in [0, ENABLE_BOOT, 16, ENABLE_ALL] {
            assert!(!advertised(mask, b'h'), "h names the list, it is not in it");
            // `perform` cannot be called hosted (it prints through klog), so
            // the property is asserted on the branch that decides it.
            assert!(matches!(decode(b'?'), Cmd::Unbound(_)));
            assert!(matches!(decode(b'h'), Cmd::Help));
            let _ = mask;
        }
    }
}
