// Linux's `C_A_D` global (`kernel/reboot.c:41`) and `ctrl_alt_del()`
// (`kernel/reboot.c:828-836`), the only consumer of `LINUX_REBOOT_CMD_CAD_ON`
// / `CAD_OFF`.
//
// `C_A_D` starts at 1 (`int C_A_D = 1;`): out of the box Ctrl-Alt-Del reboots
// the machine. `reboot(..., CAD_OFF, ...)` — which is what systemd issues at
// startup — turns the key combination into a SIGINT delivered to the init
// process instead, so init can run an orderly shutdown. Storing the flag
// without wiring the keyboard would make both commands no-ops that lie about
// having taken effect.

use core::sync::atomic::{AtomicBool, Ordering};

/// `int C_A_D = 1;` — Ctrl-Alt-Del reboots until userspace says otherwise.
static C_A_D: AtomicBool = AtomicBool::new(true);

/// `C_A_D = cmd == LINUX_REBOOT_CMD_CAD_ON`. # C: O(1)
pub fn set_cad(on: bool) { C_A_D.store(on, Ordering::Release); }

/// Current `C_A_D`. Read by the keyboard driver and by procfs. # C: O(1)
pub fn cad_enabled() -> bool { C_A_D.load(Ordering::Acquire) }

/// What `ctrl_alt_del()` does with a Ctrl-Alt-Del keypress.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CadAction {
    /// `C_A_D` set: `schedule_work(&cad_work)` → `kernel_restart(NULL)`.
    Restart,
    /// `C_A_D` clear: `kill_cad_pid(SIGINT, 1)` — init decides what to do.
    SignalInit,
}

/// `ctrl_alt_del()`'s decision (`kernel/reboot.c:828-836`). Pure so the rule is
/// testable; the keyboard driver performs the outcome.
/// # C: O(1)
pub const fn cad_action(enabled: bool) -> CadAction {
    if enabled { CadAction::Restart } else { CadAction::SignalInit }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_combination_reboots_until_userspace_disables_it() {
        // Linux initialises `C_A_D = 1`. Defaulting to 0 would silently drop
        // Ctrl-Alt-Del on a machine whose init never calls reboot(CAD_OFF).
        assert_eq!(cad_action(true), CadAction::Restart);
        assert_eq!(cad_action(false), CadAction::SignalInit);
    }

    #[test]
    fn cad_state_round_trips() {
        assert!(cad_enabled());
        set_cad(false);
        assert!(!cad_enabled());
        set_cad(true);
        assert!(cad_enabled());
    }
}
