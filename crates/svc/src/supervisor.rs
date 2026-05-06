// Service supervisor state machine. Pure logic — no syscalls.
// PID 1 (or any embedder) feeds it events:
//   - tick(t)            : current time advances
//   - on_started(unit, pid)
//   - on_exited(pid, status)
// and asks for actions:
//   - poll_actions() -> Vec<Action>
//
// The state machine emits Action::Spawn { unit, argv } when a unit
// becomes ready (deps satisfied + not running) and respects
// RestartPolicy with a fixed-window backoff.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{RestartPolicy, ServiceType, Unit};

/// Backoff in monotonic ticks before a unit is eligible to restart.
pub const RESTART_BACKOFF_TICKS: u64 = 5;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum State {
    Idle,
    Starting,
    Running,
    Stopped,        // exited 0 with Restart=no or oneshot done
    Failed,         // exited != 0; awaiting restart eligibility
}

#[derive(Clone, Debug)]
pub struct Slot {
    pub unit:        Unit,
    pub state:       State,
    pub pid:         Option<u32>,
    pub last_exit:   Option<i32>,
    pub restart_at:  Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Spawn { name: String, argv: Vec<String> },
}

pub struct Supervisor {
    slots: BTreeMap<String, Slot>,
    now:   u64,
}

impl Supervisor {
    /// # C: O(1)
    pub fn new() -> Self { Self { slots: BTreeMap::new(), now: 0 } }

    /// Add a unit. Initial state = Idle.
    /// # C: O(1)
    pub fn add(&mut self, u: Unit) {
        let name = u.name.clone();
        self.slots.insert(name.clone(), Slot {
            unit: u, state: State::Idle, pid: None,
            last_exit: None, restart_at: None,
        });
    }

    /// # C: O(1)
    pub fn tick(&mut self, t: u64) { self.now = t; }
    /// # C: O(1)
    pub fn now(&self) -> u64 { self.now }

    /// # C: O(1)
    pub fn state(&self, name: &str) -> Option<State> {
        self.slots.get(name).map(|s| s.state)
    }
    /// # C: O(1)
    pub fn pid_of(&self, name: &str) -> Option<u32> {
        self.slots.get(name).and_then(|s| s.pid)
    }

    /// Caller fires this once they've spawned the unit. Moves
    /// state Idle/Failed → Starting → Running.
    /// # C: O(1)
    pub fn on_started(&mut self, name: &str, pid: u32) {
        if let Some(s) = self.slots.get_mut(name) {
            s.pid = Some(pid);
            s.state = match s.unit.kind {
                ServiceType::Simple | ServiceType::Forking => State::Running,
                ServiceType::Oneshot => State::Running, // exits when done
            };
        }
    }

    /// Caller fires this when waitpid reports an exit. `status` is
    /// the exit code (0 = clean). Updates state per Restart policy.
    /// # C: O(1)
    pub fn on_exited(&mut self, pid: u32, status: i32) -> Option<String> {
        let name = self.slots.iter().find_map(|(n, s)| {
            if s.pid == Some(pid) { Some(n.clone()) } else { None }
        })?;
        let s = self.slots.get_mut(&name)?;
        s.pid = None;
        s.last_exit = Some(status);
        let success = status == 0;
        s.state = match s.unit.kind {
            ServiceType::Oneshot if success => State::Stopped,
            _ => match s.unit.restart {
                RestartPolicy::No        => if success { State::Stopped } else { State::Failed },
                RestartPolicy::Always    => { s.restart_at = Some(self.now + RESTART_BACKOFF_TICKS); State::Failed }
                RestartPolicy::OnFailure => {
                    if success { State::Stopped }
                    else { s.restart_at = Some(self.now + RESTART_BACKOFF_TICKS); State::Failed }
                }
            }
        };
        Some(name)
    }

    /// Compute what to spawn now. Honors `After=` deps + restart
    /// backoff. Idempotent — caller must follow up with on_started
    /// for each Spawn it emits.
    /// # C: O(1)
    pub fn poll_actions(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        // snapshot to avoid borrow issues during iteration.
        let names: Vec<String> = self.slots.keys().cloned().collect();
        for n in &names {
            let ready = {
                let s = match self.slots.get(n) { Some(s) => s, None => continue };
                let need_start = match s.state {
                    State::Idle => true,
                    State::Failed => match s.restart_at {
                        Some(t) => self.now >= t && matches!(
                            s.unit.restart,
                            RestartPolicy::Always | RestartPolicy::OnFailure
                        ),
                        None => false,
                    },
                    _ => false,
                };
                if !need_start { false }
                else {
                    s.unit.after.iter().all(|dep| {
                        match self.slots.get(dep.as_str()).map(|x| x.state) {
                            Some(State::Running) | Some(State::Stopped) => true,
                            // External (unmanaged) dep: assume satisfied.
                            None => true,
                            _ => false,
                        }
                    })
                }
            };
            if ready {
                let s = self.slots.get_mut(n).unwrap();
                s.state = State::Starting;
                s.restart_at = None;
                out.push(Action::Spawn {
                    name: s.unit.name.clone(),
                    argv: s.unit.exec_start.clone(),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceType;

    fn mk(name: &str, after: &[&str], restart: RestartPolicy, kind: ServiceType) -> Unit {
        let mut u = Unit::default();
        u.name = name.into();
        u.exec_start = alloc::vec!["/bin/true".into()];
        u.after = after.iter().map(|x| (*x).into()).collect();
        u.restart = restart;
        u.kind = kind;
        u
    }

    #[test]
    fn spawn_simple_chain_in_order() {
        let mut s = Supervisor::new();
        s.add(mk("a", &[],     RestartPolicy::No, ServiceType::Simple));
        s.add(mk("b", &["a"],  RestartPolicy::No, ServiceType::Simple));
        let acts = s.poll_actions();
        // only `a` is ready (no deps); `b` waits on a.
        assert_eq!(acts.len(), 1);
        match &acts[0] { Action::Spawn { name, .. } => assert_eq!(name, "a") }
        s.on_started("a", 100);
        // now `b` becomes ready.
        let acts = s.poll_actions();
        assert_eq!(acts.len(), 1);
        match &acts[0] { Action::Spawn { name, .. } => assert_eq!(name, "b") }
    }

    #[test]
    fn restart_on_failure_backoff() {
        let mut s = Supervisor::new();
        s.add(mk("svc", &[], RestartPolicy::OnFailure, ServiceType::Simple));
        s.poll_actions();
        s.on_started("svc", 7);
        let renamed = s.on_exited(7, 1).unwrap();
        assert_eq!(renamed, "svc");
        assert_eq!(s.state("svc"), Some(State::Failed));
        // immediately polling: not yet eligible.
        assert_eq!(s.poll_actions().len(), 0);
        s.tick(RESTART_BACKOFF_TICKS);
        let acts = s.poll_actions();
        assert_eq!(acts.len(), 1);
    }

    #[test]
    fn restart_always_loops() {
        let mut s = Supervisor::new();
        s.add(mk("svc", &[], RestartPolicy::Always, ServiceType::Simple));
        for cycle in 0..3 {
            s.tick((cycle as u64) * RESTART_BACKOFF_TICKS);
            let acts = s.poll_actions();
            assert_eq!(acts.len(), 1, "cycle {} expected one spawn", cycle);
            s.on_started("svc", 200 + cycle);
            assert_eq!(s.state("svc"), Some(State::Running));
            // exit cleanly — Always still restarts.
            s.on_exited(200 + cycle, 0).unwrap();
            assert_eq!(s.state("svc"), Some(State::Failed));
        }
    }

    #[test]
    fn restart_no_keeps_stopped() {
        let mut s = Supervisor::new();
        s.add(mk("once", &[], RestartPolicy::No, ServiceType::Oneshot));
        s.poll_actions();
        s.on_started("once", 9);
        s.on_exited(9, 0);
        assert_eq!(s.state("once"), Some(State::Stopped));
        assert_eq!(s.poll_actions().len(), 0);
    }

    #[test]
    fn external_dep_assumed_satisfied() {
        let mut s = Supervisor::new();
        s.add(mk("x", &["sysinit.target"], RestartPolicy::No, ServiceType::Simple));
        // sysinit.target not registered — supervisor treats unknown
        // names as already-up.
        let acts = s.poll_actions();
        assert_eq!(acts.len(), 1);
    }
}
