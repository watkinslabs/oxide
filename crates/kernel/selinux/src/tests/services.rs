// Access-vector computation against the synthetic fixture policy.

use crate::services::fixture::*;

use crate::avc::{AVD_FLAGS_NEVERAUDIT, AVD_FLAGS_PERMISSIVE};
use crate::context::Context;
use crate::mapping::{kernel_perm_bit, Mapping};
use crate::policydb::Policydb;
use crate::services::av::compute_av;
use crate::sidtab::{Sid, Sidtab};
use crate::uapi::classmap::class_by_name;

/// Policy sequence number the tests pass through.
const SEQNO: u32 = 7;

/// Kernel class value of a class the fixture defines.
fn kcls(name: &str) -> u16 { class_by_name(name).expect("kernel class") }

/// Kernel access-vector bit of a named permission.
fn kperm(class: u16, name: &str) -> u32 { kernel_perm_bit(class, name).expect("kernel perm") }

/// A SID for one context.
fn sid(sidtab: &mut Sidtab, c: crate::context::ValidContext) -> Sid {
    sidtab.context_to_sid(Context::Valid(c)).expect("sid")
}

struct Env {
    db: Policydb,
    map: Mapping,
    sidtab: Sidtab,
}

fn env() -> Env {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    Env { db, map, sidtab: Sidtab::new() }
}

impl Env {
    fn rebuild_map(&mut self) { self.map = Mapping::build(&self.db).expect("mapping"); }

    fn av(&mut self, ssid: Sid, tsid: Sid, class: u16) -> crate::avc::AvDecision {
        compute_av(&self.db, &self.map, &self.sidtab, ssid, tsid, class, SEQNO)
    }
}

#[test]
fn allow_rule_grants_exactly_its_bits() {
    let mut e = env();
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let file = kcls("file");
    let avd = e.av(s, t, file);
    let want = kperm(file, "read") | kperm(file, "write") | kperm(file, "getattr");
    assert_eq!(avd.allowed, want);
    assert_eq!(avd.seqno, SEQNO);
}

#[test]
fn attribute_rule_reaches_a_member_type_and_no_other() {
    let mut e = env();
    let file = kcls("file");
    let target = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let member = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_USER, S0, &[]));
    let outsider = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_LONE, S0, &[]));

    // `user_t` is a member of the attribute the rule is stored against.
    let granted = e.av(member, target, file);
    assert_eq!(granted.allowed, kperm(file, "read") | kperm(file, "write"));
    // `lone_t` belongs to no attribute, so the same query must deny.
    let denied = e.av(outsider, target, file);
    assert_eq!(denied.allowed, 0);
}

#[test]
fn attribute_rule_reaches_an_attribute_target() {
    let mut e = env();
    let file = kcls("file");
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_USER, S0, &[]));
    let etc = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_ETC, S0, &[]));
    let avd = e.av(s, etc, file);
    assert_eq!(avd.allowed, kperm(file, "read") | kperm(file, "write"));
}

#[test]
fn auditdeny_starts_all_ones_and_a_suppression_clears_bits() {
    let mut e = env();
    let file = kcls("file");
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let suppressed = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]));
    let plain = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_USER, S0, &[]));

    let write = kperm(file, "write");
    let read = kperm(file, "read");

    // No suppression rule covers this pair: every denial is still audited.
    let a = e.av(plain, t, file);
    assert_eq!(a.auditdeny & write, write);
    assert_eq!(a.auditdeny & read, read);

    // The suppression rule removes the write bit and leaves the rest.
    let b = e.av(suppressed, t, file);
    assert_eq!(b.auditdeny & write, 0);
    assert_eq!(b.auditdeny & read, read);
}

#[test]
fn auditallow_records_the_named_permission() {
    let mut e = env();
    let file = kcls("file");
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let avd = e.av(s, t, file);
    assert_eq!(avd.auditallow, kperm(file, "read"));
}

#[test]
fn conditional_rule_is_invisible_until_enabled() {
    let mut e = env();
    let file = kcls("file");
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let open = kperm(file, "open");

    set_conditional(&mut e.db, false);
    assert_eq!(e.av(s, t, file).allowed & open, 0);

    set_conditional(&mut e.db, true);
    assert_eq!(e.av(s, t, file).allowed & open, open);
}

#[test]
fn constraint_removes_only_the_permissions_it_guards() {
    let mut e = env();
    let file = kcls("file");
    let write = kperm(file, "write");
    let read = kperm(file, "read");
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));

    // Levels equal: the constraint holds and takes nothing away.
    let same = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]));
    let a = e.av(same, t, file);
    assert_eq!(a.allowed & write, write);

    // Levels differ: the guarded permission goes, the others stay.
    let higher = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S1, &[]));
    let b = e.av(higher, t, file);
    assert_eq!(b.allowed & write, 0);
    assert_eq!(b.allowed & read, read);
}

#[test]
fn role_allow_gates_process_transitions() {
    let mut e = env();
    let process = kcls("process");
    let trans = kperm(process, "transition") | kperm(process, "dyntransition");
    let fork = kperm(process, "fork");
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]));

    // The policy pairs system_r with user_r.
    let permitted = sid(&mut e.sidtab, ctx(U_SYSTEM, R_USER, T_USER, S0, &[]));
    let a = e.av(s, permitted, process);
    assert_eq!(a.allowed & trans, trans);

    // It does not pair system_r with admin_r.
    let refused = sid(&mut e.sidtab, ctx(U_SYSTEM, R_ADMIN, T_USER, S0, &[]));
    let b = e.av(s, refused, process);
    assert_eq!(b.allowed & trans, 0);
    assert_eq!(b.allowed & fork, fork);
}

#[test]
fn same_role_needs_no_role_allow_entry() {
    let mut e = env();
    let process = kcls("process");
    let trans = kperm(process, "transition");
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_ADMIN, T_INIT, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_ADMIN, T_USER, S0, &[]));
    assert_eq!(e.av(s, t, process).allowed & trans, trans);
}

#[test]
fn bounds_mask_what_the_bounding_type_lacks() {
    let mut e = env();
    let file = kcls("file");
    let execute = kperm(file, "execute");
    let read = kperm(file, "read");
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_CHILD, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));

    let bounded = e.av(s, t, file);
    assert_eq!(bounded.allowed & execute, 0);
    assert_eq!(bounded.allowed & read, read);

    // With the bound removed the same rule grants the permission, so the
    // masking above is the bound's doing and not an absent rule.
    e.db.symbols.types[(T_CHILD - 1) as usize].bounds = 0;
    let free = e.av(s, t, file);
    assert_eq!(free.allowed & execute, execute);
}

#[test]
fn bounds_cycle_terminates() {
    let mut e = env();
    let file = kcls("file");
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_CYCLE_A, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let avd = e.av(s, t, file);
    assert_eq!(avd.allowed & kperm(file, "read"), kperm(file, "read"));
}

#[test]
fn permissive_and_neveraudit_short_circuit_to_everything() {
    let mut e = env();
    let file = kcls("file");
    e.db.permissive_map.set(T_INIT, true);
    e.db.neveraudit_map.set(T_INIT, true);
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let avd = e.av(s, t, file);
    assert_eq!(avd.allowed, u32::MAX);
    assert_eq!(avd.flags & (AVD_FLAGS_PERMISSIVE | AVD_FLAGS_NEVERAUDIT),
               AVD_FLAGS_PERMISSIVE | AVD_FLAGS_NEVERAUDIT);
}

#[test]
fn neveraudit_alone_silences_auditing_but_not_the_verdict() {
    let mut e = env();
    let file = kcls("file");
    e.db.neveraudit_map.set(T_INIT, true);
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let avd = e.av(s, t, file);
    assert_eq!(avd.allowed & kperm(file, "read"), kperm(file, "read"));
    assert_eq!(avd.auditallow, 0);
    assert_eq!(avd.auditdeny, 0);
    assert_eq!(avd.flags & AVD_FLAGS_NEVERAUDIT, AVD_FLAGS_NEVERAUDIT);
}

#[test]
fn permissive_alone_still_computes_the_real_verdict() {
    let mut e = env();
    let file = kcls("file");
    e.db.permissive_map.set(T_LONE, true);
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_LONE, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let avd = e.av(s, t, file);
    assert_eq!(avd.allowed, 0);
    assert_eq!(avd.flags & AVD_FLAGS_PERMISSIVE, AVD_FLAGS_PERMISSIVE);
}

#[test]
fn unresolvable_sid_denies_everything() {
    let mut e = env();
    let file = kcls("file");
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    let avd = e.av(u32::MAX - 1, t, file);
    assert_eq!(avd.allowed, 0);
    assert_eq!(avd.auditdeny, u32::MAX);
}

#[test]
fn unknown_class_follows_the_policy_stance() {
    let mut e = env();
    // `filesystem` is a kernel class the fixture policy never declares.
    let unknown = kcls("filesystem");
    assert!(e.map.unknown_classes().contains(&unknown));
    let s = sid(&mut e.sidtab, ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]));
    let t = sid(&mut e.sidtab, ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]));
    assert_eq!(e.av(s, t, unknown).allowed, 0);

    e.db.allow_unknown = true;
    e.rebuild_map();
    assert_eq!(e.av(s, t, unknown).allowed, u32::MAX);
}
