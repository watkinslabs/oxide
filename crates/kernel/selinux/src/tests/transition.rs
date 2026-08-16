// Label computation for created, relabelled and polyinstantiated objects.

use crate::services::fixture::*;

use crate::context::{Context, ValidContext};
use crate::error::Error;
use crate::mapping::Mapping;
use crate::mls::Range;
use crate::policydb::symbols::{Default1, DefaultRange, OBJECT_R_VAL};
use crate::policydb::Policydb;
use crate::services::transition::{change_sid, compute_sid, is_socket_class, member_sid,
                                  transition_sid, TransitionKind, TransitionRequest};
use crate::sidtab::{Sid, Sidtab};
use crate::uapi::classmap::class_by_name;

fn kcls(name: &str) -> u16 { class_by_name(name).expect("kernel class") }

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
    fn sid(&mut self, c: ValidContext) -> Sid {
        self.sidtab.context_to_sid(Context::Valid(c)).expect("sid")
    }

    fn context(&self, sid: Sid) -> ValidContext {
        self.sidtab.lookup(sid).and_then(Context::valid).cloned().expect("context")
    }

    fn class_mut(&mut self, value: u32) -> &mut crate::policydb::symbols::Class {
        &mut self.db.symbols.classes[(value - 1) as usize]
    }
}

/// Source domain and the executable it runs.
fn exec_pair() -> (ValidContext, ValidContext) {
    (ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]),
     ctx(U_SYSTEM, R_OBJECT, T_SHELL_EXEC, S0, &[]))
}

#[test]
fn type_transition_supplies_the_new_type() {
    let mut e = env();
    let (s, t) = exec_pair();
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("process"), None)
        .expect("transition");
    let c = e.context(out);
    assert_eq!(c.ty, T_SHELL);
}

#[test]
fn role_transition_overrides_the_default_role() {
    let mut e = env();
    let (s, t) = exec_pair();
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("process"), None)
        .expect("transition");
    assert_eq!(e.context(out).role, R_USER);

    // Without the rule the process class keeps the source's role.
    e.db.role_tr.clear();
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("process"), None)
        .expect("transition");
    assert_eq!(e.context(out).role, R_SYSTEM);
}

#[test]
fn range_transition_supplies_the_range() {
    let mut e = env();
    let (s, t) = exec_pair();
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("process"), None)
        .expect("transition");
    assert_eq!(e.context(out).range, one(S1, &[0]));

    // Without the rule the process class inherits the source's whole range.
    e.db.range_tr.clear();
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("process"), None)
        .expect("transition");
    assert_eq!(e.context(out).range, one(S0, &[]));
}

#[test]
fn filename_transition_overrides_the_type_rule() {
    let mut e = env();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_ETC, S0, &[]);
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let file = kcls("file");

    // No name: the ordinary type transition decides.
    let plain = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, file, None)
        .expect("transition");
    assert_eq!(e.context(plain).ty, T_FILE);

    // The matching name replaces that answer outright.
    let named = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, file,
                               Some(FTRANS_NAME)).expect("transition");
    assert_eq!(e.context(named).ty, T_ETC);

    // A name the table does not carry leaves the ordinary answer alone.
    let other = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, file, Some("shadow"))
        .expect("transition");
    assert_eq!(e.context(other).ty, T_FILE);
}

#[test]
fn filename_transition_is_skipped_for_untouched_target_types() {
    let mut e = env();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_ETC, S0, &[]);
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    // Clearing the fast-path bitmap must hide the transition entirely: the
    // bitmap and the table are two views of one fact.
    e.db.filename_trans_ttypes = Default::default();
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("file"),
                             Some(FTRANS_NAME)).expect("transition");
    assert_eq!(e.context(out).ty, T_FILE);
}

#[test]
fn a_file_takes_the_object_role_and_the_source_user() {
    let mut e = env();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_USER, R_OBJECT, T_ETC, S0, &[]);
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("file"), None)
        .expect("transition");
    let c = e.context(out);
    assert_eq!(c.role, OBJECT_R_VAL);
    assert_eq!(c.user, U_SYSTEM);
}

#[test]
fn class_defaults_choose_the_component_source() {
    let mut e = env();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_USER, R_USER, T_ETC, S0, &[]);
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let file = kcls("file");

    e.class_mut(CLS_FILE).default_user = Default1::Target;
    e.class_mut(CLS_FILE).default_role = Default1::Target;
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, file, None)
        .expect("transition");
    let c = e.context(out);
    assert_eq!(c.user, U_USER);
    assert_eq!(c.role, R_USER);

    // A default type displaces the fallback but not a matching rule.
    e.db.te_avtab = crate::avtab::Avtab::with_capacity(4);
    e.class_mut(CLS_FILE).default_type = Default1::Source;
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, file, None)
        .expect("transition");
    assert_eq!(e.context(out).ty, T_INIT);
}

#[test]
fn without_a_rule_a_file_keeps_the_target_type() {
    let mut e = env();
    e.db.te_avtab = crate::avtab::Avtab::with_capacity(4);
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_ETC, S0, &[]);
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("file"), None)
        .expect("transition");
    assert_eq!(e.context(out).ty, T_ETC);
}

#[test]
fn without_a_rule_a_process_keeps_the_source_type() {
    let mut e = env();
    e.db.te_avtab = crate::avtab::Avtab::with_capacity(4);
    e.db.range_tr.clear();
    e.db.role_tr.clear();
    let (s, t) = exec_pair();
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("process"), None)
        .expect("transition");
    // The result IS the source context, so the source's own SID comes back.
    assert_eq!(out, ssid);
}

#[test]
fn a_conditional_type_rule_applies_only_when_enabled() {
    let mut e = env();
    e.db.te_avtab = crate::avtab::Avtab::with_capacity(4);
    let mut cond = crate::avtab::Avtab::with_capacity(2);
    cond.insert(crate::avtab::Rule {
        key: crate::avtab::Key {
            source_type: T_INIT as u16,
            target_type: T_ETC as u16,
            target_class: CLS_FILE as u16,
            specified: crate::avtab::AVTAB_TRANSITION,
        },
        datum: crate::avtab::Datum::Word(T_FILE),
    });
    e.db.te_cond_avtab = cond;
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_ETC, S0, &[]);
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let file = kcls("file");

    let off = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, file, None)
        .expect("transition");
    assert_eq!(e.context(off).ty, T_ETC);

    set_conditional(&mut e.db, true);
    let on = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, file, None)
        .expect("transition");
    assert_eq!(e.context(on).ty, T_FILE);
}

#[test]
fn member_takes_the_target_user_and_the_source_low_level() {
    let mut e = env();
    let s = ctx_range(U_SYSTEM, R_SYSTEM, T_INIT, level(S0, &[]), level(S2, &[0, 1]));
    let t = ctx(U_USER, R_OBJECT, T_ETC, S1, &[0]);
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let out = member_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("file"))
        .expect("member");
    let c = e.context(out);
    assert_eq!(c.user, U_USER);
    assert_eq!(c.range, one(S0, &[]));
}

#[test]
fn change_uses_the_relabel_rule_kind() {
    let mut e = env();
    e.db.te_avtab.insert(crate::avtab::Rule {
        key: crate::avtab::Key {
            source_type: T_INIT as u16,
            target_type: T_ETC as u16,
            target_class: CLS_FILE as u16,
            specified: crate::avtab::AVTAB_CHANGE,
        },
        datum: crate::avtab::Datum::Word(T_LONE),
    });
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_ETC, S0, &[]);
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    let out = change_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("file")).expect("change");
    assert_eq!(e.context(out).ty, T_LONE);
}

#[test]
fn default_range_variants_each_select_their_own_levels() {
    let cases: [(DefaultRange, Range); 7] = [
        (DefaultRange::SourceLow, Range::single(level(S0, &[]))),
        (DefaultRange::SourceHigh, Range::single(level(S2, &[0, 1]))),
        (DefaultRange::SourceLowHigh, Range { low: level(S0, &[]), high: level(S2, &[0, 1]) }),
        (DefaultRange::TargetLow, Range::single(level(S1, &[1]))),
        (DefaultRange::TargetHigh, Range::single(level(S1, &[1, 2]))),
        (DefaultRange::TargetLowHigh, Range { low: level(S1, &[1]), high: level(S1, &[1, 2]) }),
        // Greatest lower bound: the higher low sensitivity with the union of
        // low categories, the lower high sensitivity with their intersection.
        (DefaultRange::Glblub, Range { low: level(S1, &[1]), high: level(S1, &[1]) }),
    ];
    for (variant, want) in cases {
        let mut e = env();
        e.db.te_avtab = crate::avtab::Avtab::with_capacity(4);
        e.db.range_tr.clear();
        e.class_mut(CLS_FILE).default_range = variant;
        let s = ctx_range(U_SYSTEM, R_SYSTEM, T_INIT, level(S0, &[]), level(S2, &[0, 1]));
        let t = ctx_range(U_SYSTEM, R_OBJECT, T_ETC, level(S1, &[1]), level(S1, &[1, 2]));
        let (ssid, tsid) = (e.sid(s), e.sid(t));
        let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid, kcls("file"), None)
            .expect("transition");
        assert_eq!(e.context(out).range, want, "{variant:?}");
    }
}

#[test]
fn an_unknown_sid_is_refused() {
    let mut e = env();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let ssid = e.sid(s);
    let err = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, u32::MAX - 1, kcls("file"), None);
    assert_eq!(err, Err(Error::UnknownSid));
}

#[test]
fn an_invalid_result_is_refused_rather_than_labelled() {
    let mut e = env();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_SHELL_EXEC, S0, &[]);
    let (ssid, tsid) = (e.sid(s), e.sid(t));
    // The transition names an ATTRIBUTE as the new type, which no context may
    // carry; the request must fail rather than mint an uninterpretable label.
    e.db.te_avtab = crate::avtab::Avtab::with_capacity(4);
    e.db.te_avtab.insert(crate::avtab::Rule {
        key: crate::avtab::Key {
            source_type: T_INIT as u16,
            target_type: T_SHELL_EXEC as u16,
            target_class: CLS_PROCESS as u16,
            specified: crate::avtab::AVTAB_TRANSITION,
        },
        datum: crate::avtab::Datum::Word(T_ATTR_DOMAIN),
    });
    let out = compute_sid(&e.db, &e.map, &mut e.sidtab, &TransitionRequest {
        ssid, tsid, kernel_class: kcls("process"), objname: None,
        kind: TransitionKind::Transition,
    });
    assert_eq!(out, Err(Error::InvalidContext));
}

#[test]
fn socket_classes_are_recognised_by_name() {
    let mut e = env();
    assert!(!is_socket_class(&e.db, CLS_FILE));
    e.class_mut(CLS_FILE).name = alloc::string::String::from("unix_stream_socket");
    assert!(is_socket_class(&e.db, CLS_FILE));
}

#[test]
fn a_socket_class_inherits_the_source_role_type_and_range() {
    let mut e = env();
    e.db.te_avtab = crate::avtab::Avtab::with_capacity(4);
    e.class_mut(CLS_FILE).name = alloc::string::String::from("unix_stream_socket");
    e.rebuild();
    let s = ctx_range(U_SYSTEM, R_SYSTEM, T_INIT, level(S0, &[]), level(S2, &[0, 1]));
    let t = ctx(U_SYSTEM, R_OBJECT, T_ETC, S0, &[]);
    let (ssid, tsid) = (e.sid(s.clone()), e.sid(t));
    let out = transition_sid(&e.db, &e.map, &mut e.sidtab, ssid, tsid,
                             kcls("unix_stream_socket"), None).expect("transition");
    assert_eq!(out, ssid);
    assert_eq!(e.context(out), s);
}

impl Env {
    fn rebuild(&mut self) { self.map = Mapping::build(&self.db).expect("mapping"); }
}
