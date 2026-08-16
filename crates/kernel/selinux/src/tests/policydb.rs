// Policy-image reader tests.
//
// Two provenances, deliberately: a synthetic image whose every field this test
// chose, which pins the format record by record, and the distribution policy a
// real system loads, which is the only thing that can catch a field this test
// and the reader agree about but the format does not.

extern crate std;

use alloc::vec::Vec;
use std::{fs, println, vec};

use crate::avtab::{AVTAB_ALLOWED, AVTAB_ENABLED, AVTAB_TRANSITION};
use crate::error::Error;
use crate::policydb::sections::FsUse;
use crate::policydb::symbols::{Default1, DefaultRange, OBJECT_R, OBJECT_R_VAL, SYM_BOOLS,
                               SYM_CATS, SYM_CLASSES, SYM_LEVELS, SYM_ROLES, SYM_TYPES,
                               SYM_USERS};
use crate::policydb::{load, Policydb};

#[path = "fixture.rs"]
mod fixture;

use fixture::{build, synth, Opts, CLASS_FILE_VAL, CLASS_PROCESS_VAL, ROLE_USER_VAL, SENS_S0,
              SYNTH_VERSION, TYPE_DOMAIN_VAL, TYPE_FILE_VAL, TYPE_USER_VAL, USER_VAL};

/// Distribution policy a real system loads; absent on a bare build machine.
const REAL_POLICY: &str =
    "/home/nd/oxide/images/build/lite-x86_64-root/etc/selinux/targeted/policy/policy.34";

/// Version of the distribution policy.
const REAL_VERSION: u32 = 34;

/// End of the header's config word: magic, signature and version precede it.
const CONFIG_WORD_END: usize = 24;

/// Record count of the distribution policy's commons table.
const COUNT_COMMONS_NEL: usize = 288;
/// First count word of the classes table.
const COUNT_CLASSES_NPRIM: usize = 2406;
/// Second count word of the classes table.
const COUNT_CLASSES_NEL: usize = 2410;

/// Error a rejected image produced; `Policydb` carries no `Debug`, so the
/// success case is reported by the panic rather than by `unwrap_err`.
fn err_of(image: &[u8]) -> Error {
    match load(image) { Ok(_) => panic!("image loaded but must be refused"), Err(e) => e }
}

fn real_policy() -> Option<Vec<u8>> {
    match fs::read(REAL_POLICY) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            println!("skipping: {REAL_POLICY} is not present on this machine");
            None
        }
    }
}

#[test]
fn synth_header_and_config() {
    let db = load(&synth()).expect("synthetic image loads");
    assert_eq!(db.version, SYNTH_VERSION);
    assert!(db.mls);
    assert!(!db.reject_unknown);
    assert!(!db.allow_unknown);
    assert!(db.policycap(0) && db.policycap(2) && !db.policycap(1));
    assert!(db.type_is_permissive(TYPE_USER_VAL));
    assert!(!db.type_is_permissive(TYPE_FILE_VAL));
    assert!(db.neveraudit_map.is_empty());
}

#[test]
fn synth_symbol_tables_are_value_indexed() {
    let db = load(&synth()).expect("loads");
    let s = &db.symbols;
    assert_eq!(s.nprim[SYM_CLASSES], 2);
    assert_eq!(s.nprim[SYM_ROLES], 2);
    assert_eq!(s.nprim[SYM_TYPES], 3);
    assert_eq!(s.nprim[SYM_USERS], 1);
    assert_eq!(s.nprim[SYM_BOOLS], 2);
    assert_eq!(s.nprim[SYM_LEVELS], 1);
    assert_eq!(s.nprim[SYM_CATS], 1);

    // The image lists `file` before `process`; the vector must still be
    // ordered by value, because every other section refers to values.
    assert_eq!(s.class(CLASS_PROCESS_VAL).unwrap().name, "process");
    assert_eq!(s.class(CLASS_FILE_VAL).unwrap().name, "file");
    assert_eq!(s.class_by_name("file"), Some(CLASS_FILE_VAL));

    let file = s.class(CLASS_FILE_VAL).unwrap();
    assert_eq!(file.common_name.as_deref(), Some("file"));
    assert_eq!(file.common, Some(1));
    assert_eq!(file.perms.len(), 1);
    // Declared permission count includes the two the common supplies.
    assert_eq!(file.nprim, 3);
    assert_eq!(file.perms[0].name, "open");
    assert_eq!(file.default_user, Default1::Unset);
    assert_eq!(file.default_range, DefaultRange::Unset);
    assert_eq!(s.commons.len(), 1);
    assert_eq!(s.commons[0].perms.len(), 2);

    assert_eq!(s.role(OBJECT_R_VAL).unwrap().name, OBJECT_R);
    assert_eq!(s.role(ROLE_USER_VAL).unwrap().name, "user_r");
    assert!(s.role(ROLE_USER_VAL).unwrap().types.get(TYPE_USER_VAL - 1));

    assert!(s.ty(TYPE_DOMAIN_VAL).unwrap().attribute);
    assert!(!s.ty(TYPE_USER_VAL).unwrap().attribute);
    assert!(s.ty(TYPE_USER_VAL).unwrap().primary);
    assert_eq!(s.type_by_name("file_t"), Some(TYPE_FILE_VAL));

    let user = s.user(USER_VAL).unwrap();
    assert_eq!(user.name, "user_u");
    assert!(user.roles.get(ROLE_USER_VAL - 1));
    assert_eq!(user.range.low.sens, SENS_S0);
    assert_eq!(user.dfltlevel.sens, SENS_S0);

    // Boolean records order value and state before the name length.
    assert_eq!(s.bools[0].name, "b_on");
    assert!(s.bools[0].state);
    assert_eq!(s.bools[1].name, "b_off");
    assert!(!s.bools[1].state);

    assert_eq!(s.sens.len(), 1);
    assert_eq!(s.sens_name(SENS_S0), Some("s0"));
    assert_eq!(s.cat_by_name("c0"), Some(1));
}

#[test]
fn synth_rules_and_conditionals() {
    let db = load(&synth()).expect("loads");
    assert_eq!(db.process_class, CLASS_PROCESS_VAL);
    // transition is permission 1 and dyntransition permission 2 of `process`.
    assert_eq!(db.process_trans_perms, 0b11);
    assert_eq!(db.te_avtab.len(), 3);
    let kinds: Vec<u16> = db.te_avtab.rules().iter().map(|r| r.key.kind()).collect();
    assert!(kinds.contains(&AVTAB_ALLOWED) && kinds.contains(&AVTAB_TRANSITION));

    assert_eq!(db.cond_list.len(), 1);
    assert_eq!(db.te_cond_avtab.len(), 1);
    // `b_on` is committed true, so the block's true arm must be enabled.
    assert!(db.cond_list[0].cur_state);
    assert_eq!(db.cond_list[0].true_list, vec![0]);
    assert!(db.cond_list[0].false_list.is_empty());
    assert!(db.te_cond_avtab.rules()[0].key.specified & AVTAB_ENABLED != 0);
}

#[test]
fn synth_conditional_follows_boolean_state() {
    let mut db = load(&synth()).expect("loads");
    db.symbols.bools[0].state = false;
    crate::policydb::read::evaluate_cond_nodes(&mut db);
    assert!(!db.cond_list[0].cur_state);
    assert!(db.te_cond_avtab.rules()[0].key.specified & AVTAB_ENABLED == 0);
}

#[test]
fn synth_transitions_and_contexts() {
    let db = load(&synth()).expect("loads");
    assert_eq!(db.role_tr.len(), 1);
    assert_eq!(db.role_tr[0].tclass, CLASS_PROCESS_VAL);
    assert_eq!(db.role_allow, vec![(ROLE_USER_VAL, ROLE_USER_VAL)]);

    assert_eq!(db.filename_trans.len(), 1);
    let ft = &db.filename_trans[0];
    assert_eq!(ft.name, "log");
    assert_eq!(ft.ttype, TYPE_FILE_VAL);
    assert_eq!(ft.otype_for(TYPE_USER_VAL), Some(TYPE_FILE_VAL));
    assert_eq!(ft.otype_for(TYPE_FILE_VAL), None);
    assert!(db.filename_trans_ttypes.get(TYPE_FILE_VAL));

    assert_eq!(db.range_tr.len(), 1);
    assert_eq!(db.range_tr[0].target_class, CLASS_PROCESS_VAL);

    let o = &db.ocontexts;
    assert_eq!(o.isid(1).unwrap().ty, TYPE_USER_VAL);
    assert_eq!(o.port(6, 80).unwrap().ty, TYPE_FILE_VAL);
    assert!(o.port(17, 80).is_none());
    assert_eq!(o.netifs[0].name, "eth0");
    assert_eq!(o.nodes[0].addr, 0x0100_007f);
    assert_eq!(o.nodes6.len(), 1);
    assert_eq!(o.fs_use_of("ext4").unwrap().behavior, FsUse::Xattr);
    assert_eq!(o.ibpkeys[0].high, 4);
    assert_eq!(o.ibendports[0].port, 1);
}

#[test]
fn synth_genfs_is_longest_prefix_first() {
    let db = load(&synth()).expect("loads");
    let proc = db.genfs.iter().find(|g| g.fstype == "proc").expect("proc genfs");
    assert_eq!(proc.paths.len(), 2);
    // Written shortest-first; a load that keeps that order answers `/` here.
    assert_eq!(proc.paths[0].path, "/sys/kernel");
    let ctx = proc.lookup("/sys/kernel/x", CLASS_FILE_VAL).expect("match");
    assert_eq!(ctx.ty, TYPE_USER_VAL);
    assert_eq!(proc.lookup("/other", CLASS_FILE_VAL).unwrap().ty, TYPE_FILE_VAL);
}

#[test]
fn synth_type_attr_map_carries_the_self_bit() {
    let db = load(&synth()).expect("loads");
    assert_eq!(db.type_attr_map.len(), 3);
    for (i, set) in db.type_attr_map.iter().enumerate() {
        assert!(set.get(i as u32), "type {} lost its own bit", i + 1);
    }
    // user_t additionally carries the `domain` attribute the image declared.
    assert!(db.type_attr_map[(TYPE_USER_VAL - 1) as usize].get(TYPE_DOMAIN_VAL - 1));
    assert!(!db.type_attr_map[(TYPE_FILE_VAL - 1) as usize].get(TYPE_DOMAIN_VAL - 1));
    assert!(db.type_attrs(TYPE_USER_VAL).unwrap().get(TYPE_USER_VAL - 1));
}

#[test]
fn header_rejections() {
    let bad = |o: Opts| err_of(&build(&o));
    assert_eq!(bad(Opts { magic: 0, ..Opts::default() }), Error::BadMagic);
    assert_eq!(bad(Opts { signature: b"SE Linuy", ..Opts::default() }), Error::BadSignature);
    assert_eq!(bad(Opts { signature: b"SELinux", ..Opts::default() }), Error::BadSignature);
    assert_eq!(bad(Opts { version: 14, ..Opts::default() }), Error::UnsupportedVersion(14));
    assert_eq!(bad(Opts { version: 36, ..Opts::default() }), Error::UnsupportedVersion(36));
    // MLS predates its own config bit at version 18.
    assert_eq!(bad(Opts { version: 18, config: 1, ..Opts::default() }), Error::MlsMismatch);
    assert_eq!(bad(Opts { sym_num: 7, ..Opts::default() }), Error::Malformed);
    assert_eq!(bad(Opts { ocon_num: 7, ..Opts::default() }), Error::Malformed);
}

#[test]
fn body_rejections() {
    let bad = |o: Opts| err_of(&build(&o));
    // A class naming a common no image declared.
    assert_eq!(bad(Opts { file_common: "nofile", ..Opts::default() }), Error::UnknownSymbol);
    // A boolean value outside its table leaves a hole no value fills.
    assert_eq!(bad(Opts { bool_value: 9, ..Opts::default() }), Error::Malformed);
    assert_eq!(bad(Opts { bool_value: 0, ..Opts::default() }), Error::Malformed);
    // One type-attribute map short: the last type would be read from the
    // bytes after the image.
    assert_eq!(bad(Opts { type_attr_count: 2, ..Opts::default() }), Error::Truncated);
    assert_eq!(bad(Opts { trailing: 4, ..Opts::default() }), Error::Malformed);
}

#[test]
fn synth_truncation_is_refused() {
    let image = synth();
    for cut in 0..image.len() {
        assert!(load(&image[..cut]).is_err(), "prefix of {cut} bytes loaded");
    }
}

#[test]
fn real_policy_loads() {
    let Some(bytes) = real_policy() else { return };
    let db = load(&bytes).expect("distribution policy loads");
    assert_eq!(db.version, REAL_VERSION);
    assert!(db.mls);
    assert_eq!(db.process_class, db.symbols.class_by_name("process").unwrap());
    assert!(db.process_trans_perms != 0);

    let file = db.symbols.class(db.symbols.class_by_name("file").unwrap()).unwrap();
    assert!(file.perms.iter().any(|p| p.name == "open")
            || db.symbols.commons.iter().any(|c| c.perms.iter().any(|p| p.name == "open")));
    assert!(!db.te_avtab.is_empty());
    assert!(!db.cond_list.is_empty());
    assert!(!db.te_cond_avtab.is_empty());
    assert!(db.genfs.iter().any(|g| g.fstype == "proc"));
    assert_eq!(db.ocontexts.fs_use_of("ext4").unwrap().behavior, FsUse::Xattr);
    assert!(db.symbols.role_by_name(OBJECT_R) == Some(OBJECT_R_VAL));
    assert!(!db.filename_trans.is_empty());
    assert!(!db.ocontexts.isids.is_empty());
    assert!(!db.range_tr.is_empty());
    check_real_invariants(&db);
}

fn check_real_invariants(db: &Policydb) {
    // Every type value has a map entry, and every entry names its own type:
    // the decision path expands a concrete type through this set, so a missing
    // self bit hides every rule written against the plain type.
    assert_eq!(db.type_attr_map.len(), db.symbols.nprim[SYM_TYPES] as usize);
    for (i, set) in db.type_attr_map.iter().enumerate() {
        assert!(set.get(i as u32), "type value {} lost its own bit", i + 1);
    }
    // Genfs paths are longest-first, so the first match is the most specific.
    for g in &db.genfs {
        for pair in g.paths.windows(2) {
            assert!(pair[0].path.len() >= pair[1].path.len(),
                    "{}: {} before {}", g.fstype, pair[0].path, pair[1].path);
        }
    }
    // Every context the image carries resolves against the symbol tables.
    for isid in &db.ocontexts.isids {
        assert!(db.symbols.ty(isid.context.ty).is_some());
        assert!(db.symbols.user(isid.context.user).is_some());
        assert!(db.symbols.role(isid.context.role).is_some());
    }
}

#[test]
fn real_policy_is_consumed_exactly() {
    let Some(bytes) = real_policy() else { return };
    let mut r = crate::reader::Reader::new(&bytes);
    assert!(super::load_from(&mut r).is_ok());
    // Every section is positional, so stopping short means a later section was
    // read from the wrong offset and happened to parse.
    assert_eq!(r.position(), bytes.len());
    assert!(r.at_end());
}

#[test]
fn real_policy_truncation_is_refused() {
    let Some(bytes) = real_policy() else { return };
    let step = bytes.len() / 250;
    let mut cut = 0;
    let mut checked = 0;
    while cut < bytes.len() {
        assert!(load(&bytes[..cut]).is_err(), "prefix of {cut} bytes loaded");
        cut += step;
        checked += 1;
    }
    assert!(checked >= 200, "only {checked} truncation points");
}

/// Sweep a policy image, corrupting one place at a time.
///
/// Two kinds of corruption, with different expectations: a structural word
/// replaced by an absurd count must always be refused, while a single flipped
/// byte may legitimately still parse (it may land in a name or an access
/// vector). Both must stay inside the error path.
fn corruption_sweep(bytes: &[u8]) -> Outcome {
    let mut outcome = Outcome::default();
    let hook = std::panic::take_hook();
    std::panic::set_hook(std::boxed::Box::new(|_| {}));
    for off in (CONFIG_WORD_END..4096).step_by(4) {
        let mut copy = bytes.to_vec();
        copy[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        outcome.record(&copy, off);
    }
    let step = bytes.len() / 200;
    let mut off = 0;
    while off < bytes.len() {
        let mut copy = bytes.to_vec();
        copy[off] ^= 0xff;
        outcome.record(&copy, off);
        off += step;
    }
    std::panic::set_hook(hook);
    outcome
}

#[test]
fn real_policy_corruption_is_never_accepted() {
    let Some(bytes) = real_policy() else { return };
    let outcome = corruption_sweep(&bytes);
    println!("corruption sweep: {} refused, {} parsed on, {} panicked",
             outcome.refused, outcome.parsed, outcome.panicked.len());
    assert!(outcome.refused > 500, "only {} refusals", outcome.refused);

    // Most words of an image are data — a bitmap half, an access vector — for
    // which any value is legal, so the sweep above cannot demand a refusal.
    // These four are counts, and an absurd count must never be honoured.
    // The commons table's first count is its highest permission value, which
    // nothing indexes by, so only the other three can be checked here.
    for off in [COUNT_COMMONS_NEL, COUNT_CLASSES_NPRIM, COUNT_CLASSES_NEL] {
        let mut copy = bytes.clone();
        copy[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        // Which refusal it is depends on where the count runs out; that it
        // refuses is the contract.
        let _ = err_of(&copy);
    }
}

#[test]
// A policy image is untrusted input, so a panic is a denial of service: every
// corruption must be refused, never trip an arithmetic overflow on the way.
fn real_policy_corruption_never_panics() {
    let Some(bytes) = real_policy() else { return };
    let outcome = corruption_sweep(&bytes);
    assert!(outcome.panicked.is_empty(),
            "corrupt image panicked instead of being refused, at offsets {:?}",
            &outcome.panicked[..outcome.panicked.len().min(8)]);
}

/// Tally of one corruption sweep.
#[derive(Default)]
struct Outcome {
    refused: usize,
    parsed: usize,
    /// Offsets that reached a panic instead of an error.
    panicked: Vec<usize>,
}

impl Outcome {
    fn record(&mut self, image: &[u8], off: usize) {
        match std::panic::catch_unwind(|| load(image).is_ok()) {
            Ok(true) => self.parsed += 1,
            Ok(false) => self.refused += 1,
            Err(_) => self.panicked.push(off),
        }
    }
}
