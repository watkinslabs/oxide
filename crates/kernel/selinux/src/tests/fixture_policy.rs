// Synthetic policy fixture for the decision-engine tests.
//
// Built as a value rather than parsed from an image, so a defect in the image
// reader cannot mask a defect in the engine and vice versa. The permission
// numbering here deliberately DISAGREES with the kernel's for every class, so
// a test that passes only because the two happened to coincide cannot pass.

#![allow(dead_code)]

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::avtab::{Avtab, Datum, Key, Rule, AVTAB_ALLOWED, AVTAB_AUDITALLOW, AVTAB_AUDITDENY,
                   AVTAB_ENABLED, AVTAB_TRANSITION};
use crate::context::ValidContext;
use crate::ebitmap::Ebitmap;
use crate::mls::{Level, Range};
use crate::policydb::Policydb;
use crate::policydb::constraints::{Constraint, Expr, CEXPR_ATTR, CEXPR_EQ, CEXPR_L1L2};
use crate::policydb::sections::{FilenameTrans, FilenameTransDatum, Genfs, GenfsPath, IsidCon,
                                Ocontexts, RangeTrans, RoleTrans};
use crate::policydb::symbols::{Cat, Class, Common, Perm, Role, Sens, Symbols, Type, User,
                               SYM_CATS, SYM_CLASSES, SYM_NUM, SYM_ROLES, SYM_TYPES, SYM_USERS};

/// Policy class values.
pub const CLS_PROCESS: u32 = 1;
/// File class value.
pub const CLS_FILE: u32 = 2;
/// Directory class value.
pub const CLS_DIR: u32 = 3;

/// Type values.
pub const T_ATTR_DOMAIN: u32 = 1;
/// Attribute grouping file types.
pub const T_ATTR_FILE: u32 = 2;
/// Domain of the first user process.
pub const T_INIT: u32 = 3;
/// Domain of an ordinary user process.
pub const T_USER: u32 = 4;
/// Ordinary file type.
pub const T_FILE: u32 = 5;
/// Configuration file type.
pub const T_ETC: u32 = 6;
/// Domain bounded by `T_INIT`.
pub const T_CHILD: u32 = 7;
/// Concrete type belonging to no attribute.
pub const T_LONE: u32 = 8;
/// First half of a bounding cycle.
pub const T_CYCLE_A: u32 = 9;
/// Second half of a bounding cycle.
pub const T_CYCLE_B: u32 = 10;
/// Domain a shell runs in.
pub const T_SHELL: u32 = 11;
/// Entry-point file type of the shell domain.
pub const T_SHELL_EXEC: u32 = 12;
/// Number of declared types.
pub const T_COUNT: u32 = 12;

/// Role values.
pub const R_OBJECT: u32 = 1;
/// System role.
pub const R_SYSTEM: u32 = 2;
/// Ordinary user role.
pub const R_USER: u32 = 3;
/// Administrative role, dominating the system role.
pub const R_ADMIN: u32 = 4;

/// User values.
pub const U_SYSTEM: u32 = 1;
/// Unprivileged user.
pub const U_USER: u32 = 2;

/// Sensitivity values.
pub const S0: u32 = 1;
/// Middle sensitivity.
pub const S1: u32 = 2;
/// Highest sensitivity.
pub const S2: u32 = 3;
/// Number of declared categories.
pub const CAT_COUNT: u32 = 6;

/// Policy access-vector bits of the `process` class.
pub const P_TRANSITION: u32 = 1 << 0;
/// Fork permission bit.
pub const P_FORK: u32 = 1 << 1;
/// Sigchld permission bit.
pub const P_SIGCHLD: u32 = 1 << 2;
/// Dyntransition permission bit.
pub const P_DYNTRANSITION: u32 = 1 << 3;

/// Policy access-vector bits of the `file` class.
pub const F_READ: u32 = 1 << 0;
/// Write permission bit.
pub const F_WRITE: u32 = 1 << 1;
/// Getattr permission bit.
pub const F_GETATTR: u32 = 1 << 2;
/// Open permission bit, granted only by the conditional rule.
pub const F_OPEN: u32 = 1 << 3;
/// Ioctl permission bit.
pub const F_IOCTL: u32 = 1 << 4;
/// Execute permission bit.
pub const F_EXECUTE: u32 = 1 << 5;
/// Entrypoint permission bit.
pub const F_ENTRYPOINT: u32 = 1 << 6;
/// Relabelto permission bit.
pub const F_RELABELTO: u32 = 1 << 7;

/// Permissions the `process` class treats as a domain transition.
pub const PROCESS_TRANS_PERMS: u32 = P_TRANSITION | P_DYNTRANSITION;

/// Name the filename transition matches.
pub const FTRANS_NAME: &str = "passwd";

/// A level with the named categories set.
pub fn level(sens: u32, cats: &[u32]) -> Level {
    let mut cat = Ebitmap::new();
    for c in cats { cat.set(*c, true); }
    Level { sens, cat }
}

/// A single-level range.
pub fn one(sens: u32, cats: &[u32]) -> Range { Range::single(level(sens, cats)) }

/// A context at one level.
pub fn ctx(user: u32, role: u32, ty: u32, sens: u32, cats: &[u32]) -> ValidContext {
    ValidContext { user, role, ty, range: one(sens, cats) }
}

/// A context spanning two levels.
pub fn ctx_range(user: u32, role: u32, ty: u32, low: Level, high: Level) -> ValidContext {
    ValidContext { user, role, ty, range: Range { low, high } }
}

fn perms(names: &[&str]) -> Vec<Perm> {
    names.iter().enumerate()
        .map(|(i, n)| Perm { name: (*n).to_string(), value: i as u32 + 1 })
        .collect()
}

fn bits(values: &[u32]) -> Ebitmap {
    let mut b = Ebitmap::new();
    for v in values { b.set(*v, true); }
    b
}

fn ty(name: &str, value: u32, attribute: bool, bounds: u32) -> Type {
    Type { name: name.to_string(), value, primary: true, attribute, bounds }
}

/// The `file` class inherits these; the class's own values continue after them.
fn common_file() -> Common {
    Common {
        name: "file".to_string(),
        value: 1,
        nprim: 5,
        perms: perms(&["read", "write", "getattr", "open", "ioctl"]),
    }
}

fn class_process() -> Class {
    Class {
        name: "process".to_string(),
        value: CLS_PROCESS,
        nprim: 4,
        perms: perms(&["transition", "fork", "sigchld", "dyntransition"]),
        ..Default::default()
    }
}

/// The `file` class carries the MLS constraint: writing needs equal levels.
fn class_file() -> Class {
    let expr = vec![Expr {
        expr_type: CEXPR_ATTR,
        attr: CEXPR_L1L2,
        op: CEXPR_EQ,
        names: Ebitmap::new(),
        type_names: None,
    }];
    Class {
        name: "file".to_string(),
        value: CLS_FILE,
        common_name: Some("file".to_string()),
        common: Some(1),
        nprim: 3,
        perms: vec![
            Perm { name: "execute".to_string(), value: 6 },
            Perm { name: "entrypoint".to_string(), value: 7 },
            Perm { name: "relabelto".to_string(), value: 8 },
        ],
        constraints: vec![Constraint { permissions: F_WRITE, expr }],
        ..Default::default()
    }
}

fn class_dir() -> Class {
    Class {
        name: "dir".to_string(),
        value: CLS_DIR,
        nprim: 6,
        perms: perms(&["search", "read", "write", "add_name", "remove_name", "getattr"]),
        ..Default::default()
    }
}

fn symbols() -> Symbols {
    let all_types = bits(&[T_INIT - 1, T_USER - 1, T_FILE - 1, T_ETC - 1, T_CHILD - 1,
                           T_LONE - 1, T_CYCLE_A - 1, T_CYCLE_B - 1, T_SHELL - 1,
                           T_SHELL_EXEC - 1]);
    let mut nprim = [0u32; SYM_NUM];
    nprim[SYM_CLASSES] = 3;
    nprim[SYM_ROLES] = 4;
    nprim[SYM_TYPES] = T_COUNT;
    nprim[SYM_USERS] = 2;
    nprim[SYM_CATS] = CAT_COUNT;

    Symbols {
        commons: vec![common_file()],
        classes: vec![class_process(), class_file(), class_dir()],
        roles: vec![
            Role { name: "object_r".to_string(), value: R_OBJECT,
                   dominates: bits(&[R_OBJECT - 1]), types: all_types.clone(), bounds: 0 },
            Role { name: "system_r".to_string(), value: R_SYSTEM,
                   dominates: bits(&[R_SYSTEM - 1]), types: all_types.clone(), bounds: 0 },
            Role { name: "user_r".to_string(), value: R_USER,
                   dominates: bits(&[R_USER - 1]), types: all_types.clone(), bounds: 0 },
            // The administrative role dominates the system role; the system
            // role does not dominate it, which is what the DOMBY tests turn on.
            Role { name: "admin_r".to_string(), value: R_ADMIN,
                   dominates: bits(&[R_ADMIN - 1, R_SYSTEM - 1]), types: all_types, bounds: 0 },
        ],
        types: vec![
            ty("attr_domain", T_ATTR_DOMAIN, true, 0),
            ty("attr_file", T_ATTR_FILE, true, 0),
            ty("init_t", T_INIT, false, 0),
            ty("user_t", T_USER, false, 0),
            ty("file_t", T_FILE, false, 0),
            ty("etc_t", T_ETC, false, 0),
            ty("child_t", T_CHILD, false, T_INIT),
            ty("lone_t", T_LONE, false, 0),
            ty("cycle_a", T_CYCLE_A, false, T_CYCLE_B),
            ty("cycle_b", T_CYCLE_B, false, T_CYCLE_A),
            ty("shell_t", T_SHELL, false, 0),
            ty("shell_exec_t", T_SHELL_EXEC, false, 0),
        ],
        users: vec![
            User { name: "system_u".to_string(), value: U_SYSTEM, bounds: 0,
                   roles: bits(&[R_OBJECT - 1, R_SYSTEM - 1, R_USER - 1, R_ADMIN - 1]),
                   range: Range { low: level(S0, &[]), high: level(S2, &[0, 1, 2, 3, 4, 5]) },
                   dfltlevel: level(S0, &[]) },
            User { name: "user_u".to_string(), value: U_USER, bounds: 0,
                   roles: bits(&[R_OBJECT - 1, R_USER - 1]),
                   range: Range { low: level(S0, &[]), high: level(S1, &[0, 1]) },
                   dfltlevel: level(S0, &[]) },
        ],
        bools: Vec::new(),
        sens: vec![
            Sens { name: "s0".to_string(), isalias: false, level: level(S0, &[]) },
            Sens { name: "s1".to_string(), isalias: false, level: level(S1, &[]) },
            Sens { name: "s2".to_string(), isalias: false, level: level(S2, &[]) },
        ],
        cats: (0..CAT_COUNT).map(|i| Cat {
            name: cat_name(i), value: i + 1, isalias: false,
        }).collect(),
        nprim,
    }
}

fn cat_name(bit: u32) -> String {
    let mut s = String::from("c");
    s.push((b'0' + bit as u8) as char);
    s
}

/// Attribute set of each type, indexed by type value minus one.
fn type_attr_map() -> Vec<Ebitmap> {
    let d = T_ATTR_DOMAIN - 1;
    let f = T_ATTR_FILE - 1;
    vec![
        bits(&[T_ATTR_DOMAIN - 1]),
        bits(&[T_ATTR_FILE - 1]),
        bits(&[T_INIT - 1, d]),
        bits(&[T_USER - 1, d]),
        bits(&[T_FILE - 1, f]),
        bits(&[T_ETC - 1, f]),
        bits(&[T_CHILD - 1, d]),
        bits(&[T_LONE - 1]),
        bits(&[T_CYCLE_A - 1, d]),
        bits(&[T_CYCLE_B - 1, d]),
        bits(&[T_SHELL - 1, d]),
        bits(&[T_SHELL_EXEC - 1, f]),
    ]
}

fn rule(source: u32, target: u32, class: u32, specified: u16, word: u32) -> Rule {
    Rule {
        key: Key {
            source_type: source as u16,
            target_type: target as u16,
            target_class: class as u16,
            specified,
        },
        datum: Datum::Word(word),
    }
}

fn te_avtab() -> Avtab {
    let mut t = Avtab::with_capacity(16);
    // Attribute-based grant: every domain may read and write every file type.
    t.insert(rule(T_ATTR_DOMAIN, T_ATTR_FILE, CLS_FILE, AVTAB_ALLOWED, F_READ | F_WRITE));
    // Type-based grant on top of it.
    t.insert(rule(T_INIT, T_FILE, CLS_FILE, AVTAB_ALLOWED, F_GETATTR));
    t.insert(rule(T_INIT, T_FILE, CLS_FILE, AVTAB_AUDITALLOW, F_READ));
    // Suppression: denials of write against this pair are not recorded.
    t.insert(rule(T_INIT, T_FILE, CLS_FILE, AVTAB_AUDITDENY, !F_WRITE));
    // The bounded domain asks for more than its bound is granted.
    t.insert(rule(T_CHILD, T_FILE, CLS_FILE, AVTAB_ALLOWED, F_EXECUTE | F_READ));
    // Domain-to-domain process access, including the transition permissions.
    t.insert(rule(T_ATTR_DOMAIN, T_ATTR_DOMAIN, CLS_PROCESS, AVTAB_ALLOWED,
                  P_TRANSITION | P_FORK | P_DYNTRANSITION | P_SIGCHLD));
    // Type transitions.
    t.insert(rule(T_INIT, T_SHELL_EXEC, CLS_PROCESS, AVTAB_TRANSITION, T_SHELL));
    t.insert(rule(T_INIT, T_ETC, CLS_FILE, AVTAB_TRANSITION, T_FILE));
    t
}

/// Conditional rules, shipped DISABLED so a test can prove both states.
fn te_cond_avtab() -> Avtab {
    let mut t = Avtab::with_capacity(4);
    t.insert(rule(T_INIT, T_FILE, CLS_FILE, AVTAB_ALLOWED, F_OPEN));
    t
}

/// Turn every conditional rule on or off.
pub fn set_conditional(db: &mut Policydb, enabled: bool) {
    for i in 0..db.te_cond_avtab.len() {
        let Some(r) = db.te_cond_avtab.rule_mut(i) else { continue };
        if enabled { r.key.specified |= AVTAB_ENABLED; } else { r.key.specified &= !AVTAB_ENABLED; }
    }
}

fn ocontexts() -> Ocontexts {
    Ocontexts {
        isids: vec![
            IsidCon { sid: 1, context: ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]) },
            IsidCon { sid: 3, context: ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]) },
            IsidCon { sid: 5, context: ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]) },
        ],
        ..Default::default()
    }
}

fn genfs() -> Vec<Genfs> {
    vec![Genfs {
        fstype: "proc".to_string(),
        paths: vec![
            GenfsPath { path: "/net".to_string(), sclass: CLS_FILE,
                        context: ctx(U_SYSTEM, R_OBJECT, T_ETC, S0, &[]) },
            GenfsPath { path: "/".to_string(), sclass: 0,
                        context: ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]) },
        ],
    }]
}

/// The fixture policy.
pub fn policy() -> Policydb {
    Policydb {
        version: crate::uapi::version::POLICYDB_VERSION_MAX,
        mls: true,
        reject_unknown: false,
        allow_unknown: false,
        symbols: symbols(),
        te_avtab: te_avtab(),
        te_cond_avtab: te_cond_avtab(),
        cond_list: Vec::new(),
        role_tr: vec![RoleTrans { role: R_SYSTEM, ty: T_SHELL_EXEC, tclass: CLS_PROCESS,
                                  new_role: R_USER }],
        role_allow: vec![(R_SYSTEM, R_USER)],
        filename_trans: vec![FilenameTrans {
            ttype: T_ETC,
            tclass: CLS_FILE,
            name: FTRANS_NAME.to_string(),
            data: vec![FilenameTransDatum { stypes: bits(&[T_INIT - 1]), otype: T_ETC }],
        }],
        filename_trans_ttypes: bits(&[T_ETC]),
        ocontexts: ocontexts(),
        genfs: genfs(),
        range_tr: vec![RangeTrans { source_type: T_INIT, target_type: T_SHELL_EXEC,
                                    target_class: CLS_PROCESS, range: one(S1, &[0]) }],
        type_attr_map: type_attr_map(),
        permissive_map: Ebitmap::new(),
        neveraudit_map: Ebitmap::new(),
        policycaps: Ebitmap::new(),
        process_class: CLS_PROCESS,
        process_trans_perms: PROCESS_TRANS_PERMS,
    }
}
