use super::*;
use super::relabel::CLASS_FILESYSTEM;
use super::sb::context_sid;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use selinux::context::ValidContext;
use selinux::policydb::sections::{Genfs, GenfsPath};
use selinux::policydb::FsUse;
use selinux::sidtab::Sid;
use selinux::uapi::classmap::class_by_name;
use selinux::{BootConfig, SecurityServer};

#[cfg(test)]
extern crate std;

/// The distribution policy the composed image ships. Loading the real thing is
/// what makes the mount-behaviour assertions below statements about a policy
/// people actually run, rather than about a fixture written to pass.
const DISTRO_POLICY: &str =
    "/home/nd/oxide/images/build/lite-x86_64-root/etc/selinux/targeted/policy/policy.34";

const REG: u32 = 0o100644;
const DIR: u32 = 0o040755;
const LNK: u32 = 0o120777;
const CHR: u32 = 0o020666;
const BLK: u32 = 0o060660;
const FIFO: u32 = 0o010644;
const SOCK: u32 = 0o140666;

fn class(name: &str) -> u16 { class_by_name(name).expect(name) }

fn loaded() -> Option<SecurityServer> {
    let image = match std::fs::read(DISTRO_POLICY) {
        Ok(b) => b,
        Err(_) => { std::println!("skipping: {DISTRO_POLICY} is not present on this machine"); return None; }
    };
    let mut s = SecurityServer::new(BootConfig::default());
    s.load_policy(&image).expect("the distribution policy must load");
    Some(s)
}

fn plan_for(srv: &SecurityServer, fstype: &str) -> SbPlan {
    sb_plan(srv.policy().expect("a policy is loaded"), fstype, &MountOptions::default())
}

// ---- mount behaviour, against the real policy -----------------------------

#[test]
fn a_disk_filesystem_labels_from_the_attribute() {
    let Some(s) = loaded() else { return };
    let p = plan_for(&s, "ext4");
    assert_eq!(p.behavior, FsUse::Xattr, "ext4 carries per-inode labels");
    assert!(p.behavior.uses_xattr());
    assert!(p.default_context.is_some(), "the statement supplies a fallback label");
}

#[test]
fn the_pseudo_filesystems_label_from_path_prefixes() {
    let Some(s) = loaded() else { return };
    for fstype in ["proc", "sysfs"] {
        let p = plan_for(&s, fstype);
        assert_eq!(p.behavior, FsUse::Genfs, "{fstype} has no fs_use statement");
        assert!(p.default_context.is_some(), "{fstype} root resolves from its prefixes");
    }
}

#[test]
fn a_memory_filesystem_follows_the_statement_the_policy_makes() {
    let Some(s) = loaded() else { return };
    let db = s.policy().unwrap();
    let stated = db.ocontexts.fs_use_of("tmpfs").expect("the policy states tmpfs").behavior;
    assert_eq!(plan_for(&s, "tmpfs").behavior, stated);
    assert_eq!(stated, FsUse::Trans, "tmpfs inodes transition from their creator");
}

#[test]
fn every_stated_behaviour_survives_the_decision_unchanged() {
    let Some(s) = loaded() else { return };
    let db = s.policy().unwrap();
    let stated: Vec<(String, FsUse)> = db.ocontexts.fs_use.iter()
        .map(|f| (f.name.clone(), f.behavior)).collect();
    assert!(stated.len() > 1, "the policy states several filesystems");
    let mut seen: Vec<FsUse> = Vec::new();
    for (name, behavior) in stated {
        assert_eq!(sb_plan(db, &name, &MountOptions::default()).behavior, behavior);
        if !seen.contains(&behavior) { seen.push(behavior); }
    }
    assert!(seen.len() >= 3, "the policy exercises several distinct behaviours");
}

#[test]
fn a_filesystem_the_policy_never_names_carries_no_labels() {
    let Some(s) = loaded() else { return };
    let p = plan_for(&s, "no-such-filesystem-type");
    assert_eq!(p.behavior, FsUse::None);
    assert_eq!(p.default_context, None, "borrowing another filesystem's label would be a guess");
}

#[test]
fn a_context_option_gives_the_whole_mount_one_label() {
    let Some(s) = loaded() else { return };
    let ctx = "system_u:object_r:etc_t:s0";
    let opts = MountOptions { context: Some(ctx), ..MountOptions::default() };
    let p = sb_plan(s.policy().unwrap(), "ext4", &opts);
    assert_eq!(p.behavior, FsUse::Mntpoint, "the attribute is not consulted at all");
    assert_eq!(p.sb_context.as_deref(), Some(ctx));
    assert_eq!(p.default_context.as_deref(), Some(ctx));
}

#[test]
fn a_defcontext_option_changes_only_the_fallback() {
    let Some(s) = loaded() else { return };
    let ctx = "system_u:object_r:etc_t:s0";
    let db = s.policy().unwrap();
    let base = sb_plan(db, "ext4", &MountOptions::default());
    let opts = MountOptions { defcontext: Some(ctx), ..MountOptions::default() };
    let p = sb_plan(db, "ext4", &opts);
    assert_eq!(p.behavior, FsUse::Xattr);
    assert_eq!(p.default_context.as_deref(), Some(ctx));
    assert_eq!(p.sb_context, base.sb_context, "the filesystem object keeps its own label");
}

#[test]
fn the_resolved_mount_has_real_sids() {
    let Some(mut s) = loaded() else { return };
    let sb = superblock_security(&mut s, "ext4", &MountOptions::default());
    assert_eq!(sb.behavior, FsUse::Xattr);
    assert_ne!(sb.default_sid, 0);
    assert!(s.sid_to_context(sb.default_sid).is_ok());
}

// ---- path prefixes --------------------------------------------------------

/// A filesystem with a nested prefix beneath a broader one, ordered as the
/// reader orders them: longest first.
fn nested_genfs(db_class: u32) -> Genfs {
    let ctx = |ty: u32| ValidContext { user: 1, role: 1, ty, range: Default::default() };
    Genfs {
        fstype: "nestfs".to_string(),
        paths: alloc::vec![
            GenfsPath { path: "/sys/kernel/debug".to_string(), sclass: db_class, context: ctx(2) },
            GenfsPath { path: "/sys".to_string(), sclass: db_class, context: ctx(1) },
        ],
    }
}

#[test]
fn the_longest_matching_prefix_wins() {
    let g = nested_genfs(0);
    let deep = resolve::genfs_match(&g, "/sys/kernel/debug/tracing", 0)
        .expect("the nested entry matches");
    let shallow = resolve::genfs_match(&g, "/sys/devices", 0).expect("the broad entry matches");
    assert_eq!(deep.ty, 2, "a nested prefix must not fall back to its parent");
    assert_eq!(shallow.ty, 1);
    // The same table scanned shortest-first answers the broad entry for BOTH,
    // which is the mislabelling this ordering exists to prevent.
    let mut wrong = g.paths.clone();
    wrong.sort_by_key(|p| p.path.len());
    assert_eq!(wrong.iter().find(|p| "/sys/kernel/debug/tracing".starts_with(&p.path))
               .map(|p| p.context.ty), Some(1));
}

#[test]
fn a_real_nested_prefix_resolves_to_its_own_context() {
    let Some(s) = loaded() else { return };
    let db = s.policy().unwrap();
    let Some(entry) = db.genfs.iter().find(|g| g.fstype == "proc") else { return };
    // Find a prefix that has another, shorter prefix of it in the same table.
    let nested = entry.paths.iter().find(|p| {
        entry.paths.iter().any(|q| q.path != p.path && p.path.starts_with(&q.path))
    });
    let Some(nested) = nested else { return };
    let got = genfs_context(db, "proc", &nested.path, class("file"));
    let want = selinux::services::render::valid_context_to_string(db, &nested.context).ok();
    assert!(got.is_some(), "a stated prefix must resolve");
    if nested.sclass == 0 { assert_eq!(got, want, "the nested entry answers, not its parent"); }
}

#[test]
fn a_path_no_prefix_covers_has_no_context() {
    let Some(s) = loaded() else { return };
    let db = s.policy().unwrap();
    assert_eq!(genfs_context(db, "no-such-filesystem-type", "/anything", class("file")), None);
}

// ---- per-inode label ------------------------------------------------------

#[test]
fn an_absent_attribute_falls_back_to_the_mount_default() {
    assert_eq!(existing_inode_plan(FsUse::Xattr, None, None), LabelPlan::Default);
    assert_eq!(existing_inode_plan(FsUse::Native, None, None), LabelPlan::Default);
    assert_eq!(existing_inode_plan(FsUse::Xattr, Some("u:r:t:s0"), None),
               LabelPlan::Context("u:r:t:s0".to_string()));
}

#[test]
fn each_behaviour_names_its_own_source() {
    assert_eq!(existing_inode_plan(FsUse::Trans, None, None), LabelPlan::TransitionFromMount);
    assert_eq!(existing_inode_plan(FsUse::Task, None, None), LabelPlan::TaskSid);
    assert_eq!(existing_inode_plan(FsUse::None, Some("u:r:t:s0"), Some("u:r:t:s0")),
               LabelPlan::Unlabeled, "a filesystem with no labels has none to read");
    assert_eq!(existing_inode_plan(FsUse::Mntpoint, Some("u:r:t:s0"), None), LabelPlan::Default,
               "one label for the whole mount is never refined per inode");
    assert_eq!(existing_inode_plan(FsUse::Genfs, None, Some("u:r:t:s0")),
               LabelPlan::Context("u:r:t:s0".to_string()));
    assert_eq!(existing_inode_plan(FsUse::Genfs, None, None), LabelPlan::Default);
}

#[test]
fn a_label_the_policy_cannot_read_is_unlabeled_and_not_an_error() {
    let Some(mut s) = loaded() else { return };
    let sid = context_sid(&mut s, Some("no_such_user:no_such_role:no_such_type:s0"));
    assert_eq!(sid, crate::label::unlabeled_sid(),
               "one dropped type must not lock the system out of every object that carried it");
}

#[test]
fn an_unreadable_attribute_leaves_the_object_reachable() {
    let Some(mut s) = loaded() else { return };
    let sb = superblock_security(&mut s, "ext4", &MountOptions::default());
    let sid = existing_inode_sid(&mut s, &sb, crate::label::kernel_sid(), class("file"),
                                 Some("garbage"), None);
    assert_eq!(sid, crate::label::unlabeled_sid());
    assert!(s.sid_to_context(sid).is_ok(), "unlabeled is a label policy can write rules about");
}

#[test]
fn an_attribute_the_policy_reads_becomes_that_label() {
    let Some(mut s) = loaded() else { return };
    let sb = superblock_security(&mut s, "ext4", &MountOptions::default());
    let want = s.sid_to_context(sb.default_sid).expect("the default renders");
    let sid = existing_inode_sid(&mut s, &sb, crate::label::kernel_sid(), class("file"),
                                 Some(&want), None);
    assert_eq!(s.sid_to_context(sid).ok(), Some(want));
}

// ---- creating an object ---------------------------------------------------

/// Every filename transition the policy states for the `file` class, as
/// `(source type, parent type, produced type, name)`.
fn filename_transition_cases(s: &SecurityServer) -> Vec<(String, String, String, String)> {
    let mut out = Vec::new();
    let Some(db) = s.policy() else { return out };
    let Some(policy_file) = db.symbols.classes.iter().find(|c| c.name == "file").map(|c| c.value)
        else { return out };
    for ft in &db.filename_trans {
        if ft.tclass != policy_file { continue; }
        let Some(datum) = ft.data.first() else { continue };
        let Some(stype) = (0..db.symbols.types.len() as u32).find(|v| datum.stypes.get(*v))
            else { continue };
        let (Some(source), Some(target), Some(produced)) = (
            db.symbols.ty(stype + 1), db.symbols.ty(ft.ttype), db.symbols.ty(datum.otype))
            else { continue };
        out.push((source.name.clone(), target.name.clone(), produced.name.clone(),
                  ft.name.clone()));
    }
    out
}

#[test]
fn a_new_object_takes_the_name_into_the_transition() {
    let Some(mut s) = loaded() else { return };
    let cases = filename_transition_cases(&s);
    assert!(!cases.is_empty(), "the distribution policy states filename transitions");
    let sb = superblock_security(&mut s, "ext4", &MountOptions::default());
    let file = class("file");
    // A rule whose name-keyed answer differs from the un-named one. Most rules
    // agree with the ordinary transition; the ones that do not are exactly the
    // rules a caller that drops the name would silently lose.
    let mut decided = 0;
    for (source, target, produced, name) in cases.iter().take(4096) {
        let Ok(ssid) = s.context_to_sid(&alloc::format!("system_u:system_r:{source}:s0"))
            else { continue };
        let Ok(dsid) = s.context_to_sid(&alloc::format!("system_u:object_r:{target}:s0"))
            else { continue };
        let with_name = new_inode_sid(&mut s, &sb, None, ssid, dsid, file, Some(name));
        let without = new_inode_sid(&mut s, &sb, None, ssid, dsid, file, None);
        if with_name == without { continue; }
        let rendered = s.sid_to_context(with_name).expect("the new label renders");
        assert!(rendered.contains(produced.as_str()),
                "the filename rule must decide the label: {rendered} lacks {produced}");
        decided += 1;
        if decided == 3 { break; }
    }
    assert!(decided > 0,
            "at least one stated rule must be decided by the name, or dropping the \
             name could never be detected");
}

#[test]
fn a_staged_label_overrides_the_computed_one() {
    let staged: Sid = 42;
    assert_eq!(new_inode_plan(FsUse::Xattr, Some(staged)), NewInodePlan::Staged(staged));
    assert_eq!(new_inode_plan(FsUse::Xattr, None), NewInodePlan::Transition);
}

#[test]
fn a_single_label_mount_ignores_both_the_stage_and_the_transition() {
    assert_eq!(new_inode_plan(FsUse::Mntpoint, Some(42)), NewInodePlan::MountSid);
    assert_eq!(new_inode_plan(FsUse::Mntpoint, None), NewInodePlan::MountSid);
}

// ---- relabelling ----------------------------------------------------------

fn request() -> RelabelRequest {
    RelabelRequest { ssid: 1, old_sid: 2, new_sid: 3, sb_sid: 4, class: class("file") }
}

#[test]
fn a_relabel_asks_three_questions() {
    let checks = relabel_checks(&request());
    assert_eq!(checks[0], Check { ssid: 1, tsid: 2, class: class("file"), perm: PERM_RELABELFROM });
    assert_eq!(checks[1], Check { ssid: 1, tsid: 3, class: class("file"), perm: PERM_RELABELTO });
    assert_eq!(checks[2], Check { ssid: 3, tsid: 4, class: class(CLASS_FILESYSTEM),
                                  perm: PERM_ASSOCIATE });
    assert!(checks.iter().all(|c| c.av() != 0), "every question names a real permission");
}

#[test]
fn every_one_of_the_three_can_refuse_a_relabel() {
    let req = request();
    assert!(relabel_decision(&req, |_| true), "all three granted allows the relabel");
    for refused in 0..3 {
        let mut n = 0;
        let allowed = relabel_decision(&req, |_| { n += 1; n - 1 != refused });
        assert!(!allowed, "check {refused} refusing must refuse the relabel");
    }
}

#[test]
fn the_filesystem_question_is_asked_against_the_new_label() {
    let checks = relabel_checks(&request());
    assert_eq!(checks[2].ssid, 3, "a label may only be placed where policy lets it live");
    assert_eq!(checks[2].tsid, 4);
}

// ---- the attribute gate ---------------------------------------------------

#[test]
fn reading_the_label_costs_a_metadata_read() {
    assert_eq!(selinux_xattr_gate(crate::label::XATTR_NAME_SELINUX, XattrOp::Get),
               XattrGate::Perm(xattr::PERM_GETATTR));
}

#[test]
fn writing_the_label_costs_a_relabel() {
    assert_eq!(selinux_xattr_gate(crate::label::XATTR_NAME_SELINUX, XattrOp::Set),
               XattrGate::Relabel);
}

#[test]
fn the_label_cannot_be_deleted_at_any_price() {
    assert_eq!(selinux_xattr_gate(crate::label::XATTR_NAME_SELINUX, XattrOp::Remove),
               XattrGate::Refuse, "every object must carry a label");
}

#[test]
fn other_attributes_keep_their_own_rules() {
    for name in ["security.capability", "user.thing", "trusted.thing", "system.posix_acl_access"] {
        assert_eq!(selinux_xattr_gate(name, XattrOp::Set), XattrGate::NotOurs, "{name}");
        assert_eq!(selinux_xattr_gate(name, XattrOp::Get), XattrGate::NotOurs, "{name}");
    }
}

// ---- the ordinary permission check ----------------------------------------

#[test]
fn an_empty_mask_asks_nothing() {
    assert_eq!(inode_permission_av(REG, 0), None, "an existence test is not an access");
    assert_eq!(inode_permission_av(DIR, 0), None);
}

#[test]
fn each_file_type_asks_within_its_own_class() {
    use crate::label::{MAY_EXEC, MAY_READ, MAY_WRITE};
    for (mode, name) in [(REG, "file"), (LNK, "lnk_file"), (CHR, "chr_file"),
                         (BLK, "blk_file"), (FIFO, "fifo_file"), (SOCK, "sock_file")] {
        let (c, av) = inode_permission_av(mode, MAY_READ).expect(name);
        assert_eq!(c, class(name));
        assert_eq!(av, selinux::uapi::classmap::perm_bit(class(name), "read").unwrap());
    }
    let (c, av) = inode_permission_av(DIR, MAY_EXEC).expect("dir");
    assert_eq!(c, class("dir"));
    assert_eq!(av, selinux::uapi::classmap::perm_bit(class("dir"), "search").unwrap(),
               "a directory's execute bit is search, not execute");
    let (_, av) = inode_permission_av(REG, MAY_READ | MAY_WRITE).unwrap();
    let want = selinux::uapi::classmap::perm_bit(class("file"), "read").unwrap()
        | selinux::uapi::classmap::perm_bit(class("file"), "write").unwrap();
    assert_eq!(av, want);
}
