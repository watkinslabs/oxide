// What writing an object's label costs.
//
// Three separate questions, and all three must be answered yes. They are not
// interchangeable: the first two bound which labels a domain may move an
// object BETWEEN, and the third bounds which filesystems may hold an object of
// the new label at all. Dropping the third lets a domain place a label into a
// filesystem the policy never allowed it to hold.

use selinux::sidtab::Sid;
use selinux::uapi::classmap::{class_by_name, perm_bit};

/// Permission to take a label off an object.
pub const PERM_RELABELFROM: &str = "relabelfrom";
/// Permission to put a label onto an object.
pub const PERM_RELABELTO: &str = "relabelto";
/// Permission for a label to exist on a filesystem.
pub const PERM_ASSOCIATE: &str = "associate";
/// Class of the filesystem object a label associates with.
pub const CLASS_FILESYSTEM: &str = "filesystem";
/// Class value standing for "this kernel knows no such class".
const NO_CLASS: u16 = 0;
/// Access vector asking for nothing, which no policy ever grants.
const NO_PERMISSION: u32 = 0;

/// One permission question: may `ssid` exercise `perm` of `class` on `tsid`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Check {
    /// Subject of the question.
    pub ssid: Sid,
    /// Object of the question.
    pub tsid: Sid,
    /// Security class the permission belongs to.
    pub class: u16,
    /// Permission name within that class.
    pub perm: &'static str,
}

impl Check {
    /// Access-vector bit this check asks for. # C: O(perms)
    pub fn av(&self) -> u32 { perm_bit(self.class, self.perm).unwrap_or(NO_PERMISSION) }
}

/// One request to write an object's label.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RelabelRequest {
    /// Label of the task doing the relabel.
    pub ssid: Sid,
    /// Label the object carries now.
    pub old_sid: Sid,
    /// Label the object is being given.
    pub new_sid: Sid,
    /// Label of the filesystem holding the object.
    pub sb_sid: Sid,
    /// Security class of the object.
    pub class: u16,
}

/// The three questions a relabel asks, in the order they are asked.
/// # C: O(classes)
///
/// Ordering matters to the record a denial leaves: the first refusal is the
/// one reported, and reporting `relabelto` for a domain that may not even take
/// the old label off sends the reader after the wrong rule.
pub fn relabel_checks(req: &RelabelRequest) -> [Check; 3] {
    let fs_class = class_by_name(CLASS_FILESYSTEM).unwrap_or(NO_CLASS);
    [
        Check { ssid: req.ssid, tsid: req.old_sid, class: req.class, perm: PERM_RELABELFROM },
        Check { ssid: req.ssid, tsid: req.new_sid, class: req.class, perm: PERM_RELABELTO },
        Check { ssid: req.new_sid, tsid: req.sb_sid, class: fs_class, perm: PERM_ASSOCIATE },
    ]
}

/// Whether a relabel may proceed, given a way to ask one question.
/// # C: O(1) per check
///
/// The asking is the caller's, so this decision is a value function and the
/// caller keeps the audit record its own layer can describe better.
pub fn relabel_decision(req: &RelabelRequest, mut ask: impl FnMut(&Check) -> bool) -> bool {
    relabel_checks(req).iter().all(|c| ask(c))
}
