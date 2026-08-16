// SELinux ABI constants (`docs/63`).
//
// Module manifest:
//   classmap  — kernel security-class and permission enumeration
//   initsid   — initial SID numbers and their policy symbol names
//   version   — policy database magic, signature and version range
//   policycap — policy capability bit numbers and names

pub mod classmap;
pub mod initsid;
pub mod version;
pub mod policycap;

pub use classmap::{ClassDef, SECCLASS_MAP, class_by_name, class_def, perm_bit};
pub use initsid::{InitSid, SECINITSID_NUM, initsid_name};
pub use version::{POLICYDB_MAGIC, POLICYDB_SIGNATURE, POLICYDB_VERSION_MAX, POLICYDB_VERSION_MIN};
