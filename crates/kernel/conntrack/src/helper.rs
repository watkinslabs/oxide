//! Helpers. A helper reads the payload of a control connection and announces
//! the data connections it implies. Attaching one is a privilege decision: a
//! helper bound to the wrong flow can be made to open holes, so a helper
//! already chosen explicitly is never silently replaced by a different one.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use sync::{Socket as SocketLockClass, Spinlock};

use crate::limits::{EXPECT_CLASS_MAX, EXPECT_MAX_CNT};
use crate::tuple::Tuple;
use crate::uapi::IPS_HELPER;

/// Per-class expectation budget a helper declares.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExpectPolicy {
    pub max_expected: u32,
    /// Lifetime of one announced expectation, seconds.
    pub timeout: u32,
}

impl Default for ExpectPolicy {
    fn default() -> Self { Self { max_expected: EXPECT_MAX_CNT, timeout: 300 } }
}

/// A registered helper.
#[derive(Clone, Debug)]
pub struct Helper {
    pub name: String,
    /// L3 family the helper serves.
    pub l3num: u8,
    pub protonum: u8,
    /// Port the helper is registered on. Zero means any.
    pub port: u16,
    pub policies: Vec<ExpectPolicy>,
}

impl Helper {
    /// Budget for one expectation class, falling back to the default when the
    /// helper declares none for it. # C: O(1)
    pub fn policy(&self, class: u8) -> ExpectPolicy {
        self.policies.get(class as usize).copied().unwrap_or_default()
    }
}

/// Why a helper registration was refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HelperError {
    /// A helper of that name already exists.
    Exists,
    /// A declared class budget exceeds the hard ceiling, or too many classes.
    BadPolicy,
}

/// Registered helpers, by name.
pub struct HelperRegistry { helpers: Spinlock<Vec<Helper>, SocketLockClass> }

impl HelperRegistry {
    /// # C: O(1)
    pub const fn new() -> Self { Self { helpers: Spinlock::new(Vec::new()) } }

    /// # C: O(N)
    pub fn register(&self, h: Helper) -> Result<(), HelperError> {
        if h.policies.len() > EXPECT_CLASS_MAX as usize + 1 {
            return Err(HelperError::BadPolicy);
        }
        if h.policies.iter().any(|p| p.max_expected > EXPECT_MAX_CNT) {
            return Err(HelperError::BadPolicy);
        }
        let mut g = self.helpers.lock();
        if g.iter().any(|e| e.name == h.name) { return Err(HelperError::Exists); }
        g.push(h);
        Ok(())
    }

    /// # C: O(N)
    pub fn unregister(&self, name: &str) -> bool {
        let mut g = self.helpers.lock();
        match g.iter().position(|e| e.name == name) {
            Some(i) => { g.remove(i); true }
            None => false,
        }
    }

    /// # C: O(N)
    pub fn find(&self, name: &str) -> Option<Helper> {
        self.helpers.lock().iter().find(|e| e.name == name).cloned()
    }

    /// The helper that claims a tuple by its destination port. Matching on the
    /// destination is deliberate: a helper watches a service, and the client's
    /// source port is arbitrary. # C: O(N)
    pub fn find_for(&self, t: &Tuple) -> Option<Helper> {
        self.helpers.lock().iter().find(|h| {
            h.l3num == t.l3num && h.protonum == t.protonum
                && (h.port == 0 || h.port == t.dst.proto.port)
        }).cloned()
    }

    /// # C: O(N)
    pub fn snapshot(&self) -> Vec<Helper> { self.helpers.lock().clone() }
}

impl Default for HelperRegistry { fn default() -> Self { Self::new() } }

/// Outcome of resolving which helper a new flow gets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HelperAssign {
    /// Leave whatever is already attached.
    Keep,
    /// Attach this helper.
    Attach(String),
    /// Detach any helper currently attached.
    Detach,
}

/// Decide the helper for a new entry. `status` is the entry's `IPS_*` word,
/// `current` the helper already on it, `from_template` the helper the
/// conntrack template names.
///
/// An explicit choice (`IPS_HELPER`) always wins: that bit means a rule
/// deliberately set the helper, and letting automatic port matching override
/// it would silently reattach a payload parser somebody turned off.
/// # C: O(1)
pub fn assign(status: u32, current: Option<&str>, from_template: Option<&str>)
    -> HelperAssign
{
    if status & IPS_HELPER != 0 { return HelperAssign::Keep; }
    match (from_template, current) {
        (None, Some(_))    => HelperAssign::Detach,
        (None, None)       => HelperAssign::Keep,
        (Some(_), Some(_)) => HelperAssign::Keep,
        (Some(t), None)    => HelperAssign::Attach(String::from(t)),
    }
}
