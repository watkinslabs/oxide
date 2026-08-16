// A security context: the user, role and type triple, plus an MLS range when
// the policy carries MLS.
//
// A context that the loaded policy cannot interpret is NOT discarded. It is
// retained verbatim as an opaque string so that a policy reload which removes
// a type does not silently relabel every object that carried it; the object
// stays unlabelled-but-remembered, and a later reload that restores the type
// re-validates it. Dropping such contexts is how a reload turns into a mass
// relabel.

use alloc::string::String;

use crate::error::Result;
use crate::mls::Range;
use crate::reader::Reader;

/// A security context, either interpreted against a policy or held verbatim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Context {
    /// Interpreted against the policy that was loaded when it was resolved.
    Valid(ValidContext),
    /// Uninterpretable under the current policy; kept exactly as written.
    Unmapped(String),
}

/// A context whose components resolve in the current policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidContext {
    /// User symbol value.
    pub user: u32,
    /// Role symbol value.
    pub role: u32,
    /// Type symbol value.
    pub ty: u32,
    /// MLS range; both levels are zero when the policy has no MLS.
    pub range: Range,
}

impl Context {
    /// Interpreted form, or `None` for a retained unmapped context. # C: O(1)
    pub const fn valid(&self) -> Option<&ValidContext> {
        match self { Self::Valid(c) => Some(c), Self::Unmapped(_) => None }
    }

    /// Type value, or `None` when the context is unmapped. # C: O(1)
    pub const fn ty(&self) -> Option<u32> {
        match self { Self::Valid(c) => Some(c.ty), Self::Unmapped(_) => None }
    }

    /// Whether this context could not be interpreted. # C: O(1)
    pub const fn is_unmapped(&self) -> bool { matches!(self, Self::Unmapped(_)) }
}

impl ValidContext {
    /// Read a context: user, role, type, then an MLS range when present. # C: O(categories)
    pub fn read(r: &mut Reader<'_>, mls: bool) -> Result<Self> {
        let [user, role, ty] = r.u32_array::<3>()?;
        let range = if mls { Range::read(r)? } else { Range::default() };
        Ok(Self { user, role, ty, range })
    }
}
