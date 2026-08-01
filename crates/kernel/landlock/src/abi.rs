// Pure argument admission for slots 444/445/446. No user memory, no task
// state, no allocation: every function here is a decision the hosted suite can
// drive directly, which is why the kernel-gated slot files carry none of it.

use syscall::errno::Errno;

use crate::uapi::*;

/// What `landlock_create_ruleset`'s `flags` word asks for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CreateIntent {
    /// Build a ruleset from `attr`.
    Ruleset,
    /// Report the supported ABI version instead.
    Version,
    /// Report the errata bitmask instead.
    Errata,
}

/// `flags` admission. A non-zero `flags` is a pure query: it forbids both
/// `attr` and `size`, and only two exact values are queries at all — a
/// combination of the two, or any unknown bit, is invalid.
/// # C: O(1)
pub fn create_intent(attr: u64, size: usize, flags: u32) -> Result<CreateIntent, Errno> {
    if flags == 0 { return Ok(CreateIntent::Ruleset); }
    if attr != 0 || size != 0 { return Err(Errno::Einval); }
    if flags == CREATE_RULESET_VERSION { return Ok(CreateIntent::Version); }
    if flags == CREATE_RULESET_ERRATA  { return Ok(CreateIntent::Errata); }
    Err(Errno::Einval)
}

/// Buffer admission shared by every growable Landlock attr. A null pointer is
/// EFAULT rather than EINVAL: the size ranges are only meaningful once there is
/// something to read.
/// # C: O(1)
pub fn attr_buffer_ok(attr: u64, size: usize, min_size: usize) -> Result<(), Errno> {
    if attr == 0 { return Err(Errno::Efault); }
    if size < min_size { return Err(Errno::Einval); }
    if size > ATTR_MAX_SIZE { return Err(Errno::E2big); }
    Ok(())
}

/// Decoded `struct landlock_ruleset_attr`. Members past the caller's `size` are
/// zero, which is what "an older program on a newer kernel" must mean.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct RulesetAttr {
    pub handled_fs:  AccessMask,
    pub handled_net: AccessMask,
    pub scoped:      AccessMask,
}

impl RulesetAttr {
    /// Decode from the zero-extended attr bytes.
    /// # C: O(1)
    pub fn decode(buf: &[u8; RULESET_ATTR_SIZE]) -> Self {
        let w = |i: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[i * 8..i * 8 + 8]);
            u64::from_le_bytes(b)
        };
        Self { handled_fs: w(0), handled_net: w(1), scoped: w(2) }
    }

    /// Content admission. Unknown bits in any mask are rejected rather than
    /// ignored: silently dropping a right a caller believed it had handled is
    /// the difference between a sandbox and the appearance of one. A ruleset
    /// that handles nothing at all is refused so the caller learns its policy
    /// would have had no effect.
    /// # C: O(1)
    pub fn validate(&self) -> Result<(), Errno> {
        if (self.handled_fs  | MASK_ACCESS_FS)  != MASK_ACCESS_FS  { return Err(Errno::Einval); }
        if (self.handled_net | MASK_ACCESS_NET) != MASK_ACCESS_NET { return Err(Errno::Einval); }
        if (self.scoped      | MASK_SCOPE)      != MASK_SCOPE      { return Err(Errno::Einval); }
        if self.handled_fs == 0 && self.handled_net == 0 && self.scoped == 0 {
            return Err(Errno::Enomsg);
        }
        Ok(())
    }
}

/// `landlock_add_rule`'s `flags`: no flag is defined at this ABI level.
/// # C: O(1)
pub fn add_rule_flags_ok(flags: u32) -> Result<(), Errno> {
    if (flags | MASK_ADD_RULE) != MASK_ADD_RULE { return Err(Errno::Einval); }
    Ok(())
}

/// Shared rule admission for both rule types.
///
/// An all-zero `allowed_access` is a rule that can never grant anything;
/// reporting ENOMSG tells the caller its policy is inert instead of letting it
/// believe an allow-rule was installed. `allowed_access` outside the ruleset's
/// handled mask is EINVAL — a rule may never grant a right the ruleset does not
/// filter.
/// # C: O(1)
pub fn rule_access_ok(allowed: AccessMask, handled: AccessMask) -> Result<(), Errno> {
    if allowed == 0 { return Err(Errno::Enomsg); }
    if (allowed | handled) != handled { return Err(Errno::Einval); }
    Ok(())
}

/// A net rule may only name a real port number.
/// # C: O(1)
pub fn net_port_ok(port: u64) -> Result<(), Errno> {
    if port > PORT_MAX { return Err(Errno::Einval); }
    Ok(())
}

/// A rule anchored on a non-directory may only carry rights that mean something
/// for a single file; directory-shaped rights on a file would silently never
/// apply.
/// # C: O(1)
pub fn path_target_ok(is_dir: bool, allowed: AccessMask) -> Result<(), Errno> {
    if !is_dir && (allowed | ACCESS_FILE) != ACCESS_FILE { return Err(Errno::Einval); }
    Ok(())
}

/// Rights a stored rule grants. Rights the ruleset does not handle are added so
/// the rule stays meaningful if it is ever evaluated against a wider request:
/// a layer never filters what it did not declare.
/// # C: O(1)
pub fn absolute_access(allowed: AccessMask, handled_fs: AccessMask) -> AccessMask {
    allowed | (MASK_ACCESS_FS & !fs_layer_mask(handled_fs))
}

/// Rights a layer actually filters: everything it declared, plus the rights
/// denied by default regardless of declaration.
/// # C: O(1)
pub fn fs_layer_mask(handled_fs: AccessMask) -> AccessMask {
    handled_fs | ACCESS_FS_INITIALLY_DENIED
}

/// `landlock_restrict_self` admission before the ruleset fd is resolved.
///
///
/// Enforcing a policy is refused unless the thread cannot gain privileges, or
/// holds the administrative capability in its user namespace. Without that an
/// unprivileged thread could install a policy that a later set-user-ID exec
/// would still be subject to, turning a sandbox into a way to confuse a
/// privileged program. The failure is EPERM, not EACCES.
/// # C: O(1)
pub fn restrict_self_precheck(no_new_privs: bool, cap_sys_admin: bool, flags: u32)
    -> Result<(), Errno>
{
    if !no_new_privs && !cap_sys_admin { return Err(Errno::Eperm); }
    if (flags | MASK_RESTRICT_SELF) != MASK_RESTRICT_SELF { return Err(Errno::Einval); }
    Ok(())
}

/// Whether another layer may be stacked on a domain that already has `layers`.
/// # C: O(1)
pub fn may_stack_layer(layers: usize) -> Result<(), Errno> {
    if layers >= MAX_NUM_LAYERS { return Err(Errno::E2big); }
    Ok(())
}

#[cfg(test)]
#[path = "tests/abi.rs"]
mod tests;
