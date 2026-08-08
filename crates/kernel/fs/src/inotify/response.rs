// fanotify RESPONSE admission — the `struct fanotify_response { __s32 fd;
// __u32 response }` a daemon writes back to unblock a permission event, and the
// verdict→errno mapping the blocked accessor reports.
//
// Deliberately free of any target gate so the whole ladder is hosted-testable;
// `group.rs` only sequences these helpers (docs/53).

use syscall::errno::Errno;

/// `FAN_ALLOW`.
pub(crate) const FAN_ALLOW: u32 = 0x01;
/// `FAN_DENY`.
pub(crate) const FAN_DENY: u32 = 0x02;
/// `FAN_AUDIT` — record the verdict in the audit log.
pub(crate) const FAN_AUDIT: u32 = 0x10;
/// `FAN_INFO` — an info record follows the response struct.
pub(crate) const FAN_INFO: u32 = 0x20;

/// The verdict field of a response word.
pub(crate) const RESPONSE_ACCESS: u32 = FAN_ALLOW | FAN_DENY;
/// The modifier flags of a response word.
pub(crate) const RESPONSE_FLAGS: u32 = FAN_AUDIT | FAN_INFO;

/// `FAN_ERRNO_BITS` — width of the errno a `FAN_DENY` may carry.
const ERRNO_BITS: u32 = 8;
/// `FAN_ERRNO_SHIFT`.
const ERRNO_SHIFT: u32 = 32 - ERRNO_BITS;
/// `FAN_ERRNO_MASK`.
const ERRNO_MASK: u32 = (1 << ERRNO_BITS) - 1;
/// Every bit a response word may carry: the verdict, the modifiers, and the
/// packed errno.
pub(crate) const RESPONSE_VALID_MASK: u32 =
    RESPONSE_ACCESS | RESPONSE_FLAGS | (ERRNO_MASK << ERRNO_SHIFT);

/// `sizeof(struct fanotify_response)`.
pub(crate) const RESPONSE_LEN: usize = 8;

/// `FAN_RESPONSE_INFO_NONE` — the response carries no additional record.
/// Kept for ABI completeness: it is a defined header type, but the ONLY type a
/// response may carry is the audit rule, so nothing on the write path compares
/// against it — `parse_response_info` rejects everything that is not
/// `FAN_RESPONSE_INFO_AUDIT_RULE`. Named here so the rejection tests can state
/// what they are rejecting rather than a bare `0`.
#[allow(dead_code)]
pub(crate) const FAN_RESPONSE_INFO_NONE: u8 = 0;
/// `FAN_RESPONSE_INFO_AUDIT_RULE` — the record names the userspace rule that
/// produced the verdict. The only record type a response may carry.
pub(crate) const FAN_RESPONSE_INFO_AUDIT_RULE: u8 = 1;

/// `sizeof(struct fanotify_response_info_audit_rule)`: the 4-byte
/// `fanotify_response_info_header {type u8, pad u8, len u16}` followed by
/// `rule_number`, `subj_trust` and `obj_trust`.
pub(crate) const AUDIT_RULE_LEN: usize = 16;

/// The audit record a daemon attaches to a verdict: which of its rules decided,
/// and how far it trusts the subject and the object. Recorded on the permission
/// event so the verdict's justification is not lost between the write that
/// carried it and whatever renders it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuditRule {
    pub(crate) rule_number: u32,
    pub(crate) subj_trust:  u32,
    pub(crate) obj_trust:   u32,
}

/// Parse the `struct fanotify_response_info_audit_rule` that follows the
/// response struct when the verdict sets `FAN_INFO`.
///
/// Every field is checked, and the checks are the whole user-visible contract
/// of the flag: the trailing bytes must be EXACTLY one record (a longer write
/// is not two records and a shorter one is not a truncated record — both are
/// `EINVAL`), the type must be the audit-rule type, the header's own length
/// must agree with the record it heads, and the pad byte must be zero so the
/// field stays available. A response whose record fails any of these leaves the
/// permission event untouched — the daemon may write a correct one instead.
/// # C: O(1)
pub(crate) fn parse_response_info(info: &[u8]) -> Result<AuditRule, Errno> {
    if info.len() != AUDIT_RULE_LEN { return Err(Errno::Einval); }
    if info[0] != FAN_RESPONSE_INFO_AUDIT_RULE { return Err(Errno::Einval); }
    if info[1] != 0 { return Err(Errno::Einval); }
    if u16::from_le_bytes([info[2], info[3]]) as usize != AUDIT_RULE_LEN {
        return Err(Errno::Einval);
    }
    Ok(AuditRule {
        rule_number: u32::from_le_bytes([info[4], info[5], info[6], info[7]]),
        subj_trust:  u32::from_le_bytes([info[8], info[9], info[10], info[11]]),
        obj_trust:   u32::from_le_bytes([info[12], info[13], info[14], info[15]]),
    })
}

/// The response word an audit record carries, or `None` when the verdict did
/// not ask to be audited.
///
/// The recorded word keeps the verdict AND the modifier flags but drops the
/// audit request itself: that flag says how the decision is to be handled, not
/// what was decided, and a reader comparing records would otherwise see it on
/// every one. The packed errno is dropped too — it is the accessor's answer,
/// not the daemon's decision.
/// # C: O(1)
pub(crate) fn audited_response(raw: u32) -> Option<u32> {
    if raw & FAN_AUDIT == 0 { return None; }
    Some(raw & (RESPONSE_ACCESS | RESPONSE_FLAGS) & !FAN_AUDIT)
}

/// The errno packed into the high byte of a response word (`FAN_DENY_ERRNO`).
/// # C: O(1)
pub(crate) fn response_errno(response: u32) -> u32 { (response >> ERRNO_SHIFT) & ERRNO_MASK }

/// The only errnos a `FAN_DENY` may name. A denial carrying anything else is
/// rejected outright rather than surfaced to the blocked accessor, so a daemon
/// cannot invent an errno the access path could never otherwise produce.
const DENY_ERRNOS: [u32; 7] = [
    Errno::Eio as u32, Errno::Eperm as u32, Errno::Ebusy as u32, Errno::Etxtbsy as u32,
    Errno::Eagain as u32, Errno::Enospc as u32, Errno::Edquot as u32,
];

/// A validated verdict, ready to store on the perm event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Verdict {
    /// `FAN_ALLOW` or `FAN_DENY`.
    pub(crate) access: u32,
    /// The errno a denial names; `0` selects the default.
    pub(crate) errno: u32,
}

impl Verdict {
    /// The error a blocked accessor reports for this verdict. A denial with no
    /// explicit errno is `EPERM` — NOT `EACCES`: the accessor is being refused
    /// by policy, not by the file's mode bits, and a caller that distinguishes
    /// the two (a shell reporting why an exec failed) sees the wrong reason
    /// otherwise. # C: O(1)
    pub(crate) fn as_result(&self) -> Result<(), Errno> {
        if self.access == FAN_ALLOW { Ok(()) } else { Err(errno_from_u32(self.errno)) }
    }
}

/// Map a validated deny errno back to its typed form. `0` (and anything the
/// deny ladder would have rejected) is the default `EPERM`. # C: O(1)
fn errno_from_u32(e: u32) -> Errno {
    match e {
        x if x == Errno::Eio as u32     => Errno::Eio,
        x if x == Errno::Eperm as u32   => Errno::Eperm,
        x if x == Errno::Ebusy as u32   => Errno::Ebusy,
        x if x == Errno::Etxtbsy as u32 => Errno::Etxtbsy,
        x if x == Errno::Eagain as u32  => Errno::Eagain,
        x if x == Errno::Enospc as u32  => Errno::Enospc,
        x if x == Errno::Edquot as u32  => Errno::Edquot,
        _ => Errno::Eperm,
    }
}

/// Validate one response word against the writing group's properties, in the
/// order the checks are applied: unknown bits, then the verdict selector, then
/// the errno rules for each verdict, then the audit gate.
///
/// `pre_content` is whether the group was created with the pre-content class —
/// only such a group may name an errno on a denial, because only it sits early
/// enough in the access path for the errno to mean anything.
/// `audit_enabled` is `FAN_ENABLE_AUDIT` on the group.
/// # C: O(1)
pub(crate) fn validate_response(response: u32, pre_content: bool, audit_enabled: bool)
    -> Result<Verdict, Errno> {
    if response & !RESPONSE_VALID_MASK != 0 { return Err(Errno::Einval); }
    let errno = response_errno(response);
    let access = response & RESPONSE_ACCESS;
    match access {
        FAN_ALLOW => { if errno != 0 { return Err(Errno::Einval); } }
        FAN_DENY => {
            if errno != 0 && !pre_content { return Err(Errno::Einval); }
            if errno != 0 && !DENY_ERRNOS.contains(&errno) { return Err(Errno::Einval); }
        }
        // Neither bit, or BOTH — a response word must name exactly one verdict.
        _ => return Err(Errno::Einval),
    }
    if response & FAN_AUDIT != 0 && !audit_enabled { return Err(Errno::Einval); }
    Ok(Verdict { access, errno })
}

/// The fd field's own admission, applied after the response word validates and
/// before the pending list is searched: a negative descriptor names no event.
/// # C: O(1)
pub(crate) fn validate_response_fd(fd: i32) -> Result<i32, Errno> {
    if fd < 0 { return Err(Errno::Einval); }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One write carries exactly one 8-byte response struct. # C: O(1)
    #[test]
    fn response_struct_is_two_words() { assert_eq!(RESPONSE_LEN, 8); }

    #[test]
    fn a_bare_allow_or_deny_validates() {
        assert_eq!(validate_response(FAN_ALLOW, false, false),
                   Ok(Verdict { access: FAN_ALLOW, errno: 0 }));
        assert_eq!(validate_response(FAN_DENY, false, false),
                   Ok(Verdict { access: FAN_DENY, errno: 0 }));
    }

    /// A response naming neither verdict, or both at once, is rejected — the
    /// blocked accessor must not be resumed on an ambiguous word. # C: O(1)
    #[test]
    fn a_response_must_name_exactly_one_verdict() {
        assert_eq!(validate_response(0, false, false), Err(Errno::Einval));
        assert_eq!(validate_response(FAN_ALLOW | FAN_DENY, false, false), Err(Errno::Einval));
        assert_eq!(validate_response(FAN_AUDIT, false, true), Err(Errno::Einval),
                   "a modifier alone is not a verdict");
    }

    #[test]
    fn unknown_bits_are_rejected_before_the_verdict_is_read() {
        assert_eq!(validate_response(FAN_ALLOW | 0x40, false, false), Err(Errno::Einval));
        assert_eq!(validate_response(FAN_ALLOW | 0x0080_0000, false, false), Err(Errno::Einval),
                   "the byte just below the errno field is not a response bit");
        // The errno field itself IS inside the valid mask.
        assert_eq!(RESPONSE_VALID_MASK & 0xff00_0000, 0xff00_0000);
    }

    /// `FAN_AUDIT` is only meaningful on a group that asked for auditing; a
    /// group that did not gets EINVAL rather than a silently-dropped flag.
    /// # C: O(1)
    #[test]
    fn audit_requires_the_group_to_have_enabled_it() {
        assert_eq!(validate_response(FAN_ALLOW | FAN_AUDIT, false, false), Err(Errno::Einval));
        assert_eq!(validate_response(FAN_ALLOW | FAN_AUDIT, false, true),
                   Ok(Verdict { access: FAN_ALLOW, errno: 0 }));
    }

    /// An errno rides in the top byte and only a denial from a pre-content
    /// group may carry one. # C: O(1)
    #[test]
    fn only_a_pre_content_denial_may_name_an_errno() {
        let deny_eio = FAN_DENY | ((Errno::Eio as u32) << ERRNO_SHIFT);
        assert_eq!(validate_response(deny_eio, false, false), Err(Errno::Einval),
                   "a non-pre-content group may not name an errno");
        assert_eq!(validate_response(deny_eio, true, false),
                   Ok(Verdict { access: FAN_DENY, errno: Errno::Eio as u32 }));
        let allow_eio = FAN_ALLOW | ((Errno::Eio as u32) << ERRNO_SHIFT);
        assert_eq!(validate_response(allow_eio, true, false), Err(Errno::Einval),
                   "an ALLOW never carries an errno");
    }

    /// The deny-errno allowlist is closed: an errno outside it is EINVAL even
    /// for a pre-content group. # C: O(1)
    #[test]
    fn the_deny_errno_allowlist_is_closed() {
        for e in DENY_ERRNOS {
            let r = FAN_DENY | (e << ERRNO_SHIFT);
            assert_eq!(validate_response(r, true, false), Ok(Verdict { access: FAN_DENY, errno: e }),
                       "errno {e} should be accepted");
        }
        for e in [Errno::Enoent as u32, Errno::Einval as u32, Errno::Eacces as u32, 0xff] {
            let r = FAN_DENY | (e << ERRNO_SHIFT);
            assert_eq!(validate_response(r, true, false), Err(Errno::Einval), "errno {e}");
        }
    }

    /// A denial with no errno reports EPERM. This is the single most
    /// user-visible fact about a permission event: `open()` on a denied file
    /// fails with EPERM, not EACCES. # C: O(1)
    #[test]
    fn a_bare_denial_reports_eperm_not_eacces() {
        let v = validate_response(FAN_DENY, false, false).unwrap();
        assert_eq!(v.as_result(), Err(Errno::Eperm));
        assert_ne!(v.as_result(), Err(Errno::Eacces));
    }

    /// An allow resumes the accessor with no error at all. # C: O(1)
    #[test]
    fn an_allow_resumes_the_accessor() {
        assert_eq!(validate_response(FAN_ALLOW, false, false).unwrap().as_result(), Ok(()));
    }

    /// A pre-content denial's named errno is what the accessor reports. # C: O(1)
    #[test]
    fn a_named_deny_errno_reaches_the_accessor() {
        for (e, want) in [(Errno::Eio as u32, Errno::Eio), (Errno::Etxtbsy as u32, Errno::Etxtbsy),
                          (Errno::Edquot as u32, Errno::Edquot)] {
            let r = FAN_DENY | (e << ERRNO_SHIFT);
            let v = validate_response(r, true, false).unwrap();
            assert_eq!(v.as_result(), Err(want));
        }
    }

    /// A negative descriptor names no pending event. # C: O(1)
    #[test]
    fn a_negative_response_fd_is_einval() {
        assert_eq!(validate_response_fd(-1), Err(Errno::Einval));
        assert_eq!(validate_response_fd(-2), Err(Errno::Einval));
        assert_eq!(validate_response_fd(0), Ok(0));
        assert_eq!(validate_response_fd(7), Ok(7));
    }

    /// One `struct fanotify_response_info_audit_rule` in wire order. # C: O(1)
    fn rule(ty: u8, pad: u8, len: u16, n: u32, subj: u32, obj: u32) -> [u8; AUDIT_RULE_LEN] {
        let mut b = [0u8; AUDIT_RULE_LEN];
        b[0] = ty;
        b[1] = pad;
        b[2..4].copy_from_slice(&len.to_le_bytes());
        b[4..8].copy_from_slice(&n.to_le_bytes());
        b[8..12].copy_from_slice(&subj.to_le_bytes());
        b[12..16].copy_from_slice(&obj.to_le_bytes());
        b
    }

    /// The record's three payload words are read at the offsets the struct
    /// puts them at, after its 4-byte header. # C: O(1)
    #[test]
    fn an_audit_rule_record_decodes_its_three_payload_words() {
        let b = rule(FAN_RESPONSE_INFO_AUDIT_RULE, 0, AUDIT_RULE_LEN as u16, 0x1234, 7, 9);
        assert_eq!(parse_response_info(&b),
                   Ok(AuditRule { rule_number: 0x1234, subj_trust: 7, obj_trust: 9 }));
    }

    /// The trailing bytes are EXACTLY one record: a truncated one is not a
    /// short record and a longer one is not two records. # C: O(1)
    #[test]
    fn the_record_length_must_match_exactly() {
        let b = rule(FAN_RESPONSE_INFO_AUDIT_RULE, 0, AUDIT_RULE_LEN as u16, 1, 0, 0);
        assert_eq!(parse_response_info(&b[..AUDIT_RULE_LEN - 1]), Err(Errno::Einval));
        let mut long = alloc::vec::Vec::from(b);
        long.push(0);
        assert_eq!(parse_response_info(&long), Err(Errno::Einval));
        assert_eq!(parse_response_info(&[]), Err(Errno::Einval));
    }

    /// Audit-rule is the only record type a response may carry, the pad byte
    /// must stay zero, and the header's length must agree with the record it
    /// heads. # C: O(1)
    #[test]
    fn every_header_field_of_the_record_is_checked() {
        let good = AUDIT_RULE_LEN as u16;
        assert_eq!(parse_response_info(&rule(FAN_RESPONSE_INFO_NONE, 0, good, 1, 0, 0)),
                   Err(Errno::Einval));
        assert_eq!(parse_response_info(&rule(2, 0, good, 1, 0, 0)), Err(Errno::Einval));
        assert_eq!(parse_response_info(&rule(FAN_RESPONSE_INFO_AUDIT_RULE, 1, good, 1, 0, 0)),
                   Err(Errno::Einval));
        assert_eq!(parse_response_info(&rule(FAN_RESPONSE_INFO_AUDIT_RULE, 0, good - 1, 1, 0, 0)),
                   Err(Errno::Einval));
    }

    /// `response_errno` reads only the top byte. # C: O(1)
    #[test]
    fn errno_is_packed_into_the_high_byte() {
        assert_eq!(response_errno(FAN_DENY), 0);
        assert_eq!(response_errno(FAN_DENY | (5 << 24)), 5);
        assert_eq!(response_errno(0xff00_0000), 0xff);
        assert_eq!(response_errno(0x00ff_ffff), 0, "no low bit leaks into the errno");
    }

    /// A verdict that did not ask to be audited produces no record at all.
    #[test]
    fn a_verdict_without_the_audit_flag_records_nothing() {
        assert_eq!(audited_response(FAN_ALLOW), None);
        assert_eq!(audited_response(FAN_DENY), None);
        assert_eq!(audited_response(FAN_DENY | FAN_INFO), None);
        assert_eq!(audited_response(0), None);
    }

    /// The audit request itself is dropped from the recorded word: it says how
    /// the decision is to be handled, not what was decided.
    #[test]
    fn the_recorded_word_keeps_the_verdict_and_drops_the_audit_request() {
        assert_eq!(audited_response(FAN_ALLOW | FAN_AUDIT), Some(FAN_ALLOW));
        assert_eq!(audited_response(FAN_DENY | FAN_AUDIT), Some(FAN_DENY));
        assert_eq!(audited_response(FAN_DENY | FAN_AUDIT | FAN_INFO),
            Some(FAN_DENY | FAN_INFO));
    }

    /// The packed errno is the accessor's answer, not the daemon's decision,
    /// so it does not reach the record.
    #[test]
    fn the_recorded_word_drops_the_packed_errno() {
        let denial = FAN_DENY | FAN_AUDIT | (Errno::Enospc as u32) << ERRNO_SHIFT;
        assert_eq!(audited_response(denial), Some(FAN_DENY));
    }
}
