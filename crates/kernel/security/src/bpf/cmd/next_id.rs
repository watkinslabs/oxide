// `BPF_OBJ_GET_NEXT_ID` — one ladder shared by every object kind.
//
// PROG, MAP, BTF and LINK differ only in which registry the walk consults;
// the admission order, the `INT_MAX` bound, the capability, the ENOENT for
// an exhausted walk and the write-back offset are identical, so they live
// here once and each command supplies its walker.

use syscall::errno::Errno;

use super::super::attr::{self, Attr, Caps};
use super::super::uapi;
use super::super::user;

/// Admission for one `BPF_OBJ_GET_NEXT_ID`: the zero-tail check and the
/// `INT_MAX` bound are one `-EINVAL` decided *before* the capability, so
/// an unprivileged caller passing a silly `start_id` sees EINVAL rather
/// than EPERM. Returns the starting id the walk resumes from.
/// # C: O(ATTR_SIZE)
pub(crate) fn admit(a: &Attr, caps: Caps) -> Result<u32, Errno> {
    use uapi::off::object_id as o;
    attr::check_attr(a, o::NEXT_LAST_END)?;
    let start = a.u32_at(o::START_ID);
    if start >= uapi::OBJECT_ID_LIMIT { return Err(Errno::Einval); }
    if !caps.sys_admin { return Err(Errno::Eperm); }
    Ok(start)
}

/// Address `next_id` is written back to. # C: O(1)
pub(crate) fn next_id_out(attr_ptr: u64) -> Result<u64, Errno> {
    attr_ptr
        .checked_add(uapi::off::object_id::NEXT_ID as u64)
        .ok_or(Errno::Efault)
}

/// Run the whole command: admit, walk strictly above `start_id`, and copy
/// the answer back into the caller's attr. An exhausted walk is `-ENOENT`
/// and writes nothing. # C: O(live objects of that kind)
pub(crate) fn get_next_id(
    a: &Attr,
    attr_ptr: u64,
    caps: Caps,
    walk: impl FnOnce(u32) -> Option<u32>,
) -> Result<i64, Errno> {
    let start = admit(a, caps)?;
    let next = walk(start).ok_or(Errno::Enoent)?;
    user::write_bytes(next_id_out(attr_ptr)?, &next.to_ne_bytes())?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> Caps { Caps { bpf: false, sys_admin: true, net_admin: false, perfmon: false } }

    fn attr_with(start: u32) -> Attr {
        let mut a = Attr::zeroed();
        let off = uapi::off::object_id::START_ID;
        a.bytes[off..off + 4].copy_from_slice(&start.to_ne_bytes());
        a
    }

    #[test]
    fn zero_tail_boundary_is_offsetofend_next_id() {
        assert_eq!(uapi::off::object_id::NEXT_LAST_END, 8);
        let mut a = attr_with(1);
        // `next_id` itself sits inside the checked region's start; a byte
        // set past it is the caller asking for a field that is not part
        // of this command.
        a.bytes[uapi::off::object_id::NEXT_LAST_END] = 1;
        assert_eq!(admit(&a, admin()), Err(Errno::Einval));
    }

    #[test]
    fn start_id_at_or_above_int_max_is_einval_before_the_capability() {
        let unprivileged = Caps::default();
        assert_eq!(admit(&attr_with(uapi::OBJECT_ID_LIMIT), unprivileged), Err(Errno::Einval));
        assert_eq!(admit(&attr_with(u32::MAX), admin()), Err(Errno::Einval));
        assert_eq!(admit(&attr_with(uapi::OBJECT_ID_LIMIT - 1), admin()), Ok(uapi::OBJECT_ID_LIMIT - 1));
    }

    #[test]
    fn a_well_formed_request_without_cap_sys_admin_is_eperm() {
        assert_eq!(admit(&attr_with(0), Caps::default()), Err(Errno::Eperm));
        let bpf_only = Caps { bpf: true, sys_admin: false, net_admin: true, perfmon: true };
        assert_eq!(admit(&attr_with(0), bpf_only), Err(Errno::Eperm));
    }

    #[test]
    fn the_walk_starts_strictly_above_start_id_and_ends_in_enoent() {
        let live = [3u32, 7, 9];
        let walk = |start: u32| live.iter().copied().find(|id| *id > start);
        assert_eq!(walk(0), Some(3));
        assert_eq!(walk(3), Some(7));
        assert_eq!(walk(9), None);

        let mut out = [0u8; uapi::ATTR_SIZE];
        let ptr = out.as_mut_ptr() as u64;
        assert_eq!(get_next_id(&attr_with(3), ptr, admin(), walk), Ok(0));
        let off = uapi::off::object_id::NEXT_ID;
        assert_eq!(u32::from_ne_bytes(out[off..off + 4].try_into().unwrap()), 7);

        assert_eq!(get_next_id(&attr_with(9), ptr, admin(), walk), Err(Errno::Enoent));
        // ENOENT wrote nothing: the previous answer is still there.
        assert_eq!(u32::from_ne_bytes(out[off..off + 4].try_into().unwrap()), 7);
    }

    #[test]
    fn the_write_back_offset_is_next_id_not_start_id() {
        assert_eq!(uapi::off::object_id::NEXT_ID, 4);
        assert_eq!(next_id_out(0x1000), Ok(0x1004));
        assert_eq!(next_id_out(u64::MAX), Err(Errno::Efault));
    }
}
