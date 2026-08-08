// `BPF_PROG_ASSOC_STRUCT_OPS` — associate a loaded program with the
// struct_ops map whose implementation it participates in.
//
// The association itself needs a `BPF_MAP_TYPE_STRUCT_OPS` map. This
// kernel implements no such map type, so every request that survives the
// ladder below ends on the reference's own "that map is not a struct_ops
// map" `-EINVAL` — the last rung, reached in the right order, rather than
// a substituted refusal earlier on. See the missing-struct_ops row in
// `scratch/known_issues.md`.

use syscall::errno::Errno;

use super::super::attr::{self, Attr};
use super::super::uapi;
use super::super::{BpfMapInode, BpfProgInode};
use super::objfd;

/// A `BPF_PROG_TYPE_STRUCT_OPS` program *is* an implementation rather
/// than a participant, so associating one is a caller error. # C: O(1)
fn assoc_prog_type_verdict(prog_type: u32) -> Result<(), Errno> {
    if prog_type == uapi::prog_type::STRUCT_OPS { return Err(Errno::Einval); }
    Ok(())
}

/// Only a struct_ops map can be associated with. # C: O(1)
fn assoc_map_type_verdict(map_type: u32) -> Result<(), Errno> {
    // `BPF_MAP_TYPE_STRUCT_OPS` has no entry in this kernel's map-type
    // table, so no created map can carry it and every map reaching here
    // fails this test.
    let _ = map_type;
    Err(Errno::Einval)
}

/// `prog_assoc_struct_ops()`. # C: O(1)
pub(in super::super) fn assoc(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::prog_assoc_struct_ops as o;
    attr::check_attr(a, o::LAST_END)?;
    if a.u32_at(o::FLAGS) != 0 { return Err(Errno::Einval); }
    let prog = objfd::prog_from_fd(a.u32_at(o::PROG_FD))?;
    assoc_prog_type_verdict(prog.private::<BpfProgInode>().ok_or(Errno::Einval)?.prog_type)?;
    let map = super::super::map::map_from_fd(a.u32_at(o::MAP_FD))?;
    assoc_map_type_verdict(map.private::<BpfMapInode>().ok_or(Errno::Einval)?.map_type)
        .map(|()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_attr_boundary_is_offsetofend_prog_assoc_struct_ops_flags() {
        assert_eq!(uapi::off::prog_assoc_struct_ops::LAST_END, 12);
        assert_eq!(uapi::off::prog_assoc_struct_ops::MAP_FD, 0);
        assert_eq!(uapi::off::prog_assoc_struct_ops::PROG_FD, 4);
        let mut a = Attr::zeroed();
        a.bytes[uapi::off::prog_assoc_struct_ops::LAST_END] = 1;
        assert_eq!(assoc(&a), Err(Errno::Einval));
    }

    /// `flags` is rejected before either descriptor is resolved, so a
    /// nonzero flag with closed fds is EINVAL rather than EBADF.
    #[test]
    fn nonzero_flags_are_rejected_before_the_descriptors() {
        let mut a = Attr::zeroed();
        let o = uapi::off::prog_assoc_struct_ops::FLAGS;
        a.bytes[o..o + 4].copy_from_slice(&1u32.to_ne_bytes());
        let fd = uapi::off::prog_assoc_struct_ops::PROG_FD;
        a.bytes[fd..fd + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(assoc(&a), Err(Errno::Einval));
    }

    #[test]
    fn a_struct_ops_program_cannot_be_associated_with_a_struct_ops_map() {
        assert_eq!(assoc_prog_type_verdict(uapi::prog_type::STRUCT_OPS), Err(Errno::Einval));
        assert_eq!(assoc_prog_type_verdict(uapi::prog_type::SOCKET_FILTER), Ok(()));
        assert_eq!(assoc_prog_type_verdict(uapi::prog_type::CGROUP_SKB), Ok(()));
    }

    /// No map type this kernel can create is a struct_ops map, so the
    /// association's last rung refuses every one of them.
    #[test]
    fn no_creatable_map_type_satisfies_the_association() {
        use uapi::map_type as m;
        for map_type in [m::HASH, m::ARRAY, m::LPM_TRIE] {
            assert_eq!(assoc_map_type_verdict(map_type), Err(Errno::Einval));
        }
    }
}
