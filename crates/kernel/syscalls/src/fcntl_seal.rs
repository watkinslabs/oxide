use syscall::errno::Errno;
use vfs::{
    F_ALL_SEALS, F_SEAL_EXEC, F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL,
    F_SEAL_SHRINK, F_SEAL_WRITE,
};

/// Linux `memfd_add_seals` admission and implied-seal decision
/// (`mm/memfd.c`). The caller atomically publishes the returned bits.
/// # C: O(1)
pub fn plan_add_seals(
    writable: bool,
    requested: u32,
    current: Option<u32>,
    inode_mode: u16,
) -> Result<u32, Errno> {
    if !writable {
        return Err(Errno::Eperm);
    }
    if requested & !F_ALL_SEALS != 0 {
        return Err(Errno::Einval);
    }
    let current = current.ok_or(Errno::Einval)?;
    if current & F_SEAL_SEAL != 0 {
        return Err(Errno::Eperm);
    }
    let mut add = requested;
    if requested & F_SEAL_EXEC != 0 && inode_mode & 0o111 != 0 {
        add |= F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
    }
    Ok(add)
}

/// Linux `memfd_check_seals_mmap`: either write seal rejects a new
/// `MAP_SHARED|PROT_WRITE` mapping and removes `VM_MAYWRITE` from a new
/// read-only shared mapping. Private mappings are unaffected. # C: O(1)
pub fn plan_write_sealed_mmap(
    seals: u32,
    shared: bool,
    write: bool,
    may_write: bool,
) -> Result<bool, Errno> {
    if !shared || seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) == 0 {
        return Ok(may_write);
    }
    if write { return Err(Errno::Eperm); }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_fd_precedes_mask_and_inode_type_checks() {
        assert_eq!(plan_add_seals(false, u32::MAX, None, 0o777), Err(Errno::Eperm));
    }

    #[test]
    fn mask_precedes_inode_type_and_seal_seal() {
        assert_eq!(plan_add_seals(true, 1 << 31, None, 0o777), Err(Errno::Einval));
        assert_eq!(
            plan_add_seals(true, 1 << 31, Some(F_SEAL_SEAL), 0o777),
            Err(Errno::Einval),
        );
    }

    #[test]
    fn only_sealable_inodes_accept_valid_requests() {
        assert_eq!(plan_add_seals(true, F_SEAL_EXEC, None, 0o777), Err(Errno::Einval));
        assert_eq!(
            plan_add_seals(true, F_SEAL_EXEC, Some(F_SEAL_SEAL), 0o777),
            Err(Errno::Eperm),
        );
    }

    #[test]
    fn exec_seal_on_executable_inode_implies_write_and_size_seals() {
        let add = plan_add_seals(true, F_SEAL_EXEC, Some(0), 0o777).unwrap();
        assert_eq!(
            add,
            F_SEAL_EXEC
                | F_SEAL_SHRINK
                | F_SEAL_GROW
                | F_SEAL_WRITE
                | F_SEAL_FUTURE_WRITE,
        );
    }

    #[test]
    fn exec_seal_on_non_executable_inode_adds_only_itself() {
        assert_eq!(
            plan_add_seals(true, F_SEAL_EXEC, Some(0), 0o666),
            Ok(F_SEAL_EXEC),
        );
    }

    #[test]
    fn every_linux_seal_bit_is_accepted() {
        assert_eq!(plan_add_seals(true, F_ALL_SEALS, Some(0), 0), Ok(F_ALL_SEALS));
    }

    #[test]
    fn either_write_seal_rejects_new_writable_shared_mappings() {
        for seal in [F_SEAL_WRITE, F_SEAL_FUTURE_WRITE] {
            assert_eq!(
                plan_write_sealed_mmap(seal, true, true, true),
                Err(Errno::Eperm),
            );
        }
    }

    #[test]
    fn either_write_seal_strips_maywrite_from_new_read_only_shared_mappings() {
        for seal in [F_SEAL_WRITE, F_SEAL_FUTURE_WRITE] {
            assert_eq!(plan_write_sealed_mmap(seal, true, false, true), Ok(false));
        }
    }

    #[test]
    fn private_and_unsealed_mappings_keep_their_maywrite_right() {
        assert_eq!(plan_write_sealed_mmap(F_SEAL_WRITE, false, true, true), Ok(true));
        assert_eq!(plan_write_sealed_mmap(0, true, true, true), Ok(true));
    }
}
