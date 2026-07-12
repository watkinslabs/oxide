use super::cooked_tty;
use vfs::VfsError;

#[test]
fn tioc_excl_blocks_non_admin_reopen_until_cleared() {
    let tty = cooked_tty();
    assert_eq!(tty.open_with_cap_sys_admin(false), Ok(1));
    tty.set_exclusive(true);
    assert!(tty.exclusive());
    assert_eq!(tty.open_with_cap_sys_admin(false), Err(VfsError::Ebusy));
    assert_eq!(tty.open_count(), 1, "rejected reopen must not bump count");
    tty.set_exclusive(false);
    assert_eq!(tty.open_with_cap_sys_admin(false), Ok(2));
}

#[test]
fn tioc_excl_admin_bypass_matches_linux_reopen_rule() {
    let tty = cooked_tty();
    assert_eq!(tty.open_with_cap_sys_admin(false), Ok(1));
    tty.set_exclusive(true);
    assert_eq!(tty.open_with_cap_sys_admin(true), Ok(2));
}
