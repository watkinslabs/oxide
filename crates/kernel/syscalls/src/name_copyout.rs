// Name-query value-result copyout admission shared by getsockname/getpeername.

use syscall::errno::Errno;

/// Match Linux `move_addr_to_user`: publish full length before address copy. # Lk: net/socket.c:move_addr_to_user # C: O(1)
pub(crate) fn copy_sockaddr_value_result(read_len: impl FnOnce() -> Result<i32, Errno>,
    full_len: u32, write_len: impl FnOnce(u32) -> Result<(), Errno>,
    copy_addr: impl FnOnce(usize) -> Result<(), Errno>) -> Result<(), Errno>
{
    let user_len = read_len()?;
    if user_len < 0 { return Err(Errno::Einval); }
    let copy_len = core::cmp::min(user_len as usize, full_len as usize);
    write_len(full_len)?;
    if copy_len != 0 { copy_addr(copy_len)?; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    fn invalid_address_after_length(route: &str) {
        let published = Cell::new(None);
        let result = copy_sockaddr_value_result(|| Ok(128), 16,
            |len| { published.set(Some(len)); Ok(()) },
            |_| { assert_eq!(published.get(), Some(16), "{route}"); Err(Errno::Efault) });
        assert_eq!(result, Err(Errno::Efault));
        assert_eq!(published.get(), Some(16));
    }

    #[test]
    fn getsockname_and_getpeername_publish_length_before_invalid_address() {
        invalid_address_after_length("getsockname");
        invalid_address_after_length("getpeername");
    }

    #[test]
    fn zero_length_publishes_full_length_without_address_access() {
        let published = Cell::new(None);
        let address_called = Cell::new(false);
        let result = copy_sockaddr_value_result(|| Ok(0), 16,
            |len| { published.set(Some(len)); Ok(()) },
            |_| { address_called.set(true); Ok(()) });
        assert_eq!(result, Ok(()));
        assert_eq!(published.get(), Some(16));
        assert!(!address_called.get());
    }

    #[test]
    fn negative_length_rejects_without_copyout() {
        let copied = Cell::new(false);
        let result = copy_sockaddr_value_result(|| Ok(-1), 16,
            |_| { copied.set(true); Ok(()) }, |_| { copied.set(true); Ok(()) });
        assert_eq!(result, Err(Errno::Einval));
        assert!(!copied.get());
    }

    #[test]
    fn short_buffer_publishes_full_length_and_copies_the_short_prefix() {
        let published = Cell::new(None);
        let copied = Cell::new(None);
        let result = copy_sockaddr_value_result(|| Ok(4), 16,
            |len| { published.set(Some(len)); Ok(()) },
            |len| { copied.set(Some(len)); Ok(()) });
        assert_eq!(result, Ok(()));
        assert_eq!(published.get(), Some(16));
        assert_eq!(copied.get(), Some(4));
    }
}
