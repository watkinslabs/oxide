// Native recvmsg entry admission — settle the message layout before any
// user-visible work, then do the descriptor and the msghdr in Linux's order.

use syscall::errno::Errno;

use crate::msg_layout::{EntryAbi, MsgLayout, entry_layout};

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// Ask the layout owner first, then resolve the descriptor, then import the
/// caller's `msghdr` in the layout it answered with. The import takes the
/// layout as an argument: no step below re-reads `MSG_CMSG_COMPAT` to pick a
/// shape. # C: O(1)
pub(crate) fn prepare<T, U>(flags: u64, abi: EntryAbi, lookup: impl FnOnce() -> Result<T, i64>,
    import: impl FnOnce(MsgLayout) -> Result<U, i64>) -> Result<(MsgLayout, T, U), i64>
{
    let layout = entry_layout(flags, abi).map_err(err)?;
    let target = lookup()?;
    let user = import(layout)?;
    Ok((layout, target, user))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU8, Ordering};
    use net::uapi::{MSG_CMSG_CLOEXEC, MSG_CMSG_COMPAT};

    const LOOKUP_CALLED: u8 = 1;
    const IMPORT_CALLED: u8 = 2;

    #[test]
    fn cmsg_compat_precedes_invalid_fd_and_msghdr() {
        let calls = AtomicU8::new(0);
        let result: Result<(MsgLayout, (), ()), i64> = prepare(MSG_CMSG_COMPAT, EntryAbi::Native,
            || { calls.fetch_or(LOOKUP_CALLED, Ordering::Relaxed); Err(Errno::Ebadf.as_i32() as i64) },
            |_| { calls.fetch_or(IMPORT_CALLED, Ordering::Relaxed); Err(Errno::Efault.as_i32() as i64) });
        assert_eq!(result, Err(err(Errno::Einval)));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cmsg_cloexec_keeps_normal_lookup_and_import_order() {
        let calls = AtomicU8::new(0);
        let result = prepare(MSG_CMSG_CLOEXEC, EntryAbi::Native,
            || { calls.fetch_or(LOOKUP_CALLED, Ordering::Relaxed); Ok::<_, i64>("fd") },
            |_| { calls.fetch_or(IMPORT_CALLED, Ordering::Relaxed); Ok::<_, i64>("msghdr") });
        assert_eq!(result, Ok((MsgLayout::Native, "fd", "msghdr")));
        assert_eq!(calls.load(Ordering::Relaxed), LOOKUP_CALLED | IMPORT_CALLED);
    }

    // The compat entry is the one caller allowed to speak the 32-bit layout,
    // and the importer it hands the descriptor to is told so by value.
    #[test]
    fn the_compat_entry_selects_the_compat_layout_for_the_importer() {
        let seen = AtomicU8::new(0);
        let result = prepare(MSG_CMSG_COMPAT, EntryAbi::Compat, || Ok::<_, i64>("fd"),
            |layout| { if layout.is_compat() { seen.store(1, Ordering::Relaxed); } Ok::<_, i64>(layout) });
        assert_eq!(result, Ok((MsgLayout::Compat, "fd", MsgLayout::Compat)));
        assert_eq!(seen.load(Ordering::Relaxed), 1);
    }

    // A compat caller reaches the compat layout even when the bit did not
    // survive its way in: the ENTRY is the fact, the flag only records it.
    #[test]
    fn the_compat_entry_does_not_depend_on_the_flag_reaching_it() {
        let result = prepare(0, EntryAbi::Compat, || Ok::<_, i64>(()), |layout| Ok::<_, i64>(layout));
        assert_eq!(result, Ok((MsgLayout::Compat, (), MsgLayout::Compat)));
    }
}
