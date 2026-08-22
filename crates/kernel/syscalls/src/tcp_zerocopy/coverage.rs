// Target-neutral seams for the TCP zero-copy receive's VMA and copy rules.
// The target syscall supplies the live address-space and uaccess owners.

use syscall::errno::Errno;

/// One candidate receive-window span in the caller's address space. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowSpan {
    pub start: u64,
    pub end: u64,
}

/// Admit an address only when it lies inside the TCP-owned VMA. # C: O(1)
pub fn window_at(address: u64, span: WindowSpan) -> Option<WindowSpan> {
    (address >= span.start && address < span.end).then_some(span)
}

/// Limit one receive fragment to the caller's remaining copy buffer, invoke
/// the uaccess owner, and report bytes consumed only after that succeeds.
/// # C: O(1)
pub fn copy_chunk<F>(src: &[u8], remaining: u32, copy: F) -> Result<(usize, usize), Errno>
where F: FnOnce(&[u8]) -> Result<(), Errno>
{
    let take = src.len().min(remaining as usize);
    if take == 0 { return Ok((0, 0)); }
    copy(&src[..take])?;
    Ok((take, take))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_tcp_owned_vma_span_resolves_the_address() {
        let span = WindowSpan { start: 0x10_000, end: 0x12_000 };
        assert_eq!(window_at(0x10_000, span), Some(span));
        assert_eq!(window_at(0x11_fff, span), Some(span));
        assert_eq!(window_at(0x0f_fff, span), None);
        assert_eq!(window_at(0x12_000, span), None);
    }

    #[test]
    fn a_faulting_copy_does_not_report_or_consume_the_fragment() {
        let mut called = false;
        let result = copy_chunk(b"payload", 7, |_| {
            called = true;
            Err(Errno::Efault)
        });
        assert_eq!(result, Err(Errno::Efault));
        assert!(called);
    }

    #[test]
    fn a_copy_reports_only_the_offered_prefix_after_uaccess_succeeds() {
        let mut copied = alloc::vec::Vec::new();
        let result = copy_chunk(b"payload", 4, |part| {
            copied.extend_from_slice(part);
            Ok(())
        });
        assert_eq!(result, Ok((4, 4)));
        assert_eq!(copied, b"payl");
    }
}
