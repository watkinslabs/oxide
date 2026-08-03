// Fault-recoverable transfer of a fixed-size ioctl argument struct.
//
// A raw `read_volatile`/`write_volatile` on a user pointer is NOT how the
// kernel touches user memory: a range check proves only that the address is in
// the user half, not that it is mapped with the right permission. Such a
// dereference from kernel mode has no exception-table entry, so a bogus pointer
// halts the CPU instead of returning `EFAULT` — a fault any unprivileged
// process can trigger at will. `uaccess` routes through the arch copy routines
// whose faulting instructions ARE in the exception table. Going through a byte
// buffer also removes the alignment requirement a typed dereference imposes on
// a pointer userspace chose.

use syscall::errno::Errno;

/// Read one `repr(C)` ioctl argument struct out of user memory.
/// # C: O(size_of::<T>())
pub fn read_arg<T: Copy>(arg: u64) -> Result<T, Errno> {
    let mut raw = [0u8; MAX_ARG_BYTES];
    let len = core::mem::size_of::<T>();
    if len > MAX_ARG_BYTES { return Err(Errno::Einval); }
    uaccess::copy_from_user(&mut raw[..len], arg)?;
    // SAFETY: `T: Copy` is a plain-data ioctl struct with no padding invariant
    // and no niche, `raw` holds exactly `size_of::<T>()` initialized bytes
    // copied from user memory, and `read_unaligned` imposes no alignment on the
    // stack buffer. Any bit pattern is a valid `T` for these repr(C) structs.
    Ok(unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const T) })
}

/// Write one `repr(C)` ioctl argument struct back to user memory.
/// # C: O(size_of::<T>())
pub fn write_arg<T: Copy>(arg: u64, value: T) -> Result<(), Errno> {
    let mut raw = [0u8; MAX_ARG_BYTES];
    let len = core::mem::size_of::<T>();
    if len > MAX_ARG_BYTES { return Err(Errno::Einval); }
    // SAFETY: `value` lives on this frame for the whole copy, `raw` has at
    // least `len` bytes, and the two cannot overlap (one is a parameter by
    // value, the other a local array). `T: Copy` means the byte image is a
    // complete description of the value.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (&value as *const T) as *const u8, raw.as_mut_ptr(), len);
    }
    uaccess::copy_to_user(arg, &raw[..len])
}

/// Copy a driver-identity string into a user buffer, truncated to the length
/// the caller advertised. The caller's pointer and length are its own claim
/// about its buffer; `uaccess` decides whether the range is really writable,
/// and a short or unmapped buffer is `EFAULT` rather than a kernel fault.
/// # C: O(min(len, bytes))
pub fn write_str(dst: u64, len: u64, bytes: &[u8]) -> Result<(), Errno> {
    if dst == 0 || len == 0 { return Ok(()); }
    let n = (len as usize).min(bytes.len());
    if n == 0 { return Ok(()); }
    uaccess::copy_to_user(dst, &bytes[..n])
}

/// Largest DRM ioctl argument struct handled through [`read_arg`]/[`write_arg`].
/// `DrmModeFbCmd2` (4 handles + 4 pitches + 4 offsets + 4 modifiers) is the
/// biggest at 88 bytes; the buffer is sized with headroom and every call checks.
const MAX_ARG_BYTES: usize = 128;

#[cfg(test)]
mod tests {
    use super::{MAX_ARG_BYTES, read_arg, write_arg};

    #[test]
    fn every_drm_ioctl_arg_struct_fits_the_transfer_buffer() {
        use crate::dumb::*;
        assert!(core::mem::size_of::<DrmModeCreateDumb>() <= MAX_ARG_BYTES);
        assert!(core::mem::size_of::<DrmModeMapDumb>() <= MAX_ARG_BYTES);
        assert!(core::mem::size_of::<DrmModeDestroyDumb>() <= MAX_ARG_BYTES);
        assert!(core::mem::size_of::<DrmModeFbCmd>() <= MAX_ARG_BYTES);
        assert!(core::mem::size_of::<DrmModeFbCmd2>() <= MAX_ARG_BYTES);
        assert!(core::mem::size_of::<DrmModeCloseFb>() <= MAX_ARG_BYTES);
        assert!(core::mem::size_of::<DrmGemClose>() <= MAX_ARG_BYTES);
    }

    /// A user pointer of zero must reach the caller as an error, not a
    /// dereference — the property the raw `read_volatile` could not provide.
    #[test]
    fn a_null_user_pointer_is_reported_not_dereferenced() {
        assert!(read_arg::<u64>(0).is_err());
        assert!(write_arg::<u64>(0, 0).is_err());
    }

    /// The handlers converted to the fault-recoverable path stay converted.
    /// A raw dereference reintroduced into any of them is a fault an
    /// unprivileged process can aim at the kernel, and nothing else in the
    /// tree would notice it — `cargo check` compiles it happily.
    #[test]
    fn the_converted_ioctl_handlers_hold_no_raw_user_dereference() {
        for (name, source) in [
            ("node.rs", include_str!("node.rs")),
            ("node/client_caps.rs", include_str!("node/client_caps.rs")),
            ("node/virtgpu.rs", include_str!("node/virtgpu.rs")),
            ("crtc/handlers.rs", include_str!("crtc/handlers.rs")),
        ] {
            assert!(!source.contains("read_volatile"), "{name} dereferences a user pointer");
            assert!(!source.contains("write_volatile"), "{name} writes a user pointer");
        }
    }

    /// A driver-identity string is copied only where the caller offered room:
    /// a null pointer or a zero length is the caller declining the field, not
    /// an error, which is how the reference answers a two-pass size query.
    #[test]
    fn a_declined_string_field_is_skipped_rather_than_written() {
        assert!(super::write_str(0, 16, b"virtio_gpu").is_ok());
        assert!(super::write_str(0x1000, 0, b"virtio_gpu").is_ok());
        // With room offered, the transfer is attempted rather than skipped:
        // an address outside the user half is reported, not written.
        assert!(super::write_str(u64::MAX, 16, b"virtio_gpu").is_err());
    }
}
