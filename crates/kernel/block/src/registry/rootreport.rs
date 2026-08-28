//! Rendering the "which block devices could the root have been" listing.
//!
//! Buffer-based and ungated, following the same pattern as the fault
//! reporter: the FORM is what a reader hands to a mount command or a boot
//! line, so it is testable without a kernel, and a whole line is built before
//! anything is emitted — several CPUs writing a line a field at a time
//! interleave into something nobody can read, and this listing exists for the
//! moment a boot has already gone wrong.

extern crate alloc;

/// Longest disk line this renders, including its newline.
pub const DISK_LINE_MAX: usize = 128;
/// Longest partition line this renders, including its newline.
pub const PART_LINE_MAX: usize = 256;

/// Append `src` to `out` at `n`, truncating rather than panicking. # C: O(len)
fn put(out: &mut [u8], n: &mut usize, src: &[u8]) {
    let room = out.len().saturating_sub(*n);
    let take = core::cmp::min(src.len(), room);
    out[*n..*n + take].copy_from_slice(&src[..take]);
    *n += take;
}

/// One unsigned value in decimal, no padding. # C: O(digits)
fn put_dec(out: &mut [u8], n: &mut usize, mut v: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 { break; }
    }
    put(out, n, &digits[i..]);
}

/// `  <name> sectors=<n>[ serial=<s>]` and a newline. # C: O(line)
pub fn write_disk_line(out: &mut [u8], name: &[u8], sectors_512: u64, serial: Option<&[u8]>) -> usize {
    let mut n = 0;
    put(out, &mut n, b"  ");
    put(out, &mut n, name);
    put(out, &mut n, b" sectors=");
    put_dec(out, &mut n, sectors_512);
    if let Some(s) = serial {
        put(out, &mut n, b" serial=");
        put(out, &mut n, s);
    }
    put(out, &mut n, b"\n");
    n
}

/// `    <name> start=<lba> sectors=<n> label=<l> uuid=<u>` and a newline.
///
/// A field with no value prints `-` rather than being omitted, so the columns
/// line up down the listing and an absent label is visibly absent.
/// # C: O(line)
pub fn write_partition_line(out: &mut [u8], name: &[u8], start_lba: u64, sectors: u64,
    label: Option<&[u8]>, uuid: Option<&[u8]>) -> usize {
    let mut n = 0;
    put(out, &mut n, b"    ");
    put(out, &mut n, name);
    put(out, &mut n, b" start=");
    put_dec(out, &mut n, start_lba);
    put(out, &mut n, b" sectors=");
    put_dec(out, &mut n, sectors);
    put(out, &mut n, b" label=");
    put(out, &mut n, label.unwrap_or(b"-"));
    put(out, &mut n, b" uuid=");
    put(out, &mut n, uuid.unwrap_or(b"-"));
    put(out, &mut n, b"\n");
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(buf: &[u8], n: usize) -> &str { core::str::from_utf8(&buf[..n]).unwrap() }

    #[test]
    fn a_disk_line_names_the_node_and_its_size() {
        let mut b = [0u8; DISK_LINE_MAX];
        let n = write_disk_line(&mut b, b"vda", 265728, None);
        assert_eq!(rendered(&b, n), "  vda sectors=265728\n");
    }

    #[test]
    fn a_serial_is_appended_when_the_disk_reports_one() {
        let mut b = [0u8; DISK_LINE_MAX];
        let n = write_disk_line(&mut b, b"vda", 1, Some(b"oxide-root"));
        assert_eq!(rendered(&b, n), "  vda sectors=1 serial=oxide-root\n");
    }

    #[test]
    fn a_partition_line_carries_what_a_root_spec_can_name_it_by() {
        let mut b = [0u8; PART_LINE_MAX];
        let n = write_partition_line(&mut b, b"vda4", 44904, 220024,
            Some(b"oxide-root"), Some(b"1234abcd-04"));
        assert_eq!(rendered(&b, n),
            "    vda4 start=44904 sectors=220024 label=oxide-root uuid=1234abcd-04\n");
    }

    /// An absent field keeps its column so the listing stays readable, and so
    /// a missing label is visibly missing rather than shifting every field
    /// after it one place left.
    #[test]
    fn an_absent_label_or_uuid_prints_a_dash() {
        let mut b = [0u8; PART_LINE_MAX];
        let n = write_partition_line(&mut b, b"vda1", 2048, 4096, None, None);
        assert_eq!(rendered(&b, n), "    vda1 start=2048 sectors=4096 label=- uuid=-\n");
    }

    #[test]
    fn zero_renders_as_one_digit() {
        let mut b = [0u8; DISK_LINE_MAX];
        let n = write_disk_line(&mut b, b"loop0", 0, None);
        assert_eq!(rendered(&b, n), "  loop0 sectors=0\n");
    }

    /// A name longer than the buffer truncates rather than panicking: this
    /// renders while a boot is already failing.
    #[test]
    fn an_oversized_field_truncates_instead_of_panicking() {
        let mut b = [0u8; 8];
        let n = write_disk_line(&mut b, b"a-very-long-disk-node-name", 1, None);
        assert_eq!(n, 8);
        assert_eq!(&b[..2], b"  ");
    }
}
