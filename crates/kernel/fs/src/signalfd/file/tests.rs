//! signalfd file-surface contracts provable without a runqueue: the mask
//! admitted by the inode, the `fdinfo` rendering, and the buffer-size rule.

use super::*;

fn fdinfo_of(mask: u64) -> alloc::string::String {
    let inode = make_signalfd_inode(mask);
    let mut out = Vec::new();
    inode.fdinfo_extra(&mut out);
    alloc::string::String::from_utf8(out).unwrap()
}

#[test]
fn fdinfo_renders_sixteen_nibbles_most_significant_first() {
    // Signal 64 is the top bit of the first nibble; signal 1 the bottom bit
    // of the last. Getting the direction wrong silently mislabels every fd.
    let sig1 = 1u64 << 0;
    let sig64 = 1u64 << 63;
    assert_eq!(fdinfo_of(sig1), "sigmask:\t0000000000000001\n");
    assert_eq!(fdinfo_of(sig64), "sigmask:\t8000000000000000\n");
    assert_eq!(fdinfo_of(0), "sigmask:\t0000000000000000\n");
    assert_eq!(fdinfo_of(u64::MAX), "sigmask:\tffffffffffffffff\n");
}

#[test]
fn fdinfo_reports_the_accepted_set_not_its_complement() {
    let sigusr1 = 1u64 << (sched::signum::Signum::Sigusr1 as u64 - 1);
    let text = fdinfo_of(sigusr1);
    assert!(text.ends_with("0000000000000200\n"), "got {text}");
}

#[test]
fn a_signalfd_has_no_write_operation() {
    let inode = make_signalfd_inode(0);
    assert_eq!(inode.i_fop().write(&inode, 0, &[0u8; 8]), Err(VfsError::Einval));
}

#[test]
fn a_buffer_shorter_than_one_record_is_einval_not_a_short_read() {
    let inode = make_signalfd_inode(u64::MAX);
    let mut buf = [0u8; SIGINFO_SIZE - 1];
    assert_eq!(inode.i_fop().read(&inode, 0, &mut buf), Err(VfsError::Einval));
    assert_eq!(inode.i_fop().read_nonblock(&inode, 0, &mut buf), Err(VfsError::Einval));
}
