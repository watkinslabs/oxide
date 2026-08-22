// `/sys/kernel/btf/vmlinux` — the kernel's canonical BTF object.
//
// The security BPF owner builds and resolves one byte object. Sysfs projects
// that SAME object rather than serialising a second description: loaders read
// the type ids here and hand them back to the BPF load path, so two owners
// could make a valid id name the wrong attach target.

use alloc::sync::Arc;

use vfs::{mk_mode, FileOps, FileType, Inode, InodeBuilder, KResult, VfsError};

use crate::{register, register_dir, RO_PERM};

const INO_VMLINUX: u64 = crate::ids::BTF_VMLINUX;

struct KernelBtfOps;
impl FileOps for KernelBtfOps {
    /// kernfs binary attributes install a poll operation even though this
    /// immutable object never changes. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    /// `sysfs_bin_attr_simple_read`: honour the caller's file offset and drain
    /// the canonical kernel BTF byte object directly. # C: O(buf length)
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        Ok(security::bpf::kernel_btf_read(off, buf))
    }

    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

fn make_vmlinux_inode() -> Option<vfs::InodeRef> {
    let size = security::bpf::kernel_btf_len();
    if size == 0 { return None; }
    Some(InodeBuilder::new(INO_VMLINUX, mk_mode(FileType::Regular, RO_PERM),
        crate::kobject::attr_inode_ops(), Arc::new(KernelBtfOps))
        .size(size)
        .build())
}

/// Publish the BTF directory only when the kernel has a non-empty object,
/// matching Linux's `btf_vmlinux_init` omission rule. # C: O(BTF build)
pub(super) fn init() {
    let Some(inode) = make_vmlinux_inode() else { return; };
    register_dir("/sys/kernel/btf");
    register("/sys/kernel/btf/vmlinux", inode);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_reads_drain_the_canonical_kernel_btf_object() {
        let inode = make_vmlinux_inode().expect("kernel BTF object");
        let size = security::bpf::kernel_btf_len();
        assert_eq!(inode.size(), size);

        let mut got = [0u8; 23];
        let mut expected = [0u8; 23];
        let got_n = inode.read(7, &mut got).expect("sysfs BTF read");
        let expected_n = security::bpf::kernel_btf_read(7, &mut expected);
        assert_eq!(got_n, expected_n);
        assert_eq!(&got[..got_n], &expected[..expected_n]);
        assert_eq!(inode.read(size, &mut got), Ok(0), "EOF is the object length");
    }

    #[test]
    fn the_binary_attribute_is_read_only() {
        let inode = make_vmlinux_inode().expect("kernel BTF object");
        assert_eq!(inode.write(0, b"not btf"), Err(VfsError::Erofs));
        assert_eq!(inode.i_mode() & 0o777, RO_PERM);
    }
}
