use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::{FdTable, OpenFlags};

use cgroup::tree::ROOT;
use super::super::link::{cgroup_link_by_id, prime_bpf_cgroup_link_with};
use super::super::{
    make_bpf_prog_inode,
};
use super::super::uapi;

fn prog() -> vfs::InodeRef {
    make_bpf_prog_inode(uapi::prog_type::CGROUP_DEVICE, alloc::vec::Vec::new())
}

#[test]
fn emfile_happens_before_link_id_or_attachment_resources_are_reserved() {
    let fdt = Arc::new(FdTable::new());
    let _runtime = cgroup::bpf::root_runtime();
    let before = cgroup::bpf::query(ROOT, cgroup::CgroupBpfAttachType::Device)
        .unwrap().revision;
    let result = prime_bpf_cgroup_link_with(
        Arc::clone(&fdt),
        0,
        ROOT,
        cgroup::CgroupBpfAttachType::Device,
        prog(),
    );
    assert!(matches!(result, Err(Errno::Emfile)));
    assert_eq!(fdt.count(), 0);
    assert_eq!(
        cgroup::bpf::query(ROOT, cgroup::CgroupBpfAttachType::Device)
            .unwrap().revision,
        before,
    );
}

#[test]
fn unsettled_link_id_is_eagain_and_failed_attach_cleans_its_fd() {
    let fdt = Arc::new(FdTable::new());
    let program = prog();
    let _runtime = cgroup::bpf::root_runtime();
    let before = cgroup::bpf::query(ROOT, cgroup::CgroupBpfAttachType::Device)
        .unwrap().revision;
    let primer = prime_bpf_cgroup_link_with(
        Arc::clone(&fdt),
        1,
        ROOT,
        cgroup::CgroupBpfAttachType::Device,
        Arc::clone(&program),
    ).unwrap();
    let id = primer.id();
    assert!(matches!(cgroup_link_by_id(id), Err(Errno::Eagain)));

    assert_eq!(
        cgroup::bpf::attach_link(
            ROOT,
            cgroup::CgroupBpfAttachType::Device,
            id as u64,
            program,
            cgroup::BpfAttachOrder::DEFAULT,
            before.wrapping_add(1),
        ),
        Err(cgroup::BpfAttachError::Stale),
    );
    drop(primer);
    assert!(matches!(cgroup_link_by_id(id), Err(Errno::Enoent)));
    assert_eq!(
        cgroup::bpf::query(ROOT, cgroup::CgroupBpfAttachType::Device)
            .unwrap().revision,
        before,
    );
    let fd = fdt.get_unused_fd_flags(OpenFlags::O_CLOEXEC, 1)
        .expect("failed attach returned its primed descriptor");
    assert_eq!(fd, 0);
    fdt.put_unused_fd(fd);
}

#[test]
fn settlement_publishes_the_id_and_reserved_descriptor_together() {
    let fdt = Arc::new(FdTable::new());
    let primer = prime_bpf_cgroup_link_with(
        Arc::clone(&fdt),
        1,
        ROOT,
        cgroup::CgroupBpfAttachType::Device,
        prog(),
    ).unwrap();
    let id = primer.id();
    assert_eq!(primer.settle(), 0);
    assert!(matches!(cgroup_link_by_id(id), Ok(_)));
    assert!(fdt.get(0).is_ok());
    fdt.close(0).unwrap();
    assert!(matches!(cgroup_link_by_id(id), Err(Errno::Enoent)));
}
