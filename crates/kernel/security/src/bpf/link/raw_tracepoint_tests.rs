use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

static DETACHED: AtomicU64 = AtomicU64::new(0);

fn unused_attach(_: &[u8], _: u64, _: InodeRef, _: u64)
    -> Result<&'static str, Errno> { Err(Errno::Enoent) }

fn detach(_: &str, id: u64) { DETACHED.store(id, Ordering::Release); }

fn hooks() -> RawTracepointHooks { RawTracepointHooks { attach: unused_attach, detach } }

#[test]
fn raw_link_pins_program_reports_name_and_detaches_on_final_close() {
    let fdt = Arc::new(vfs::FdTable::new());
    let prog = super::super::make_bpf_prog_inode(
        super::super::uapi::prog_type::RAW_TRACEPOINT,
        alloc::vec::Vec::new(),
    );
    let primer = prime_bpf_raw_tracepoint_link_with(
        Arc::clone(&fdt), 1, Arc::clone(&prog), 0x1234, hooks(),
    ).unwrap();
    let id = primer.id();
    assert_eq!(primer.settle("sys_enter"), 0);

    let file = fdt.get(0).unwrap();
    let info = raw_tracepoint_link_info(file.inode()).unwrap();
    assert!(Arc::ptr_eq(&info.prog, &prog));
    assert_eq!(info.name, "sys_enter");
    assert_eq!(info.cookie, 0x1234);

    DETACHED.store(0, Ordering::Release);
    drop(file);
    fdt.close(0).unwrap();
    assert_eq!(DETACHED.load(Ordering::Acquire), id);
}

#[test]
fn raw_link_reserves_fd_before_link_identity() {
    let fdt = Arc::new(vfs::FdTable::new());
    let prog = super::super::make_bpf_prog_inode(
        super::super::uapi::prog_type::RAW_TRACEPOINT,
        alloc::vec::Vec::new(),
    );
    assert!(matches!(prime_bpf_raw_tracepoint_link_with(
        fdt, 0, prog, 0, hooks(),
    ), Err(Errno::Emfile)));
}
