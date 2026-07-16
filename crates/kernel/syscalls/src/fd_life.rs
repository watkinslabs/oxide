use alloc::sync::Arc;

pub(crate) fn op(task: &sched::Task, fdt: &vfs::FdTable, name: &'static [u8],
    first: i32, second: i32, _rv: i64)
{
    let (operation, second) = if name == b"unshare" || name == b"close-range-unshare" {
        (vfs::fdtable::debug::OP_UNSHARE, second)
    } else if name == b"close" {
        (vfs::fdtable::debug::OP_CLOSE_CALL,
            task.vtid.load(core::sync::atomic::Ordering::Acquire) as i32)
    } else {
        return;
    };
    vfs::fdtable::debug::record(fdt, operation, first, second);
}

pub(crate) fn clone(_parent: &sched::Task, _child: &sched::Task, _flags: u64,
    parent_fdt: &Arc<vfs::FdTable>, child_fdt: &Arc<vfs::FdTable>)
{
    let operation = if Arc::ptr_eq(parent_fdt, child_fdt) {
        vfs::fdtable::debug::OP_CLONE_SHARED
    } else {
        vfs::fdtable::debug::OP_CLONE_PRIVATE
    };
    vfs::fdtable::debug::record(parent_fdt, operation, -1, -1);
    if !Arc::ptr_eq(parent_fdt, child_fdt) {
        vfs::fdtable::debug::record_object(child_fdt, operation, -1, -1,
            Arc::as_ptr(parent_fdt) as u64);
    }
}
