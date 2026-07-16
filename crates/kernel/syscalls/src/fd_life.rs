use alloc::sync::Arc;

fn selected(task: &sched::Task) -> bool {
    task.vtgid.load(core::sync::atomic::Ordering::Acquire) == 1
        || task.comm().contains("dbus-broker")
}

fn head(task: &sched::Task, op: &'static [u8], fdt: &vfs::FdTable) {
    klog::write_raw(b"[FDLIFE op="); klog::write_raw(op);
    klog::write_raw(b" pid="); klog::write_dec_u64(task.vtgid.load(core::sync::atomic::Ordering::Acquire) as u64);
    klog::write_raw(b" tid="); klog::write_dec_u64(task.vtid.load(core::sync::atomic::Ordering::Acquire) as u64);
    klog::write_raw(b" table="); klog::write_hex_u64(fdt as *const vfs::FdTable as u64);
}

pub(crate) fn op(task: &sched::Task, fdt: &vfs::FdTable, name: &'static [u8], first: i32, second: i32, rv: i64) {
    if !selected(task) { return; }
    head(task, name, fdt);
    klog::write_raw(b" a="); klog::write_dec_u64(first as u32 as u64);
    klog::write_raw(b" b="); klog::write_dec_u64(second as u32 as u64);
    klog::write_raw(b" rv="); klog::write_hex_u64(rv as u64);
    klog::write_raw(b" live="); klog::write_dec_u64(fdt.count() as u64);
    klog::write_raw(b"]\n");
}

pub(crate) fn clone(parent: &sched::Task, child: &sched::Task, flags: u64,
                    parent_fdt: &Arc<vfs::FdTable>, child_fdt: &Arc<vfs::FdTable>) {
    if !selected(parent) { return; }
    head(parent, b"clone", parent_fdt);
    klog::write_raw(b" child="); klog::write_dec_u64(child.vtgid.load(core::sync::atomic::Ordering::Acquire) as u64);
    klog::write_raw(b" flags="); klog::write_hex_u64(flags);
    klog::write_raw(b" child_table="); klog::write_hex_u64(Arc::as_ptr(child_fdt) as u64);
    klog::write_raw(b" shared="); klog::write_dec_u64(Arc::ptr_eq(parent_fdt, child_fdt) as u64);
    klog::write_raw(b"]\n");
}
