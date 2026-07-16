#![cfg(target_os = "oxide-kernel")]

pub(super) fn unshare_fd_table_and_close_on_exec(cur: &sched::Task) {
    #[cfg(feature = "debug-fdlife")]
    if let Some(fdt) = unsafe { cur.fd_table_ref() } { crate::fd_life::op(cur, fdt, b"exec-before", -1, -1, 0); }
    let shared = unsafe {
        cur.fd_table_ref()
            .map(|fdt| alloc::sync::Arc::strong_count(fdt) > 1)
            .unwrap_or(false)
    };
    if shared {
        let new_fdt = unsafe {
            cur.fd_table_ref()
                .map(|fdt| alloc::sync::Arc::new(fdt.fork_clone()))
        };
        if let Some(fdt) = new_fdt {
            // SAFETY: execve is the sole fd-table mutator for this task.
            unsafe { cur.replace_fd_table(Some(fdt)); }
        }
    }
    // SAFETY: execve is the sole fd-table mutator for this task.
    if let Some(fdt) = unsafe { cur.fd_table_ref() } { fdt.close_on_exec(); }
    #[cfg(feature = "debug-fdlife")]
    if let Some(fdt) = unsafe { cur.fd_table_ref() } { crate::fd_life::op(cur, fdt, b"exec-after", -1, -1, 0); }
}
