// Task-owned resource final-release transitions.

use core::sync::atomic::Ordering;

use super::Task;

impl Drop for Task {
    fn drop(&mut self) {
        // Release the lazily-allocated debug-register shadows. No other
        // reference to this task exists here, so the claim is uncontended.
        self.debugregs.free();
        #[cfg(target_arch = "aarch64")]
        self.hw_break.free();
        #[cfg(feature = "debug-taskdrop")]
        {
            let top = self.kernel_stack.load(Ordering::Acquire) as u64;
            let len = self.stack.as_ref().map(|s| s.len() as u64).unwrap_or(0);
            klog::write_raw(b"[TASK-DROP] tid=");
            klog::write_dec_u64(self.tid as u64);
            klog::write_raw(b" stack_top=0x");
            klog::write_hex_u64(top);
            klog::write_raw(b" stack_len=0x");
            klog::write_hex_u64(len);
            klog::write_raw(b"\n");
        }
        // Backstop for the `RLIMIT_NPROC` charge, in the same shape as the
        // kernel-stack uncharge below. `mark_done` releases it at Linux's
        // timing (`__exit_signal`); this catches a task that never got that
        // far — a clone refused after the charge, or a hosted fixture — and
        // is a no-op for one that did, because the release is latched.
        crate::ucounts::uncharge_task(self);
        let cgid = self.kernel_stack_memcg.swap(cgroup::NO_MEMCG, Ordering::AcqRel);
        let bytes = self.kernel_stack_charge_bytes.swap(0, Ordering::AcqRel);
        if cgid != cgroup::NO_MEMCG && bytes != 0 {
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::KernelStack, bytes);
        }
    }
}
