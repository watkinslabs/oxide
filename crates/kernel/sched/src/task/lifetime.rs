// Task-owned resource final-release transitions.

use core::sync::atomic::Ordering;

use super::Task;

impl Drop for Task {
    fn drop(&mut self) {
        let cgid = self.kernel_stack_memcg.swap(cgroup::NO_MEMCG, Ordering::AcqRel);
        let bytes = self.kernel_stack_charge_bytes.swap(0, Ordering::AcqRel);
        if cgid != cgroup::NO_MEMCG && bytes != 0 {
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::KernelStack, bytes);
        }
    }
}
