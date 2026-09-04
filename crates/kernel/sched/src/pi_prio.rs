// Module manifest:
// - policy: priority-inheritance ordering and effective-class decisions.
// - tree: task-owned intrusive PI waiter tree.
// - tests: policy decision coverage.

#[path = "pi_prio/policy.rs"]
mod policy;
#[path = "pi_prio/tree.rs"]
mod tree;

pub use policy::{base_class, class_with_key, donor_key_outranks, is_boosted, outranks,
    PiDlParams, PiDonorKey};
#[cfg(test)]
pub use policy::boost_class;
pub use tree::{PiTreeNode, PiWaiterTree};

#[cfg(test)]
#[path = "pi_prio/tests.rs"]
mod tests;
