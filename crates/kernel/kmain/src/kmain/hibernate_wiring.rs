//! Kernel adapters joining hibernation policy to canonical machine owners.

// Module manifest:
// - `backend`: production write-side transaction joined to machine owners.
// - `filesystems`: one ordered mounted-superblock freeze transaction.
// - `snapshot`: PMM topology/free-state and image-copy adapter.
// - `storage`: canonical swap-area lease persistence adapter.
// - `restore`: cold-image safe-plan construction and terminal arch transfer.
// - `resume`: cold-boot image admission, loading and fresh-kernel quiesce.
// - `release`: bounded post-recovery disposal of retained snapshot frames.
// - `irq_restore`: diagnostic bracket around the first admitted local IRQ.

mod backend;
mod filesystems;
mod snapshot;
mod storage;
mod restore;
mod resume;
mod release;
mod irq_restore;

pub use backend::install;
use backend::MachineBackend;
pub use filesystems::FrozenFilesystems;
pub use snapshot::{PreparedSnapshotMemory, RestoreMemory, SnapshotMemory, SnapshotStream};
pub use storage::{ImageStorage, ResumeStorage};
pub use restore::{enter_arch_restore, prepare_arch_restore, validate_arch_header, PreparedArchRestore};
pub use resume::{software_resume, ResumeOutcome};
