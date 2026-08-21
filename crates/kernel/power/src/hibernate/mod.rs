// Hibernation storage manifest per `32b`.
//
// Module manifest:
// - `format`: fixed page wire layouts and CRC32.
// - `scratch`: heap-owned page-sized I/O and decode workspaces.
// - `bitmap`: bounded O(1) PFN and block-locator membership metadata.
// - `codec`:  bounded LZO/LZ4 chunk encoding and decoding.
// - `image`:  signature-last writer and consume-first reader.
// - `identity`: build, topology, firmware and CPU compatibility identity.
// - `mode`:   admitted power-down modes and `/sys/power/disk` policy.
// - `notifier`: bounded prepare/post callback chain.
// - `snapshot`: sole physical-image selection and copy owner.
// - `stream`: image-info and original-PFN metadata pages.
// - `backend`: generic transaction boundary supplied by subsystem owners.
// - `sequence`: forward phases and their exact reverse actions.
// - `run`: write-side transaction and restored-continuation split.
// - `restore`: admitted stream loading and collision ownership.
// - `settings`: sole boot/sysfs hibernation configuration owner.
// - `entry`: single machine hook used by sysfs and reboot(2).
// - `sysfs`: hibernation-owned `/sys/power` attributes.

pub mod backend;
mod bitmap;
mod codec;
mod scratch;
pub mod format;
pub mod image;
pub mod log;
pub mod identity;
pub mod mode;
pub mod notifier;
pub mod run;
pub mod restore;
pub mod sequence;
pub mod snapshot;
pub mod stream;
pub mod settings;
pub mod entry;
pub mod sysfs;
