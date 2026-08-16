//! Who may issue each command, and in what ORDER the refusals happen.
//!
//! Module manifest:
//! - `volume`:  the prologue, the administrative ladder, the range collectors.
//! - `file`:    staging, pinning, sealing, per-file trimming, the small ones.
//! - `feature`: the feature gates and the commands behind them.

#[path = "perm/volume.rs"]
mod volume;
#[path = "perm/file.rs"]
mod file;
#[path = "perm/feature.rs"]
mod feature;
