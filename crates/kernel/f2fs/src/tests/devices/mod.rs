//! What a volume spread over several devices must get right.
//!
//! - `table`:  the member spans the superblock's segment counts imply.
//! - `route`:  a request split at the member boundaries.
//! - `flush`:  the segment window one member occupies.
//! - `alias`:  a file that stands for a whole member.
//! - `aliasvol`: the same, on a mounted volume, through the command that asks.
//! - `spread`: the same volume flat and split, which must read the same.

#[path = "table.rs"]
mod table;
#[path = "route.rs"]
mod route;
#[path = "flush.rs"]
mod flush;
#[path = "alias.rs"]
mod alias;
#[path = "aliasvol.rs"]
mod aliasvol;
#[path = "spread.rs"]
mod spread;
