//! PMM movable-owner contract shared by physical memory and its owners.
#![no_std]

/// Opaque generation-checked identity for one PMM movable-page owner.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OwnerId { pub slot: u32, pub generation: u32 }

/// Linux-shaped migration retry disposition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MoveError { Busy, Permanent }

/// Reason class supplied to a movable owner during isolation/migration.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode { Async, Sync }

/// Owner callbacks corresponding to Linux `movable_operations`.
#[derive(Copy, Clone)]
pub struct Ops {
    pub isolate: fn(OwnerId, u64, Mode) -> bool,
    pub migrate: fn(OwnerId, u64, u64, Mode) -> Result<(), MoveError>,
    pub putback: fn(OwnerId, u64),
}
