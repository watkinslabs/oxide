//! The two conditions a replay raises and lowers, and which way round.
//!
//! Both were the wrong way round and both matter, in opposite directions:
//!
//! - the IN-PROGRESS condition was lowered whether the pass succeeded or not.
//!   Everything that reads it — the cleaner, the allocators that keep a reserve
//!   back, the status word a tool reads — is asking whether this volume's tail
//!   is still unresolved. After a FAILED replay it is, and a cleaner told
//!   otherwise starts moving live blocks the chain still names.
//! - the RECOVERED condition was raised only on success. It records that this
//!   mount took a roll-forward on itself, which a failed pass did just as much
//!   as a finished one: the tail was read and the logs were opened. Not raised,
//!   a tool cannot tell such a mount from one that came up clean.
//!
//! Driven by hand rather than through a mount, because a mount that fails its
//! replay returns the error and drops the volume — so the mount path is
//! precisely where these flags cannot be observed. That is a reason to test
//! them here, not a reason they do not matter: the first repair-and-continue
//! mount reads both.

use crate::fault::Fault;
use crate::sbflags::bits;
use crate::volume::recover::fixture::*;
use crate::volume::recover::Recovery;
use crate::volume::Volume;

use sectors::MemImage;

/// Fail every write from here on. The chain SCAN only reads, so the pass gets
/// far enough to find the chain and then fails putting it back — which is the
/// one window the two conditions disagree in.
/// # C: O(1)
fn fail_writes(v: &Volume<MemImage>) {
    v.set_fault(1, 0, crate::fault::Which::RATE).unwrap();
    v.set_fault(0, Fault::WriteIo.bit(), crate::fault::Which::TYPE).unwrap();
}

fn recovered(v: &Volume<MemImage>) -> bool { v.sbi.is_set(bits::IS_RECOVERED) }

/// A WRITABLE volume with a chain still standing, so a test can drive the pass
/// itself and read what it did.
///
/// Declining the roll-forward is what leaves the tail there; the mount is still
/// writable, because the pass under test writes. # C: O(image bytes)
fn with_a_standing_chain(name: &[u8]) -> Volume<MemImage> {
    let (mut v, ino) = checkpointed_unmounted(name);
    grow_and_fsync(&mut v, ino, 0xE1);
    standing(v.into_source().snapshot())
}

/// The bytes, mounted writable with the replay declined. # C: O(image bytes)
fn standing(bytes: alloc::vec::Vec<u8>) -> Volume<MemImage> {
    remount_opts(bytes, true, crate::opts::Options {
        recovery: false, ..crate::opts::Options::defaults()
    })
}

#[test]
fn a_failed_replay_leaves_the_in_progress_condition_raised() {
    let mut v = with_a_standing_chain(b"f");
    assert!(!v.is_recovering(), "the fixture is already mid-recovery");
    assert!(!recovered(&v), "the fixture already claims a recovery");
    fail_writes(&v);

    v.begin_recovery();
    let outcome = v.recover();
    v.finish_recovery(outcome.is_ok());

    assert!(outcome.is_err(), "the fixture's replay did not fail; the flags prove nothing");
    assert!(v.is_recovering(),
            "a failed replay lowered the condition every reader uses to stay off the tail");
    assert!(recovered(&v),
            "a mount that read a chain and failed to put it back reports as never having tried");
}

#[test]
fn a_replay_that_succeeded_lowers_the_in_progress_condition() {
    let mut v = with_a_standing_chain(b"f");
    v.begin_recovery();
    let outcome = v.recover();
    v.finish_recovery(outcome.is_ok());

    assert!(matches!(outcome, Ok(Recovery::Replayed(_))), "the fixture had no chain to replay");
    assert!(!v.is_recovering(), "a finished replay left the volume reported as mid-recovery");
    assert!(recovered(&v));
}

#[test]
fn a_volume_with_nothing_to_replay_claims_no_recovery() {
    let (v, _) = checkpointed_unmounted(b"f");
    let mut v = standing(v.into_source().snapshot());
    v.begin_recovery();
    let outcome = v.recover();
    v.finish_recovery(outcome.is_ok());

    assert_eq!(outcome.expect("clean"), Recovery::Clean);
    assert!(!v.is_recovering());
    assert!(!recovered(&v), "a mount that found no chain must not report a roll-forward");
}

#[test]
fn a_chain_that_cannot_even_be_walked_claims_no_recovery() {
    // The condition records having taken a roll-forward, and a scan that never
    // completed did not take one: nothing was put back and no log was moved.
    // The distinction is exactly where the condition is raised — after the chain
    // is FOUND, not before the search for it.
    //
    // The failure is put in the READ the walk does, because that is the only way
    // to fail the search on a volume that mounted: a chain malformed enough to
    // refuse the walk is refused by the mount itself, and there is no volume
    // left to read a flag off.
    let mut v = with_a_standing_chain(b"f");
    v.set_fault(1, 0, crate::fault::Which::RATE).unwrap();
    v.set_fault(0, Fault::ReadIo.bit(), crate::fault::Which::TYPE).unwrap();

    v.begin_recovery();
    let outcome = v.recover();
    v.finish_recovery(outcome.is_ok());

    assert!(outcome.is_err(), "the fixture's walk completed after all");
    assert!(v.is_recovering());
    assert!(!recovered(&v), "a walk that never completed reported a roll-forward");
}
