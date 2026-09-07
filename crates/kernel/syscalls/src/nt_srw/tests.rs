//! Slim reader/writer transitions: the field split, who may take the lock,
//! what a release installs, and which sleepers it must disturb.

use super::state::*;

/// Build a word from its two halves the way the layout defines them.
fn word(exclusive_half: u32, owner_count: u32) -> u32 { (owner_count << OWNERS_SHIFT) | exclusive_half }

#[test]
fn the_two_halves_do_not_overlap() {
    assert_eq!(owners(word(0xffff, 0)), 0);
    assert_eq!(exclusive(word(0, 0xffff)), 0);
    assert_eq!(owners(word(0xffff, 7)), 7);
    assert_eq!(exclusive(word(0x1234, 7)), 0x1234);
    assert_eq!(ONE_OWNER, 1 << OWNERS_SHIFT);
    assert_eq!(EXCLUSIVE_WAITER, EXCLUSIVE_HELD << 1);
    // The owner half must not be the low half: a blocked writer parks on the
    // owner bytes alone, which is only a distinct address above the base.
    assert_eq!(OWNERS_BYTE_OFFSET, 2);
}

#[test]
fn an_unowned_lock_admits_a_reader_a_writer_and_a_try() {
    assert_eq!(take_shared(0), Some(word(0, 1)));
    assert_eq!(try_take_exclusive(0), Some(word(EXCLUSIVE_HELD, 1)));
    // An announced writer sees its own waiter in the word it retires.
    assert_eq!(take_announced_exclusive(word(EXCLUSIVE_WAITER, 0)), Some(word(EXCLUSIVE_HELD, 1)));
}

#[test]
fn a_reader_joins_readers_but_never_overtakes_a_writer() {
    assert_eq!(take_shared(word(0, 3)), Some(word(0, 4)));
    assert_eq!(take_shared(word(EXCLUSIVE_HELD, 1)), None);
    // A writer merely waiting is enough to stop a new reader.
    assert_eq!(take_shared(word(EXCLUSIVE_WAITER, 2)), None);
}

#[test]
fn a_writer_waits_for_every_owner_including_readers() {
    assert_eq!(take_announced_exclusive(word(EXCLUSIVE_WAITER, 1)), None);
    assert_eq!(take_announced_exclusive(word(EXCLUSIVE_HELD | EXCLUSIVE_WAITER, 1)), None);
    assert_eq!(try_take_exclusive(word(0, 1)), None);
    assert_eq!(try_take_exclusive(word(EXCLUSIVE_HELD, 1)), None);
}

#[test]
fn an_announcement_adds_one_waiter_and_a_take_retires_exactly_one() {
    let announced = announce_exclusive_waiter(word(0, 2));
    assert_eq!(announced, word(EXCLUSIVE_WAITER, 2));
    let twice = announce_exclusive_waiter(announced);
    assert_eq!(twice, word(2 * EXCLUSIVE_WAITER, 2));
    // The owner half survives an announcement untouched.
    assert_eq!(owners(twice), 2);
    // One of the two waiters takes it; the other's announcement remains.
    assert_eq!(take_announced_exclusive(word(2 * EXCLUSIVE_WAITER, 0)),
        Some(word(EXCLUSIVE_WAITER | EXCLUSIVE_HELD, 1)));
}

#[test]
fn a_non_blocking_take_never_announces_a_waiter() {
    // The try path sets the held bit and leaves the waiter count alone, so a
    // caller that fails and retries cannot inflate it.
    assert_eq!(try_take_exclusive(word(2 * EXCLUSIVE_WAITER, 0)),
        Some(word(2 * EXCLUSIVE_WAITER | EXCLUSIVE_HELD, 1)));
}

#[test]
fn a_release_clears_its_own_claim_and_nothing_else() {
    assert_eq!(drop_exclusive(word(EXCLUSIVE_HELD, 1)), 0);
    assert_eq!(drop_exclusive(word(EXCLUSIVE_HELD | 2 * EXCLUSIVE_WAITER, 1)), word(2 * EXCLUSIVE_WAITER, 0));
    assert_eq!(drop_shared(word(0, 3)), word(0, 2));
    assert_eq!(drop_shared(word(EXCLUSIVE_WAITER, 1)), word(EXCLUSIVE_WAITER, 0));
}

#[test]
fn a_release_wakes_a_writer_only_when_one_is_waiting() {
    assert_eq!(wake_after_exclusive_release(word(EXCLUSIVE_WAITER, 0)), Wake::OneWriter);
    assert_eq!(wake_after_exclusive_release(0), Wake::AllOnWord);
    assert_eq!(wake_after_shared_release(word(EXCLUSIVE_WAITER, 0)), Wake::OneWriter);
    // Readers still hold it, so nobody can make progress yet.
    assert_eq!(wake_after_shared_release(word(EXCLUSIVE_WAITER, 1)), Wake::None);
    assert_eq!(wake_after_shared_release(word(0, 2)), Wake::None);
}

#[test]
fn a_writer_hands_the_lock_to_the_next_writer_without_letting_readers_in() {
    // Two writers announce, one takes and releases; the word it installs still
    // carries the second announcement, which keeps readers out.
    let announced = announce_exclusive_waiter(announce_exclusive_waiter(0));
    let held = take_announced_exclusive(announced).unwrap();
    assert_eq!(take_shared(held), None);
    let released = drop_exclusive(held);
    assert_eq!(take_shared(released), None);
    assert_eq!(wake_after_exclusive_release(released), Wake::OneWriter);
    let next = take_announced_exclusive(released).unwrap();
    assert_eq!(next, word(EXCLUSIVE_HELD, 1));
    // With the last writer served, readers are admitted again.
    let free = drop_exclusive(next);
    assert_eq!(wake_after_exclusive_release(free), Wake::AllOnWord);
    assert_eq!(take_shared(free), Some(word(0, 1)));
}

#[test]
fn readers_drain_before_a_waiting_writer_runs() {
    let mut lock = take_shared(take_shared(0).unwrap()).unwrap();
    assert_eq!(owners(lock), 2);
    lock = announce_exclusive_waiter(lock);
    assert_eq!(take_announced_exclusive(lock), None);
    lock = drop_shared(lock);
    assert_eq!(wake_after_shared_release(lock), Wake::None);
    assert_eq!(take_announced_exclusive(lock), None);
    lock = drop_shared(lock);
    assert_eq!(wake_after_shared_release(lock), Wake::OneWriter);
    assert_eq!(take_announced_exclusive(lock), Some(word(EXCLUSIVE_HELD, 1)));
}

#[test]
fn the_shared_condition_variable_mode_is_the_low_flag_bit() {
    assert_eq!(CONDITION_VARIABLE_LOCKMODE_SHARED, 1);
}
