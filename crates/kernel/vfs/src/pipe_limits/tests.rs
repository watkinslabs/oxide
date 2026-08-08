// Admission arithmetic for the per-user pipe page charge. Every case pins a
// behaviour a program can observe: the size a fresh pipe reports, the errno
// `F_SETPIPE_SZ` returns, and which of them a capability changes.
//
// The tunables are process-global and the hosted harness runs tests in
// parallel, so each case restores every limit it moves and uses its own uid.

use super::*;

/// The tunables are process-global; the hosted harness runs these cases in
/// parallel threads. Every case that moves a limit holds this first, so one
/// case's window cannot be observed by another.
static SERIALIZE: Spinlock<(), TaskListClass> = Spinlock::new(());

fn restore() {
    set_max_size(PIPE_MAX_SIZE_DEFAULT);
    set_user_pages_soft(PIPE_USER_PAGES_SOFT_DEFAULT);
    set_user_pages_hard(PIPE_USER_PAGES_HARD_DEFAULT);
}

#[test]
fn a_fresh_pipe_gets_the_default_pages_when_the_owner_holds_nothing() {
    let _serial = SERIALIZE.lock();
    restore();
    assert_eq!(alloc_pages(0, PipeCaps::unprivileged()), Some(PIPE_DEF_BUFFERS));
}

#[test]
fn past_the_soft_limit_a_pipe_is_cut_down_rather_than_refused() {
    let _serial = SERIALIZE.lock();
    set_user_pages_soft(20);
    set_user_pages_hard(0);
    // 16 already held + 16 default = 32, past the soft limit of 20.
    assert_eq!(alloc_pages(16, PipeCaps::unprivileged()), Some(PIPE_MIN_DEF_BUFFERS),
        "the pipe is still created, at the minimum size");
    assert_eq!(alloc_pages(16, PipeCaps::privileged()), Some(PIPE_DEF_BUFFERS),
        "a privileged owner is not cut down");
    restore();
}

#[test]
fn past_the_hard_limit_the_pipe_is_refused_outright() {
    let _serial = SERIALIZE.lock();
    set_user_pages_soft(0);
    set_user_pages_hard(10);
    assert_eq!(alloc_pages(9, PipeCaps::unprivileged()), None);
    assert_eq!(alloc_pages(9, PipeCaps::privileged()), Some(PIPE_DEF_BUFFERS),
        "the hard limit does not apply to a privileged owner");
    restore();
}

#[test]
fn the_soft_cut_can_still_land_under_the_hard_limit() {
    let _serial = SERIALIZE.lock();
    set_user_pages_soft(10);
    set_user_pages_hard(20);
    // 16 held: default would total 32 (over hard), the cut totals 18 (under).
    assert_eq!(alloc_pages(16, PipeCaps::unprivileged()), Some(PIPE_MIN_DEF_BUFFERS));
    restore();
}

#[test]
fn a_zero_limit_is_no_limit() {
    let _serial = SERIALIZE.lock();
    set_user_pages_soft(0);
    set_user_pages_hard(0);
    assert!(!too_many_soft(i64::MAX));
    assert!(!too_many_hard(i64::MAX));
    assert_eq!(alloc_pages(1 << 40, PipeCaps::unprivileged()), Some(PIPE_DEF_BUFFERS));
    restore();
}

#[test]
fn a_lowered_ceiling_shrinks_a_new_pipe_for_an_ordinary_caller_only() {
    let _serial = SERIALIZE.lock();
    set_max_size(2 * PIPE_PAGE_BYTES);
    assert_eq!(alloc_pages(0, PipeCaps::unprivileged()), Some(2));
    assert_eq!(alloc_pages(0, PipeCaps::privileged()), Some(PIPE_DEF_BUFFERS));
    restore();
}

#[test]
fn shrinking_is_allowed_even_over_every_limit() {
    let _serial = SERIALIZE.lock();
    set_user_pages_soft(1);
    set_user_pages_hard(1);
    set_max_size(PIPE_PAGE_BYTES);
    assert_eq!(resize_ok(64, 8, 4096, PipeCaps::unprivileged()), Ok(()));
    assert_eq!(resize_ok(64, 64, 4096, PipeCaps::unprivileged()), Ok(()),
        "an unchanged size is not a growth");
    restore();
}

#[test]
fn growing_past_the_ceiling_needs_the_resource_capability() {
    let _serial = SERIALIZE.lock();
    restore();
    let over = (PIPE_MAX_SIZE_DEFAULT / PIPE_PAGE_BYTES) + 1;
    assert_eq!(resize_ok(16, over, 16, PipeCaps::unprivileged()), Err(crate::VfsError::Eperm));
    assert_eq!(resize_ok(16, over, 16, PipeCaps::privileged()), Ok(()));
}

#[test]
fn growing_past_a_user_limit_is_eperm_not_a_clamp() {
    let _serial = SERIALIZE.lock();
    set_user_pages_soft(32);
    set_user_pages_hard(0);
    assert_eq!(resize_ok(16, 64, 16, PipeCaps::unprivileged()), Err(crate::VfsError::Eperm));
    assert_eq!(resize_ok(16, 64, 16, PipeCaps::privileged()), Ok(()));
    set_user_pages_soft(0);
    set_user_pages_hard(32);
    assert_eq!(resize_ok(16, 64, 16, PipeCaps::unprivileged()), Err(crate::VfsError::Eperm));
    restore();
}

#[test]
fn the_charge_is_per_user_and_saturates_at_zero() {
    let _serial = SERIALIZE.lock();
    let (a, b) = (92_101u32, 92_102u32);
    assert_eq!(account(a, 0, 16), 16);
    assert_eq!(account(a, 16, 64), 64, "a resize moves the charge, it does not add one");
    assert_eq!(charged(b), 0, "b's account is its own");
    assert_eq!(account(a, 64, 0), 0);
    assert_eq!(account(a, 16, 0), 0, "a double release mints no credit");
    assert_eq!(charged(a), 0);
}
