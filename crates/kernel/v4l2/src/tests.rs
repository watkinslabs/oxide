//! Hosted tests for the video device core.
//!
//! Every child is bound by an explicit path, because a bare `mod` inside a
//! `#[path]`-bound module binds relative to that module's directory and would
//! silently name an implementation file instead of a test file.
//!
//! Module manifest:
//! - `harness`: the fake device, allocator, user memory and context.
//! - `abi`: the numbers and layouts, re-derived rather than restated.
//! - `format_tests`: negotiation, clamping, image-size arithmetic.
//! - `buffer_tests`: the buffer state machine and its illegal transitions.
//! - `queue_tests`: allocation arithmetic and the queue command errors.
//! - `stream_tests`: start, stop, completion, poll.
//! - `control_tests`: ranges, steps, menus, the query walk, batches.
//! - `event_tests`: subscription, overflow, the sequence gap.
//! - `order_tests`: the order in which the dispatch applies its checks.

#[path = "tests/harness.rs"] mod harness;
#[path = "tests/abi.rs"] mod abi;
#[path = "tests/format_tests.rs"] mod format_tests;
#[path = "tests/buffer_tests.rs"] mod buffer_tests;
#[path = "tests/queue_tests.rs"] mod queue_tests;
#[path = "tests/stream_tests.rs"] mod stream_tests;
#[path = "tests/control_tests.rs"] mod control_tests;
#[path = "tests/event_tests.rs"] mod event_tests;
#[path = "tests/order_tests.rs"] mod order_tests;
