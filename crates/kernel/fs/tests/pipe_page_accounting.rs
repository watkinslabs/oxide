// The per-user pipe page charge, driven through the real pipe constructor and
// the real `F_SETPIPE_SZ` entry point rather than through the arithmetic alone.
//
// Off the scheduler the account is uid 0 with no capability exemption, which is
// exactly the standing an ordinary process has, so every ladder below is the
// one a program meets.

use vfs::pipe_limits::{account, alloc_pages, charged, max_size, set_max_size, set_user_pages_hard,
    set_user_pages_soft, user_pages_hard, user_pages_soft, PipeCaps, PIPE_DEF_BUFFERS,
    PIPE_MIN_DEF_BUFFERS, PIPE_PAGE_BYTES};
use fs::pipe::{make_pipe_inode, pipe_size, set_pipe_size};
use vfs::VfsError;

/// The hosted harness runs test binaries in parallel threads and the tunables
/// are process-global, so the cases in this file run under one lock.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Restore { soft: i64, hard: i64, max: i64, charged_before: i64 }

fn save() -> Restore {
    Restore { soft: user_pages_soft(), hard: user_pages_hard(), max: max_size(),
        charged_before: charged(0) }
}

impl Drop for Restore {
    fn drop(&mut self) {
        set_user_pages_soft(self.soft);
        set_user_pages_hard(self.hard);
        set_max_size(self.max);
        account(0, charged(0), self.charged_before);
    }
}

#[test]
fn a_new_pipe_charges_its_pages_and_a_dropped_one_gives_them_back() {
    let _serial = SERIAL.lock().unwrap();
    let _restore = save();
    set_user_pages_soft(0);
    set_user_pages_hard(0);
    let before = charged(0);
    let pipe = make_pipe_inode().expect("a pipe under no limit");
    assert_eq!(charged(0), before + PIPE_DEF_BUFFERS, "the ring's pages are charged");
    assert_eq!(pipe_size(&pipe), Some((PIPE_DEF_BUFFERS * PIPE_PAGE_BYTES) as usize));
    drop(pipe);
    assert_eq!(charged(0), before, "the charge is released with the ring");
}

#[test]
fn past_the_soft_limit_a_pipe_is_smaller_rather_than_refused() {
    let _serial = SERIAL.lock().unwrap();
    let _restore = save();
    set_user_pages_hard(0);
    // A soft limit already exceeded by whatever this account holds.
    set_user_pages_soft(charged(0).max(1));
    let pipe = make_pipe_inode().expect("the pipe is still created");
    assert_eq!(pipe_size(&pipe), Some((PIPE_MIN_DEF_BUFFERS * PIPE_PAGE_BYTES) as usize),
        "it is created at the minimum size");
}

#[test]
fn past_the_hard_limit_the_pipe_is_enomem() {
    let _serial = SERIAL.lock().unwrap();
    let _restore = save();
    set_user_pages_soft(0);
    set_user_pages_hard(charged(0).max(1));
    assert_eq!(make_pipe_inode().err(), Some(VfsError::Enomem));
}

#[test]
fn a_resize_moves_the_charge_instead_of_adding_one() {
    let _serial = SERIAL.lock().unwrap();
    let _restore = save();
    set_user_pages_soft(0);
    set_user_pages_hard(0);
    let before = charged(0);
    let pipe = make_pipe_inode().expect("a pipe under no limit");
    let want = (4 * PIPE_DEF_BUFFERS * PIPE_PAGE_BYTES) as usize;
    assert_eq!(set_pipe_size(&pipe, want), Ok(want));
    assert_eq!(charged(0), before + 4 * PIPE_DEF_BUFFERS,
        "the account holds the new size, not the sum of both");
    let smaller = (2 * PIPE_PAGE_BYTES) as usize;
    assert_eq!(set_pipe_size(&pipe, smaller), Ok(smaller));
    assert_eq!(charged(0), before + 2, "shrinking gives pages back");
    drop(pipe);
    assert_eq!(charged(0), before);
}

#[test]
fn a_growth_past_the_ceiling_is_eperm_and_charges_nothing() {
    let _serial = SERIAL.lock().unwrap();
    let _restore = save();
    set_user_pages_soft(0);
    set_user_pages_hard(0);
    let pipe = make_pipe_inode().expect("a pipe under no limit");
    let held = charged(0);
    set_max_size(PIPE_DEF_BUFFERS * PIPE_PAGE_BYTES);
    let over = ((PIPE_DEF_BUFFERS + 1) * PIPE_PAGE_BYTES) as usize;
    assert_eq!(set_pipe_size(&pipe, over), Err(VfsError::Eperm));
    assert_eq!(charged(0), held, "a refused resize leaves the account alone");
    assert_eq!(pipe_size(&pipe), Some((PIPE_DEF_BUFFERS * PIPE_PAGE_BYTES) as usize),
        "and leaves the pipe at the size it had");
}

#[test]
fn the_ladder_and_the_constructor_agree_on_the_size() {
    let _serial = SERIAL.lock().unwrap();
    let _restore = save();
    set_user_pages_soft(0);
    set_user_pages_hard(0);
    let expected = alloc_pages(charged(0), PipeCaps::unprivileged()).expect("admitted");
    let pipe = make_pipe_inode().expect("a pipe");
    assert_eq!(pipe_size(&pipe), Some((expected * PIPE_PAGE_BYTES) as usize),
        "the constructor takes the size the ladder decided, not a constant");
}
