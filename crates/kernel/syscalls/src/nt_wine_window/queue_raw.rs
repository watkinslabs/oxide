//! Message-queue ordinals: quit, thread posts, replies, waits and the
//! per-thread notification helpers user32 reaches through win32u (`31t§3`).

#[path = "queue_raw/pointer.rs"]
pub(crate) mod pointer;
#[path = "queue_raw/wait.rs"]
pub(crate) mod wait;
#[path = "queue_raw/startup.rs"]
pub(crate) mod startup;

pub(crate) const POST_QUIT_MESSAGE: u64 = 0x14d1;
pub(crate) const POST_THREAD_MESSAGE: u64 = 0x14d2;
pub(crate) const REPLY_MESSAGE: u64 = 0x1521;
pub(crate) const MSG_WAIT_FOR_MULTIPLE_OBJECTS_EX: u64 = 0x14bb;
pub(crate) const WAIT_MESSAGE: u64 = 0x15fb;
pub(crate) const SCHEDULE_DISPATCH_NOTIFICATION: u64 = 0x1529;
pub(crate) const MESSAGE_BEEP: u64 = 0x14b4;
pub(crate) const MODIFY_USER_STARTUP_INFO_FLAGS: u64 = 0x14b8;
pub(crate) const SET_ADDITIONAL_FOREGROUND_BOOST_PROCESSES: u64 = 0x1533;
