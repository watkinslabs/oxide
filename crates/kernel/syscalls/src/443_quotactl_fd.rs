// 443 quotactl_fd — one syscall, one file (docs/53 §0).
//
// Linux `quotactl_fd(int fd, unsigned cmd, int id, void *addr)`. Identical
// semantics to `quotactl(2)` (slot 179) except the target filesystem is named
// by an open fd rather than a `special` device path.
#![cfg(any(target_os = "oxide-kernel", test))]

#[path = "443_quotactl_fd/dispatch.rs"] mod dispatch;
#[path = "443_quotactl_fd/sys.rs"] mod sys;
#[cfg(test)] #[path = "443_quotactl_fd/tests.rs"] mod tests;
pub use dispatch::quotactl_fd_file;
pub use sys::sys_quotactl_fd;
