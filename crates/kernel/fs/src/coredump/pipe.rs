// The `|program` destination: hand the dump to a crash reporter.
//
// The program is started as a kernel -> userspace helper, so it runs with the
// initial namespace's root and a full credential set rather than with anything
// inherited from the process that just crashed. Its standard input is the read
// end of a fresh pipe; the kernel keeps the write end and pushes the dump
// through it. That is the whole reason for the shape: a crashing process needs
// no write access anywhere for its dump to be collected.

#![cfg(target_os = "oxide-kernel")]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{File, OpenFlags};

use super::pattern::{CoreContext, COREDUMP_PIDFD_NUMBER};

/// Standard input, where the helper reads the dump from.
const STDIN_FD: i32 = 0;

/// Context the helper's setup callback needs, handed across as the request's
/// opaque data.
struct PipeSetup {
    /// Read end, installed as the helper's standard input.
    read_end: Arc<File>,
    /// Namespace-visible id of the dying process, for the `%F` descriptor.
    vpid: u32,
    /// Whether the pattern asked for a process descriptor.
    wants_pidfd: bool,
}

/// Send the dump to the program the pattern names.
///
/// Returns false when no dump was delivered — the program is missing, is not
/// executable, the helper gate is closed, or the pattern names nothing runnable.
/// The caller must treat that as "no dump", never as success.
/// # C: O(dump size) + O(helper start)
pub fn dump_to_program(pattern: &[u8], cx: &CoreContext, body: &[u8]) -> bool {
    let Some((argv, wants_pidfd)) = super::pattern::pipe_argv(pattern, cx) else { return false };
    let (read_end, write_end) = match make_pipe() { Some(p) => p, None => return false };

    let data = Box::into_raw(Box::new(PipeSetup {
        read_end, vpid: cx.vpid, wants_pidfd,
    })) as usize;
    let argv_slices: Vec<&[u8]> = argv.iter().map(|a| a.as_slice()).collect();
    let info = umh::call_usermodehelper_setup(
        &argv[0], &argv_slices, &[], Some(install_stdin), Some(release_setup), data);

    // Wait for the exec, not for the program: the dump has to be written while
    // the reader is alive, and the reader cannot finish before it has the dump.
    let rc = umh::call_usermodehelper_exec(info, umh::UMH_WAIT_EXEC);
    if rc != 0 { return false; }

    write_all(&write_end, body)
}

fn make_pipe() -> Option<(Arc<File>, Arc<File>)> {
    let inode = crate::pipe::make_pipe_inode();
    let pd = crate::pipe::pipe_data(&inode)?;
    pd.readers.store(1, core::sync::atomic::Ordering::Release);
    pd.writers.store(1, core::sync::atomic::Ordering::Release);
    let dentry = vfs::dcache::d_alloc_pseudo("pipe", inode.clone(), &crate::anon_dname::PIPE_OPS);
    let read_end = File::new(inode.clone(), dentry.clone(), OpenFlags::O_RDONLY);
    let write_end = File::new(inode, dentry, OpenFlags::O_WRONLY);
    Some((read_end, write_end))
}

/// Helper setup callback: give the program its standard input, and its process
/// descriptor if the pattern asked for one.
fn install_stdin(info: &mut umh::SubprocessInfo, ctx: &umh::HelperCtx) -> i32 {
    // SAFETY: `data` is the raw form of the Box created in dump_to_program and is released only by release_setup, which cannot run before the helper is finished with it.
    let setup = unsafe { &*(info.data as *const PipeSetup) };
    if let Err(e) = ctx.fdt.try_fd_install(STDIN_FD, Arc::clone(&setup.read_end)) {
        return -(e as i32);
    }
    if setup.wants_pidfd {
        match pidfd::file_for_pid(&ctx.task, setup.vpid) {
            Some(f) => {
                if let Err(e) = ctx.fdt.try_fd_install(COREDUMP_PIDFD_NUMBER, f) {
                    return -(e as i32);
                }
            }
            // The pattern asked for a descriptor the kernel could not produce.
            // Starting the program without it would hand it a descriptor number
            // that names nothing.
            None => return -(syscall::errno::Errno::Esrch.as_i32()),
        }
    }
    0
}

fn release_setup(info: &mut umh::SubprocessInfo) {
    if info.data == 0 { return; }
    // SAFETY: `data` is the raw form of the Box created in dump_to_program; the request is released exactly once, so this is its single reclaim.
    drop(unsafe { Box::from_raw(info.data as *mut PipeSetup) });
    info.data = 0;
}

/// Push the whole dump into the pipe. The helper drains it as we write, so a
/// dump larger than the pipe's buffer is delivered across several writes.
fn write_all(write_end: &Arc<File>, mut body: &[u8]) -> bool {
    while !body.is_empty() {
        match write_end.inode().write(0, body) {
            Ok(0) => return false,
            Ok(n) => body = &body[n..],
            // The reader is gone: the program exited or was killed before it
            // read the whole dump. Nothing more can be delivered.
            Err(_) => return false,
        }
    }
    true
}
