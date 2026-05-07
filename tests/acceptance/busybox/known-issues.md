# busybox 1.37.0 acceptance — status

## Status

**Working** as of P34b (the mmap-into-current-task-AS fix).

`/bin/busybox echo HELLO_FROM_BUSYBOX` runs end-to-end:
- fork+execve from oxide-sh
- set_thread_area (for FS_BASE / TLS)
- prlimit64, brk×2, mmap (one -EINVAL probe, one accepted)
- write to stdout: `HELLO_FROM_BUSYBOX`
- exit code 0; parent reaps via wait4

`/bin/busybox ls /` lists `bin dev etc proc sys usr`. Dirent entries
with non-resolvable stat (lost+found, /init, /hello.txt) print
`No such file or directory` errors but ls completes.

## Pre-fix root cause

`glue_mmap` was inserting VMAs into the boot global AS via
`with(|as_| as_.mmap(...))`. After execve, the running task had its
own per-task `mm: Arc<AddressSpace>` and CR3 pointed at it; mmap'd
ranges weren't visible to the demand-page handler walking the
task's mm. Every userspace mmap+write fault terminated the task
with `[FAULT] vec=0x0e cr2=<low addr>` because the VMA wasn't
where the handler looked.

Fix: route `glue_mmap` through `current().mm_ref()` for tasks with
a per-task AS; fall back to the boot global only for kthreads /
the boot anchor (which is the only legitimate user of `with()`).

## Follow-ups

- More acceptance scenarios: cat /etc/hostname, cat /proc/cpuinfo,
  uname -a, mount, ps, top, uptime.
- ls's stat-fail entries for /init, /hello.txt, /sbin, /lib, /lib64,
  /lost+found suggest devfs lookup gaps when a path has wrong
  file_type or doesn't resolve cleanly. Track separately.
