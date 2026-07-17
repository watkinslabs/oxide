// xtask: CI entry, 07§8.
use std::process::ExitCode;
mod buildns;
mod artifacts;
mod cmds;
mod gc;
mod glibc;
mod ldso;
mod folded;
mod sysroot;
mod glibc_test;
mod image_qemu;
mod path;
mod stats;
mod rootfs;
mod rootfs_glibc;
mod rootfs_disks;
use crate::cmds::{cmd_doc_check, cmd_kernel, cmd_spec_lint, cmd_test, parse_arg, run, stub};
use crate::rootfs::cmd_rootfs;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() { return usage(); }

    let cmd = args[0].as_str();
    let rest = &args[1..];

    let res = match cmd {
        "spec-lint" => cmd_spec_lint(rest),
        "kernel"    => cmd_kernel(rest),
        "test"      => cmd_test(rest),
        "user"      => stub("user", "29a"),
        "glibc"     => glibc::cmd_glibc(rest),
        "ldso"      => ldso::cmd_ldso(rest),
        "folded"    => folded::cmd_folded(rest),
        "sysroot"   => sysroot::cmd_sysroot(rest),
        "glibc-test" => glibc_test::cmd_glibc_test(rest),
        "rootfs"    => cmd_rootfs(rest),
        "image"     => image_qemu::cmd_image(rest),
        "grub"      => image_qemu::cmd_grub(rest),
        "soak"      => stub("soak", "40"),
        "bench"     => stub("bench", "04"),
        "doc-check" => cmd_doc_check(rest),
        "stats"     => stats::cmd_stats(rest),
        "gc"        => gc::cmd_gc(rest),
        "path"      => path::cmd_path(rest),
        "artifacts" => artifacts::cmd_artifacts(rest),
        "-h" | "--help" => return usage(),
        _ => { eprintln!("xtask: unknown subcommand `{cmd}`"); return usage(); }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: xtask <kernel|user|glibc|sysroot|glibc-test|image|test|qemu|rootfs|grub|gc|path|artifacts|soak|bench|spec-lint|doc-check|stats> [args]");
    ExitCode::from(2)
}
