// xtask: CI entry, 07§8.
use std::process::ExitCode;
mod cmds;
mod image_qemu;
mod l2_deps;
mod stats;
mod rootfs;
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
        "rootfs"    => cmd_rootfs(rest),
        "grub"      => image_qemu::cmd_grub(rest),
        "selfboot"  => image_qemu::cmd_selfboot(rest),
        "soak"      => stub("soak", "40"),
        "bench"     => stub("bench", "04"),
        "doc-check" => cmd_doc_check(rest),
        "stats"     => stats::cmd_stats(rest),
        "-h" | "--help" => return usage(),
        _ => { eprintln!("xtask: unknown subcommand `{cmd}`"); return usage(); }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: xtask <kernel|user|test|grub|selfboot|rootfs|soak|bench|spec-lint|doc-check|stats> [args]");
    ExitCode::from(2)
}
