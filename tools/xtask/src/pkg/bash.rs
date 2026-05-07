// bash 5.2.x cross-build recipe.
//
// Build flags chosen for an oxide musl-static target:
//   --without-bash-malloc — bash's bundled malloc fights musl's
//                           static-linked malloc with duplicate
//                           symbols; use musl's.
//   --disable-nls         — drop gettext locale machinery; we have
//                           no locale data installed.
//   --disable-readline    — dynamic readline isn't an option here;
//                           bash falls back to its bundled stub
//                           (no line-edit + history). Real readline
//                           rides a successor recipe once we have
//                           per-fd termios.
//   CC=musl-gcc           — produces *-linux-musl ELF.
//   CFLAGS/LDFLAGS=-static — single static-linked binary so the
//                            kernel's static-PIE loader path runs it
//                            without a dynamic linker.
//
// First kernel runtime gaps bash will hit: TCGETS/TCSETS ioctls,
// tcgetpgrp/tcsetpgrp, sigprocmask edge cases. Each lands in a
// follow-up kernel-completeness PR as bash exposes it.

use std::process::Command;

use super::{Ctx, InstallSpec, Meta, Recipe, musl_gcc_env, run_in};

pub struct Bash;

impl Recipe for Bash {
    fn meta(&self) -> Meta {
        Meta {
            name:        "bash",
            version:     "5.2.37",
            url:         "https://ftp.gnu.org/gnu/bash/bash-5.2.37.tar.gz",
            // Verify with `sha256sum bash-5.2.37.tar.gz` after first
            // fetch; the engine reports actual sha on mismatch so an
            // upstream change just needs a one-line edit here.
            sha256:      "9599b22ecd1d5787ad7d3b7bf0c59f312b3396d1e281175dd1f8a4014da621ff",
            extract_dir: "bash-5.2.37",
        }
    }

    fn build_and_install(&self, ctx: &Ctx) -> Result<Vec<InstallSpec>, u8> {
        let src = ctx.build_dir.join("bash-5.2.37");

        // Configure (idempotent — bash's configure is happy to re-run).
        let mut c = Command::new("./configure");
        c.args([
            "--prefix=/",
            "--without-bash-malloc",
            "--disable-nls",
            "--disable-readline",
            "--disable-history",
            "--enable-static-link",
            "--host=x86_64-linux-musl",
        ]);
        for (k, v) in musl_gcc_env() {
            c.env(k, v);
        }
        run_in(&src, c)?;

        // Build only the `bash` binary (skip docs/tests).
        let nproc = std::thread::available_parallelism()
            .map(|n| n.get()).unwrap_or(1);
        let mut m = Command::new("make");
        m.arg(format!("-j{}", nproc));
        m.arg("bash");
        for (k, v) in musl_gcc_env() {
            m.env(k, v);
        }
        run_in(&src, m)?;

        // Strip the binary — bash with debug info is ~1.2 MiB, stripped
        // is ~700 KiB. We have a small rootfs envelope.
        let _ = Command::new("strip")
            .arg(src.join("bash"))
            .status();

        Ok(vec![
            InstallSpec {
                host: src.join("bash"),
                dst:  "/bin/bash",
                mode: 0o755,
            },
        ])
    }
}
