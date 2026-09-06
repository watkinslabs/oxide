//! Cargo target-directory resolution for probe artifacts.

use std::path::PathBuf;
use std::process::Command;

/// Resolve the target directory Cargo will use for a probe workspace. The
/// resolver is authoritative: metadata failure never falls back to `target/`.
pub(super) fn target_dir(workspace: &str) -> Result<PathBuf, u8> {
    let output = Command::new("python3")
        .arg("tools/probe-target-directory.py")
        .arg("--workspace")
        .arg(workspace)
        .output()
        .map_err(|error| {
            eprintln!("xtask: probe target-directory resolver failed to start: {error}");
            2u8
        })?;
    if !output.status.success() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        eprintln!("xtask: probe target-directory resolver failed for {workspace}");
        return Err(2);
    }
    let stdout = String::from_utf8(output.stdout).map_err(|_| {
        eprintln!("xtask: probe target-directory resolver returned non-UTF-8 output");
        2u8
    })?;
    let mut lines = stdout.lines();
    let line = lines.next().filter(|line| !line.is_empty()).ok_or_else(|| {
        eprintln!("xtask: probe target-directory resolver returned no path");
        2u8
    })?;
    if lines.next().is_some() {
        eprintln!("xtask: probe target-directory resolver returned multiple paths");
        return Err(2);
    }
    let path = PathBuf::from(line);
    if !path.is_absolute() {
        eprintln!("xtask: probe target-directory resolver returned a relative path");
        return Err(2);
    }
    Ok(path)
}

#[cfg(test)]
#[path = "probe_artifact/tests.rs"]
mod tests;
