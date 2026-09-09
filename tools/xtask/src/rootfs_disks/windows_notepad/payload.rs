//! Read-only post-staging payload gate; the packaged Wine version establishes provenance.
use std::path::Path;
use std::process::Command;

/// Validate the requested runtime before reusing a staged disk. # C: O(payload bytes)
pub(crate) fn verify_cached_windows(image: &Path) -> Result<(), u8> {
    if std::env::var_os("OXIDE_WINDOWS_NOTEPAD_SMOKE").is_none() && std::env::var_os("OXIDE_WINE_PROFILE").is_none() { return Ok(()); }
    let profile = std::env::var("OXIDE_WINE_PROFILE").unwrap_or_else(|_| "release".into());
    verify(image, super::catalog::EXPECTED.trim(), &profile)
}

pub(super) fn verify(image: &Path, wine_version: &str, profile: &str) -> Result<(), u8> {
    let status = command(image, wine_version, profile).status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => { eprintln!("xtask rootfs: staged Windows payload gate failed"); Err(2) }
    }
}

/// Reject a mismatched packaged profile before staging. # C: O(image metadata)
pub(super) fn verify_profile(image:&Path,version:&str,profile:&str)->Result<(),u8>{
    match command(image,version,profile).arg("--profile-only").status(){
        Ok(status) if status.success()=>Ok(()),
        _=>{eprintln!("xtask rootfs: Wine profile selection does not match image");Err(2)}
    }
}

fn command(image: &Path, wine_version: &str, profile: &str) -> Command {
    let mut command = Command::new("python3");
    command.arg("tools/windows-rootfs-payload-check.py").arg("--image").arg(image)
        .arg("--expected-wine-version").arg(wine_version).arg("--expected-wine-profile").arg(profile);
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gate_receives_exact_image_and_expected_wine_version() {
        let command = command(Path::new("root image.img"), "11.16", "debug");
        assert_eq!(command.get_program(), "python3");
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["tools/windows-rootfs-payload-check.py", "--image",
            "root image.img", "--expected-wine-version", "11.16", "--expected-wine-profile", "debug"]);
    }
}
