//! Read-only post-staging payload gate; the packaged Wine version establishes provenance.
use std::path::Path;
use std::process::Command;

pub(super) fn verify(image: &Path, wine_version: &str) -> Result<(), u8> {
    let status = command(image, wine_version).status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => { eprintln!("xtask rootfs: staged Windows payload gate failed"); Err(2) }
    }
}

fn command(image: &Path, wine_version: &str) -> Command {
    let mut command = Command::new("python3");
    command.arg("tools/windows-rootfs-payload-check.py").arg("--image").arg(image)
        .arg("--expected-wine-version").arg(wine_version);
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gate_receives_exact_image_and_expected_wine_version() {
        let command = command(Path::new("root image.img"), "11.16");
        assert_eq!(command.get_program(), "python3");
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["tools/windows-rootfs-payload-check.py", "--image",
            "root image.img", "--expected-wine-version", "11.16"]);
    }
}
