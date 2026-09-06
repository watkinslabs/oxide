//! Read-only post-staging payload gate; selected native inputs establish byte identity.
use std::path::Path;
use std::process::Command;

pub(super) fn verify(image: &Path, ntdll: &Path, win32u: &Path) -> Result<(), u8> {
    let status = command(image, ntdll, win32u).status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => { eprintln!("xtask rootfs: staged Windows payload gate failed"); Err(2) }
    }
}

fn command(image: &Path, ntdll: &Path, win32u: &Path) -> Command {
    let mut command = Command::new("python3");
    command.arg("tools/windows-rootfs-payload-check.py").arg("--image").arg(image)
        .arg("--expected-ntdll").arg(ntdll).arg("--expected-win32u").arg(win32u);
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gate_receives_exact_image_and_selected_native_pair() {
        let command = command(Path::new("root image.img"), Path::new("built ntdll.so"), Path::new("built win32u.so"));
        assert_eq!(command.get_program(), "python3");
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["tools/windows-rootfs-payload-check.py", "--image",
            "root image.img", "--expected-ntdll", "built ntdll.so", "--expected-win32u", "built win32u.so"]);
    }
}
