// Standard distro /etc items (login env, naming, readline, skel) for the
// rootfs image, split out of `rootfs.rs` to keep it under the 1000-line cap
// (`docs/08§7`). Takes the parent's `stage` (tempfile a blob) + `put` (write
// it into the image via debugfs) closures by reference.

use std::path::Path;

/// Write `/etc/{shells,hosts,environment,motd,bash.bashrc,inputrc}`, the
/// `/etc/profile.d/*.sh` drop-ins, and `/etc/skel` + per-user dotfiles.
/// # C: O(files)
pub fn write_standard_etc<S, P>(stage: &S, put: &P) -> Result<(), u8>
where
    S: Fn(&str, &[u8]) -> Result<std::path::PathBuf, u8>,
    P: Fn(&Path, &str) -> Result<(), u8>,
{
    // /etc/shells — valid login shells (chsh/passwd -s, sshd validate it).
    put(&stage("shells",
b"/bin/sh
/bin/bash
/usr/bin/bash
")?, "/etc/shells")?;

    // /etc/hosts — static name resolution (nsswitch hosts: files).
    put(&stage("hosts",
b"127.0.0.1   localhost localhost.localdomain oxide
::1         localhost localhost.localdomain ip6-localhost
")?, "/etc/hosts")?;

    // /etc/environment — system-wide env (PAM pam_env / login read it).
    put(&stage("environment",
b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=C.UTF-8
")?, "/etc/environment")?;

    // /etc/motd — shown after login.
    put(&stage("motd", b"Welcome to oxide Linux.\n")?, "/etc/motd")?;

    // /etc/bash.bashrc — system-wide interactive bash rc (aliases, prompt).
    put(&stage("bash.bashrc",
b"# system-wide bashrc for interactive shells
[ -z \"$PS1\" ] && return
alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'
")?, "/etc/bash.bashrc")?;

    // /etc/inputrc — system readline defaults.
    put(&stage("inputrc",
b"set enable-bracketed-paste on
set completion-ignore-case on
\"\\e[A\": history-search-backward
\"\\e[B\": history-search-forward
")?, "/etc/inputrc")?;

    // /etc/profile.d drop-ins (sourced by /etc/profile).
    put(&stage("profile.d.umask", b"umask 022\n")?, "/etc/profile.d/umask.sh")?;
    put(&stage("profile.d.lang",
b"export LANG=C.UTF-8\nexport LC_COLLATE=C\n")?, "/etc/profile.d/lang.sh")?;
    put(&stage("profile.d.aliases",
b"alias ll='ls -alF'\nalias la='ls -A'\n")?, "/etc/profile.d/aliases.sh")?;

    // /etc/skel — default dotfiles copied into new user homes (useradd -m).
    let skel_profile =
b"# ~/.profile: executed by login shells.
[ -r /etc/profile ] && . /etc/profile
[ -d \"$HOME/bin\" ] && PATH=\"$HOME/bin:$PATH\"
[ -n \"$BASH\" ] && [ -r \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\"
";
    let skel_bashrc =
b"# ~/.bashrc: executed by interactive non-login shells.
[ -z \"$PS1\" ] && return
[ -r /etc/bash.bashrc ] && . /etc/bash.bashrc
export PS1='\\u@\\h:\\w\\$ '
export HISTSIZE=1000 HISTFILESIZE=2000
";
    put(&stage("skel.profile", skel_profile)?, "/etc/skel/.profile")?;
    put(&stage("skel.bashrc",  skel_bashrc)?,  "/etc/skel/.bashrc")?;
    // Seed root + alice with the same dotfiles so interactive shells behave.
    put(&stage("root.bashrc",   skel_bashrc)?,  "/root/.bashrc")?;
    put(&stage("alice.profile", skel_profile)?, "/home/alice/.profile")?;
    put(&stage("alice.bashrc",  skel_bashrc)?,  "/home/alice/.bashrc")?;
    Ok(())
}
