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

    // /etc/bash.bashrc — system-wide interactive bash rc (aliases, prompt,
    // locale), for interactive NON-login shells (sub-shells), sourced via
    // ~/.bashrc. Mirrors Debian's /etc/bash.bashrc role. NOTE: util-linux
    // login DOES exec a login shell (argv[0]="-sh"; verified `shopt
    // login_shell` == on), so /etc/profile + /etc/profile.d/*.sh ARE sourced
    // at login — that path owns login-session env; this owns sub-shell env.
    put(&stage("bash.bashrc",
b"# system-wide bashrc for interactive shells
[ -z \"$PS1\" ] && return
export LANG=C.UTF-8
export LC_COLLATE=C
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

/// Write `/etc/{issue,os-release,hostname,passwd,group,shadow,sshd_config}`,
/// the `/etc/pam.d/{sshd,login}` stacks, the `/sl_target` symlink fixture, and
/// the opt-in boot markers (init-smokes/vsock/arch/dhcpcd/udhcpc). Split out of
/// `rootfs.rs` to keep it under the 1000-line cap (`docs/08§7`). Takes the
/// parent's `stage`/`put`/`dbg` closures by reference.
/// # C: O(files)
pub fn write_accounts_and_markers<S, P, D>(stage: &S, put: &P, dbg: &D, arch: &str) -> Result<(), u8>
where
    S: Fn(&str, &[u8]) -> Result<std::path::PathBuf, u8>,
    P: Fn(&Path, &str) -> Result<(), u8>,
    D: Fn(&str) -> Result<(), u8>,
{
    put(&stage("issue", b"oxide \\s on \\l\n\n")?, "/etc/issue")?;
    // K2V V6: symlink-follow fixture for /bin/symlink_probe (ext4 symlink
    // CREATE isn't implemented, so bake a real ext4 symlink at build).
    put(&stage("sl_target", b"SLOK")?, "/sl_target")?;
    dbg("symlink /sl_link /sl_target")?;
    // F149-3: present → init runs kernel-acceptance smokes (set 0 to skip).
    if std::env::var("OXIDE_INIT_SMOKES").as_deref() != Ok("0") {
        put(&stage("oxide-init-smokes", b"1\n")?, "/etc/oxide-init-smokes")?;
    }
    // D3.3: present → rcS smoke runs /bin/vsock_probe against the host
    // echo peer (boot-smoke-vsock.sh sets OXIDE_VSOCK_SMOKE=1 + starts
    // the host socat/python AF_VSOCK server). Absent on normal boots so
    // the guarded probe is skipped (no host peer → would false-fail).
    if std::env::var("OXIDE_VSOCK_SMOKE").as_deref() == Ok("1") {
        put(&stage("oxide-vsock-smoke", b"1\n")?, "/etc/oxide-vsock-smoke")?;
    }
    // F211: arch marker — rcS picks sshd daemonize mode by this file.
    if arch == "aarch64" {
        put(&stage("oxide-arch-is-aarch64", b"1\n")?, "/etc/oxide-arch-is-aarch64")?;
    }
    // B44: opt-in marker (off by default) for reproducing the
    // dhcpcd userspace heap-corruption hunt. The kernel now
    // survives the resulting user-mode #GP (delivers SIGSEGV
    // instead of halting), but dhcpcd itself still crashes; auto-
    // launch stays gated until the userspace cause is fixed.
    if std::env::var("OXIDE_DHCPCD_ENABLE").as_deref() == Ok("1") {
        put(&stage("oxide-dhcpcd-enable", b"1\n")?, "/etc/oxide-dhcpcd-enable")?;
    }
    // F141: udhcpc marker — opt-in DHCP client.
    if std::env::var("OXIDE_UDHCPC_ENABLE").as_deref() == Ok("1") {
        put(&stage("oxide-udhcpc-enable", b"1\n")?, "/etc/oxide-udhcpc-enable")?;
    }
    put(&stage("os-release",
        b"NAME=oxide\nVERSION=0.1\nID=oxide\nPRETTY_NAME=\"oxide-os 0.1\"\n")?,
        "/etc/os-release")?;
    put(&stage("hostname", b"oxide\n")?, "/etc/hostname")?;
    // root: no password; alice: "swordfish". systemd-network (uid/gid 192):
    // networkd privsep-drops to it (sysusers.d on every distro) — aborts at
    // startup ("Cannot resolve user name systemd-network") without it.
    put(&stage("passwd",
        b"root:x:0:0:root:/root:/bin/sh\n\
          systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin\n\
          alice:x:1000:1000:Alice User:/home/alice:/bin/sh\n\
          nobody:x:65534:65534:nobody:/:/bin/false\n")?,
        "/etc/passwd")?;
    put(&stage("group",
        b"root:x:0:\n\
          systemd-network:x:192:\n\
          wheel:x:10:alice\n\
          users:x:100:alice\n\
          nobody:x:65534:\n")?,
        "/etc/group")?;
    // shadow: root empty (no pw), alice = sha512(salt|swordfish|salt)
    // (matches crypt::sha512crypt v1; will be regenerated when we
    //  ship Drepper-2007 parity in P14-08).
    put(&stage("shadow",
        b"root::19000:0:99999:7:::\n\
          systemd-network:!*:19000:0:99999:7:::\n\
          alice:$6$alsalt$Gy2r/DsI0Nj04MSfT1ob.ARb1hRHSZAx9elcKZSElN4EA7.NvTuioqQSs7hTeM7c/.mZ2Sk6GuR4vey3Lk1521:19000:0:99999:7:::\n\
          nobody:!:19000:0:99999:7:::\n")?,
        "/etc/shadow")?;
    // F231: sshd_config UsePAM=yes — libpam dlopens modules from
    // /usr/lib/security/ at session setup.
    put(&stage("sshd_config",
        b"Port 22\n\
AddressFamily inet\n\
ListenAddress 0.0.0.0\n\
HostKey /etc/ssh/ssh_host_ed25519_key\n\
PermitRootLogin no\n\
PasswordAuthentication yes\n\
PermitEmptyPasswords no\n\
PubkeyAuthentication yes\n\
UsePAM yes\n\
Compression yes\n\
PrintMotd no\n\
PrintLastLog no\n\
UseDNS no\n\
StrictModes no\n\
LogLevel INFO\n")?,
        "/etc/ssh/sshd_config")?;
    dbg("mkdir /etc/pam.d")?;
    put(&stage("pam_sshd",
        b"# pam_unix activated -- openssh built with real pthread\n\
# (-DUNSUPPORTED_POSIX_THREADS_HACK) + 128 MB kernel heap (F246).\n\
auth       required   pam_unix.so\n\
account    required   pam_unix.so\n\
password   required   pam_unix.so\n\
session    required   pam_unix.so\n")?,
        "/etc/pam.d/sshd")?;
    // B18: util-linux login(1) calls pam_start("login",...); without
    // /etc/pam.d/login libpam aborts with PAM_ABORT before any prompt
    // ("PAM failure, aborting: Critical error - immediate abort"), so
    // console login was broken since util-linux landed in D1. Mirror
    // the sshd stack: full pam_unix once T14 lands a real one; for now
    // the stub unblocks the console.
    put(&stage("pam_login",
        b"# console login PAM stack - mirrors the sshd stack (pam_unix.so +
# /etc/shadow); nullok accepts the empty root password (root + Enter).
auth       required   pam_unix.so nullok
account    required   pam_unix.so
password   required   pam_unix.so nullok
session    required   pam_unix.so
")?,
        "/etc/pam.d/login")?;
    Ok(())
}
