use std::path::Path;

pub(super) fn stage_tools<P, D, L>(
    repo: &Path,
    arch: &str,
    put: &P,
    dbg: &D,
    ln_via_debugfs: &L,
) -> Result<(), u8>
where
    P: Fn(&Path, &str) -> Result<(), u8>,
    D: Fn(&str) -> Result<(), u8>,
    L: Fn(&str, &str) -> Result<(), u8>,
{
// F259 (D1): util-linux.
for (name, dest) in &[
    ("login",   "/bin/login"),
    ("agetty",  "/sbin/agetty"),
    // util-linux mount is non-PIE dynamic on x86 → fails to load
    // under our kernel; /bin/mount is the GNU/util-linux mount.
    ("mount",   "/usr/sbin/mount.util-linux"),
    ("umount",  "/usr/sbin/umount.util-linux"),
    ("su",      "/bin/su"),
    ("kill",    "/bin/kill"),
    ("cal",     "/usr/bin/cal"),
    ("losetup", "/sbin/losetup"),
] {
    let host = repo.join(format!("vendor/util-linux/{name}-{arch}"));
    if host.is_file() {
        put(&host, dest)?;
    }
}
ln_via_debugfs("/sbin/agetty",  "/sbin/getty")?;
ln_via_debugfs("/bin/login",    "/usr/bin/login")?;
ln_via_debugfs("/bin/su",       "/usr/bin/su")?;

// F260 (D2): shadow-utils — useradd/passwd/groupadd/etc.
for (name, dest) in &[
    ("useradd",   "/usr/sbin/useradd"),
    ("userdel",   "/usr/sbin/userdel"),
    ("usermod",   "/usr/sbin/usermod"),
    ("groupadd",  "/usr/sbin/groupadd"),
    ("groupdel",  "/usr/sbin/groupdel"),
    ("groupmod",  "/usr/sbin/groupmod"),
    ("passwd",    "/usr/bin/passwd"),
    ("chage",     "/usr/bin/chage"),
    ("gpasswd",   "/usr/bin/gpasswd"),
    ("newgrp",    "/usr/bin/newgrp"),
    ("chgpasswd", "/usr/sbin/chgpasswd"),
] {
    let host = repo.join(format!("vendor/shadow/{name}-{arch}"));
    if host.is_file() {
        put(&host, dest)?;
    }
}
ln_via_debugfs("/usr/bin/passwd", "/bin/passwd")?;

// F261 (D3): procps-ng — ps/top/free/etc.
for (name, dest) in &[
    ("ps","/bin/ps"),("top","/usr/bin/top"),("free","/usr/bin/free"),
    ("vmstat","/usr/bin/vmstat"),("uptime","/usr/bin/uptime"),
    ("pgrep","/usr/bin/pgrep"),("pkill","/usr/bin/pkill"),
    ("pmap","/usr/bin/pmap"),("tload","/usr/bin/tload"),
    ("w","/usr/bin/w"),("watch","/usr/bin/watch"),
    ("slabtop","/usr/bin/slabtop"),("sysctl","/sbin/sysctl"),
] {
    let host = repo.join(format!("vendor/procps-ng/{name}-{arch}"));
    if host.is_file() {
        put(&host, dest)?;
    }
}

// F262 (D4): iproute2 — ip, ss, tc, bridge, etc.
for (name, dest) in &[
    ("ip","/sbin/ip"),("ss","/sbin/ss"),("tc","/sbin/tc"),
    ("bridge","/sbin/bridge"),("rtmon","/sbin/rtmon"),
    ("lnstat","/usr/sbin/lnstat"),("nstat","/usr/sbin/nstat"),
    ("ifstat","/usr/sbin/ifstat"),
] {
    let host = repo.join(format!("vendor/iproute2/{name}-{arch}"));
    if host.is_file() {
        put(&host, dest)?;
    }
}
ln_via_debugfs("/sbin/ip", "/bin/ip")?;

// F251: vim 9.1.0950 static-musl + vendored ncurses → /usr/bin/vim.
let vim_bin = repo.join(format!("vendor/vim/vim-{}", arch));
if vim_bin.is_file() {
    put(&vim_bin, "/usr/bin/vim")?;
}

// F254: less 643 static-musl + vendored ncurses → /usr/bin/less.
let less_bin = repo.join(format!("vendor/less/less-{}", arch));
if less_bin.is_file() {
    put(&less_bin, "/usr/bin/less")?;
}

// ripgrep 14.1.1 static-musl (Rust) → /usr/bin/rg.
let rg_bin = repo.join(format!("vendor/ripgrep/rg-{}", arch));
if rg_bin.is_file() {
    put(&rg_bin, "/usr/bin/rg")?;
}
// Tooling backlog (static-musl): fd, bat, eza (Rust); jq (C).
for (dir, file, dest) in [
    ("fd", "fd", "/usr/bin/fd"),
    ("bat", "bat", "/usr/bin/bat"),
    ("eza", "eza", "/usr/bin/eza"),
    ("jq", "jq", "/usr/bin/jq"),
    ("tealdeer", "tldr", "/usr/bin/tldr"),
    ("hyperfine", "hyperfine", "/usr/bin/hyperfine"),
    ("dust", "dust", "/usr/bin/dust"),
    ("sd", "sd", "/usr/bin/sd"),
    ("bottom", "btm", "/usr/bin/btm"),
    ("procs", "procs", "/usr/bin/procs"),
    ("zoxide", "zoxide", "/usr/bin/zoxide"),
    ("ncdu", "ncdu", "/usr/bin/ncdu"),
    ("htop", "htop", "/usr/bin/htop"),
    ("tree", "tree", "/usr/bin/tree"),
    ("dos2unix", "dos2unix", "/usr/bin/dos2unix"),
    ("dos2unix", "unix2dos", "/usr/bin/unix2dos"),
    ("curl", "curl", "/usr/bin/curl"),
    ("wget", "wget", "/usr/bin/wget"),
    ("fzf", "fzf", "/usr/bin/fzf"),
    ("tmux", "tmux", "/usr/bin/tmux"),
    ("lazygit", "lazygit", "/usr/bin/lazygit"),
    ("yq", "yq", "/usr/bin/yq"),
    ("delta", "delta", "/usr/bin/delta"),
    ("choose", "choose", "/usr/bin/choose"),
    ("hexyl", "hexyl", "/usr/bin/hexyl"),
    ("rsync", "rsync", "/usr/bin/rsync"),
    ("nano", "nano", "/usr/bin/nano"),
    ("tokei", "tokei", "/usr/bin/tokei"),
    ("grex", "grex", "/usr/bin/grex"),
    ("xh", "xh", "/usr/bin/xh"),
    ("yazi", "yazi", "/usr/bin/yazi"),
    ("yazi", "ya", "/usr/bin/ya"),
    ("dialog", "dialog", "/usr/bin/dialog"),
    ("btop", "btop", "/usr/bin/btop"),
    ("dua", "dua", "/usr/bin/dua"),
    ("gron", "gron", "/usr/bin/gron"),
    ("pv", "pv", "/usr/bin/pv"),
    ("entr", "entr", "/usr/bin/entr"),
    ("unzip", "unzip", "/usr/bin/unzip"),
    ("zip", "zip", "/usr/bin/zip"),
    ("glow", "glow", "/usr/bin/glow"),
    ("micro", "micro", "/usr/bin/micro"),
    ("starship", "starship", "/usr/bin/starship"),
    // duf/glow/micro (Go) + starship (Rust): build recipes vendored +
    // binaries built, but NOT staged — they HANG on startup, UNKILLABLY
    // (verified post-F425-SMP: `timeout 6 duf --version` never returns,
    // SIGTERM/SIGKILL don't terminate it ⇒ stuck in an uninterruptible
    // kernel syscall during Go/Rust runtime init — a real syscall gap, NOT
    // an SMP/threading issue). Other Go apps (lazygit, fzf) run fine, so
    // it's a specific syscall these call at startup. Needs a hypervisor
    // RIP/syscall trace of the hung process (smp-distro-plan.md §E).
] {
    let b = repo.join(format!("vendor/{}/{}-{}", dir, file, arch));
    if b.is_file() { put(&b, dest)?; }
}

// GNU gzip 1.13 static-musl → /usr/bin/gzip (+gunzip via argv[0]).
let gzip_bin = repo.join(format!("vendor/gzip/gzip-{}", arch));
if gzip_bin.is_file() {
    put(&gzip_bin, "/usr/bin/gzip")?;
    ln_via_debugfs("/usr/bin/gzip", "/usr/bin/gunzip")?;
}

// F217: vendored GNU sed 4.9 — static-musl. Drops in at /usr/bin/sed
// ahead of any other /bin sed (PATH order /usr/bin before /bin).
// Per vendor/sed/build.sh.
let sed_bin = repo.join(format!("vendor/sed/sed-{}", arch));
if sed_bin.is_file() {
    put(&sed_bin, "/usr/bin/sed")?;
}

// F219: vendored GNU grep 3.11 — static-musl /usr/bin/grep.
let grep_bin = repo.join(format!("vendor/grep/grep-{}", arch));
if grep_bin.is_file() {
    put(&grep_bin, "/usr/bin/grep")?;
}

// F220: vendored GNU tar 1.35 — static-musl /usr/bin/tar.
let tar_bin = repo.join(format!("vendor/tar/tar-{}", arch));
if tar_bin.is_file() {
    put(&tar_bin, "/usr/bin/tar")?;
}

// F221: vendored GNU make 4.4.1 — static-musl /usr/bin/make.
let make_bin = repo.join(format!("vendor/make/make-{}", arch));
if make_bin.is_file() {
    put(&make_bin, "/usr/bin/make")?;
}

// F225: vendored GNU patch 2.7.6 — static-musl /usr/bin/patch.
let patch_bin = repo.join(format!("vendor/patch/patch-{}", arch));
if patch_bin.is_file() { put(&patch_bin, "/usr/bin/patch")?; }

// F226: vendored bzip2 1.0.8 — static-musl /usr/bin/bzip2.
let bz_bin = repo.join(format!("vendor/bzip2/bzip2-{}", arch));
if bz_bin.is_file() { put(&bz_bin, "/usr/bin/bzip2")?; }

// F227: vendored xz-utils 5.6.3 — static-musl /usr/bin/xz.
let xz_bin = repo.join(format!("vendor/xz/xz-{}", arch));
if xz_bin.is_file() { put(&xz_bin, "/usr/bin/xz")?; }

// F224: vendored GNU diffutils 3.10 — static-musl /usr/bin/diff + cmp.
let diff_bin = repo.join(format!("vendor/diffutils/diff-{}", arch));
let cmp_bin  = repo.join(format!("vendor/diffutils/cmp-{}",  arch));
if diff_bin.is_file() { put(&diff_bin, "/usr/bin/diff")?; }
if cmp_bin.is_file()  { put(&cmp_bin,  "/usr/bin/cmp")?;  }

// F223: vendored GNU findutils 4.10.0 — static-musl /usr/bin/find +
// /usr/bin/xargs. Real find supports -printf, -regex, -prune,
// -newer, -mtime, -exec ... +, etc. (full GNU findutils).
let find_bin = repo.join(format!("vendor/findutils/find-{}", arch));
let xargs_bin = repo.join(format!("vendor/findutils/xargs-{}", arch));
if find_bin.is_file() { put(&find_bin, "/usr/bin/find")?; }
if xargs_bin.is_file() { put(&xargs_bin, "/usr/bin/xargs")?; }

// F222: vendored GNU gawk 5.3.1 — static-musl /usr/bin/gawk +
// /usr/bin/awk hardlink so POSIX `awk ...` resolves to gawk.
let gawk_bin = repo.join(format!("vendor/gawk/gawk-{}", arch));
if gawk_bin.is_file() {
    put(&gawk_bin, "/usr/bin/gawk")?;
    ln_via_debugfs("/usr/bin/gawk", "/usr/bin/awk")?;
}

// F218: coreutils 8.32 single-binary (vendor/coreutils/build.sh).
    let cu_bin = repo.join(format!("vendor/coreutils/coreutils-{}", arch));
    if cu_bin.is_file() {
        put(&cu_bin, "/usr/libexec/coreutils")?;
        let dbg_ln = |target: &str, link: &str| -> Result<(), u8> {
            ln_via_debugfs(target, link)
        };
    for applet in &[
        "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "ln",
        "chmod", "chown", "chgrp", "touch", "stat", "dd",
        "head", "tail", "wc", "sort", "uniq", "tr", "cut", "tee", "tac",
        "mktemp", "readlink", "realpath", "dirname", "basename",
        "sleep", "date", "whoami", "id", "uname", "seq", "yes", "nproc",
        "nohup", "env", "printf", "printenv", "pwd",
        "expr", "factor", "expand", "unexpand", "fold", "fmt",
        "split", "csplit", "comm", "join", "paste", "shuf", "shred",
        "df", "du", "sync", "kill", "nice", "timeout", "tty", "stty",
        "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
        "base32", "base64", "basenc", "od",
        "nl", "pr", "ptx", "tsort", "truncate", "link", "unlink",
        "logname", "groups", "users", "who", "uptime", "hostid",
        "mkfifo", "mknod", "numfmt",
    ] {
        dbg_ln("/usr/libexec/coreutils", &format!("/usr/bin/{applet}"))?;
    }
    // Install coreutils as the /bin file/text applets (rm any prior link
    // first, then relink to coreutils). grep/find/sed/awk/tar/vi own their
    // own tools (below). systemd is PID1.
    for applet in &["ls","cat","cp","mv","rm","mkdir","rmdir","ln","head","tail","wc","sort","uniq","touch","chmod","chown","env","printf","yes","seq","expr","id","whoami","tr","cut","date","df","du","stat","sleep","tee","uname","pwd","basename","dirname","mknod","tty"] {
        dbg(&format!("rm /bin/{applet}"))?;
        dbg_ln("/usr/libexec/coreutils", &format!("/bin/{applet}"))?;
    }
}

// Install GNU /bin text/archive tools staged at /usr/bin above: link the
// GNU binary into /bin so /bin/grep etc. is unambiguously GNU regardless
// of PATH order. systemd is PID1 so the boot path is unaffected.
for (present, binname, target) in &[
    (grep_bin.is_file(), "grep", "/usr/bin/grep"),
    (sed_bin.is_file(),  "sed",  "/usr/bin/sed"),
    (find_bin.is_file(), "find", "/usr/bin/find"),
    (tar_bin.is_file(),  "tar",  "/usr/bin/tar"),
    (gawk_bin.is_file(), "awk",  "/usr/bin/awk"),
    (less_bin.is_file(), "less", "/usr/bin/less"),
    (vim_bin.is_file(),  "vi",   "/usr/bin/vim"),
    (gzip_bin.is_file(), "gzip",   "/usr/bin/gzip"),
    (gzip_bin.is_file(), "gunzip", "/usr/bin/gunzip"),
] {
        if *present {
            dbg(&format!("rm /bin/{binname}"))?;
            ln_via_debugfs(target, &format!("/bin/{binname}"))?;
        }
    }

// F362: CPython 3.13.1 static-musl → /usr/bin/python3.13 (+python3
// symlink). All stdlib C extensions are builtin (zlib/_socket/select/
// hashlib); the pure-python stdlib ships zipped at /usr/lib/python313.zip
// (CPython getpath adds <prefix>/lib/python313.zip to sys.path, so
// `python3 -c ...` works with no PYTHONPATH). _ssl/_ctypes gapped until
// openssl/libffi cross-detection lands.
let py_bin = repo.join(format!("vendor/python/python3-{}", arch));
let py_zip = repo.join("vendor/python/python313.zip");
if py_bin.is_file() && py_zip.is_file() {
    put(&py_bin, "/usr/bin/python3.13")?;
    ln_via_debugfs("/usr/bin/python3.13", "/usr/bin/python3")?;
    put(&py_zip, "/usr/lib/python313.zip")?;
}

let sshd_bin = repo.join(format!("vendor/openssh/sshd-{}", arch));
let sshdsess_bin = repo.join(format!("vendor/openssh/sshd-session-{}", arch));
let sshkeygen_bin = repo.join(format!("vendor/openssh/ssh-keygen-{}", arch));
let ssh_bin = repo.join(format!("vendor/openssh/ssh-{}", arch));
if sshd_bin.is_file() && sshdsess_bin.is_file() && sshkeygen_bin.is_file() {
    put(&sshd_bin,      "/usr/sbin/sshd")?;
    put(&sshdsess_bin,  "/usr/libexec/sshd-session")?;
    put(&sshkeygen_bin, "/usr/bin/ssh-keygen")?;
    if ssh_bin.is_file() { put(&ssh_bin, "/usr/bin/ssh")?; }
    dbg("mkdir /etc/ssh")?;
    // /var/empty is sshd's privsep chroot. We `--with-privsep-user=root`
    // so privsep is degenerate, but sshd still wants the dir to exist.
    dbg("mkdir /var/empty")?;
}

    Ok(())
}
