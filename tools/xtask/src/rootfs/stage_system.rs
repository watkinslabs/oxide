use std::path::Path;

use crate::l2_deps;

pub(super) fn stage_system<P, D, L>(
    repo: &Path,
    arch: &str,
    pam_vendor_sec: &Path,
    put: &P,
    dbg: &D,
    ln_via_debugfs: &L,
) -> Result<(), u8>
where
    P: Fn(&Path, &str) -> Result<(), u8>,
    D: Fn(&str) -> Result<(), u8>,
    L: Fn(&str, &str) -> Result<(), u8>,
{
// /etc/issue + /etc/os-release + /etc/passwd + /etc/group +
// /etc/shadow + /etc/inittab written via tempfile then put().
let tmp = repo.join("target/oxide-rootfs-staging");
std::fs::create_dir_all(&tmp).map_err(|_| 1u8)?;

let stage = |name: &str, content: &[u8]| -> Result<std::path::PathBuf, u8> {
    let p = tmp.join(name);
    std::fs::write(&p, content).map_err(|_| 1u8)?;
    Ok(p)
};

// /etc accounts, PAM stacks, and opt-in boot markers — split out to keep
// this file under the 1000-line cap (`docs/08§7`).
crate::rootfs_etc::write_accounts_and_markers(&stage, &put, &dbg, &arch)?;
// Stage PAM modules at /usr/lib/security/ (libpam DEFAULT_MODULE_PATH).
// Sources are upstream Linux-PAM 1.7.2 under vendor/pam/.../modules/,
// built by vendor/pam/build.sh into install-<arch>/modules/.
let pam_vendor = |name: &str| pam_vendor_sec.join(name);
put(&pam_vendor("pam_permit.so"),  "/usr/lib/security/pam_permit.so")?;
put(&pam_vendor("pam_deny.so"),    "/usr/lib/security/pam_deny.so")?;
put(&pam_vendor("pam_nologin.so"), "/usr/lib/security/pam_nologin.so")?;
put(&pam_vendor("pam_warn.so"),    "/usr/lib/security/pam_warn.so")?;
put(&pam_vendor("pam_rootok.so"),  "/usr/lib/security/pam_rootok.so")?;
put(&pam_vendor("pam_unix.so"),    "/usr/lib/security/pam_unix.so")?;
// unix_chkpwd setuid helper — su/passwd fork it to validate /etc/shadow.
let chkpwd_src = repo.join(format!("vendor/pam/install-{arch}/unix_chkpwd"));
put(&chkpwd_src, "/usr/sbin/unix_chkpwd")?;
// Shared libpam + libpam_misc — login, sshd, su DT_NEEDED them.
let pam_lib = repo.join(format!("vendor/pam/install-{arch}/lib"));
put(&pam_lib.join("libpam.so.0.85.1"),         "/usr/lib/libpam.so.0.85.1")?;
put(&pam_lib.join("libpam_misc.so.0.82.1"),    "/usr/lib/libpam_misc.so.0.82.1")?;
ln_via_debugfs("/usr/lib/libpam.so.0.85.1",      "/usr/lib/libpam.so.0")?;
ln_via_debugfs("/usr/lib/libpam.so.0.85.1",      "/usr/lib/libpam.so")?;
ln_via_debugfs("/usr/lib/libpam_misc.so.0.82.1", "/usr/lib/libpam_misc.so.0")?;
ln_via_debugfs("/usr/lib/libpam_misc.so.0.82.1", "/usr/lib/libpam_misc.so")?;
// L2 shared libs → /usr/lib: real .so + soname/linker-name symlinks.
let stage_so = |vendor: &str, real: &str, soname: &str, linker: &str| -> Result<(), u8> {
    let dir = repo.join(format!("vendor/{vendor}/install-{arch}/lib"));
    put(&dir.join(real), &format!("/usr/lib/{real}"))?;
    // Skip the self-link when real == SONAME (e.g. openssl libssl.so.3).
    if soname != real { ln_via_debugfs(&format!("/usr/lib/{real}"), &format!("/usr/lib/{soname}"))?; }
    ln_via_debugfs(&format!("/usr/lib/{real}"), &format!("/usr/lib/{linker}"))?;
    Ok(())
};
for (vendor, real, soname, linker) in l2_deps::L2_LIBS {
    stage_so(vendor, real, soname, linker)?;
}
// NB: do NOT pre-create /run/systemd/netif — networkd makes it 192:192.
for d in ["/lib/systemd", "/usr/lib/systemd", "/usr/lib/systemd/system",
          "/etc/systemd", "/etc/systemd/system", "/etc/systemd/system/multi-user.target.wants",
          "/etc/systemd/network", "/var/lib/systemd", "/var/lib/systemd/network"] { dbg(&format!("mkdir {d}"))?; }
for (rel, tgt) in l2_deps::SYSTEMD_STAGE {
    put(&repo.join(format!("vendor/systemd/install-{arch}/{rel}")), tgt)?;
    // Unit files → 0644 (PID1 warns on exec); debugfs sif keeps S_IFREG.
    if tgt.ends_with(".target") || tgt.ends_with(".service") {
        dbg(&format!("sif {tgt} mode 0100644"))?;
    }
}

// systemd-networkd (D6 net): built+staged+enabled but NOT pulled by
// default.target yet (auto-start gated on executor↔PID1 readiness + CPU
// fairness); run by hand it pulls a real DHCPv4 lease. Bodies in l2_deps.
put(&stage("systemd-networkd.service", l2_deps::NETWORKD_SERVICE)?,
    "/usr/lib/systemd/system/systemd-networkd.service")?;
dbg("sif /usr/lib/systemd/system/systemd-networkd.service mode 0100644")?;
put(&stage("eth0.network", l2_deps::ETH0_NETWORK)?, "/etc/systemd/network/eth0.network")?;
dbg("sif /etc/systemd/network/eth0.network mode 0100644")?;
// default.target authored here (not SYSTEMD_STAGE — debugfs can't overwrite).
put(&stage("default.target", l2_deps::DEFAULT_TARGET)?,
    "/usr/lib/systemd/system/default.target")?;
dbg("sif /usr/lib/systemd/system/default.target mode 0100644")?;
put(&stage("serial-getty-ttyS0.service", l2_deps::SERIAL_GETTY_TTYS0_SERVICE)?,
    "/usr/lib/systemd/system/serial-getty-ttyS0.service")?;
dbg("sif /usr/lib/systemd/system/serial-getty-ttyS0.service mode 0100644")?;
// /etc/inittab — legacy sysv format (systemd is PID1; kept informational).
put(&stage("inittab",
b"::sysinit:/etc/init.d/rcS
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
ttyS0::respawn:/sbin/getty --noreset --noclear -L 115200 ttyS0 vt100
")?,
    "/etc/inittab")?;

// /etc/dhcpcd.conf — minimal config (10s bind timeout; no hooks dir).
put(&stage("dhcpcd.conf",
b"# F123: minimal dhcpcd.conf for oxide userspace.
duid
persistent
option domain_name_servers, domain_name, domain_search, host_name
option classless_static_routes
option interface_mtu
require dhcp_server_identifier
slaac private
timeout 10
")?,
    "/etc/dhcpcd.conf")?;

// /etc/init.d/rcS — sysinit shell script.
put(&stage("rcS",
b"#!/bin/sh
mount -t proc  proc  /proc 2>/dev/null
mount -t sysfs sysfs /sys  2>/dev/null
mount -t tmpfs tmpfs /tmp  2>/dev/null
mount -t tmpfs tmpfs /var/run 2>/dev/null
mount -t tmpfs tmpfs /var/db  2>/dev/null
mount -t devpts devpts /dev/pts 2>/dev/null
# syslogd creates /dev/log socket + writes /var/log/messages.
# Captures pam_unix's pam_syslog() so we can see why auth fails.
mkdir -p /var/log
syslogd -O /var/log/messages -S 2>/dev/null
hostname -F /etc/hostname 2>/dev/null
ifconfig lo 127.0.0.1 up 2>/dev/null
ifconfig eth0 up 2>/dev/null
# F141: udhcpc is the legacy DHCP client (already in
# the rootfs, no separate vendor binary). Real upstream dhcpcd
# still wedges post-lease-setup; udhcpc's simpler state machine
# hits fewer of the gap-y syscall paths. Gated behind
# /etc/oxide-udhcpc-enable so the default boot stays fast.
if [ -e /etc/oxide-udhcpc-enable ] && [ -x /sbin/udhcpc ]; then
# Foreground -t 3 -T 2: ~6s ceiling for a slirp lease; once
# bound, default.script (F147) installs ifaddr + default route
# via SIOCSIFADDR / SIOCADDRT, and the kernel net stack is
# routable (F148/F149).
/sbin/udhcpc -i eth0 -s /usr/share/udhcpc/default.script -q -n -t 3 -T 2
# Confirm with a real outbound DNS round-trip (slirp's 10.0.2.3).
[ -x /bin/online_smoke ] && /bin/online_smoke
[ -x /bin/tcp_smoke ]    && /bin/tcp_smoke
fi
[ -x /etc/init.d/oxide-smokes ] && /etc/init.d/oxide-smokes
# F210: openssh sshd (port 22). Generates host keys on first boot
# (only the ed25519 type, since the binary was built without OpenSSL
# and the other key types depend on it), then forks the daemon.
if [ -x /usr/sbin/sshd ]; then
echo sshd-step-pre-keygen
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    /usr/bin/ssh-keygen -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key 2>&1
    echo ssh-keygen-rv=$?
fi
echo sshd-step-post-keygen
ls -l /etc/ssh/ 2>&1
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>/dev/null
route add default gw 10.0.2.2 2>/dev/null
echo sshd-step-launch
/usr/sbin/sshd -D -e 2>&1 &
echo sshd-step-launched-bg pid=$!
fi
:
")?,
    "/etc/init.d/rcS")?;
dbg("sif /etc/init.d/rcS mode 0100755")?;

// /etc/init.d/oxide-smokes — kernel-acceptance smoke harness
// (replaces the C harness from old userspace/init/init.c). Gated
// by the marker file so OXIDE_INIT_SMOKES=0 boots skip it.
// oxide-smokes script lives in assets/oxide-smokes.sh (kept out of
// this file for the 1000-line cap; edit the .sh to add probes).
put(&stage("oxide-smokes", include_bytes!("../assets/oxide-smokes.sh"))?,
    "/etc/init.d/oxide-smokes")?;
dbg("sif /etc/init.d/oxide-smokes mode 0100755")?;

// F147/F149: udhcpc lease-event script. $1 ∈ {deconfig,bound,
// renew}; bound/renew set iface+route+resolv.conf, deconfig tears
// the addr down. Lease fields arrive as env vars from udhcpc.
put(&stage("udhcpc-default.script",
b"#!/bin/sh
# udhcpc lease-event handler. Invoked by udhcpc with
# $1 = event name and lease fields exported as env vars.
RESOLV=/etc/resolv.conf
case \"$1\" in
deconfig)
    ifconfig $interface 0.0.0.0 2>/dev/null
    ;;
bound|renew)
    ifconfig $interface $ip netmask ${subnet:-255.255.255.0} \\
        broadcast ${broadcast:-+} 2>/dev/null
    if [ -n \"$router\" ]; then
        while route del default gw 0.0.0.0 dev $interface 2>/dev/null; do :; done
        for r in $router; do
            route add default gw $r dev $interface 2>/dev/null
        done
    fi
    : > $RESOLV
    [ -n \"$domain\" ] && echo \"search $domain\" >> $RESOLV
    for s in $dns; do
        echo \"nameserver $s\" >> $RESOLV
    done
    echo \"udhcpc: configured $interface as $ip via $router\"
    ;;
esac
exit 0
")?,
    "/usr/share/udhcpc/default.script")?;
dbg("sif /usr/share/udhcpc/default.script mode 0100755")?;

// /etc/profile — login-shell environment. Sources /etc/profile.d/*.sh
// and a per-user ~/.bashrc, like a real distro.
put(&stage("profile",
b"export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PS1='\\h:\\w\\$ '
# oxide's console is an xterm-class emulator (xterm key sequences + ?1049
# alt-screen / DEC line-drawing / 256-color), so xterm-256color not linux,
# whose terminfo lacks smcup (that blocked htop/vim alt-screen). See B123.
export TERM=xterm-256color
umask 022
if [ -d /etc/profile.d ]; then
  for _f in /etc/profile.d/*.sh; do
[ -r \"$_f\" ] && . \"$_f\"
  done
  unset _f
fi
if [ -n \"$BASH\" ] && [ -r ~/.bashrc ]; then . ~/.bashrc; fi
")?,
    "/etc/profile")?;

// /etc/login.defs — login(1) (util-linux) reads ENV_PATH / ENV_SUPATH
// and sets them as PATH in the child env before exec'ing the
// shell, regardless of whether /etc/profile gets sourced. Keeps
// `ls`, `cat`, etc. usable from the very first prompt.
put(&stage("login.defs",
b"ENV_PATH        PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
ENV_SUPATH      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
")?,
    "/etc/login.defs")?;

// /root/.profile — sourced by login shells after /etc/profile.
// Belt-and-suspenders: if /etc/profile fails to source for any
// reason, this still seeds PATH for root's interactive sessions.
put(&stage("root.profile",
b"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PS1='\\h:\\w# '
")?,
    "/root/.profile")?;

// /etc/fstab (informational; for `mount -a`).
put(&stage("fstab",
b"proc    /proc    proc    defaults  0 0
sysfs   /sys     sysfs   defaults  0 0
tmpfs   /tmp     tmpfs   defaults  0 0
devpts  /dev/pts devpts  defaults  0 0
")?,
    "/etc/fstab")?;

// /etc/nsswitch.conf — files-only resolver.
put(&stage("nsswitch.conf",
b"passwd: files
group:  files
shadow: files
hosts:  files
")?,
    "/etc/nsswitch.conf")?;

put(&stage("hello.txt", b"hello-from-ext4-mini\n")?, "/hello.txt")?;

// /etc/keymap — runtime-loadable keyboard layout. Drop another
// text file at this path (or `loadkeys <name>` once we ship it)
// to switch layouts. See `userspace/keymaps/` for the source maps.
let km_us = include_bytes!("../../../../userspace/keymaps/us.kmap");
let km_uk = include_bytes!("../../../../userspace/keymaps/uk.kmap");
let km_de = include_bytes!("../../../../userspace/keymaps/de.kmap");
let km_fr = include_bytes!("../../../../userspace/keymaps/fr.kmap");
let km_es = include_bytes!("../../../../userspace/keymaps/es.kmap");
put(&stage("keymap", km_us)?, "/etc/keymap")?;
put(&stage("us.kmap", km_us)?, "/usr/share/keymaps/us.kmap")?;
put(&stage("uk.kmap", km_uk)?, "/usr/share/keymaps/uk.kmap")?;
put(&stage("de.kmap", km_de)?, "/usr/share/keymaps/de.kmap")?;
put(&stage("fr.kmap", km_fr)?, "/usr/share/keymaps/fr.kmap")?;
put(&stage("es.kmap", km_es)?, "/usr/share/keymaps/es.kmap")?;

// F252: minimal terminfo db for ncurses-linked programs.
for (sub, name) in &[
    ("d", "dumb"), ("l", "linux"), ("s", "screen"),
    ("v", "vt100"), ("x", "xterm"), ("x", "xterm-256color"),
] {
    let host = repo.join(format!("vendor/terminfo/{sub}/{name}"));
    put(&host, &format!("/usr/share/terminfo/{sub}/{name}"))?;
}

// Standard distro /etc items (shells, hosts, environment, motd,
// bash.bashrc, inputrc, profile.d/*, skel + dotfiles) — split out to
// keep this file under the 1000-line cap (`docs/08§7`).
crate::rootfs_etc::write_standard_etc(&stage, &put)?;

    Ok(())
}
