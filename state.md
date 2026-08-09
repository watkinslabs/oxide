# Session hand-off — 2026-08-09 (boot-freeze campaign)

## Headline
The intermittent ~5s boot freeze is ROOT-CAUSED and FIXED (B2010, PR #4902):
`local_bh_enable` drained softirqs inside irqsave sections; a drained
InputDrain re-took the VT port lock its own stack held. GDB-captured RIP.
Alongside it, ten one-CPU softirq-vs-process deadlock instances were fixed
across gpu/block/snd/input/vsock/ahci/net (B2007-B2009, B2011). Boots now
reach graphical.target at ~75s attempt 1; the sssd-kcm/udisks2 failures were
freeze collateral and are healthy (PR #4903 closed the row with evidence).

## Merged today
#4894 VT=/dev/console (serial mirrors) · #4895 packet-ring BhGuard ·
#4896 GPU 1280x800 · #4897 minimal-boot-time rule · #4898 ext4 unwritten-split
(34x less I/O) · #4899 gpu CTX lock_bh · #4900 block DiskState/MappingState ·
#4901 snd/input/vsock/ahci locks · #4902 bh-enable irqs-off drain guard ·
#4903 services-row close · #4904 NET_RX per-instance locks via FibLock.

## Open, in priority order
1. SUSPECTED softirq-lock remainder (raw4/raw6/ping RX, AF_PACKET fanout) —
   audit agent report goes in `scratch/known_issues.md`; fix shape = FibLock
   conversion, proven mechanical.
2. VT detached-sink: fbcon render still runs under the port lock irqsave
   (latency, not deadlock) — row filed, serial's split is the template.
3. ext4 drops `datasync` — full design in the row (per-mount commit
   generation + per-inode sync/datasync tids + barrier watermark; the
   accidental-safety shortcut is documented as forbidden).
4. Stack-gate red on clean main (boot-stack rows need their own root class
   via the tool's --irq-roots mechanism) — every push needs SKIP_STACK_GATE=1.
5. GNOME desktop layer (greeter/session) — untouched today; boot layer is
   now solid underneath it.

## First command next session
grep -n "OPEN" scratch/known_issues.md | head -30
