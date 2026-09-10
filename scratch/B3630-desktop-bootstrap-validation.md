# Interactive desktop namespace initialization

| Status | Branch | Item |
|---|---|---|
| FIXED | B3630-paint-region-collapse | KI0924 canonical desktop bootstrap |

Actual launch requests \Windows\WindowStations\WinSta0, but namespace seed stopped at \Windows. Canonical station publication rejects missing parents; nt_exec attachment therefore returned without station/default-desktop membership. Live diagnostic5341a7a34 returned NULL screen DCs throughout Open construction; HWND100011 then requested1px height. Probe exit7 pins missing desktop HWND and both forms of desktop DC, with working screen metrics and compatible DC creation.

Repair adds the permanent WindowStations directory in the existing object namespace initializer. No alternate lookup or implicit-parent creation. Exact-path joined regression consumes nt_desktop_names, canonical bootstrap/handle tables, membership/root resolution and real desktop GDI lease. Two process tables share identity; final temporary-handle closure preserves permanent parent.

Before repair: actual-path test fails Namespace(ParentMissing), /tmp/B3630-desktop-bootstrap-red.log. After repair:4 boundary tests and104 object tests pass, /tmp/B3630-desktop-bootstrap-{green,objects}.log. Full scheduler2029 tests PASS. Both release builds, feature checks and frame gates PASS. Static gate remains KI0019:334x86/277ARM rows, no added or increased paths; exceptions7664/6368 unchanged. Logs /tmp/B3630-desktop-bootstrap-{stack,frame-arm,stack-arm,push}.log. Post-fix run4192767: initial token and measured File/Open clicks pass; all observed screen DC returns nonzero, filename edit height15px instead of1, and identical PE diagnostic exits0 instead of7. Full dialog observation still fails missing chrome and severe retained-paint corruption. KI0923 remaining combo acceptance, KI0887 complete dialog acceptance remain open; file-type/encoding dropdown selection, popup geometry and repaint need actual UI checks.

Diagnostic VM4127880 exited0 at1789046321.9160104; no quit/reboot issued, cause unknown. Runner25062; target/B3630-measure-verification-debug/live.json and uart-4127818.log. Initial token visibly correct but harness observation failed; measured manual File168,156 then Open196,196 created the broken dialog. Probe /tmp/B3630-dc-probe-status.log exited7. Native GDI trace absent despite guest launch flag; do not claim its runtime coverage. Staged kernel e139e10deddc632ce74c2c4498a28438a8ca3c4615da7b3f22fa5ac7ce98a222, native runtime de2f38e35cbccf6b66ddf7aa42dc38ef579f01f1598eb791184de5727886f719; these predate namespace repair.

Post-fix VM4192826 exited0 at1789047577.5589137 without issued shutdown. Kernel e04ec52945893be256529255aa7b4345c695b2d2f268d30698617832998a6681; ISO69f01dad499311c11dd1b7f0e47f2a6c00a0ee3e1e074e825c1b56c0015bcf82. UART target/B3630-desktop-verification-debug/uart-4192767.log. Probe /tmp/B3630-desktop-probe.log exited0. No native measurement traces observed; KI0926 remains.
