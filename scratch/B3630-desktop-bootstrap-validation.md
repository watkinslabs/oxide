# Interactive desktop namespace initialization

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0924 canonical desktop bootstrap |

Actual launch requests \Windows\WindowStations\WinSta0, but namespace seed stopped at \Windows. Canonical station publication rejects missing parents; nt_exec attachment therefore returned without station/default-desktop membership. Live diagnostic5341a7a34 returned NULL screen DCs throughout Open construction; HWND100011 then requested1px height. Probe exit7 pins missing desktop HWND and both forms of desktop DC, with working screen metrics and compatible DC creation.

Repair adds the permanent WindowStations directory in the existing object namespace initializer. No alternate lookup or implicit-parent creation. Exact-path joined regression consumes nt_desktop_names, canonical bootstrap/handle tables, membership/root resolution and real desktop GDI lease. Two process tables share identity; final temporary-handle closure preserves permanent parent.

Before repair: actual-path test fails Namespace(ParentMissing), /tmp/B3630-desktop-bootstrap-red.log. After repair:4 boundary tests and104 object tests pass, /tmp/B3630-desktop-bootstrap-{green,objects}.log. Full scheduler2029 tests PASS. Both release builds, feature checks and frame gates PASS. Static gate remains KI0019:334x86/277ARM rows, no added or increased paths; exceptions7664/6368 unchanged. Logs /tmp/B3630-desktop-bootstrap-{stack,frame-arm,stack-arm,push}.log. Post-fix guest verification pending. KI0923 combo sizing, KI0887 complete dialog acceptance remain open; file-type/encoding dropdown selection, popup geometry and repaint need actual UI checks.

Diagnostic VM4127880 exited0 at1789046321.9160104; no quit/reboot issued, cause unknown. Runner25062; target/B3630-measure-verification-debug/live.json and uart-4127818.log. Initial token visibly correct but harness observation failed; measured manual File168,156 then Open196,196 created the broken dialog. Probe /tmp/B3630-dc-probe-status.log exited7. Native GDI trace absent despite guest launch flag; do not claim its runtime coverage. Staged kernel e139e10deddc632ce74c2c4498a28438a8ca3c4615da7b3f22fa5ac7ce98a222, native runtime de2f38e35cbccf6b66ddf7aa42dc38ef579f01f1598eb791184de5727886f719; these predate namespace repair.
