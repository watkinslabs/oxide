# Combo popup reparenting

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0927 native reparent publication |

Live4192767: file-type list100014 is created as child of combo100013. Initialization reparents it to desktop, but canonical SetParent never publishes native reparenting. Expanded list rectangle398,556..713,586 is invisible; readback X11(8). Keyboard Alt+Down,Down,Enter changes Text files to All files. File-type arrow click focuses control but did not visibly expand; mouse behavior remains unverified. Encoding attempt occurred after VM exit and produced no input; no encoding result may be claimed.

Source repair adds checked reparent opcode9 to existing bridge and publishes canonical parent/geometry after unlocked SetParent. Existing XID and retained backing survive; no second Windows parent owner. Actual-X-server regression checks native parent identity, visible pixels outside former parent, same drawable and reparent-back. Removing X request fails server-parent assertion. Actual syscall hook fixture uses real tree_api and WindowManager with hosted caller/access/transport seams; removing publication fails, restored passes. Codec and canonical snapshot checks pass;3277 syscall library tests pass. Both kernel target checks and both compositor release builds pass. Final kernel builds/frame/static gates and guest verification pending.

Logs /tmp/B3630-reparent-{backend,backend-red,backend-all,hook,hook-red,hook-green,payload,codec,check-x86,check-arm}.log. Backend suite101pass including retained pixels before/after reparent, unknown-parent rejection and native BadWindow refusal. Snapshot of actual kernel/UI traces remains target/B3630-desktop-verification-debug. New reparent code has not run in guest.

Full SetParent callback/desktop-handle/cross-thread semantics remain a separate ledger gap; current regression proves canonical parent publication, not those callback contracts.

Final1438c3913 x86 release/frame PASS. Static334 rows; raw window router18184->18216bytes remains increased, other previously increased paths restored. Final log /tmp/B3630-reparent-final-stack.log. User authorized merging current unfinished work; do not call full static or guest acceptance green.

Final ARM release/frame PASS;277 static rows with raw window router15424->15472bytes, no other added/increased primary path. KI0929 tracks remaining growth. Source1438c3913 push hosted/features PASS. No post-reparent guest verification.
