# B1686 — filesystem parameter tables

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| IN-PROGRESS B1686 | high | **Unknown filesystem parameters are silently ACCEPTED, so the mount-option-support query always answers "yes".** systemd probes an option with `fsconfig(SET_FLAG/SET_STRING)` and reads success as "supported"; every `fsopen`ed context here uses one generic parameter path that stores any key and returns Consumed. Consequence in the desktop image: `ProtectProc=`/`ProcSubset=` are enabled because `proc` claims `hidepid`/`subset`, while procfs ignores mount data entirely — a confinement userspace believes it applied and which is absent. Fix is the whole contract: per-filesystem parameter tables with the reference's `fs_parse` semantics and errno split (unknown key vs bad value), AND real `hidepid=`/`subset=pid` support in procfs. | Discovered by B1678 while disproving the `fsconfig` EINVAL row; systemd 259 `mount_option_supported` is the reader. | B1686 |
