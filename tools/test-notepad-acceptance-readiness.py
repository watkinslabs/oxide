#!/usr/bin/env python3
import importlib.util
from pathlib import Path

source = Path(__file__).with_name("windows-notepad-acceptance.py")
spec = importlib.util.spec_from_file_location("windows_notepad_acceptance", source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

assert module.desktop_ready_text("Sep 5 21:22")
assert not module.desktop_ready_text("[26.039] gnome-session-binary: Entering running state")
assert not module.desktop_ready_text("[15.530] systemd[1]: Startup finished in 3.856s")
assert "[WINDOWS-DESKTOP] frame-ack" in module.MILESTONES
assert "[WINDOWS-GDI] present" in module.MILESTONES
assert "[WINDOWS-USER32] create-window" in module.MILESTONES
# The native bridge has no requirement to issue a Wine-server RPC. A desktop
# ACK supplements, rather than substitutes for, creation and rendered pixels.
assert "[WINDOWS-NT-SERVER] entry" not in module.MILESTONES
print("notepad-acceptance-readiness: PASS")
