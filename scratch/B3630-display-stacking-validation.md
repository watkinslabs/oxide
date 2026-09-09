# Display stacking validation

- KI-0897: Position insertion identifies preceding HWND in canonical top-to-bottom order. Backend placed target above that sibling, reversing projection. Child order now uses Below.
- Reparented top-level windows beneath separate decoration frames reproduce X11 BadMatch. Backend now sends original ConfigureRequest to root window manager on that specific error; other errors fail. No frame/XID registry added.
- Real Xvfb RED: preceding-sibling projection returns reversed three-window order; reparented request fails X11; corrected existing protocol expectation also fails. /tmp/B3630-stacking-red.log.
- Broad error-swallowing control changes BadWindow into success and fails server_destroyed_top_level assertion. Restored production passes. /tmp/B3630-stacking-error-control.log.
- Final full compositor suite100 PASS (93 library+7 integration). /tmp/B3630-stacking-final-tests.log. Reparent test checks actual synthetic event fields delivered to root observer; it proves submission, not desktop-manager policy acceptance.
- x86/ARM compositor release builds PASS. /tmp/B3630-stacking-final-build-{x86,arm}.log. ARM uses existing completed Fedora sysroot target/B3630-arm-sysroot; system sysroot unchanged.
- Backend refusal diagnostics retain request sequence/HWND/error. Stacking X11 failures retain target/sibling/mode/error. Command handler invokes position in x11/position.rs; no kernel runtime changed in this repair.
- No boot: live Notepad acceptance remains outstanding. This repairs demonstrated stacking defects, not all retained visibility/destroy refusals or rendering defects.
