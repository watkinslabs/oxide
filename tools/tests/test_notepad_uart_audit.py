"""Hosted regression tests for the Notepad UART finding audit.

Positive control: `test_clean_log_passes` is the negative case every other
test inverts -- a log with none of the documented markers must produce an
empty finding list and PASS, and each marker-kind test below plants exactly
one marker and requires a FAIL with that marker's kind. A parser that always
returned "clean" or always returned "dirty" fails at least one of these.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import notepad_uart_audit as audit_mod  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"

CLEAN_LOG = "\n".join([
    "[50.100] [WINDOWS-PE-START] entry=0000000180001000",
    "[50.200] [WINDOWS-NT-UNIX] entry",
    "[50.300] [WINDOWS-USER32] create-window",
    "[50.400] [WINDOWS-CALLBACK-CALL] ordinal=4e540000000000c2",
    "[50.500] [WINDOWS-GDI] present",
    "[50.600] [WINDOWS-NOTEPAD] runtime-exit status=0",
]) + "\n"

# A tiny synthetic PE32+ image whose export table exposes exactly one
# service-thunk export at ordinal 0x14dd, so the decode path is exercised
# without depending on a real win32u.dll being installed.
_SYNTHETIC_WIN32U_ORDINALS = {0x14dd: "NtUserQueryInputContext"}


def _fixture_text(name):
    return (FIXTURES / name).read_text()


def test_clean_log_passes():
    result = audit_mod.audit(CLEAN_LOG)
    assert result.passed is True
    assert result.findings == []
    assert "PASS" in audit_mod.render_table(result)


def test_scrollbar_failures_preserve_message_and_callback_status():
    text = ("[12.001] [WINDOWS-SCROLL-PROC-UNHANDLED] hwnd=10001b msg=201\n"
            "[12.002] [WINDOWS-SCROLL-PAINT-FAIL] hwnd=10001b status=c000000d\n")
    result = audit_mod.audit(text)
    assert not result.passed
    assert [finding.kind for finding in result.findings] == ["scroll-proc-unhandled", "scroll-paint-fail"]
    assert "msg=201" in result.findings[0].detail
    assert "status=c000000d" in result.findings[1].detail


def test_dialog_creation_and_bridge_refusals_fail_with_original_context():
    text = ("[116.482] [WINDOWS-WINDOW-CREATE-FAIL] stage=publish hwnd=000000000010001a transport=0000000000000003\n"
            "[116.488] [WINDOWS-BRIDGE-REFUSED] op=0000000000000002 hwnd=000000000010001a seq=00000000000000aa status=0000000000000001\n")
    result = audit_mod.audit(text)
    assert not result.passed
    assert [finding.kind for finding in result.findings] == ["window-create-fail", "bridge-refused"]
    assert [finding.first_ts for finding in result.findings] == ["116.482", "116.488"]
    assert "stage=publish" in result.findings[0].detail
    assert "transport=0000000000000003" in result.findings[0].detail
    assert "seq=00000000000000aa status=0000000000000001" in result.findings[1].detail


def test_raw_unclaimed_marker_fails_and_decodes_ordinal():
    text = _fixture_text("uart-raw-unclaimed.log")
    result = audit_mod.audit(text, _SYNTHETIC_WIN32U_ORDINALS)
    assert result.passed is False
    kinds = {f.kind for f in result.findings}
    assert "raw-unclaimed" in kinds
    finding = next(f for f in result.findings if f.kind == "raw-unclaimed")
    assert finding.first_ts == "52.378"
    assert finding.count == 1
    assert finding.detail == "ordinal=0x14dd name=NtUserQueryInputContext"


def test_raw_unclaimed_falls_back_to_raw_hex_without_a_decoder():
    text = _fixture_text("uart-raw-unclaimed.log")
    result = audit_mod.audit(text, win32u_ordinals=None)
    finding = next(f for f in result.findings if f.kind == "raw-unclaimed")
    assert finding.detail == "ordinal=0x14dd"
    assert "name=" not in finding.detail


def test_ldr_fail_marker_fails_and_groups_by_detail():
    text = _fixture_text("uart-ldr-fail.log")
    result = audit_mod.audit(text)
    assert result.passed is False
    finding = next(f for f in result.findings if f.kind == "ldr-fail")
    assert finding.detail == "step=map name=imm32.dll"
    assert finding.first_ts == "50.360"
    assert finding.count == 1


def test_delayload_fail_marker_fires_from_the_sample_log():
    text = _fixture_text("uart-delayload-fail.log")
    result = audit_mod.audit(text)
    assert result.passed is False
    kinds = {f.kind for f in result.findings}
    assert "delayload-fail" in kinds
    finding = next(f for f in result.findings if f.kind == "delayload-fail")
    assert finding.detail == "dll=imm32.dll api=ImmGetContext status=0x00000000c0000135"
    assert finding.first_ts == "141.821"


def test_wndproc_reject_marker_fails():
    text = "[10.0] [WINDOWS-WNDPROC-REJECT] reason=callback-depth hwnd=1 msg=2 wndproc=3\n"
    result = audit_mod.audit(text)
    assert result.passed is False
    finding = result.findings[0]
    assert finding.kind == "wndproc-reject"
    assert finding.detail == "reason=callback-depth"
    assert finding.first_ts == "10.0"


def test_user_callback_reject_marker_fails():
    text = "[11.5] [WINDOWS-USER-CALLBACK-REJECT] reason=no-routine index=00000007\n"
    result = audit_mod.audit(text)
    assert result.passed is False
    finding = result.findings[0]
    assert finding.kind == "user-callback-reject"
    assert finding.detail == "reason=no-routine"


def test_kernelbase_console_line_fails_without_a_uart_timestamp():
    text = "failed to delay load imm32.dll.ImmGetContext\n"
    result = audit_mod.audit(text)
    assert result.passed is False
    finding = result.findings[0]
    assert finding.kind == "delayload-fail-console"
    assert finding.detail == "imm32.dll.ImmGetContext"
    assert finding.first_ts == "?"


def test_bug_line_fails():
    text = "[1.0] [BUG] assertion failed at foo.rs:42\n"
    result = audit_mod.audit(text)
    assert result.passed is False
    assert result.findings[0].kind == "bug"
    assert "assertion failed" in result.findings[0].detail


def test_segfault_line_fails():
    text = "[1.0] segfault at 0000000000000000 ip 0000000180001000 sp 00007fff\n"
    result = audit_mod.audit(text)
    assert result.passed is False
    assert result.findings[0].kind == "segfault"


def test_pe_fault_marker_fails():
    text = "[1.0] [WINDOWS-PE-FAULT] va=0 rip=0 rsp=0 cr3=0\n"
    result = audit_mod.audit(text)
    assert result.passed is False
    assert result.findings[0].kind == "pe-fault"


def test_pe_fault_frame_marker_is_not_mistaken_for_pe_fault():
    """[WINDOWS-PE-FAULT-FRAME] is a different, debug-only marker; the
    literal `[WINDOWS-PE-FAULT]` bracket must not match its prefix."""
    text = "[1.0] [WINDOWS-PE-FAULT-FRAME] rip=0 cr2=0\n"
    result = audit_mod.audit(text)
    assert result.passed is True


def test_repeated_marker_groups_into_one_finding_with_a_count():
    text = ("[1.0] [WINDOWS-LDR-FAIL] step=map name=imm32.dll\n"
            "[2.0] [WINDOWS-LDR-FAIL] step=map name=imm32.dll\n"
            "[3.0] [WINDOWS-LDR-FAIL] step=map name=imm32.dll\n")
    result = audit_mod.audit(text)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.count == 3
    assert finding.first_ts == "1.0"


def test_distinct_details_are_not_merged():
    text = ("[1.0] [WINDOWS-LDR-FAIL] step=map name=imm32.dll\n"
            "[2.0] [WINDOWS-LDR-FAIL] step=map name=uxtheme.dll\n")
    result = audit_mod.audit(text)
    assert len(result.findings) == 2


def test_render_markdown_reports_pass():
    result = audit_mod.audit(CLEAN_LOG)
    body = audit_mod.render_markdown("run123", result)
    assert "Verdict: PASS" in body


def test_render_markdown_reports_fail_table():
    result = audit_mod.audit(_fixture_text("uart-ldr-fail.log"))
    body = audit_mod.render_markdown("run123", result)
    assert "Verdict: FAIL" in body
    assert "ldr-fail" in body


def test_parse_win32u_exports_rejects_a_non_pe_blob():
    assert audit_mod.parse_win32u_exports(b"not a PE image") == {}


def test_load_win32u_ordinals_returns_empty_dict_for_missing_image():
    assert audit_mod.load_win32u_ordinals("/no/such/guest.img") == {}


def test_load_win32u_ordinals_reads_selected_guest_dll(tmp_path):
    import subprocess
    import pytest
    dll = Path(__file__).resolve().parents[2] / "target/artifacts/wine/x86_64-debug/x86_64-windows/win32u.dll"
    if not dll.is_file():
        pytest.skip("build the pinned debug Wine artifact first")
    image = tmp_path / "guest.img"
    with image.open("wb") as out:
        out.truncate(8 * 1024 * 1024)
    subprocess.run(["mkfs.ext4", "-q", "-F", str(image)], check=True, capture_output=True)
    commands = [f"mkdir {path}" for path in ("/usr", "/usr/local", "/usr/local/lib", "/usr/local/lib/oxide",
                "/usr/local/lib/oxide/windows-debug", "/usr/local/lib/oxide/windows-debug/x86_64-windows")]
    commands += ["symlink /usr/local/lib/oxide/windows windows-debug",
                 f"write {dll} /usr/local/lib/oxide/windows-debug/x86_64-windows/win32u.dll"]
    script = tmp_path / "debugfs.commands"
    script.write_text("\n".join(commands) + "\n")
    subprocess.run(["debugfs", "-w", "-f", str(script), str(image)], check=True, capture_output=True)
    expected = audit_mod.parse_win32u_exports(dll.read_bytes())
    assert "NtUserSetScrollInfo" in expected.values()
    assert audit_mod.load_win32u_ordinals(image) == expected
    subprocess.run(["debugfs", "-w", "-R", f"rm {audit_mod.WIN32U_IMAGE_PATH}", str(image)], check=True, capture_output=True)
    assert audit_mod.load_win32u_ordinals(image) == {}


def test_text_measurement_and_output_refusals_cannot_pass_caption_acceptance():
    text = ("[71.502] [WINDOWS-TEXTMEASURE-DROP] dc=000000000001008c kind=0000000000000001 step=snapshot\n"
            "[71.562] [WINDOWS-TEXTMEASURE-DROP] dc=0000000000010090 kind=0000000000000001 step=snapshot\n"
            "[72.000] [WINDOWS-TEXTOUT-DROP] dc=0000000000010090 step=coordinates\n"
            "[72.100] [WINDOWS-TEXTOUT-DROP] dc=0000000000010090 step=coordinates\n")
    result = audit_mod.audit(text)
    assert not result.passed
    assert [f.kind for f in result.findings] == ["text-measure-refused", "text-measure-refused", "text-output-refused"]
    assert [f.count for f in result.findings] == [1, 1, 2]
    assert result.findings[0].first_ts == "71.502"
    assert "dc=000000000001008c" in result.findings[0].detail
    assert "step=coordinates" in result.findings[2].detail
    assert audit_mod.audit("[71.502] [WINDOWS-TEXTOUT] dc=1008c count=2\n").passed
    null_dc = audit_mod.audit("[50.841] [WINDOWS-TEXTMEASURE-DROP] dc=0000000000000000 kind=1 step=snapshot\n")
    assert not null_dc.passed
    assert "dc=0000000000000000" in null_dc.findings[0].detail


def test_frame_readback_mismatch_is_distinct_from_match_and_unavailable():
    match = '[1.0] [WINDOWS-FRAME-READBACK] hwnd=0xb1 pixels=20 matched=1\n'
    unavailable = '[1.1] [WINDOWS-FRAME-READBACK-UNAVAILABLE] hwnd=0xb1 error=X11(8)\n'
    mismatch = '[1.2] [WINDOWS-FRAME-READBACK-MISMATCH] hwnd=0xb1 mismatches=1 first=Some((7, 9, 1, 2))\n'
    assert audit_mod.audit(match + unavailable).passed
    result = audit_mod.audit(match + unavailable + mismatch)
    assert not result.passed
    assert len(result.findings) == 1
    assert result.findings[0].kind == 'frame-readback-mismatch'
    assert 'first=Some((7, 9, 1, 2))' in result.findings[0].detail
