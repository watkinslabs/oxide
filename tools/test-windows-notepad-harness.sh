#!/usr/bin/env bash
# Static contract gate for the Notepad acceptance harness.
# A PE commit only installs the first user frame; it is not application
# readiness. Keep smoke admission tied to the user-entry event and require
# every W1-W5 boundary to have an executable positive and negative contract.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
makefile="$root/Makefile"
exec_source="$root/crates/kernel/syscalls/src/pe_exec.rs"
wine_window_source="$root/crates/kernel/syscalls/src/nt_wine_window.rs"
raw_class_source="$root/crates/kernel/syscalls/src/nt_wine_window/raw_class.rs"
wine_unix_source="$root/crates/kernel/syscalls/src/nt_wine_unix.rs"
runtime_source="$root/userspace/probes/windows-runtime/src/lib.rs"
user32_source="$root/userspace/probes/windows-user32/src/lib.rs"
loader_tests="$root/crates/kernel/exec/src/tests/pe_loader.rs"
wrapper_source="$root/tools/xtask/src/rootfs_disks/windows_notepad.rs"

require_text() {
    local label="$1" file="$2" needle="$3"
    if [[ ! -f "$file" ]]; then
        echo "windows-notepad-harness: FAIL ($label: missing $file)" >&2
        exit 1
    fi
    if ! grep -Fq -- "$needle" "$file"; then
        echo "windows-notepad-harness: FAIL ($label: missing '$needle' in $file)" >&2
        echo "windows-notepad-harness: nearby declarations:" >&2
        rg -n -- "(test|fn|pub fn|SMOKE|notepad|import|environment|window|PE)" "$file" | head -n 12 >&2 || true
        exit 1
    fi
}

require_test() {
    local label="$1" file="$2" name="$3"
    require_text "$label" "$file" "fn $name"
    require_text "$label test" "$file" "#[test]"
}

require_text "smoke admission" "$makefile" "SMOKE_MARKER='[WINDOWS-PE-START] entry='"
require_text "smoke liveness" "$makefile" "SMOKE_ALIVE_MARKER='[WINDOWS-PE-START] entry='"
require_text "smoke workload" "$makefile" "SMOKE_ALIVE_CMD=/usr/local/bin/windows-notepad-smoke"
if grep -Fq "SMOKE_MARKER='[WINDOWS-PE-COMMIT] success'" "$makefile"; then
    echo "windows-notepad-harness: commit marker must not admit readiness" >&2
    exit 1
fi

start_line="$(grep -nF '[WINDOWS-PE-START] entry=' "$exec_source" | cut -d: -f1 | head -n1)"
commit_line="$(grep -nF '[WINDOWS-PE-COMMIT] success' "$exec_source" | cut -d: -f1 | head -n1)"
test -n "$start_line" -a -n "$commit_line"
test "$start_line" -lt "$commit_line"
require_text "real PE fixture" "$wrapper_source" "head -c 2 /mnt/windows/x86_64-windows/notepad.exe"
require_text "real PE handoff" "$wrapper_source" "exec /usr/local/bin/windows-runtime"

# W1/W2: parse and load a real PE, resolve the complete graph, and reject
# malformed or architecture-incompatible input before publishing a handoff.
require_text "PE parse" "$runtime_source" "let root = pe::parse(&image).map_err(BuildError::InvalidRoot)?;"
require_text "import discovery" "$runtime_source" "root.imports()"
require_text "import closure" "$runtime_source" "validate_import_closure(&image, &modules)?;"
require_text "native loader" "$loader_tests" "load_pe_process_with_catalog_with_fallback"
require_test "real Notepad load" "$loader_tests" "installed_wine_notepad_graph_loads_native_ntdll_surface"
require_test "missing import negative" "$loader_tests" "default_loader_rejects_imports_without_an_nt_runtime"
require_test "bad PE negative" "$runtime_source" "malformed_dll_is_rejected_before_handoff"
require_test "bad architecture negative" "$runtime_source" "non_amd64_root_is_rejected_before_catalog_construction"

# W2/W3: make the process environment observable and reject invalid launch
# configuration rather than allowing a host environment to leak into PE state.
require_text "environment block" "$runtime_source" "let environment = environment_block(environment)?;"
require_text "environment ABI" "$runtime_source" "environment: user_ptr(environment.as_ptr())?"
require_test "environment positive" "$runtime_source" "x64_environment_publishes_native_processor_architecture"
require_test "environment negative" "$runtime_source" "malformed_launch_configuration_is_rejected_before_handoff"
require_text "PEB/TEB publication" "$exec_source" "cur.set_nt_peb(process.environment.peb.as_u64())"
require_text "entry state" "$loader_tests" "process.entry.gs_base, process.environment.teb"
require_test "environment rollback" "$loader_tests" "failed_environment_setup_rolls_back_the_pe_mapping"

# W4/W5: require the user32 class-to-window path and its deterministic
# malformed/unknown-class coverage; a symbol-only check is not sufficient.
require_text "user32 class registration" "$wine_window_source" "if ordinal == WINE_REGISTER_CLASS_EX { return Some(raw_class::register_class(args)); }"
require_text "user32 creation dispatch" "$wine_window_source" "if ordinal == WINE_CREATE_WINDOW_EX { return Some(raw_class::create_window(args)); }"
require_text "user32 class implementation" "$raw_class_source" "pub(super) fn register_class(args: SyscallArgs)"
require_text "user32 window implementation" "$raw_class_source" "pub(super) fn create_window(args: SyscallArgs)"
require_text "user32 client creation" "$user32_source" "pub fn create_window_ex_w"
require_text "user32 native creation" "$user32_source" "user32.create_window(parent, class.wndproc)"
require_test "user32 creation positive" "$user32_source" "classes_bind_procedures_without_duplicating_native_windows"
require_test "user32 creation negative" "$user32_source" "class_lookup_rejects_non_case_name_changes_and_malformed_termination"

# Wine's Unix request IDs are part of the W4 loader/runtime contract.
require_text "Wine mapping create" "$wine_unix_source" "const SERVER_REQ_CREATE_MAPPING: u32 = 63;"
require_text "Wine mapping open" "$wine_unix_source" "const SERVER_REQ_OPEN_MAPPING: u32 = 64;"
require_text "Wine select" "$wine_unix_source" "const SERVER_REQ_SELECT: u32 = 29;"
if grep -Fq "const SERVER_REQ_SELECT: u32 = 23;" "$wine_unix_source"; then
    echo "windows-notepad-harness: stale Wine select request ID 23" >&2
    exit 1
fi
for contract in \
    "fn server_create_mapping(" \
    "const SERVER_REQ_GET_MAPPING_INFO: u32 = 65;" \
    "const SERVER_REQ_GET_IMAGE_MAP_ADDRESS: u32 = 66;" \
    "const SERVER_REQ_MAP_VIEW: u32 = 67;" \
    "const SERVER_REQ_MAP_IMAGE_VIEW: u32 = 68;" \
    "const SERVER_REQ_GET_IMAGE_VIEW_INFO: u32 = 70;" \
    "const SERVER_REQ_UNMAP_VIEW: u32 = 71;" \
    "fn server_get_mapping_info(" "fn server_get_image_map_address(" \
    "fn server_map_image_view(" "fn server_get_image_view_info(" \
    "fn server_map_view(" "fn server_unmap_view("; do
    require_text "Wine image mapping" "$wine_unix_source" "$contract"
done
echo "windows-notepad-harness: PASS (W1-W5 PE, graph, environment, and user32 contracts verified; entry marker precedes commit marker)"
