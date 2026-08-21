use super::SnapshotResult;
#[cfg(feature = "debug-hibernate")]
use super::snapshot_result_name;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RestorePlanPhase {
    Header, CollisionChain, FixedControl, Tables, CollisionView,
    PlanValidation, SafeView, ChainValidation, TerminalControl, TerminalInstall,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RestorePlanReason {
    Header, Alignment, Range, ControlCollision, Duplicate, Unmapped, TooMany,
    MteUnsupported, Capacity, CurrentCpu, Continuation,
}

#[cfg(feature = "debug-hibernate")]
pub fn restore_plan(phase: RestorePlanPhase, result: Option<SnapshotResult>) {
    klog::write_raw(b"[hibernate] restore_plan=");
    klog::write_raw(match phase {
        RestorePlanPhase::Header => b"header",
        RestorePlanPhase::CollisionChain => b"collision_chain",
        RestorePlanPhase::FixedControl => b"fixed_control",
        RestorePlanPhase::Tables => b"tables",
        RestorePlanPhase::CollisionView => b"collision_view",
        RestorePlanPhase::PlanValidation => b"plan_validation",
        RestorePlanPhase::SafeView => b"safe_view",
        RestorePlanPhase::ChainValidation => b"chain_validation",
        RestorePlanPhase::TerminalControl => b"terminal_control",
        RestorePlanPhase::TerminalInstall => b"terminal_install",
    });
    match result {
        None => klog::write_raw(b" boundary=begin"),
        Some(result) => {
            klog::write_raw(b" boundary=end result=");
            klog::write_raw(snapshot_result_name(result));
        }
    }
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn restore_plan(_: RestorePlanPhase, _: Option<SnapshotResult>) {}

#[cfg(feature = "debug-hibernate")]
pub fn restore_plan_reason(reason: RestorePlanReason) {
    klog::write_raw(b"[hibernate] restore_plan_reason=");
    klog::write_raw(match reason {
        RestorePlanReason::Header => b"header",
        RestorePlanReason::Alignment => b"alignment",
        RestorePlanReason::Range => b"range",
        RestorePlanReason::ControlCollision => b"control_collision",
        RestorePlanReason::Duplicate => b"duplicate",
        RestorePlanReason::Unmapped => b"unmapped",
        RestorePlanReason::TooMany => b"too_many",
        RestorePlanReason::MteUnsupported => b"mte_unsupported",
        RestorePlanReason::Capacity => b"capacity",
        RestorePlanReason::CurrentCpu => b"current_cpu",
        RestorePlanReason::Continuation => b"continuation",
    });
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn restore_plan_reason(_: RestorePlanReason) {}

#[cfg(feature = "debug-hibernate")]
pub fn restore_plan_facts(root: u64, trampoline: u64, stack: u64, start: u64, end: u64) {
    klog::write_raw(b"[hibernate] restore_plan_facts root="); klog::write_hex_u64(root);
    klog::write_raw(b" trampoline="); klog::write_hex_u64(trampoline);
    klog::write_raw(b" stack="); klog::write_hex_u64(stack);
    klog::write_raw(b" direct_start="); klog::write_hex_u64(start);
    klog::write_raw(b" direct_end="); klog::write_hex_u64(end);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn restore_plan_facts(_: u64, _: u64, _: u64, _: u64, _: u64) {}

#[cfg(feature = "debug-hibernate")]
pub fn restore_plan_collision(index: u64, source: u64, destination: u64) {
    klog::write_raw(b"[hibernate] restore_plan_collision index="); klog::write_dec_u64(index);
    klog::write_raw(b" source="); klog::write_hex_u64(source);
    klog::write_raw(b" destination="); klog::write_hex_u64(destination);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn restore_plan_collision(_: u64, _: u64, _: u64) {}
