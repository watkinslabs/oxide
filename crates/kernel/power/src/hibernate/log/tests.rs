use super::*;

#[test]
fn every_frozen_phase_has_a_nonempty_static_name() {
    for step in super::super::sequence::FORWARD { assert!(!step_name(step).is_empty()); }
}

#[test]
fn every_resume_path_phase_has_a_nonempty_static_name() {
    for phase in [ResumePhase::Target, ResumePhase::Marker, ResumePhase::Admit,
        ResumePhase::Load, ResumePhase::SafePlan, ResumePhase::Quiesce,
        ResumePhase::Terminal]
    {
        assert!(!resume_phase_name(phase).is_empty());
    }
    assert_ne!(ResumePath::Cold, ResumePath::Test);
}

#[test]
fn every_noirq_boundary_is_distinct() {
    let phases = [NoirqPhase::WakeBegin, NoirqPhase::WakeEnd, NoirqPhase::IrqBegin,
        NoirqPhase::IrqEnd, NoirqPhase::DevicesBegin, NoirqPhase::DevicesEnd];
    for (index, phase) in phases.iter().enumerate() { assert!(!phases[..index].contains(phase)); }
}

#[test]
fn every_noirq_vector_phase_is_distinct() {
    let phases = [IrqPhase::Descriptor, IrqPhase::MaskBegin, IrqPhase::MaskEnd,
        IrqPhase::SyncBegin, IrqPhase::SyncEnd];
    for (index, phase) in phases.iter().enumerate() { assert!(!phases[..index].contains(phase)); }
    assert_ne!(IrqKind::Line, IrqKind::Msi);
}

#[test]
fn every_cpu_off_boundary_and_result_is_distinct() {
    let phases = [CpuOffPhase::Request, CpuOffPhase::Callfn,
        CpuOffPhase::OfflineResult, CpuOffPhase::ConfirmDead, CpuOffPhase::Unwind];
    for (index, phase) in phases.iter().enumerate() { assert!(!phases[..index].contains(phase)); }
    let results = [CpuOffResult::Begin, CpuOffResult::Ok,
        CpuOffResult::Refused, CpuOffResult::Timeout];
    for (index, result) in results.iter().enumerate() { assert!(!results[..index].contains(result)); }
    let transports = [CpuCallTransport::SameCpu, CpuCallTransport::Offline,
        CpuCallTransport::Queued, CpuCallTransport::NoHardware,
        CpuCallTransport::IcrRefused, CpuCallTransport::IcrSent];
    for (index, state) in transports.iter().enumerate() { assert!(!transports[..index].contains(state)); }
    let snapshot = [SnapshotPhase::Callback, SnapshotPhase::FinalFree,
        SnapshotPhase::Select, SnapshotPhase::Copy];
    for (index, phase) in snapshot.iter().enumerate() { assert!(!snapshot[..index].contains(phase)); }
    assert_ne!(SnapshotBoundary::Begin, SnapshotBoundary::End);
}

#[test]
fn every_restore_plan_phase_is_distinct() {
    let phases = [RestorePlanPhase::Header, RestorePlanPhase::CollisionChain,
        RestorePlanPhase::FixedControl, RestorePlanPhase::Tables,
        RestorePlanPhase::CollisionView, RestorePlanPhase::PlanValidation,
        RestorePlanPhase::SafeView, RestorePlanPhase::ChainValidation,
        RestorePlanPhase::TerminalControl, RestorePlanPhase::TerminalInstall];
    for (index, phase) in phases.iter().enumerate() { assert!(!phases[..index].contains(phase)); }
}
