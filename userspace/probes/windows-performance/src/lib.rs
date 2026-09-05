//! Strict W10 launch and NT-transition evidence parser.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evidence { pub phase: u32, pub launch_ns: u64, pub transitions: Transition, pub syscall_cost: SyscallCostEvidence }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition { pub count: u64, pub total_ns: u64, pub min_ns: u64, pub max_ns: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallCost { pub count: u64, pub total_ns: u64, pub average_ns: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallCostEvidence { Production(SyscallCost), Unavailable }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError { Malformed(&'static str), Duplicate(&'static str), Missing(&'static str), UnknownPhase, LaunchFailed, InvalidPhase, InvalidTransition, InvalidSyscallCost }

const MAX_LAUNCH_NS: u64 = 30_000_000_000;

pub fn parse(input: &str) -> Result<Evidence, EvidenceError> {
    let mut launch = None; let mut transition = None; let mut syscall_cost = SyscallCostEvidence::Unavailable;
    let mut saw_syscall_cost = false;
    for line in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let mut words = line.split_whitespace(); let kind = words.next().ok_or(EvidenceError::Malformed("record"))?;
        let version = if kind == "[SYSCOST]" { None } else { Some(words.next().ok_or(EvidenceError::Malformed("version"))?) };
        if let Some(version) = version { if version != "v1" { return Err(EvidenceError::Malformed("version")); } }
        let mut fields = std::collections::BTreeMap::new();
        if kind == "[SYSCOST]" { fields.insert("scope", words.next().ok_or(EvidenceError::Malformed("scope"))?); }
        for word in words { let (key, value) = word.split_once('=').ok_or(EvidenceError::Malformed("key/value"))?; if fields.insert(key, value).is_some() { return Err(EvidenceError::Duplicate("key")); } }
        match kind {
            "W10-LAUNCH" => { if launch.is_some() { return Err(EvidenceError::Duplicate("launch")); } let phase = number(&fields, "phase")?; let elapsed = number(&fields, "elapsed_ns")?; let exit = number(&fields, "exit_code")?; if phase == 0 { return Err(EvidenceError::InvalidPhase); } if phase > 10 { return Err(EvidenceError::UnknownPhase); } if exit != 0 { return Err(EvidenceError::LaunchFailed); } if elapsed == 0 || elapsed > MAX_LAUNCH_NS { return Err(EvidenceError::InvalidPhase); } launch = Some((phase, elapsed)); }
            "W10-TRANSITION" => { if transition.is_some() { return Err(EvidenceError::Duplicate("transition")); } transition = Some(Transition { count: number(&fields, "count")?, total_ns: number(&fields, "total_ns")?, min_ns: number(&fields, "min_ns")?, max_ns: number(&fields, "max_ns")? }); }
            "W10-SYSCOST" => { if saw_syscall_cost { return Err(EvidenceError::Duplicate("syscall_cost")); } saw_syscall_cost = true; syscall_cost = SyscallCostEvidence::Production(parse_syscall_cost(&fields, false)?); }
            "[SYSCOST]" => { if saw_syscall_cost { return Err(EvidenceError::Duplicate("syscall_cost")); } if fields.get("scope") != Some(&"all-tasks") { return Err(EvidenceError::Malformed("scope")); } saw_syscall_cost = true; syscall_cost = SyscallCostEvidence::Production(parse_syscall_cost(&fields, true)?); }
            _ => return Err(EvidenceError::UnknownPhase),
        }
    }
    let (phase, launch_ns) = launch.ok_or(EvidenceError::Missing("launch"))?; let transitions = transition.ok_or(EvidenceError::Missing("transition"))?;
    if transitions.count == 0 || transitions.min_ns == 0 || transitions.max_ns < transitions.min_ns || transitions.total_ns < transitions.count.checked_mul(transitions.min_ns).ok_or(EvidenceError::InvalidTransition)? || transitions.total_ns > transitions.count.checked_mul(transitions.max_ns).ok_or(EvidenceError::InvalidTransition)? { return Err(EvidenceError::InvalidTransition); }
    Ok(Evidence { phase: phase as u32, launch_ns, transitions, syscall_cost })
}

fn parse_syscall_cost(fields: &std::collections::BTreeMap<&str, &str>, kernel_record: bool) -> Result<SyscallCost, EvidenceError> {
    let count = number(fields, if kernel_record { "cpu_calls" } else { "count" })?;
    let total = number(fields, if kernel_record { "cpu_total_ms" } else { "total_ns" })?;
    let total_ns = if kernel_record { total.checked_mul(1_000_000).ok_or(EvidenceError::InvalidSyscallCost)? } else { total };
    let average_ns = number(fields, if kernel_record { "cpu_avg_ns" } else { "avg_ns" })?;
    if count == 0 || average_ns == 0 { return Err(EvidenceError::InvalidSyscallCost); }
    Ok(SyscallCost { count, total_ns, average_ns })
}

fn number(fields: &std::collections::BTreeMap<&str, &str>, name: &'static str) -> Result<u64, EvidenceError> { fields.get(name).ok_or(EvidenceError::Malformed(name)).and_then(|value| value.parse().map_err(|_| EvidenceError::Malformed(name))) }

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> &'static str { "W10-LAUNCH v1 phase=5 elapsed_ns=12 exit_code=0\nW10-TRANSITION v1 count=4 total_ns=20 min_ns=4 max_ns=6" }
    #[test] fn parses_valid_records_and_blank_lines() { let value = parse(&format!("\n{}\n", valid())).unwrap(); assert_eq!(value.phase, 5); assert_eq!(value.transitions.count, 4); }
    #[test] fn parses_production_kernel_syscost_record() { let input = format!("{}\n[SYSCOST] all-tasks cpu_calls=4 cpu_total_ms=2 cpu_avg_ns=500000", valid()); let value = parse(&input).unwrap(); assert_eq!(value.syscall_cost, SyscallCostEvidence::Production(SyscallCost { count: 4, total_ns: 2_000_000, average_ns: 500_000 })); }
    #[test] fn parses_versioned_syscost_record_and_marks_absence_unavailable() { let value = parse(valid()).unwrap(); assert_eq!(value.syscall_cost, SyscallCostEvidence::Unavailable); let input = format!("{}\nW10-SYSCOST v1 count=4 total_ns=2000000 avg_ns=500000", valid()); assert!(matches!(parse(&input).unwrap().syscall_cost, SyscallCostEvidence::Production(_))); }
    #[test] fn rejects_duplicate_or_malformed_syscost_records() { let duplicate = format!("{}\nW10-SYSCOST v1 count=1 total_ns=2 avg_ns=1\nW10-SYSCOST v1 count=1 total_ns=2 avg_ns=1", valid()); assert_eq!(parse(&duplicate), Err(EvidenceError::Duplicate("syscall_cost"))); let bad = format!("{}\n[SYSCOST] all-tasks cpu_calls=18446744073709551615 cpu_total_ms=18446744073709551615 cpu_avg_ns=1", valid()); assert_eq!(parse(&bad), Err(EvidenceError::InvalidSyscallCost)); }
    #[test] fn rejects_missing_records() { assert_eq!(parse("W10-LAUNCH v1 phase=5 elapsed_ns=1 exit_code=0"), Err(EvidenceError::Missing("transition"))); }
    #[test] fn rejects_unknown_and_bad_versions() { assert_eq!(parse("W10-BOGUS v1 phase=1"), Err(EvidenceError::UnknownPhase)); assert_eq!(parse("W10-LAUNCH v2 phase=1 elapsed_ns=1 exit_code=0"), Err(EvidenceError::Malformed("version"))); }
    #[test] fn rejects_failed_or_invalid_launches() { assert_eq!(parse("W10-LAUNCH v1 phase=1 elapsed_ns=1 exit_code=9\nW10-TRANSITION v1 count=1 total_ns=1 min_ns=1 max_ns=1"), Err(EvidenceError::LaunchFailed)); assert_eq!(parse("W10-LAUNCH v1 phase=0 elapsed_ns=1 exit_code=0\nW10-TRANSITION v1 count=1 total_ns=1 min_ns=1 max_ns=1"), Err(EvidenceError::InvalidPhase)); }
    #[test] fn rejects_duplicate_and_malformed_fields() { assert_eq!(parse("W10-LAUNCH v1 phase=1 phase=2 elapsed_ns=1 exit_code=0"), Err(EvidenceError::Duplicate("key"))); assert_eq!(parse("W10-LAUNCH v1 phase=1 elapsed_ns exit_code=0"), Err(EvidenceError::Malformed("key/value"))); }
    #[test] fn rejects_bad_transition_statistics() { let input = "W10-LAUNCH v1 phase=1 elapsed_ns=1 exit_code=0\nW10-TRANSITION v1 count=2 total_ns=3 min_ns=2 max_ns=4"; assert_eq!(parse(input), Err(EvidenceError::InvalidTransition)); }
    #[test] fn rejects_numeric_overflow_and_missing_numeric_fields() { let input = "W10-LAUNCH v1 phase=1 elapsed_ns=1 exit_code=0\nW10-TRANSITION v1 count=wat total_ns=1 min_ns=1 max_ns=1"; assert_eq!(parse(input), Err(EvidenceError::Malformed("count"))); }
    #[test] fn rejects_zero_and_reversed_values() { let input = "W10-LAUNCH v1 phase=1 elapsed_ns=1 exit_code=0\nW10-TRANSITION v1 count=0 total_ns=0 min_ns=0 max_ns=0"; assert_eq!(parse(input), Err(EvidenceError::InvalidTransition)); }
}
