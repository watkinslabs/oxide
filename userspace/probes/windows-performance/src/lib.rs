//! Strict W10 launch and NT-transition evidence parser.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evidence { pub phase: u32, pub launch_ns: u64, pub transitions: Transition }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition { pub count: u64, pub total_ns: u64, pub min_ns: u64, pub max_ns: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError { Malformed(&'static str), Duplicate(&'static str), Missing(&'static str), UnknownPhase, LaunchFailed, InvalidPhase, InvalidTransition }

const MAX_LAUNCH_NS: u64 = 30_000_000_000;

pub fn parse(input: &str) -> Result<Evidence, EvidenceError> {
    let mut launch = None; let mut transition = None;
    for line in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let mut words = line.split_whitespace(); let kind = words.next().ok_or(EvidenceError::Malformed("record"))?;
        let version = words.next().ok_or(EvidenceError::Malformed("version"))?;
        if version != "v1" { return Err(EvidenceError::Malformed("version")); }
        let mut fields = std::collections::BTreeMap::new();
        for word in words { let (key, value) = word.split_once('=').ok_or(EvidenceError::Malformed("key/value"))?; if fields.insert(key, value).is_some() { return Err(EvidenceError::Duplicate("key")); } }
        match kind {
            "W10-LAUNCH" => { if launch.is_some() { return Err(EvidenceError::Duplicate("launch")); } let phase = number(&fields, "phase")?; let elapsed = number(&fields, "elapsed_ns")?; let exit = number(&fields, "exit_code")?; if phase == 0 { return Err(EvidenceError::InvalidPhase); } if phase > 10 { return Err(EvidenceError::UnknownPhase); } if exit != 0 { return Err(EvidenceError::LaunchFailed); } if elapsed == 0 || elapsed > MAX_LAUNCH_NS { return Err(EvidenceError::InvalidPhase); } launch = Some((phase, elapsed)); }
            "W10-TRANSITION" => { if transition.is_some() { return Err(EvidenceError::Duplicate("transition")); } transition = Some(Transition { count: number(&fields, "count")?, total_ns: number(&fields, "total_ns")?, min_ns: number(&fields, "min_ns")?, max_ns: number(&fields, "max_ns")? }); }
            _ => return Err(EvidenceError::UnknownPhase),
        }
    }
    let (phase, launch_ns) = launch.ok_or(EvidenceError::Missing("launch"))?; let transitions = transition.ok_or(EvidenceError::Missing("transition"))?;
    if transitions.count == 0 || transitions.min_ns == 0 || transitions.max_ns < transitions.min_ns || transitions.total_ns < transitions.count.checked_mul(transitions.min_ns).ok_or(EvidenceError::InvalidTransition)? || transitions.total_ns > transitions.count.checked_mul(transitions.max_ns).ok_or(EvidenceError::InvalidTransition)? { return Err(EvidenceError::InvalidTransition); }
    Ok(Evidence { phase: phase as u32, launch_ns, transitions })
}

fn number(fields: &std::collections::BTreeMap<&str, &str>, name: &'static str) -> Result<u64, EvidenceError> { fields.get(name).ok_or(EvidenceError::Malformed(name)).and_then(|value| value.parse().map_err(|_| EvidenceError::Malformed(name))) }

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> &'static str { "W10-LAUNCH v1 phase=5 elapsed_ns=12 exit_code=0\nW10-TRANSITION v1 count=4 total_ns=20 min_ns=4 max_ns=6" }
    #[test] fn parses_valid_records_and_blank_lines() { let value = parse(&format!("\n{}\n", valid())).unwrap(); assert_eq!(value.phase, 5); assert_eq!(value.transitions.count, 4); }
    #[test] fn rejects_missing_records() { assert_eq!(parse("W10-LAUNCH v1 phase=5 elapsed_ns=1 exit_code=0"), Err(EvidenceError::Missing("transition"))); }
    #[test] fn rejects_unknown_and_bad_versions() { assert_eq!(parse("W10-BOGUS v1 phase=1"), Err(EvidenceError::UnknownPhase)); assert_eq!(parse("W10-LAUNCH v2 phase=1 elapsed_ns=1 exit_code=0"), Err(EvidenceError::Malformed("version"))); }
    #[test] fn rejects_failed_or_invalid_launches() { assert_eq!(parse("W10-LAUNCH v1 phase=1 elapsed_ns=1 exit_code=9\nW10-TRANSITION v1 count=1 total_ns=1 min_ns=1 max_ns=1"), Err(EvidenceError::LaunchFailed)); assert_eq!(parse("W10-LAUNCH v1 phase=0 elapsed_ns=1 exit_code=0\nW10-TRANSITION v1 count=1 total_ns=1 min_ns=1 max_ns=1"), Err(EvidenceError::InvalidPhase)); }
    #[test] fn rejects_duplicate_and_malformed_fields() { assert_eq!(parse("W10-LAUNCH v1 phase=1 phase=2 elapsed_ns=1 exit_code=0"), Err(EvidenceError::Duplicate("key"))); assert_eq!(parse("W10-LAUNCH v1 phase=1 elapsed_ns exit_code=0"), Err(EvidenceError::Malformed("key/value"))); }
    #[test] fn rejects_bad_transition_statistics() { let input = "W10-LAUNCH v1 phase=1 elapsed_ns=1 exit_code=0\nW10-TRANSITION v1 count=2 total_ns=3 min_ns=2 max_ns=4"; assert_eq!(parse(input), Err(EvidenceError::InvalidTransition)); }
    #[test] fn rejects_numeric_overflow_and_missing_numeric_fields() { let input = "W10-LAUNCH v1 phase=1 elapsed_ns=1 exit_code=0\nW10-TRANSITION v1 count=wat total_ns=1 min_ns=1 max_ns=1"; assert_eq!(parse(input), Err(EvidenceError::Malformed("count"))); }
    #[test] fn rejects_zero_and_reversed_values() { let input = "W10-LAUNCH v1 phase=1 elapsed_ns=1 exit_code=0\nW10-TRANSITION v1 count=0 total_ns=0 min_ns=0 max_ns=0"; assert_eq!(parse(input), Err(EvidenceError::InvalidTransition)); }
}
