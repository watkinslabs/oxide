// Rendering of the integrity tree's files. These produce the bytes; attaching
// them to a filesystem is the caller's job.
//
//   ascii_runtime_measurements   one line per record
//   binary_runtime_measurements  the records as an event log
//   runtime_measurements_count   number of records
//   violations                   number of integrity violations
//   policy                       the rules currently in force

use alloc::string::String;
use alloc::vec::Vec;

use crate::list::MeasurementList;
use crate::policy::rule::Rule;
use crate::policy::show::show_rule;

/// File names the integrity tree exposes, and whether writing them is defined.
pub const IMA_DIR: &str = "ima";
pub const F_ASCII: &str = "ascii_runtime_measurements";
pub const F_BINARY: &str = "binary_runtime_measurements";
pub const F_COUNT: &str = "runtime_measurements_count";
pub const F_VIOLATIONS: &str = "violations";
pub const F_POLICY: &str = "policy";

/// Every record, one line each. # C: O(total)
pub fn ascii_runtime_measurements(list: &MeasurementList) -> String {
    let mut s = String::new();
    for e in list.entries() { s.push_str(&e.entry.ascii_record(&e.template_digest)); }
    s
}

/// Every record, concatenated in the event-log encoding. # C: O(total)
pub fn binary_runtime_measurements(list: &MeasurementList) -> Vec<u8> {
    let mut v = Vec::new();
    for e in list.entries() { v.extend_from_slice(&e.entry.binary_record(&e.template_digest)); }
    v
}

/// Number of records, as a decimal line. # C: O(1)
pub fn runtime_measurements_count(list: &MeasurementList) -> String {
    counter_line(list.len() as u64)
}

/// Number of violations, as a decimal line. # C: O(1)
pub fn violations(list: &MeasurementList) -> String {
    counter_line(list.violations())
}

/// The rules in force, one policy line each. # C: O(n)
pub fn policy(rules: &[Rule]) -> String {
    let mut s = String::new();
    for r in rules { s.push_str(&show_rule(r)); }
    s
}

fn counter_line(v: u64) -> String {
    let mut s = String::new();
    if v == 0 { s.push('0'); } else {
        let mut d = [0u8; 20];
        let mut i = d.len();
        let mut n = v;
        while n > 0 { i -= 1; d[i] = b'0' + (n % 10) as u8; n /= 10; }
        s.push_str(&String::from_utf8_lossy(&d[i..]));
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests;
