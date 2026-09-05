use std::io::Read;
use windows_performance::SyscallCostEvidence;

fn main() {
    let mut input = String::new(); std::io::stdin().read_to_string(&mut input).unwrap();
    match windows_performance::parse(&input) {
        Ok(value) => match value.syscall_cost {
            SyscallCostEvidence::Production(stats) => println!("windows-performance: PASS phase={} launch_ns={} transitions={} syscall_cost=production count={} total_ns={} average_ns={}", value.phase, value.launch_ns, value.transitions.count, stats.count, stats.total_ns, stats.average_ns),
            SyscallCostEvidence::Unavailable => println!("windows-performance: PASS phase={} launch_ns={} transitions={} syscall_cost=unavailable", value.phase, value.launch_ns, value.transitions.count),
        },
        Err(error) => { eprintln!("windows-performance: FAIL {error:?}"); std::process::exit(1); }
    }
}
