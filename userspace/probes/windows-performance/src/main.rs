use std::io::Read;
fn main() { let mut input = String::new(); std::io::stdin().read_to_string(&mut input).unwrap(); match windows_performance::parse(&input) { Ok(value) => println!("windows-performance: PASS phase={} launch_ns={} transitions={}", value.phase, value.launch_ns, value.transitions.count), Err(error) => { eprintln!("windows-performance: FAIL {error:?}"); std::process::exit(1); } } }
