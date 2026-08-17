//! How many operations were failed on purpose, and where.
//!
//! One row per site, always all of them, whether or not the site is armed. A
//! report that listed only the armed sites would make "this site never fired"
//! and "this site was never asked to fire" the same absence, and telling
//! those two apart is the entire use of the file.

use alloc::string::String;
use alloc::vec::Vec;

use crate::fault::{Fault, Info, FAULT_MAX};

/// The report's own name under a mount's directory. # C: O(1)
pub const STATS_NAME: &str = "inject_stats";

/// The whole report. # C: O(N sites)
pub fn stats_body(info: &Info) -> Vec<u8> {
    let mut o = String::from("fault_type\t\tinjected_count\n");
    for i in 0..FAULT_MAX {
        let Some(f) = Fault::from_index(i) else { continue };
        o.push_str(&alloc::format!("{:<24}{:<10}\n", f.name(), info.count(f)));
    }
    o.into_bytes()
}
