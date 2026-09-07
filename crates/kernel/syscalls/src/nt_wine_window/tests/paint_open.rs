//! A paint that cannot be equipped still consumes the damage it was offered.
use super::*;
use alloc::vec::Vec;
use alloc::vec;

#[derive(Debug, Default)]
struct Recorder { steps: Vec<&'static str>, fail: &'static str, dc: u64 }
impl PaintOpen for Recorder {
    fn reserve(&mut self) -> bool { self.steps.push("reserve"); self.fail != "reserve" }
    fn release(&mut self) { self.steps.push("release"); }
    fn backing(&mut self) -> bool { self.steps.push("backing"); self.fail != "backing" }
    fn create_dc(&mut self) -> u64 { self.steps.push("create"); if self.fail == "create" { 0 } else { self.dc } }
    fn seed(&mut self, dc: u64) -> bool { assert_eq!(dc, self.dc); self.steps.push("seed"); self.fail != "seed" }
    fn bind(&mut self, dc: u64) -> bool { assert_eq!(dc, self.dc); self.steps.push("bind"); self.fail != "bind" }
    fn delete_dc(&mut self, dc: u64) { assert_eq!(dc, self.dc); self.steps.push("delete"); }
}

fn run(fail: &'static str) -> (Option<u64>, Vec<&'static str>) {
    let mut recorder = Recorder { steps: Vec::new(), fail, dc: 41 };
    let result = open(&mut recorder);
    (result, recorder.steps)
}

#[test]
fn the_window_is_reserved_before_any_device_context_work() {
    assert_eq!(run("none"), (Some(41), vec!["reserve", "backing", "create", "seed", "bind"]));
}

#[test]
fn every_failure_after_the_reservation_releases_the_session_exactly_once() {
    assert_eq!(run("reserve"), (None, vec!["reserve"]));
    assert_eq!(run("backing"), (None, vec!["reserve", "backing", "release"]));
    assert_eq!(run("create"), (None, vec!["reserve", "backing", "create", "release"]));
    assert_eq!(run("seed"), (None, vec!["reserve", "backing", "create", "seed", "delete", "release"]));
    assert_eq!(run("bind"), (None, vec!["reserve", "backing", "create", "seed", "bind", "delete", "release"]));
    for fail in ["backing", "create", "seed", "bind"] {
        let (_, steps) = run(fail);
        assert_eq!(steps.iter().filter(|step| **step == "release").count(), 1);
        assert!(steps.iter().position(|step| *step == "reserve") < steps.iter().position(|step| *step == "backing"));
    }
}
