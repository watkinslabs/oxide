//! Load the actual production preparation body; mutation affects OUT_DIR only.
use std::{env, fs, path::PathBuf};
fn main() {
    let here=PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source=here.join("../../src/nt_rtl/native_thread/lifecycle.rs");
    println!("cargo:rerun-if-changed={}",source.display());
    println!("cargo:rerun-if-env-changed=REMOVE_INHERIT_HOOK");
    let text=fs::read_to_string(source).unwrap();
    let end=text.find("\npub(super) fn publish(").expect("prepare boundary changed");
    let mut prepare=text[..end].to_owned();
    let hook="    let _ = sched::nt_object::ThreadDesktop::inherit_thread(&parent, task);\n";
    assert_eq!(prepare.matches(hook).count(),1,"production inheritance hook changed");
    match env::var("REMOVE_INHERIT_HOOK").as_deref() {
        Ok("1")=>prepare=prepare.replacen(hook,"",1),
        Err(env::VarError::NotPresent)=>{},
        _=>panic!("REMOVE_INHERIT_HOOK must be unset or 1"),
    }
    fs::write(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("prepare.rs"),prepare).unwrap();
}
