//! Hosted copies retain production method bodies; only platform gates/I/O are substituted.
use std::{env,fs,path::PathBuf};
fn main(){
    let here=PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source=here.join("../../src/nt_gdi").canonicalize().unwrap();
    let out=PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::create_dir_all(out.join("client")).unwrap();
    fs::create_dir_all(out.join("dc_lease")).unwrap();
    println!("cargo:rerun-if-env-changed=OXIDE_LEASE_MUTATION");
    for name in ["client.rs","client/text.rs","client/lease.rs","client/lease_geometry.rs","dc_lease/projection.rs","dc_lease/binding.rs"]{
        println!("cargo:rerun-if-changed={}",source.join(name).display());
        let mut text=fs::read_to_string(source.join(name)).unwrap()
            .replace("#![cfg(target_os = \"oxide-kernel\")]","")
            .replace("#[cfg(target_os = \"oxide-kernel\")]","");
        if name=="dc_lease/projection.rs"{
            match env::var("OXIDE_LEASE_MUTATION").as_deref(){
                Ok("reuse")=>text=text.replace("if reused {binding.geometry(dc,state.width,state.height)}else{binding.initialize(dc,pid,state)}","let _=reused;binding.initialize(dc,pid,state)"),
                Ok("release")=>text=text.replace("if reset {binding.initialize(dc,pid,state)}else{Ok(())}","let _=reset;binding.initialize(dc,pid,state)"),
                _=>{}
            }
        }
        fs::write(out.join(name),text).unwrap();
    }
    println!("cargo:rerun-if-changed=memory.rs");
    fs::copy(here.join("memory.rs"),out.join("client/memory.rs")).unwrap();
    fs::write(out.join("modules.rs"),format!("pub mod nt_gdi {{ #[path={:?}] pub mod client; }}\n#[path={:?}] mod projection;",out.join("client.rs"),out.join("dc_lease/projection.rs"))).unwrap();
}
