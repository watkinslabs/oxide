//! Isolated removal-control copies real fixture/paint sources; shared source is read-only.
use std::{env,fs,path::PathBuf};
fn main(){
    let here=PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source=here.join("../../src").canonicalize().unwrap();
    let fixture=source.join("nt_gdi/clip/tests/paint_boundary.rs");
    let paint=source.join("nt_wine_window/paint.rs");
    let out=PathBuf::from(env::var_os("OUT_DIR").unwrap());
    println!("cargo:rerun-if-env-changed=OXIDE_REMOVE_PAINT_PENDING");
    println!("cargo:rerun-if-changed={}",fixture.display());println!("cargo:rerun-if-changed={}",paint.display());
    let mut code=fs::read_to_string(&paint).unwrap();
    if env::var_os("OXIDE_REMOVE_PAINT_PENDING").is_some(){
        let hook="let accepted = if present == STATUS_PENDING_OUTPUT { STATUS_SUCCESS } else { present };";
        assert_eq!(code.matches(hook).count(),1,"pending hook changed; control must be updated");
        code=code.replace(hook,"let accepted = present;");
    }
    fs::write(out.join("paint.rs"),code).unwrap();
    let original=fs::read_to_string(&fixture).unwrap();let mut generated=String::new();
    for line in original.lines(){
        if let Some(path)=line.strip_prefix("#[path = \"").and_then(|s|s.strip_suffix("\"]")){
            let resolved=fixture.parent().unwrap().join(path).canonicalize().unwrap();
            let target=if resolved==paint{out.join("paint.rs")}else{resolved};
            println!("cargo:rerun-if-changed={}",target.display());
            generated.push_str(&format!("#[path = {:?}]\n",target));
        }else{generated.push_str(&line.replacen("//!","//",1));generated.push('\n');}
    }
    fs::write(out.join("paint_boundary.rs"),generated).unwrap();
}
