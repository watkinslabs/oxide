use std::{env,fs,path::PathBuf};
fn main() {
    let here=PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source=here.join("../../src/namei_common.rs");
    println!("cargo:rerun-if-changed={}",source.display());
    println!("cargo:rerun-if-env-changed=REMOVE_UNIX_DAC_HOOK");
    let text=fs::read_to_string(source).unwrap();
    let start=text.find("pub(crate) fn resolve_unix_addr(").expect("resolver missing");
    let end=start+text[start..].find("\n}\n").expect("resolver end missing")+3;
    let mut body=text[start..end].to_owned();
    let hook="    vfs::inode_permission(&p.inode, vfs::MAY_WRITE, &crate::pathresolve::current_cred())\n        .map_err(errno_from_vfs)?;\n";
    assert_eq!(body.matches(hook).count(),1,"production DAC hook changed");
    match env::var("REMOVE_UNIX_DAC_HOOK").as_deref() {
        Ok("1")=>body=body.replacen(hook,"",1),
        Err(env::VarError::NotPresent)=>{},
        _=>panic!("REMOVE_UNIX_DAC_HOOK must be unset or 1"),
    }
    fs::write(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("resolver.rs"),body).unwrap();
}
