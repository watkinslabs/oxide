//! Caption text-state query ingress; output copy follows shared-aware owner snapshot.
use ipc::win32_gdi::TextAttributes;
pub(crate) const GET_DC_DWORD:u64=0x11ef;
const DWORD_BYTES:u64=4;

/// No setters or lease changes; return BOOL only after complete bounded output. # C: owner snapshot cost
pub(crate) fn route(ordinal:u64,args:&[u64],snapshot:impl FnOnce(u64)->Option<TextAttributes>,
    query:impl FnOnce(u32,TextAttributes)->Option<u32>,write:impl FnOnce(u64,u32)->bool)->Option<u64> {
    if ordinal!=GET_DC_DWORD {return None;}
    let [dc,method,output,..]=args else {return Some(0);};
    let Some(attributes)=snapshot(*dc) else {return Some(0);};
    let Some(value)=query(*method as u32,attributes) else {return Some(0);};
    if *output==0 || output.checked_add(DWORD_BYTES).is_none() {return Some(0);}
    Some(u64::from(write(*output,value)))
}

#[cfg(target_os="oxide-kernel")]
#[path="dc_query_raw/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path="tests/dc_query_raw.rs"]
mod tests;
