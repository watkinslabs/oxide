//! Raw HRGN operations preserve Windows return domains and canonical region ownership.
use ipc::win32_gdi::Rect;
pub(crate) const CREATE_RECT_REGION:u64=0x10bb;
pub(crate) const GET_REGION_BOX:u64=0x121e;
pub(crate) const COMBINE_REGION:u64=0x10a2;
const RECT_BYTES:u64=16;

/// Route only admitted region signatures; owner query precedes bounded output copy. # C: owner operation cost
pub(crate) fn route(ordinal:u64,args:&[u64],create:impl FnOnce(Rect)->Option<u32>,
    query:impl FnOnce(u64)->Option<(u32,Rect)>,combine:impl FnOnce(u64,u64,u64,i32)->u32,
    write:impl FnOnce(u64,&[u8])->bool)->Option<u64> {
    Some(match ordinal {
        CREATE_RECT_REGION => {
            let [left,top,right,bottom,..]=args else { return Some(0); };
            create(Rect {left:*left as i32,top:*top as i32,right:*right as i32,bottom:*bottom as i32}).map_or(0,u64::from)
        },
        GET_REGION_BOX => {
            let [handle,output,..]=args else { return Some(0); };
            let Some((kind,rect))=query(*handle) else { return Some(0); };
            if *output==0 || output.checked_add(RECT_BYTES).is_none() { return Some(0); }
            let mut bytes=[0u8;16];
            for (i,value) in [rect.left,rect.top,rect.right,rect.bottom].into_iter().enumerate() {
                bytes[i*4..i*4+4].copy_from_slice(&value.to_le_bytes());
            }
            if write(*output,&bytes) { u64::from(kind) } else { 0 }
        },
        COMBINE_REGION => {
            let [destination,source1,source2,mode,..]=args else { return Some(0); };
            u64::from(combine(*destination,*source1,*source2,*mode as i32))
        },
        _=>return None,
    })
}

#[cfg(target_os="oxide-kernel")]
#[path="region_raw/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path="tests/region_raw.rs"]
mod tests;
