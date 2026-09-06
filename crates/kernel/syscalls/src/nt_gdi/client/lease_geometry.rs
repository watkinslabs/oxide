//! Binding metadata validation is independent of render support policy.
use syscall::nt_gdi_client as abi;
/// Only identity and new nonnegative dimensions govern this eight-byte update. # C: O(1)
pub(crate) fn prepare(bytes:&[u8],handle:u32,width:i32,height:i32)->Result<[u8;8],()>{
    if bytes.len()!=abi::DC_ATTR_SIZE||width<0||height<0||handle&0xffff==0
        ||((handle&abi::HANDLE_TYPE_MASK)>>16)&0x1f!=1
        ||u32::from_le_bytes(bytes[abi::dc::HDC..abi::dc::HDC+4].try_into().map_err(|_|())?)!=handle{return Err(());}
    let mut rect=[0;8];rect[..4].copy_from_slice(&width.to_le_bytes());rect[4..].copy_from_slice(&height.to_le_bytes());Ok(rect)
}
