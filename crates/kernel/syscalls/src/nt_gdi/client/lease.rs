//! Geometry publication validates mapping/identity without interpreting unrelated render attributes.
use super::{ClientBinding,ClientError,abi,memory};

impl ClientBinding {
    /// Lifetime gate held by caller; canonical HDC admission precedes usercopy. # C: O(DC_ATTR_SIZE)
    pub(crate) fn update_lease_dimensions(&self,handle:u32,width:i32,height:i32)->Result<(),ClientError>{
        if width<0||height<0{return Err(ClientError::Codec);}
        self.validate_current()?;
        let address=self.dc_attr_address(handle)?;
        let mut bytes=[0u8;abi::DC_ATTR_SIZE];
        uaccess::copy_from_user(&mut bytes,address).map_err(|_|ClientError::UserCopy)?;
        let rect=geometry::prepare(&bytes,handle,width,height).map_err(|_|ClientError::Codec)?;
        memory::write(address.checked_add((abi::dc::VIS_RECT+8)as u64).ok_or(ClientError::InvalidBinding)?,&rect)
    }
}

#[path = "lease_geometry.rs"]
mod geometry;
