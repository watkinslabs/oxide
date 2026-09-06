//! Binding-owned writes preserve the live shared snapshot on lease reuse.
use super::*;
use crate::nt_gdi::client::{ClientBinding,ClientError};
impl Projection for ClientBinding {
    type Error=ClientError;
    fn initialize(&self,dc:u32,pid:u16,state:TextState)->Result<(),ClientError>{self.publish_dc_state(dc,pid,state)}
    fn geometry(&self,dc:u32,width:i32,height:i32)->Result<(),ClientError>{self.update_dc_dimensions(dc,width,height)}
}
