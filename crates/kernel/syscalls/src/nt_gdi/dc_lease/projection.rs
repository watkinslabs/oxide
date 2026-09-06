//! Lease projection policy never replaces preserved shared attributes with owner defaults.
use ipc::win32_gdi::TextState;

pub(crate) trait Projection {
    type Error;
    fn initialize(&self,dc:u32,pid:u16,state:TextState)->Result<(),Self::Error>;
    fn geometry(&self,dc:u32,width:i32,height:i32)->Result<(),Self::Error>;
}

/// Existing identities retain all nongeometry shared bytes. # C: O(1)
pub(crate) fn acquire<P:Projection>(binding:&P,dc:u32,pid:u16,state:TextState,reused:bool)->Result<(),P::Error>{
    if reused {binding.geometry(dc,state.width,state.height)}else{binding.initialize(dc,pid,state)}
}

/// Preserved release writes no shared attributes. # C: O(1)
pub(crate) fn release<P:Projection>(binding:&P,dc:u32,pid:u16,state:TextState,reset:bool)->Result<(),P::Error>{
    if reset {binding.initialize(dc,pid,state)}else{Ok(())}
}

#[cfg(target_os = "oxide-kernel")]
#[path = "binding.rs"]
mod binding;
