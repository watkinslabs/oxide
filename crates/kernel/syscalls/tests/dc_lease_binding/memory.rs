//! Fixture replaces only process user-memory writes; production binding owns layout/policy.
use super::ClientError;
pub(crate) fn write(address:u64,bytes:&[u8])->Result<(),ClientError>{crate::copy_to_user(address,bytes).map_err(|_|ClientError::UserCopy)}
pub(crate) fn zero(address:u64,count:usize)->Result<(),ClientError>{write(address,&vec![0;count])}
