extern crate self as hal;
extern crate self as sched;
extern crate self as uaccess;
use std::{cell::RefCell,sync::atomic::AtomicU32};
pub const PAGE_SIZE_BYTES:usize=4096;
const PEB:u64=0x1000;
const TABLE:u64=0x2000;
const ATTRS:u64=0x200000;
pub struct Task {pub tgid:AtomicU32}
impl Task {pub fn nt_peb(&self)->u64{PEB}}
static TASK:Task=Task{tgid:AtomicU32::new(1)};
pub mod live {pub fn current()->Option<&'static crate::Task>{Some(&crate::TASK)}}
struct Memory {bytes:Vec<u8>,writes:usize,fail_write:bool}
thread_local!{static MEMORY:RefCell<Memory>=RefCell::new(Memory{bytes:vec![0;16*1024*1024],writes:0,fail_write:false});}
pub fn copy_from_user(dst:&mut[u8],address:u64)->Result<(),()>{MEMORY.with(|memory|{
    let memory=memory.borrow();let start=usize::try_from(address).map_err(|_|())?;
    dst.copy_from_slice(memory.bytes.get(start..start.checked_add(dst.len()).ok_or(())?).ok_or(())?);Ok(())
})}
pub fn copy_to_user(address:u64,src:&[u8])->Result<(),()>{MEMORY.with(|memory|{
    let mut memory=memory.borrow_mut();if memory.fail_write{return Err(());}
    let start=usize::try_from(address).map_err(|_|())?;
    memory.bytes.get_mut(start..start.checked_add(src.len()).ok_or(())?).ok_or(())?.copy_from_slice(src);
    memory.writes+=1;Ok(())
})}
pub fn get_user_u64(address:u64)->Result<u64,()>{let mut b=[0;8];copy_from_user(&mut b,address)?;Ok(u64::from_le_bytes(b))}
pub fn put_user_u64(address:u64,value:u64)->Result<(),()>{copy_to_user(address,&value.to_le_bytes())}
include!(concat!(env!("OUT_DIR"),"/modules.rs"));
#[cfg(test)]
mod tests;
