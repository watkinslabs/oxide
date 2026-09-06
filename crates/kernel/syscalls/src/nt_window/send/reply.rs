//! Shared send/position completion; values never encode pending state.
use core::sync::atomic::{AtomicU8,AtomicU64,Ordering};
const PENDING:u8=0;
const WRITING:u8=1;
const COMPLETE:u8=2;
const CANCELLED:u8=3;
#[derive(Clone,Copy)]
pub(crate) struct Continuation {pub token:u64,pub resume:fn(u64,Result<u64,()>)->u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum SendOutcome {Complete(u64),Failed,Pending}
pub(crate) struct Reply {state:AtomicU8,value:AtomicU64,pub(crate) continuation:Option<Continuation>}
impl Reply {
    /// # C: O(1)
    pub(crate) fn new()->Self{Self::with_continuation(None)}
    /// # C: O(1)
    pub(crate) fn with_continuation(continuation:Option<Continuation>)->Self{Self{state:AtomicU8::new(PENDING),value:AtomicU64::new(0),continuation}}
    /// # C: O(1)
    pub(crate) fn result(&self)->Option<u64>{self.outcome().map(|r|r.unwrap_or(0))}
    /// # C: O(1)
    pub(crate) fn outcome(&self)->Option<Result<u64,()>>{match self.state.load(Ordering::Acquire){COMPLETE=>Some(Ok(self.value.load(Ordering::Relaxed))),CANCELLED=>Some(Err(())),_=>None}}
    /// Single assignment publishes all 64 result bits. # C: O(1)
    pub(crate) fn complete(&self,value:u64){
        if self.state.compare_exchange(PENDING,WRITING,Ordering::AcqRel,Ordering::Acquire).is_ok(){
            self.value.store(value,Ordering::Relaxed);self.state.store(COMPLETE,Ordering::Release);
        }
    }
    /// # C: O(1)
    pub(crate) fn cancel(&self){let _=self.state.compare_exchange(PENDING,CANCELLED,Ordering::AcqRel,Ordering::Acquire);}
}
