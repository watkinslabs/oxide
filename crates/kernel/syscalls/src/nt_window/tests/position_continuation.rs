use super::*;
use core::sync::atomic::{AtomicU64,Ordering};
static CALLED:AtomicU64=AtomicU64::new(0);
fn resume(token:u64,state:Outcome)->u64{CALLED.store(token,Ordering::SeqCst);match state{Outcome::Complete(true)=>71,Outcome::Failed=>72,_=>73}}
#[test]
fn pending_does_not_call_or_return_success_and_final_result_resumes_token(){
    CALLED.store(0,Ordering::SeqCst);let caller=Some(Continuation{token:99,resume});
    assert_eq!(finish(caller,0x103),None);assert_eq!(CALLED.load(Ordering::SeqCst),0);
    assert_eq!(finish(caller,1),Some(71));assert_eq!(CALLED.load(Ordering::SeqCst),99);
    assert_eq!(finish(caller,0),Some(72));assert_eq!(finish(None,1),None);
}
#[test]
fn high_status_and_unknown_scalar_cannot_be_completed_bool(){
    for n in [0,2,u64::MAX,0xc000000d]{assert_eq!(outcome(n),Outcome::Failed);}
    assert_eq!(outcome(1),Outcome::Complete(true));assert_eq!(outcome(0x103),Outcome::Pending);
}
