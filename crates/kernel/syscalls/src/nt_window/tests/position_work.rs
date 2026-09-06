use super::*;
fn admit(q:&mut Vec<RemotePosition>,tid:u64,args:[u64;7])->bool{super::admit(q,tid,args,None)}
#[test]
fn remote_capacity_and_per_owner_fifo_preserve_all_seven_arguments(){
    let mut q=Vec::new();
    for i in 0..MAX_REMOTE {assert!(admit(&mut q,(i%2)as u64,[i as u64,1,2,3,4,5,0x4000]));}
    assert!(!admit(&mut q,0,[0;7]));assert!(has_remote_for_tid(&q,1));assert!(!has_remote_for_tid(&q,3));
    for i in (1..MAX_REMOTE).step_by(2){assert_eq!(take(&mut q,1).unwrap().args,[i as u64,1,2,3,4,5,0x4000]);}
    assert!(take(&mut q,1).is_none());assert!(has_remote_for_tid(&q,0));
}
#[test]
fn destruction_and_thread_exit_release_capacity_without_dropping_other_work(){
    let mut q=Vec::new();assert!(admit(&mut q,7,[10;7]));assert!(admit(&mut q,8,[20;7]));assert!(admit(&mut q,7,[30;7]));
    cancel_window(&mut q,10);assert_eq!(q.len(),2);assert_eq!(q[0].args[0],20);
    cancel_thread(&mut q,7);assert_eq!(q.len(),1);assert_eq!(take(&mut q,8).unwrap().args[0],20);assert!(q.is_empty());
}
#[test]
fn synchronous_reply_is_single_assignment_and_teardown_completes_waiter(){
    let mut q=Vec::new();let reply=Arc::new(Reply::new());assert_eq!(reply.result(),None);
    assert!(super::admit(&mut q,7,[10;7],Some(reply.clone())));cancel_thread(&mut q,7);
    assert_eq!(reply.result(),Some(0));reply.complete(1);assert_eq!(reply.result(),Some(0));
    let reply=Arc::new(Reply::new());assert!(super::admit(&mut q,8,[20;7],Some(reply.clone())));
    let request=take(&mut q,8).unwrap();request.reply.unwrap().complete(1);assert_eq!(reply.result(),Some(1));
}
