use super::*;

// Reference: Wine 10.20 server/thread.c process-default inheritance and
// server/winstation.c set_thread_default_desktop; frozen contract 31fl §6.

fn fixture()->(Arc<Task>,Task,Arc<vmm::AddressSpace>,Arc<nt_object::NtObject>) {
    OUTPUT.with(|out|out.borrow_mut().clear());FAIL_WRITE.set(false);INITIALIZED.set(false);
    let parent=Arc::new(Task::new(98201,"native-parent",canonical_sched::SchedClass::Normal{weight:1024}));
    let mut child=Task::new(98202,"native-child",canonical_sched::SchedClass::Normal{weight:1024});
    child.thread_group=parent.thread_group.clone();
    child.clear_child_tid.store(0x2000,Ordering::Release);
    let mm=vmm::AddressSpace::new(0x40000).unwrap();
    // SAFETY: fixture exclusively owns the unpublished child while installing its real mm.
    unsafe {child.replace_mm(Some(mm.clone()));}
    parent.set_nt_peb(0x30000);
    let station=nt_object::NtObject::new(nt_object::NtObjectType::WindowStation,92001);
    let default=nt_object::NtObject::new_desktop(92002,station.clone()).unwrap();
    let switched=nt_object::NtObject::new_desktop(92003,station.clone()).unwrap();
    parent.thread_group.nt_default_desktop.lock().select(&station,default.clone(),false).unwrap();
    parent.nt_desktop.lock().select(&station,switched,false).unwrap();
    parent.nt_native_thread.lock().request=Some(nt_native_thread::Request{generation:7,output:0x1000,start:0x140001000,
        parameter:0x55,stack_size:65536,suspended:false,child:None});
    registry::insert(&parent);
    (parent,child,mm,default)
}

#[test]
fn actual_prepare_inherits_process_default_before_runtime_initialization() {
    let _guard=SERIAL.lock().unwrap();let (parent,child,mm,default)=fixture();
    assert_eq!(lifecycle::prepare(&child,parent.tid as u64,7,0x1000),syscall::nt_native_thread::SUCCESS);
    assert!(INITIALIZED.get());
    assert!(Arc::ptr_eq(&child.nt_desktop.lock().object().unwrap(),&default));
    assert!(!Arc::ptr_eq(&parent.nt_desktop.lock().object().unwrap(),&default));
    assert_eq!(parent.nt_native_thread.lock().request.unwrap().child,Some(child.tid));
    assert_eq!(child.nt_native_thread.lock().child.unwrap().phase,nt_native_thread::Phase::Preparing);
    OUTPUT.with(|out|assert_eq!(&*out.borrow(),&[(0x1000,child.nt_teb()),(0x1008,parent.nt_peb())]));
    assert!(mm.vma_count()>=2);
}

#[test]
fn failed_output_rolls_back_real_mappings_without_inheriting_or_publishing() {
    let _guard=SERIAL.lock().unwrap();let (parent,child,mm,_)=fixture();
    let before=mm.vma_count();FAIL_WRITE.set(true);
    assert_eq!(lifecycle::prepare(&child,parent.tid as u64,7,0x1000),syscall::nt_native_thread::INVALID);
    assert_eq!(mm.vma_count(),before);assert!(!INITIALIZED.get());
    assert!(child.nt_desktop.lock().object().is_none());assert!(!child.is_nt_personality());
    assert!(parent.nt_native_thread.lock().request.unwrap().child.is_none());
}
