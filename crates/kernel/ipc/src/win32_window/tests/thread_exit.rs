use super::*;
#[test]
fn exit_removes_owned_windows_cross_thread_children_and_popup_closure(){
    let mut s=WindowManager::new();let root=s.create(7,None,0).unwrap();
    let child=s.create(8,Some(root),0).unwrap();let popup=s.create(9,None,0).unwrap();
    let grandchild=s.create(10,Some(popup),0).unwrap();let survivor=s.create(8,None,0).unwrap();
    s.set_popup_owner(popup,Some(root)).unwrap();
    s.post_to_window(child,WinMessage {hwnd:Some(child),message:WM_PAINT,wparam:0,lparam:0}).unwrap();
    s.post_to_window(survivor,WinMessage {hwnd:Some(survivor),message:WM_PAINT,wparam:0,lparam:0}).unwrap();
    let removed=s.exit_thread(7);
    assert_eq!(removed.len(),4);
    for id in [root,child,popup,grandchild]{assert!(removed.contains(&id));assert!(s.get(id).is_none());assert!(s.rect(id).is_none());}
    assert!(s.get(survivor).is_some());assert!(s.queues.iter().any(|(tid,_)|*tid==8));assert!(!s.queues.iter().any(|(tid,_)|*tid==7));
    assert_eq!(s.peek_for_thread(8,MessageFilter {hwnd:None,first:0,last:0},true).unwrap().hwnd,Some(survivor));
    assert!(s.peek_for_thread(8,MessageFilter {hwnd:None,first:0,last:0},true).is_none());
    assert!(removed.iter().position(|id|*id==grandchild)<removed.iter().position(|id|*id==popup));
    assert!(removed.iter().position(|id|*id==popup)<removed.iter().position(|id|*id==root));
}
#[test]
fn exit_clears_focus_capture_paint_reservations_and_thread_only_timers(){
    let mut s=WindowManager::new();let window=s.create(7,None,0).unwrap();
    s.set_rect(window,WindowRect {left:0,top:0,right:10,bottom:10}).unwrap();
    s.show(7,window,true).unwrap();s.focus=Some(window);s.capture=Some(window);s.active=Some(window);
    assert!(s.begin_paint(window).unwrap().is_some());assert_eq!(s.painting.len(),1);
    s.begin_destroy(7,window).unwrap();
    s.timers.push(WindowTimer {owner_tid:7,hwnd:None,id:1,period_ns:1,due_ns:1,proc:0});
    s.timers.push(WindowTimer {owner_tid:8,hwnd:None,id:2,period_ns:1,due_ns:1,proc:0});
    assert_eq!(s.exit_thread(7),[window]);
    assert_eq!(s.focus,None);assert_eq!(s.capture,None);assert_eq!(s.active,None);
    assert!(s.dirty.is_empty());assert!(s.painting.is_empty());assert!(s.destroying.is_empty());
    assert_eq!(s.timers.len(),1);assert_eq!(s.timers[0].owner_tid,8);
    assert!(s.exit_thread(7).is_empty());
    assert_eq!(s.post_to_window(window,WinMessage {hwnd:Some(window),message:WM_PAINT,wparam:0,lparam:0}),Err(WindowError::NoSuchWindow));
}
#[test]
fn overlapping_thread_roots_return_each_removed_handle_once(){
    let mut s=WindowManager::new();let root=s.create(7,None,0).unwrap();let child=s.create(7,Some(root),0).unwrap();
    let result=s.exit_thread(7);assert_eq!(result,[child,root]);assert!(s.windows.is_empty());
}
#[test]
fn exit_without_windows_removes_thread_queue_quit_and_timers_only(){
    let mut s=WindowManager::new();s.queues.push((7,MessageQueue::default()));s.queues.push((8,MessageQueue::default()));
    s.post_quit(7,42);s.post_quit(8,24);
    s.timers.push(WindowTimer {owner_tid:7,hwnd:None,id:1,period_ns:1,due_ns:1,proc:0});
    assert!(s.exit_thread(7).is_empty());assert!(!s.queues.iter().any(|(tid,_)|*tid==7));assert!(s.timers.is_empty());
    assert!(s.quit_pending(8));assert!(!s.quit_pending(7));
}
