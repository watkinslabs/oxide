use super::{abi::*, policy::{self,Owner}};
use super::{Context,Request,Order};
use ipc::win32_window::WindowRect;
struct Env { context: Context, sibling: Option<Context>, last: Option<Request>, fail: bool }
impl Env {
    fn new() -> Self { Self { context: Context { rect: WindowRect { left:10,top:20,right:110,bottom:70 },
        parent:Some(9),style:WS_CHILD,visible:false }, sibling:None,last:None,fail:false } }
}
impl Owner for Env {
    fn context(&mut self, hwnd:u64) -> Option<Context> { match hwnd { 2 => Some(self.context),3 => self.sibling,_ => None } }
    fn commit(&mut self, request:Request) -> bool { self.last=Some(request); !self.fail }
}
fn args(flags:u32) -> [u64;7] { [2,0,30,40,200,80,flags as u64] }
#[test]
fn notepad_edit_resize_consumes_seventh_flags() {
    let mut e=Env::new(); assert_eq!(policy::set(&mut e,&args(NOZORDER|0x0200)),1);
    let r=e.last.unwrap(); assert_eq!(r.rect,WindowRect { left:30,top:40,right:230,bottom:120 });
    assert_eq!(r.order,None); assert_eq!(r.visible,None); assert_ne!(r.flags&0x0200,0);
}
#[test]
fn nomove_nosize_ignore_even_poison_arguments() {
    for flags in [NOMOVE,NOSIZE,NOMOVE|NOSIZE] {
        let mut e=Env::new(); let mut a=args(flags|NOZORDER);
        if flags&NOMOVE!=0 { a[2]=u64::MAX;a[3]=u64::MAX; }
        if flags&NOSIZE!=0 { a[4]=u64::MAX;a[5]=u64::MAX; }
        assert_eq!(policy::set(&mut e,&a),1); let r=e.last.unwrap().rect;
        assert_eq!(r.left,if flags&NOMOVE!=0 {10} else {30});
        assert_eq!(r.right-r.left,if flags&NOSIZE!=0 {100} else {200});
        assert_eq!(r.bottom-r.top,if flags&NOSIZE!=0 {50} else {80});
    }
}
#[test]
fn statusbar_zero_and_negative_size_are_logically_zero() {
    let mut e=Env::new(); let mut a=args(NOZORDER); a[4]=u64::MAX;a[5]=0;
    assert_eq!(policy::set(&mut e,&a),1);let r=e.last.unwrap().rect;
    assert_eq!(r.left,r.right);assert_eq!(r.top,r.bottom);
}
#[test]
fn show_hide_both_flags_follow_previous_visibility() {
    for old in [false,true] { let mut e=Env::new();e.context.visible=old;
        assert_eq!(policy::set(&mut e,&args(NOZORDER|SHOW|HIDE)),1);
        assert_eq!(e.last.unwrap().visible,Some(!old));
    }
}
#[test]
fn redundant_visibility_does_not_request_transition() {
    for old in [false,true] { let mut e=Env::new();e.context.visible=old;
        assert_eq!(policy::set(&mut e,&args(NOZORDER|if old {SHOW}else{HIDE})),1);
        assert_eq!(e.last.unwrap().visible,None);
    }
}
#[test]
fn insertion_validation_precedes_all_mutation_and_nozorder_ignores_it() {
    let mut e=Env::new();let mut a=args(0);a[1]=3;
    assert_eq!(policy::set(&mut e,&a),0);assert!(e.last.is_none());
    e.sibling=Some(Context {parent:Some(99),..e.context});
    assert_eq!(policy::set(&mut e,&a),1);assert!(e.last.is_none());
    e.sibling=Some(e.context);assert_eq!(policy::set(&mut e,&a),1);
    assert_eq!(e.last.unwrap().order,Some(Order::After(3)));
    a[1]=999;a[6]=NOZORDER as u64;assert_eq!(policy::set(&mut e,&a),1);assert_eq!(e.last.unwrap().order,None);
}
#[test]
fn special_insert_handles_and_self_insertion() {
    for (after,order) in [(0,Some(Order::Top)),(1,Some(Order::Bottom)),(0xffff,Some(Order::Topmost)),
        (u64::MAX,Some(Order::Topmost)),(0xfffe,Some(Order::NotTopmost)),(2,None)] {
        let mut e=Env::new();let mut a=args(NOACTIVATE);a[1]=after;
        assert_eq!(policy::set(&mut e,&a),1);assert_eq!(e.last.unwrap().order,order);
    }
}
#[test]
fn top_level_activation_promotes_unless_noactivate() {
    let mut e=Env::new();e.context.style=0;e.context.parent=None;
    assert_eq!(policy::set(&mut e,&args(NOZORDER)),1);assert_eq!(e.last.unwrap().order,Some(Order::Top));
    assert_eq!(policy::set(&mut e,&args(NOZORDER|NOACTIVATE)),1);assert_eq!(e.last.unwrap().order,None);
}
#[test]
fn invalid_hwnd_transport_extent_and_commit_failure_return_false() {
    let mut e=Env::new();let mut a=args(NOZORDER);a[0]=999;
    assert_eq!(policy::set(&mut e,&a),0);assert!(e.last.is_none());
    a[0]=2;a[4]=32767;assert_eq!(policy::set(&mut e,&a),0);assert!(e.last.is_none());
    e.fail=true;assert_eq!(policy::set(&mut e,&args(NOZORDER)),0);
}
#[test]
fn signed_coordinates_clamp_and_owner_flags_survive() {
    let mut e=Env::new();let mut a=args(NOZORDER|0x0020|0x0100|0x0400|0x2000|0x4000);
    a[2]=(-40000i64) as u64;a[3]=40000;
    assert_eq!(policy::set(&mut e,&a),1);let r=e.last.unwrap();
    assert_eq!((r.rect.left,r.rect.top),(-32768,32767));assert_eq!(r.flags&a[6] as u32,a[6] as u32);
}

#[test]
fn notepad_statusbar_sequence_applies_to_canonical_window_manager() {
    use ipc::win32_window::{WindowManager,WindowId};
    struct Canonical { windows:WindowManager, tid:u64 }
    impl Owner for Canonical {
        fn context(&mut self, hwnd:u64) -> Option<Context> {
            let id=WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
            let record=self.windows.get(id)?;
            Some(Context {rect:self.windows.rect(id)?,parent:record.parent.map(|p|p.raw() as u64),style:WS_CHILD,visible:record.visible})
        }
        fn commit(&mut self,r:Request) -> bool {
            let id=WindowId::from_raw(r.hwnd as u32).unwrap();
            if self.windows.set_rect(id,r.rect).is_err() {return false;}
            r.visible.is_none_or(|v|self.windows.show(self.tid,id,v).is_ok())
        }
    }
    let mut e=Canonical {windows:WindowManager::new(),tid:37};
    let parent=e.windows.create(e.tid,None,0).unwrap();
    let child=e.windows.create(e.tid,Some(parent),0).unwrap();
    let a=[child.raw() as u64,0,0,0,0,0,(NOZORDER|SHOW) as u64];
    assert_eq!(policy::set(&mut e,&a),1);
    assert!(e.windows.get(child).unwrap().visible);
    assert_eq!(e.windows.client_rect(child).unwrap(),WindowRect {left:0,top:0,right:0,bottom:0});
    let a=[child.raw() as u64,0,0,480,640,20,NOZORDER as u64];
    assert_eq!(policy::set(&mut e,&a),1);
    assert_eq!(e.windows.rect(child).unwrap(),WindowRect {left:0,top:480,right:640,bottom:500});
}
