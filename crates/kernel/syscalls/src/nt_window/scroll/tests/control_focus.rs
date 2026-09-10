use super::*;
use nt_window::scroll::control_proc;
use win32_window::{WindowId,WindowRect,WM_SETFOCUS,WM_KILLFOCUS};

#[test]
fn focus_creates_gray_thumb_caret_and_loss_invalidates_thumb_then_destroys(){
    let _serial=TEST_LOCK.lock().unwrap();
    for vertical in [false,true]{
        let(_,hwnd)=setup();let id=WindowId::from_raw(hwnd as u32).unwrap();
        {let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;
            state.set_window_styles(id,vertical as u32,0).unwrap();state.initialize_scroll_control(id).unwrap();
            state.set_rect(id,WindowRect{left:0,top:0,right:if vertical{20}else{200},bottom:if vertical{200}else{20}}).unwrap();
            state.set_visible(id,true).unwrap();}
        assert_eq!(control_proc::for_current(hwnd,WM_SETFOCUS,0,0),Some(0));
        CARET_SNAPSHOTS.with(|snapshots|{let snapshots=snapshots.borrow();let s=snapshots.last().unwrap();
            assert!(s.visible);assert_eq!((s.rect.x,s.rect.y,s.rect.width,s.rect.height),if vertical{(1,17,18,14)}else{(17,1,14,18)});
            assert_eq!(&s.mask[..4],&[0,0xffffff,0,0xffffff]);});
        assert_eq!(control_proc::for_current(hwnd,WM_KILLFOCUS,0,0),Some(0));
        CARET_CALLS.with(|calls|assert_eq!(*calls.borrow(),vec![(hwnd,true),(hwnd,false)]));
        let entries=nt_window::GUI.lock();let state=&entries[0].state;
        assert!(state.current_caret_position(7).is_none());
        let expected=if vertical{WindowRect{left:0,top:17,right:20,bottom:33}}else{WindowRect{left:17,top:0,right:33,bottom:20}};
        assert_eq!(state.update_rect(id).unwrap(),Some(expected));
    }
}

#[test]
fn absent_thumb_and_zero_caret_extent_follow_signed_bitmap_and_border_rules(){
    let _serial=TEST_LOCK.lock().unwrap();
    for(width,height,disabled,caret_width,caret_height)in[(20,20,false,1,18),(200,20,true,1,18),(200,2,false,14,1)]{
        let(_,hwnd)=setup();let id=WindowId::from_raw(hwnd as u32).unwrap();
        {let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;
            state.set_window_styles(id,if disabled{win32_window::styles::WS_DISABLED}else{0},0).unwrap();state.initialize_scroll_control(id).unwrap();
            state.set_rect(id,WindowRect{left:0,top:0,right:width,bottom:height}).unwrap();state.set_visible(id,true).unwrap();}
        assert_eq!(control_proc::for_current(hwnd,WM_SETFOCUS,0,0),Some(0));
        CARET_SNAPSHOTS.with(|snapshots|{let s=snapshots.borrow();let s=s.last().unwrap();assert_eq!((s.rect.width,s.rect.height),(caret_width,caret_height));assert!(s.visible);});
        assert_eq!(control_proc::for_current(hwnd,WM_KILLFOCUS,0,0),Some(0));
        assert!(nt_window::GUI.lock()[0].state.current_caret_position(7).is_none());
        assert!(!nt_window::GUI.lock()[0].state.erase_damage(id).unwrap().erase);
    }
}
