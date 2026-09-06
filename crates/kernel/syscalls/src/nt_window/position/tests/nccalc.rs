use super::*;
fn r(x:i32,y:i32,w:i32,h:i32)->WindowRect{WindowRect{left:x,top:y,right:x+w,bottom:y+h}}
#[test]fn class_and_callback_axis_redraw_only_when_client_extent_changes(){
    let old=r(10,20,100,50);
    for(class,flag)in [(CS_HREDRAW,WVR_HREDRAW),(CS_VREDRAW,WVR_VREDRAW)]{
        let changed=if class==CS_HREDRAW{r(10,20,101,50)}else{r(10,20,100,51)};
        assert_eq!(valid(old,changed,class,0,0,[old;2]),None);
        assert_eq!(valid(old,changed,0,flag,0,[old;2]),None);
        assert!(valid(old,r(30,40,100,50),class,flag,0,[old;2]).is_some());
        let other=if class==CS_HREDRAW{r(10,20,100,51)}else{r(10,20,101,50)};
        assert!(valid(old,other,class,flag,0,[old;2]).is_some());
    }
}
#[test]fn preservation_alignment_and_validrects_clipping_follow_callback_contract(){
    let old=r(10,20,100,50);let new=r(30,40,120,70);
    assert_eq!(valid(old,new,0,0,0,[old;2]),Some([r(30,40,100,50),old]));
    assert_eq!(valid(old,new,0,WVR_ALIGNBOTTOM|WVR_ALIGNRIGHT,0,[old;2]),Some([r(50,60,100,50),old]));
    assert_eq!(valid(old,new,0,WVR_VALIDRECTS|WVR_ALIGNRIGHT,0,[r(20,30,40,40),r(20,30,20,20)]),Some([r(30,40,20,20),r(20,30,20,20)]));
    assert_eq!(valid(old,new,0,WVR_VALIDRECTS,0,[r(-100,0,1,1),old]),None);
    for flag in [SWP_NOREDRAW,SWP_SHOWWINDOW,SWP_HIDEWINDOW,SWP_NOCOPYBITS]{assert_eq!(valid(old,new,0,0,flag,[old;2]),None);}
}
