use super::*;
#[test]
fn pen_raw_signatures_keep_handles_and_truncate_only_scalars() {
    let dc=0x123400001234;let pen=0xabcd00005678;
    assert_eq!(route(CREATE_PEN,&[0x123400000000,u64::MAX,0xffff000000123456,u64::MAX],|call|{
        assert_eq!(call,PenCall::Create {style:0,width:-1,colorref:0x123456});0x300040
    }),Some(0x300040));
    assert_eq!(route(SELECT_PEN,&[dc,pen],|call|{assert_eq!(call,PenCall::Select {dc,pen});pen}),Some(pen));
    assert_eq!(route(LINE_TO,&[dc,u64::MAX,0xabc000000002],|call|{assert_eq!(call,PenCall::Line {dc,x:-1,y:2});1}),Some(1));
    assert_eq!(route(RECTANGLE,&[dc,u64::MAX,2,3,4],|call|{
        assert_eq!(call,PenCall::Rectangle {dc,rect:Rect {left:-1,top:2,right:3,bottom:4}});1
    }),Some(1));
}
#[test]
fn pen_raw_invalid_arity_and_unknown_ordinal_do_not_execute() {
    for (ordinal,count) in [(CREATE_PEN,4),(SELECT_PEN,2),(LINE_TO,3),(RECTANGLE,5)] {
        for length in 0..count {assert_eq!(route(ordinal,&[0;5][..length],|_|panic!("short call reached owner")),Some(0));}
        assert_eq!(route(ordinal,&[0;5],|_|0),Some(0));
    }
    assert_eq!(route(0x126d,&[0;5],|_|panic!("unknown call reached owner")),None);
}
