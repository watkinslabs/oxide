use super::*;
use alloc::vec::Vec;
fn points(a:(i32,i32),b:(i32,i32),bounds:Rect)->Vec<(i32,i32)> {
    let mut out=Vec::new();line(a,b,bounds,|x,y,_|{out.push((x,y));Ok(())}).unwrap();out
}
fn bounds()->Rect {Rect {left:-10,top:-10,right:11,bottom:11}}
#[test]
fn directed_lines_exclude_endpoint_and_use_octant_tie_bias() {
    assert_eq!(points((0,0),(2,1),bounds()),[(0,0),(1,0)]);
    assert_eq!(points((2,1),(0,0),bounds()),[(2,1),(1,0)]);
    assert_eq!(points((0,0),(2,-1),bounds()),[(0,0),(1,-1)]);
    assert_eq!(points((0,0),(-1,2),bounds()),[(0,0),(-1,1)]);
    assert_eq!(points((3,0),(0,0),bounds()),[(3,0),(2,0),(1,0)]);
    assert!(points((1,1),(1,1),bounds()).is_empty());
}
#[test]
fn enormous_offscreen_line_is_bounded_and_preserves_original_coverage() {
    let clip=Rect {left:0,top:0,right:4,bottom:4};
    assert_eq!(points((i32::MIN,0),(i32::MAX,0),clip),[(0,0),(1,0),(2,0),(3,0)]);
    assert_eq!(points((i32::MIN,i32::MIN),(i32::MAX,i32::MAX),clip),[(0,0),(1,1),(2,2),(3,3)]);
    for end in [(8,3),(3,8),(-8,3),(3,-8),(-8,-3),(-3,-8)] {
        let clip=Rect {left:-2,top:-2,right:3,bottom:3};
        let expected:Vec<_>=points((0,0),end,bounds()).into_iter().filter(|(x,y)|*x>=-2&&*x<3&&*y>=-2&&*y<3).collect();
        assert_eq!(points((0,0),end,clip),expected);
    }
}
