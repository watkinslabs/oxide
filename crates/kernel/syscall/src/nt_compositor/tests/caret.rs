use super::*;
fn snapshot()->Snapshot{Snapshot{generation:9,rect:Rect{x:-1,y:3,width:1,height:2},visible:true,mask:alloc::vec![0xffffff,0]}}
#[test]
fn exact_wire_offsets_roundtrip(){let s=snapshot();let p=s.encode().unwrap();assert_eq!(p.len(),40);assert_eq!(u64_at(&p,0),Ok(9));assert_eq!(u32_at(&p,8),Ok(u32::MAX));assert_eq!(u32_at(&p,24),Ok(1));assert_eq!(u32_at(&p,28),Ok(RGB_XOR));assert_eq!(Snapshot::decode(&p),Ok(s));}
#[test]
fn hidden_snapshot_has_no_mask_and_allows_empty_geometry(){let s=Snapshot{generation:1,rect:Rect{x:0,y:0,width:0,height:0},visible:false,mask:Vec::new()};assert_eq!(s.encode().unwrap().len(),32);assert_eq!(Snapshot::decode(&s.encode().unwrap()),Ok(s));}
#[test]
fn malformed_length_generation_boolean_format_and_alpha_are_rejected(){
    let p=snapshot().encode().unwrap();for n in [0,31,32,39]{assert!(validate_payload(&p[..n]).is_err());}
    for (offset,value) in [(0,0),(24,2),(28,0),(36,0xff000000)]{let mut bad=p.clone();bad[offset..offset+4].copy_from_slice(&u32::to_le_bytes(value));assert!(validate_payload(&bad).is_err());}
    let mut bad=p.clone();bad.push(0);assert!(validate_payload(&bad).is_err());
}
#[test]
fn geometry_overflow_zero_visible_and_mask_limit_are_rejected(){
    let mut s=snapshot();s.rect.x=i32::MAX;assert!(s.validate().is_err());s.rect.x=0;s.rect.width=0;assert!(s.validate().is_err());
    s.rect.width=8192;s.rect.height=8192;assert!(s.validate().is_err());
    s=snapshot();s.visible=false;assert!(s.validate().is_err());
}
#[test]
fn solid_shape_uses_resolved_dimensions_and_hidden_snapshot_drops_mask(){let rect=Rect{x:1,y:2,width:2,height:3};let s=Snapshot::solid(1,rect,true).unwrap();assert_eq!(s.mask,alloc::vec![0xffffff;6]);assert!(Snapshot::solid(2,rect,false).unwrap().mask.is_empty());}
