use super::*;
#[derive(Default)]struct State{committed:Vec<bool>,copies:Vec<(u64,Vec<u8>)>,deleted:Vec<u32>,aborted:usize,bad_owner:bool,bad_copy:bool}
impl Owner for State{
    fn commit(&mut self,_:Prepared,erase:bool)->Option<WindowRect>{if self.bad_owner{return None;}self.committed.push(erase);Some(WindowRect{left:2,top:3,right:7,bottom:9})}
    fn copy(&mut self,p:u64,bytes:&[u8])->bool{self.copies.push((p,bytes.to_vec()));!self.bad_copy}
    fn retain(&mut self,_:Prepared)->bool{true}
    fn abort(&mut self,_:Prepared){self.aborted+=1;}
    fn delete(&mut self,h:u32){self.deleted.push(h);}
}
fn prepared()->Prepared{Prepared{hwnd:1,dc:2,destination:4096,nc_region:3,tid:7,kernel:false}}
#[test]fn final_success_encodes_f_erase_and_retains_dc_for_endpaint(){
    for erase in [false,true]{let mut s=State::default();assert_eq!(finish(&mut s,prepared(),Ok(erase)),2);
        assert_eq!(s.deleted,vec![3]);assert_eq!(s.aborted,0);let b=&s.copies[0].1;
        assert_eq!(u64::from_le_bytes(b[..8].try_into().unwrap()),2);assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()),u32::from(erase));
        assert_eq!(i32::from_le_bytes(b[12..16].try_into().unwrap()),2);assert_eq!(b.len(),28);
    }
}
#[test]fn callback_failure_wrong_owner_and_copy_fault_release_resources(){
    for cause in 0..3{let mut s=State{bad_owner:cause==1,bad_copy:cause==2,..Default::default()};
        assert_eq!(finish(&mut s,prepared(),if cause==0{Err(())}else{Ok(false)}),0);
        assert_eq!(s.deleted,vec![2,3]);assert_eq!(s.aborted,1);
        if cause!=2{assert!(s.copies.is_empty());}
    }
}
#[test]fn sentinel_is_not_deleted_and_bad_destination_rolls_back_after_commit(){
    let mut p=prepared();p.nc_region=1;let mut s=State::default();assert_eq!(finish(&mut s,p,Ok(false)),2);assert!(s.deleted.is_empty());
    p.destination=u64::MAX;assert_eq!(finish(&mut s,p,Ok(false)),0);assert_eq!(s.deleted,vec![2]);assert_eq!(s.aborted,1);assert_eq!(s.committed.len(),2);
}
#[test]fn null_destination_retains_then_releases_dc_and_owned_region_once(){
    let mut p=prepared();p.destination=0;let mut s=State::default();
    assert_eq!(finish(&mut s,p,Ok(false)),0);assert_eq!(s.deleted,vec![2,3]);assert_eq!(s.aborted,1);
}
