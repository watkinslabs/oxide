use super::*;
fn payload(parent:u64)->Vec<u8>{let mut p=parent.to_le_bytes().to_vec();p.extend_from_slice(&Rect{x:10,y:20,width:30,height:40}.encode_window().unwrap());p}
#[test]
fn reparent_codec_rejects_invalid_parent_and_envelope(){
    assert_eq!(Opcode::decode(9),Ok(Opcode::Reparent));
    assert!(!Opcode::Reparent.from_backend());
    for parent in [0,1,u32::MAX as u64]{let record=Record::new(Opcode::Reparent,1,2,payload(parent)).unwrap();assert_eq!(Header::decode(&record.encode().unwrap()[..HEADER_LEN]),Ok(record.header));}
    for parent in [2,u32::MAX as u64+1]{assert_eq!(Record::new(Opcode::Reparent,1,2,payload(parent)),Err(Error::Payload));}
    for len in [0,8,16,23,25,32]{assert_eq!(Record::new(Opcode::Reparent,1,2,alloc::vec![0;len]),Err(Error::Length));}
}
