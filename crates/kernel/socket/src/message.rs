use alloc::vec::Vec;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Message {
    pub payload: Vec<u8>,
    pub payload_faulted: bool,
    pub requested_len: usize,
    pub control: Vec<u8>,
    pub name: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendOutcome {
    pub bytes: usize,
    pub complete: bool,
}
