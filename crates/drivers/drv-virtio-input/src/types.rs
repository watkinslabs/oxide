#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VirtioInputEvent {
    pub ty: u16,
    pub code: u16,
    pub value: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VirtioInputAbsInfo {
    pub min: u32,
    pub max: u32,
    pub fuzz: u32,
    pub flat: u32,
    pub res: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VirtioInputDevIds {
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct InputEvent {
    pub tv_sec: u64,
    pub tv_usec: u64,
    pub ty: u16,
    pub code: u16,
    pub value: u32,
}
