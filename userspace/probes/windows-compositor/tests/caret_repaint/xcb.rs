//! Narrow XCB test boundary: inspect server pixels and inject expose damage.
use libc::{c_char,c_int,c_void};
#[repr(C)]pub struct Connection{_private:[u8;0]}
#[repr(C)]pub struct Cookie{sequence:u32}
#[repr(C)]pub struct Image{response_type:u8,depth:u8,sequence:u16,length:u32,visual:u32,pad:[u8;20]}
#[link(name=":libxcb.so.1")]
unsafe extern "C"{
    fn xcb_connect(display:*const c_char,screen:*mut c_int)->*mut Connection;
    fn xcb_connection_has_error(c:*mut Connection)->c_int;
    fn xcb_disconnect(c:*mut Connection);
    fn xcb_get_image(c:*mut Connection,format:u8,drawable:u32,x:i16,y:i16,width:u16,height:u16,mask:u32)->Cookie;
    fn xcb_get_image_reply(c:*mut Connection,cookie:Cookie,error:*mut *mut c_void)->*mut Image;
    fn xcb_get_image_data(reply:*const Image)->*mut u8;
    fn xcb_get_image_data_length(reply:*const Image)->c_int;
    fn xcb_clear_area_checked(c:*mut Connection,exposures:u8,window:u32,x:i16,y:i16,width:u16,height:u16)->Cookie;
    fn xcb_change_window_attributes_checked(c:*mut Connection,window:u32,mask:u32,values:*const u32)->Cookie;
    fn xcb_send_event_checked(c:*mut Connection,propagate:u8,destination:u32,mask:u32,event:*const c_char)->Cookie;
    fn xcb_request_check(c:*mut Connection,cookie:Cookie)->*mut c_void;
}
pub struct Client(*mut Connection);
impl Client{
    pub fn connect(display:&str)->Self{
        let name=std::ffi::CString::new(display).unwrap();
        // SAFETY: connect retains the NUL-terminated display string for both XCB calls.
        unsafe{let c=xcb_connect(name.as_ptr(),std::ptr::null_mut());assert!(!c.is_null());assert_eq!(xcb_connection_has_error(c),0);Self(c)}
    }
    fn checked(&self,cookie:Cookie){
        // SAFETY: checked owns a live connection and releases only XCB's allocated error.
        unsafe{let error=xcb_request_check(self.0,cookie);if !error.is_null(){libc::free(error);panic!("XCB test request failed");}}
    }
    pub fn pixels(&self,xid:u32,width:u16,height:u16)->Vec<u32>{
        // SAFETY: pixels validates XCB's reply pointer/length, copies its data before free,
        // and uses the live connection owned by Client throughout the request.
        unsafe{
        let cookie=xcb_get_image(self.0,2,xid,0,0,width,height,u32::MAX);let mut error=std::ptr::null_mut();
        let image=xcb_get_image_reply(self.0,cookie,&mut error);
        assert!(error.is_null());assert!(!image.is_null());let len=xcb_get_image_data_length(image);
        assert_eq!(len as usize,width as usize*height as usize*4);
        let bytes=std::slice::from_raw_parts(xcb_get_image_data(image),len as usize);
        let pixels=bytes.chunks_exact(4).map(|b|u32::from_ne_bytes(b.try_into().unwrap())&0xffffff).collect();
        libc::free(image.cast());pixels}
    }
    pub fn clear(&self,xid:u32,width:u16,height:u16){
        // Backend windows have background=None; ClearArea would otherwise do
        // nothing. Set a distinct test background before damaging server pixels.
        // SAFETY: clear supplies one live background value for the one-bit attribute mask.
        unsafe{self.checked(xcb_change_window_attributes_checked(self.0,xid,2,&0x00553311));
        self.checked(xcb_clear_area_checked(self.0,0,xid,0,0,width,height));}
    }
    pub fn expose(&self,xid:u32,x:u16,y:u16,width:u16,height:u16){
        let mut event=[0u8;32];event[0]=12;event[4..8].copy_from_slice(&xid.to_ne_bytes());
        for (offset,value) in [(8,x),(10,y),(12,width),(14,height)]{event[offset..offset+2].copy_from_slice(&value.to_ne_bytes());}
        // SAFETY: expose retains the complete 32-byte event while XCB copies the request.
        self.checked(unsafe{xcb_send_event_checked(self.0,0,xid,1<<15,event.as_ptr().cast())});
    }
}
impl Drop for Client{fn drop(&mut self){
    // SAFETY: Client exclusively owns this connection and disconnects it exactly once.
    unsafe{xcb_disconnect(self.0);}
}}
