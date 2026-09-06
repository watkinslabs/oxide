use super::*;

impl GdiManager {
    /// Canonical storage permits empty window backing without synthetic pixels. # C: O(pixels)
    pub fn create_storage_dc(&mut self,width:i32,height:i32)->Result<u32,GdiError>{
        if width<0||height<0{return Err(GdiError::InvalidDimensions);}
        let count=(width as usize).checked_mul(height as usize).filter(|count|*count<=MAX_SURFACE_PIXELS).ok_or(GdiError::InvalidDimensions)?;
        let mut pixels=Vec::new();pixels.try_reserve_exact(count).map_err(|_|GdiError::InvalidDimensions)?;pixels.resize(count,0);
        self.dcs.try_reserve(1).map_err(|_|GdiError::HandleLimit)?;
        let handle=self.allocate(TYPE_DC)?;
        self.dcs.push((handle,DeviceContext{width,height,map_mode:MM_TEXT,font:Some(DEFAULT_DC_FONT_HANDLE),brush:None,
            dc_brush_color:0xffffff,pen:DEFAULT_DC_PEN_HANDLE,dc_pen_color:0,text:TextAttributes::default(),
            clip:None,paint_clip:None,pixels,lease:None,pending_output:Default::default()}));Ok(handle)
    }
    /// Keep the canonical DC identity and attributes across window resize.
    /// Allocation/validation precede mutation. # C: O(DCs + new pixels)
    pub fn resize_dc(&mut self, dc: u32, width: i32, height: i32) -> Result<(), GdiError> {
        if width < 0 || height < 0 { return Err(GdiError::InvalidDimensions); }
        let count = (width as usize).checked_mul(height as usize)
            .filter(|count| *count <= MAX_SURFACE_PIXELS).ok_or(GdiError::InvalidDimensions)?;
        let (_, state) = self.dcs.iter_mut().find(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        if state.lease.is_some() { return Err(GdiError::InvalidDimensions); }
        if state.width == width && state.height == height { return Ok(()); }
        let mut pixels = Vec::new();
        pixels.try_reserve_exact(count).map_err(|_| GdiError::InvalidDimensions)?;
        pixels.resize(count, 0);
        let columns = width.min(state.width) as usize;
        for row in 0..if columns==0{0}else{height.min(state.height) as usize} {
            pixels[row * width as usize..row * width as usize + columns]
                .copy_from_slice(&state.pixels[row * state.width as usize..row * state.width as usize + columns]);
        }
        state.width = width; state.height = height; state.pixels = pixels;
        state.pending_output.resized(width,height);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_reacquisition_resizes_same_dc_and_preserves_pixels_and_attributes() {
        let mut gdi = GdiManager::new();
        let dc = gdi.acquire_window_dc(7, 2, 2).unwrap();
        gdi.fill_rect(dc, Rect { left: 0, top: 0, right: 2, bottom: 2 }, 0x123456).unwrap();
        gdi.set_text_attribute(dc, TextAttribute::Foreground, 0xabcdef).unwrap();
        let font = gdi.create_font(Font { height: 17, width: 0, weight: 400, italic: false }).unwrap();
        gdi.select_font(dc, font).unwrap();
        let old = gdi.text_state(dc).unwrap();
        assert_eq!(gdi.acquire_window_dc(7, 3, 1), Ok(dc));
        assert_eq!(gdi.pixels(dc).unwrap(), &[0x123456, 0x123456, 0]);
        let resized = gdi.text_state(dc).unwrap();
        assert_eq!((resized.width, resized.height), (3, 1));
        assert_eq!(resized.attributes, old.attributes);
        assert_eq!(resized.font, old.font);
        assert!(gdi.release_window_dc(7, dc).is_ok());
    }

    #[test]
    fn invalid_resize_preserves_previous_surface() {
        let mut gdi = GdiManager::new();
        let dc = gdi.acquire_window_dc(7, 2, 2).unwrap();
        let old = gdi.text_state(dc).unwrap();
        for (width, height) in [(-1, 2), (2, -1), (i32::MAX, i32::MAX)] {
            assert!(gdi.acquire_window_dc(7, width, height).is_err());
            assert_eq!(gdi.text_state(dc).unwrap(), old);
        }
    }

    #[test]
    fn empty_storage_keeps_exact_dimensions_metrics_and_can_grow(){
        let mut gdi=GdiManager::new();
        for(width,height)in[(0,0),(0,4),(4,0)]{
            let dc=gdi.create_storage_dc(width,height).unwrap();
            assert_eq!(gdi.surface(dc).map(|(w,h,p)|(w,h,p.len())),Some((width,height,0)));
            assert!(gdi.text_metrics(dc).is_ok());
            gdi.fill_rect(dc,Rect{left:0,top:0,right:4,bottom:4},0x123456).unwrap();
            assert!(gdi.pixels(dc).unwrap().is_empty());
            gdi.resize_dc(dc,2,2).unwrap();assert_eq!(gdi.pixels(dc).unwrap(),&[0;4]);
            gdi.resize_dc(dc,width,height).unwrap();assert!(gdi.pixels(dc).unwrap().is_empty());
        }
    }

    #[test]
    fn zero_width_large_height_resize_has_no_pixel_iteration(){
        let mut gdi=GdiManager::new();let dc=gdi.create_storage_dc(0,i32::MAX).unwrap();
        gdi.resize_dc(dc,0,i32::MAX-1).unwrap();
        assert_eq!(gdi.dc_storage_surface(dc).map(|(w,h,p)|(w,h,p.len())),Some((0,i32::MAX-1,0)));
    }
}
