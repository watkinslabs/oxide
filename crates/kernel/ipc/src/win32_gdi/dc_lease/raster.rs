//! Resolve lease storage once per raster operation, preserving logical clip coverage.
use super::*;

/// A device context renders either into its own direct-colour surface or into
/// the bitmap it selected, which is the sole storage for its own bits.
pub enum RasterTarget<'a> {
    Surface { pixels: &'a mut [u32], stride: i32, height: i32 },
    Bitmap { bits: &'a mut [u8], table: &'a [super::super::Rgb], stride: i32, width: i32, height: i32, bpp: u32, masks: [u32;3] },
}

impl RasterTarget<'_> {
    /// Storage extent in pixels. # C: O(1)
    fn extent(&self) -> (i32, i32) {
        match self { Self::Surface{stride,height,..}=>(*stride,*height), Self::Bitmap{width,height,..}=>(*width,*height) }
    }
    /// XRGB colour already stored at one admitted position. # C: O(1)
    fn get(&self, x: i32, y: i32) -> u32 {
        match self {
            Self::Surface{pixels,stride,..}=>pixels[y as usize*(*stride) as usize+x as usize],
            Self::Bitmap{bits,table,stride,bpp,masks,..}=>{
                let raw=super::super::bitmap::pixels::raw_pixel(bits,*stride,*bpp,x,y).unwrap_or(0);
                super::super::bitmap::resolve(*bpp,raw,table,*masks)
            }
        }
    }
    /// Store one XRGB colour, encoding it for the target's depth; answers
    /// whether the stored value changed. # C: O(colour table)
    fn put(&mut self, x: i32, y: i32, color: u32) -> bool {
        match self {
            Self::Surface{pixels,stride,..}=>{
                let pixel=&mut pixels[y as usize*(*stride) as usize+x as usize];
                if *pixel==color{return false;} *pixel=color; true
            }
            Self::Bitmap{bits,table,stride,bpp,masks,..}=>{
                let raw=super::super::bitmap::encode(*bpp,color,table,*masks);
                let old=super::super::bitmap::pixels::raw_pixel(bits,*stride,*bpp,x,y);
                if old==Some(raw){return false;}
                super::super::bitmap::pixels::put_raw_pixel(bits,*stride,*bpp,x,y,raw).is_some()
            }
        }
    }
}

pub struct DcRaster<'a> { target: RasterTarget<'a>, origin: (i32,i32), clip: PaintRegion,
    pending:&'a mut super::super::output::PendingOutput, changed:Option<Rect> }
impl Drop for DcRaster<'_>{fn drop(&mut self){self.pending.record(self.changed);}}
impl DcRaster<'_> {
    /// Logical bounds are an iteration bound only; update checks exact coverage. # C: O(region rectangles)
    pub fn bounds(&self) -> Rect {
        self.clip.bounds().map(|r| Rect {left:r.left,top:r.top,right:r.right,bottom:r.bottom})
            .unwrap_or(Rect {left:0,top:0,right:0,bottom:0})
    }
    /// Whether the exact logical clip admits one position. # C: O(region rectangles)
    pub fn covers(&self, x: i32, y: i32) -> bool { contains(&self.clip,x,y) }
    /// XRGB colour a clipped position currently holds. # C: O(region rectangles)
    pub fn read(&self, x: i32, y: i32) -> Option<u32> {
        let (dx,dy)=(x.checked_add(self.origin.0)?,y.checked_add(self.origin.1)?);
        let (width,height)=self.target.extent();
        if dx<0||dy<0||dx>=width||dy>=height{return None;}
        Some(self.target.get(dx,dy))
    }
    /// Return whether a pixel was actually admitted and written. # C: O(region rectangles)
    pub fn update(&mut self, x: i32, y: i32, operation: impl FnOnce(u32)->u32) -> bool {
        if !contains(&self.clip,x,y) {return false;}
        let Some(dx)=x.checked_add(self.origin.0) else{return false;};
        let Some(dy)=y.checked_add(self.origin.1) else{return false;};
        let (width,height)=self.target.extent();
        if dx<0||dy<0||dx>=width||dy>=height{return false;}
        let next=operation(self.target.get(dx,dy));
        if self.target.put(dx,dy,next){super::super::output::merge(&mut self.changed,Rect{left:dx,top:dy,right:dx+1,bottom:dy+1});}true
    }
}
impl GdiManager {
    /// Direct-storage queries never pair lease dimensions with unrelated backing pixels. # C: O(DCs)
    pub fn dc_storage_surface(&self,dc:u32)->Option<(i32,i32,&[u32])>{
        let state=&self.dcs.iter().find(|(id,_)|*id==dc)?.1;
        if state.lease.is_some()||state.bitmap.is_some(){return None;}
        Some((state.width,state.height,&state.pixels))
    }
    /// Owned XRGB snapshot of one context's storage, resolving a selected
    /// bitmap through its own depth. Blits read the source through this so a
    /// bitmap-backed context has exactly one pixel store. # C: O(pixels)
    pub fn dc_pixel_snapshot(&self,dc:u32)->Option<(i32,i32,Vec<u32>)>{
        let state=&self.dcs.iter().find(|(id,_)|*id==dc)?.1;
        if let Some(handle)=state.bitmap{
            let bitmap=self.bitmap(handle).ok()?;
            let (width,height)=(bitmap.width,bitmap.height);
            let count=(width as usize).checked_mul(height as usize)?;
            let mut pixels=Vec::new();pixels.try_reserve_exact(count).ok()?;
            for y in 0..height{for x in 0..width{pixels.push(bitmap.pixel(x,y).unwrap_or(0));}}
            return Some((width,height,pixels));
        }
        let (width,height,source)=self.dc_backing_surface(dc)?;
        let mut pixels=Vec::new();pixels.try_reserve_exact(source.len()).ok()?;pixels.extend_from_slice(source);
        Some((width,height,pixels))
    }
    /// Exact logical clip combines DCE visibility with per-HDC application and paint clips. # C: O(DCs + region operations)
    pub fn dc_raster_clip(&self, dc:u32)->Result<PaintRegion,GdiError>{
        let state=&self.dcs.iter().find(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?.1;
        let mut region=match &state.lease{
            Some(lease)=>{if !lease.active{return Err(GdiError::NoSuchObject);}lease.visible.try_copy()},
            None=>PaintRegion::from_rect(WindowRect{left:0,top:0,right:state.width,bottom:state.height}),
        }.map_err(|_|GdiError::HandleLimit)?;
        let (backing,origin)=match &state.lease{Some(lease)=>(lease.backing,lease.origin),None=>(dc,(0,0))};
        let backing=&self.dcs.iter().find(|(id,_)|*id==backing).ok_or(GdiError::NoSuchObject)?.1;
        let clip=WindowRect{
            left:i32::try_from(-i64::from(origin.0)).unwrap_or(i32::MAX),
            top:i32::try_from(-i64::from(origin.1)).unwrap_or(i32::MAX),
            right:(i64::from(backing.width)-i64::from(origin.0)).clamp(i64::from(i32::MIN),i64::from(i32::MAX))as i32,
            bottom:(i64::from(backing.height)-i64::from(origin.1)).clamp(i64::from(i32::MIN),i64::from(i32::MAX))as i32};
        region=region.clipped(clip).map_err(|_|GdiError::HandleLimit)?;
        for clip in [state.clip.as_ref(),state.meta_clip.as_ref()].into_iter().flatten(){intersect(&mut region,clip)?;}
        if let Some(paint)=&state.paint_clip{intersect(&mut region,paint)?;}
        Ok(region)
    }
    /// Owned clip snapshot plus a mutable view of the sole canonical pixel backing. # C: O(DCs + region operations)
    pub fn raster_dc(&mut self,dc:u32)->Result<DcRaster<'_>,GdiError>{
        let clip=self.dc_raster_clip(dc)?;
        let state=&self.dcs.iter().find(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?.1;
        let (backing,origin)=match &state.lease{Some(lease)=>(lease.backing,lease.origin),None=>(dc,(0,0))};
        let selected=state.bitmap;
        let Self{dcs,bitmaps,..}=self;
        let state=&mut dcs.iter_mut().find(|(id,_)|*id==backing).ok_or(GdiError::NoSuchObject)?.1;
        let target=match selected{
            Some(handle)=>{
                let bitmap=&mut bitmaps.iter_mut().find(|(id,_)|*id==handle).ok_or(GdiError::NoSuchObject)?.1;
                let (stride,width,height,bpp,masks)=(bitmap.stride(),bitmap.width,bitmap.height,bitmap.bpp,bitmap.masks());
                let (bits,table)=bitmap.storage_mut();
                RasterTarget::Bitmap{bits,table,stride,width,height,bpp,masks}
            }
            None=>RasterTarget::Surface{stride:state.width,height:state.height,pixels:&mut state.pixels},
        };
        Ok(DcRaster{target,origin,clip,pending:&mut state.pending_output,changed:None})
    }
    /// Presentation reads window backing, not an empty lease-local allocation. # C: O(DCs)
    pub fn dc_backing_surface(&self,dc:u32)->Option<(i32,i32,&[u32])>{
        let state=&self.dcs.iter().find(|(id,_)|*id==dc)?.1;
        if state.bitmap.is_some(){return None;}
        let state=match &state.lease{Some(lease)=>{
            if !lease.active{return None;} &self.dcs.iter().find(|(id,_)|*id==lease.backing)?.1
        },None=>state};
        Some((state.width,state.height,&state.pixels))
    }
    /// Shared fill implementation for memory and leased HDCs. # C: O(DCs + region + clipped pixels)
    pub fn raster_fill_rect(&mut self,dc:u32,rect:Rect,color:u32)->Result<(),GdiError>{
        let mut target=self.raster_dc(dc)?;let clip=target.bounds();
        for y in rect.top.max(clip.top)..rect.bottom.min(clip.bottom){
            for x in rect.left.max(clip.left)..rect.right.min(clip.right){target.update(x,y,|_|color);}
        }Ok(())
    }
    /// Shared raster upload preserves lease origin and exact clips. # C: O(DCs + region + source pixels)
    pub fn raster_blit_pixels(&mut self,dc:u32,x:i32,y:i32,width:i32,height:i32,stride:i32,pixels:&[u32])->Result<(),GdiError>{
        if width<=0||height<=0||stride<width||pixels.len()<(height as usize).checked_mul(stride as usize).ok_or(GdiError::InvalidDimensions)?{return Err(GdiError::InvalidDimensions);}
        let mut target=self.raster_dc(dc)?;
        for row in 0..height{let Some(dy)=y.checked_add(row)else{continue;};
            for col in 0..width{let Some(dx)=x.checked_add(col)else{continue;};
                target.update(dx,dy,|_|pixels[row as usize*stride as usize+col as usize]);}
        }Ok(())
    }
    /// Snapshot source backing before destination mutation, including two aliases of one window.
    /// Source drawing clips do not constrain reads. # C: O(DCs + backing pixels + copied pixels)
    pub fn raster_bitblt(&mut self,dst:u32,dx:i32,dy:i32,src:u32,sx:i32,sy:i32,width:i32,height:i32)->Result<(),GdiError>{
        if width<=0||height<=0{return Err(GdiError::InvalidDimensions);}
        let state=&self.dcs.iter().find(|(id,_)|*id==src).ok_or(GdiError::NoSuchObject)?.1;
        let origin=state.lease.as_ref().map_or((0,0),|lease|lease.origin);
        let (sw,sh,pixels)=self.dc_pixel_snapshot(src).ok_or(GdiError::NoSuchObject)?;
        let mut target=self.raster_dc(dst)?;
        for row in 0..height{let source_y=i64::from(sy)+i64::from(row)+i64::from(origin.1);
            let Some(y)=dy.checked_add(row)else{continue;};if source_y<0||source_y>=i64::from(sh){continue;}
            for col in 0..width{let source_x=i64::from(sx)+i64::from(col)+i64::from(origin.0);
                let Some(x)=dx.checked_add(col)else{continue;};if source_x<0||source_x>=i64::from(sw){continue;}
                target.update(x,y,|_|pixels[source_y as usize*sw as usize+source_x as usize]);}
        }Ok(())
    }
}
