#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct FbVblank {
    pub flags: u32,
    pub count: u32,
    pub vcount: u32,
    pub hcount: u32,
    pub reserved: [u32; 4],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FbCmap {
    pub start: u32,
    pub len: u32,
    pub red: u64,
    pub green: u64,
    pub blue: u64,
    pub transp: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct FbBitfield {
    pub offset: u32,
    pub length: u32,
    pub msb_right: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FbVarScreeninfo {
    pub xres: u32,
    pub yres: u32,
    pub xres_virtual: u32,
    pub yres_virtual: u32,
    pub xoffset: u32,
    pub yoffset: u32,
    pub bits_per_pixel: u32,
    pub grayscale: u32,
    pub red: FbBitfield,
    pub green: FbBitfield,
    pub blue: FbBitfield,
    pub transp: FbBitfield,
    pub nonstd: u32,
    pub activate: u32,
    pub height: u32,
    pub width: u32,
    pub accel_flags: u32,
    pub pixclock: u32,
    pub left_margin: u32,
    pub right_margin: u32,
    pub upper_margin: u32,
    pub lower_margin: u32,
    pub hsync_len: u32,
    pub vsync_len: u32,
    pub sync: u32,
    pub vmode: u32,
    pub rotate: u32,
    pub colorspace: u32,
    pub reserved: [u32; 4],
}

impl Default for FbVarScreeninfo {
    fn default() -> Self {
        Self {
            xres: 0,
            yres: 0,
            xres_virtual: 0,
            yres_virtual: 0,
            xoffset: 0,
            yoffset: 0,
            bits_per_pixel: 32,
            grayscale: 0,
            red: FbBitfield { offset: 16, length: 8, msb_right: 0 },
            green: FbBitfield { offset: 8, length: 8, msb_right: 0 },
            blue: FbBitfield { offset: 0, length: 8, msb_right: 0 },
            transp: FbBitfield { offset: 24, length: 8, msb_right: 0 },
            nonstd: 0,
            activate: 0,
            height: 0,
            width: 0,
            accel_flags: 0,
            pixclock: 0,
            left_margin: 0,
            right_margin: 0,
            upper_margin: 0,
            lower_margin: 0,
            hsync_len: 0,
            vsync_len: 0,
            sync: 0,
            vmode: 0,
            rotate: 0,
            colorspace: 0,
            reserved: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FbFixScreeninfo {
    pub id: [u8; 16],
    pub smem_start: u64,
    pub smem_len: u32,
    pub ty: u32,
    pub type_aux: u32,
    pub visual: u32,
    pub xpanstep: u16,
    pub ypanstep: u16,
    pub ywrapstep: u16,
    pub line_length: u32,
    pub mmio_start: u64,
    pub mmio_len: u32,
    pub accel: u32,
    pub capabilities: u16,
    pub reserved: [u16; 2],
}

impl Default for FbFixScreeninfo {
    fn default() -> Self {
        Self {
            id: *b"oxide-fbdev    \0",
            smem_start: 0,
            smem_len: 0,
            ty: FB_TYPE_PACKED_PIXELS,
            type_aux: 0,
            visual: FB_VISUAL_TRUECOLOR,
            xpanstep: 0,
            ypanstep: 1,
            ywrapstep: 0,
            line_length: 0,
            mmio_start: 0,
            mmio_len: 0,
            accel: FB_ACCEL_NONE,
            capabilities: 0,
            reserved: [0; 2],
        }
    }
}

pub const FBIOGET_VSCREENINFO: u64 = 0x4600;
pub const FBIOPUT_VSCREENINFO: u64 = 0x4601;
pub const FBIOGET_FSCREENINFO: u64 = 0x4602;
pub const FBIOGETCMAP: u64 = 0x4604;
pub const FBIOPUTCMAP: u64 = 0x4605;
pub const FBIOPAN_DISPLAY: u64 = 0x4606;
pub const FBIOBLANK: u64 = 0x4611;
pub const FBIOGET_VBLANK: u64 = 0x80204612;
pub const FBIO_WAITFORVSYNC: u64 = 0x40044620;
pub const FB_TYPE_PACKED_PIXELS: u32 = 0;
pub const FB_TYPE_PLANES: u32 = 1;
pub const FB_TYPE_INTERLEAVED_PLANES: u32 = 2;
pub const FB_TYPE_TEXT: u32 = 3;
pub const FB_TYPE_VGA_PLANES: u32 = 4;
pub const FB_TYPE_FOURCC: u32 = 5;
pub const FB_VISUAL_MONO01: u32 = 0;
pub const FB_VISUAL_MONO10: u32 = 1;
pub const FB_VISUAL_TRUECOLOR: u32 = 2;
pub const FB_VISUAL_PSEUDOCOLOR: u32 = 3;
pub const FB_VISUAL_DIRECTCOLOR: u32 = 4;
pub const FB_VISUAL_STATIC_PSEUDOCOLOR: u32 = 5;
pub const FB_ACCEL_NONE: u32 = 0;
pub const FB_BLANK_UNBLANK: u32 = 0;
pub const FB_BLANK_NORMAL: u32 = 1;
pub const FB_BLANK_VSYNC_SUSPEND: u32 = 2;
pub const FB_BLANK_HSYNC_SUSPEND: u32 = 3;
pub const FB_BLANK_POWERDOWN: u32 = 4;
pub const FB_ACTIVATE_NOW: u32 = 0;
pub const FB_ACTIVATE_NXTOPEN: u32 = 1;
pub const FB_ACTIVATE_TEST: u32 = 2;
pub const FB_ACTIVATE_MASK: u32 = 0x0f;
pub const FB_ACTIVATE_VBL: u32 = 0x10;
pub const FB_CHANGE_CMAP_VBL: u32 = 0x20;
pub const FB_ACTIVATE_ALL: u32 = 0x40;
pub const FB_ACTIVATE_FORCE: u32 = 0x80;
pub const FB_ACTIVATE_INV_MODE: u32 = 0x100;
pub const FB_VBLANK_VBLANKING: u32 = 0x001;
pub const FB_VBLANK_HBLANKING: u32 = 0x002;
pub const FB_VBLANK_HAVE_VBLANK: u32 = 0x004;
pub const FB_VBLANK_HAVE_HBLANK: u32 = 0x008;
pub const FB_VBLANK_HAVE_COUNT: u32 = 0x010;
pub const FB_VBLANK_HAVE_VCOUNT: u32 = 0x020;
pub const FB_VBLANK_HAVE_HCOUNT: u32 = 0x040;
pub const FB_VBLANK_VSYNCING: u32 = 0x080;
pub const FB_VBLANK_HAVE_VSYNC: u32 = 0x100;
