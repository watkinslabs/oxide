use super::*;
use boot_info::{BootFramebufferBitfield as Field, BootFramebufferKind};
use std::time::Instant;

const WIDTH: u32 = 1024;
const HEIGHT: u32 = 768;
const ROUNDS: usize = 256;

struct RamScanout { pixels: Vec<u8> }

impl RamScanout {
    fn new() -> Self {
        let mut pixels = alloc::vec![0xa5; (WIDTH * HEIGHT * 4) as usize];
        let fb = BootFramebuffer { base_pa: pixels.as_mut_ptr() as u64,
            pitch: WIDTH * 4, width: WIDTH, height: HEIGHT, bpp: 32,
            kind: BootFramebufferKind::Rgb, red: Field { offset: 16, length: 8 },
            green: Field { offset: 8, length: 8 }, blue: Field { offset: 0, length: 8 }, _pad: [0; 2] };
        let aperture = fbdev::acquire_aperture(fb.base_pa, pixels.len() as u64, |_| {}).unwrap();
        let mut live = LIVE.lock();
        assert!(live.is_none());
        // SAFETY: Mapping contains only two u64 fields; all-zero is its inert
        // state, whose Drop returns without MMU access. The Vec owns this RAM.
        let mapping = unsafe { core::mem::zeroed::<mmio_map::Mapping>() };
        *live = Some(Live { fb, idx: fbdev::INVALID_FB_INDEX, mapping,
            fb_va: pixels.as_mut_ptr() as u64, bytes: pixels.len() as u64,
            aperture, drm_card: u32::MAX });
        Self { pixels }
    }
}

impl Drop for RamScanout {
    fn drop(&mut self) {
        let live = LIVE.lock().take().unwrap();
        assert!(fbdev::release_aperture(live.aperture));
        drop(live);
    }
}

#[test]
#[ignore = "bounded RAM scanout benchmark; does not measure WC device memory"]
fn render_perf_present_xrgb_and_copy_damage() {
    let mut scanout = RamScanout::new();
    let src = alloc::vec![0x3c; (WIDTH * HEIGHT * 4) as usize];
    for (label, x, y, w, h) in [("full", 0, 0, WIDTH, HEIGHT),
        ("tile64", 128, 128, 64, 64), ("pixel", 128, 128, 1, 1)] {
        for direct in [false, true] {
            scanout.pixels.fill(0xa5);
            let fb = LIVE.lock().as_ref().unwrap().fb;
            let start = Instant::now();
            for _ in 0..ROUNDS {
                if direct {
                    format::copy_damage(core::hint::black_box(&src),
                        core::hint::black_box(&mut scanout.pixels),
                        fbcon::kernel::FlushRect { x, y, w, h, stride_px: WIDTH }, fb);
                } else {
                    assert!(present_xrgb(core::hint::black_box(&src), WIDTH, WIDTH, HEIGHT, x, y, w, h));
                }
            }
            let elapsed = start.elapsed();
            for row in 0..HEIGHT {
                for col in 0..WIDTH {
                    let expected = if row >= y && row < y + h && col >= x && col < x + w { 0x3c } else { 0xa5 };
                    let off = ((row * WIDTH + col) * 4) as usize;
                    assert_eq!(&scanout.pixels[off..off + 4], &[expected; 4]);
                }
            }
            std::println!("RENDER_PERF display={} path={} rounds={} ns/op={} copied_bytes={} backing=normal-RAM-not-WC",
                label, if direct { "copy_damage" } else { "present_xrgb" }, ROUNDS,
                elapsed.as_nanos() / ROUNDS as u128, u64::from(w) * u64::from(h) * 4 * ROUNDS as u64);
        }
    }
}
