extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::font::parser::{build_font, parse_psf2, serialize, Font, GlyphData};

static DEFAULT_PSF: &[u8] = include_bytes!("../default8x16.psfu");
static ACTIVE: AtomicPtr<Font> = AtomicPtr::new(core::ptr::null_mut());

pub fn active() -> &'static Font {
    let p = ACTIVE.load(Ordering::Acquire);
    if !p.is_null() {
        return unsafe { &*p };
    }
    let font = parse_psf2(DEFAULT_PSF).expect("built-in default8x16.psfu must parse");
    let raw = Box::into_raw(Box::new(font));
    match ACTIVE.compare_exchange(core::ptr::null_mut(), raw, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => unsafe { &*raw },
        Err(winner) => {
            drop(unsafe { Box::from_raw(raw) });
            unsafe { &*winner }
        }
    }
}

pub(crate) fn install(font: Font) {
    let _ = active();
    let raw = Box::into_raw(Box::new(font));
    ACTIVE.store(raw, Ordering::Release);
}

pub fn set_font(width: u32, height: u32, count: u32, stride: usize, data: &[u8]) -> Result<(), ()> {
    let cur = active();
    let font = build_font(width, height, count, stride, data, cur.uni.clone(), cur.fallback)?;
    install(font);
    Ok(())
}

pub fn get_font(stride: usize) -> (u32, u32, u32, Vec<u8>) {
    serialize(active(), stride)
}

pub fn set_default() {
    if let Some(f) = parse_psf2(DEFAULT_PSF) {
        install(f);
    }
}

pub fn set_unimap(pairs: &[(u32, u16)]) {
    let cur = active();
    let mut uni: Vec<(u32, u16)> = pairs.to_vec();
    uni.sort_by_key(|&(c, _)| c);
    uni.dedup_by_key(|&mut (c, _)| c);
    let fallback = match uni.binary_search_by_key(&0x3f, |&(c, _)| c) {
        Ok(i) => uni[i].1,
        Err(_) => 0,
    };
    let glyphs = match &cur.glyphs {
        GlyphData::Static(s) => GlyphData::Static(s),
        GlyphData::Owned(v) => GlyphData::Owned(v.clone()),
    };
    install(Font {
        width: cur.width,
        height: cur.height,
        charsize: cur.charsize,
        row_bytes: cur.row_bytes,
        count: cur.count,
        glyphs,
        uni,
        fallback,
    });
}

pub fn clear_unimap() { set_unimap(&[]); }
pub fn unimap() -> Vec<(u32, u16)> { active().uni.clone() }
