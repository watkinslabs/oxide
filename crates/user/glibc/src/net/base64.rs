#![cfg(feature = "freestanding")]
use core::ffi::c_char;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn b64_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

// # C: int __b64_ntop(const unsigned char *src, size_t srclength,
//                     char *target, size_t targsize)
#[no_mangle]
pub unsafe extern "C" fn __b64_ntop(src: *const u8, srclength: usize, target: *mut c_char, targsize: usize) -> i32 {
    let out_len = srclength.div_ceil(3) * 4;
    if targsize <= out_len {
        return -1;
    }

    // SAFETY: src points at srclength readable bytes and target points at
    // targsize writable bytes. The size check above reserves room for NUL.
    unsafe {
        let mut si = 0usize;
        let mut di = 0usize;
        while si + 3 <= srclength {
            let b0 = *src.add(si);
            let b1 = *src.add(si + 1);
            let b2 = *src.add(si + 2);
            *target.add(di) = B64[(b0 >> 2) as usize] as c_char;
            *target.add(di + 1) = B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as c_char;
            *target.add(di + 2) = B64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as c_char;
            *target.add(di + 3) = B64[(b2 & 0x3f) as usize] as c_char;
            si += 3;
            di += 4;
        }

        match srclength - si {
            1 => {
                let b0 = *src.add(si);
                *target.add(di) = B64[(b0 >> 2) as usize] as c_char;
                *target.add(di + 1) = B64[((b0 & 0x03) << 4) as usize] as c_char;
                *target.add(di + 2) = b'=' as c_char;
                *target.add(di + 3) = b'=' as c_char;
            }
            2 => {
                let b0 = *src.add(si);
                let b1 = *src.add(si + 1);
                *target.add(di) = B64[(b0 >> 2) as usize] as c_char;
                *target.add(di + 1) = B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as c_char;
                *target.add(di + 2) = B64[((b1 & 0x0f) << 2) as usize] as c_char;
                *target.add(di + 3) = b'=' as c_char;
            }
            _ => {}
        }
        *target.add(out_len) = 0;
    }
    out_len as i32
}

fn b64_put(target: *mut u8, targsize: usize, out: &mut usize, byte: u8) -> bool {
    if *out >= targsize {
        return false;
    }
    // SAFETY: the bounds check above ensures target[*out] is writable.
    unsafe {
        *target.add(*out) = byte;
    }
    *out += 1;
    true
}

// # C: int __b64_pton(char const *src, unsigned char *target, size_t targsize)
#[no_mangle]
pub unsafe extern "C" fn __b64_pton(src: *const c_char, target: *mut u8, targsize: usize) -> i32 {
    let mut quad = [0u8; 4];
    let mut qn = 0usize;
    let mut out = 0usize;
    let mut done = false;
    let mut i = 0usize;

    loop {
        // SAFETY: src is a NUL-terminated base64 presentation string.
        let c = unsafe { *(src as *const u8).add(i) };
        i += 1;
        if c == 0 {
            break;
        }
        if b64_space(c) {
            continue;
        }
        if done {
            return -1;
        }

        quad[qn] = if c == b'=' {
            64
        } else if let Some(v) = b64_value(c) {
            v
        } else {
            return -1;
        };
        qn += 1;

        if qn != 4 {
            continue;
        }
        if quad[0] == 64 || quad[1] == 64 {
            return -1;
        }
        if quad[2] == 64 {
            if quad[3] != 64 {
                return -1;
            }
            if !b64_put(target, targsize, &mut out, (quad[0] << 2) | (quad[1] >> 4)) {
                return -1;
            }
            done = true;
        } else if quad[3] == 64 {
            if !b64_put(target, targsize, &mut out, (quad[0] << 2) | (quad[1] >> 4)) {
                return -1;
            }
            if !b64_put(target, targsize, &mut out, (quad[1] << 4) | (quad[2] >> 2)) {
                return -1;
            }
            done = true;
        } else {
            if !b64_put(target, targsize, &mut out, (quad[0] << 2) | (quad[1] >> 4)) {
                return -1;
            }
            if !b64_put(target, targsize, &mut out, (quad[1] << 4) | (quad[2] >> 2)) {
                return -1;
            }
            if !b64_put(target, targsize, &mut out, (quad[2] << 6) | quad[3]) {
                return -1;
            }
        }
        qn = 0;
    }

    if qn == 0 {
        out as i32
    } else {
        -1
    }
}
