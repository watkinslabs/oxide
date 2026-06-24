// C23 narrowing arithmetic (docs/59 §9.1): operations are evaluated in the
// wider argument type and rounded to float/_Float32 for the result.
#![cfg(feature = "freestanding")]

use super::{fma::fma, sqrt::sqrt};

fn add(x: f64, y: f64) -> f32 { (x + y) as f32 }
fn sub(x: f64, y: f64) -> f32 { (x - y) as f32 }
fn mul(x: f64, y: f64) -> f32 { (x * y) as f32 }
fn div(x: f64, y: f64) -> f32 { (x / y) as f32 }
fn msqrt(x: f64) -> f32 { sqrt(x) as f32 }
fn mfma(x: f64, y: f64, z: f64) -> f32 { fma(x, y, z) as f32 }

macro_rules! exp2 {
    ($name:ident, $alias:ident, $imp:ident) => {
        #[no_mangle]
        pub extern "C" fn $name(x: f64, y: f64) -> f32 { $imp(x, y) }
        #[no_mangle]
        pub extern "C" fn $alias(x: f64, y: f64) -> f32 { $imp(x, y) }
    };
}

macro_rules! exp1 {
    ($name:ident, $alias:ident, $imp:ident) => {
        #[no_mangle]
        pub extern "C" fn $name(x: f64) -> f32 { $imp(x) }
        #[no_mangle]
        pub extern "C" fn $alias(x: f64) -> f32 { $imp(x) }
    };
}

macro_rules! exp3 {
    ($name:ident, $alias:ident, $imp:ident) => {
        #[no_mangle]
        pub extern "C" fn $name(x: f64, y: f64, z: f64) -> f32 { $imp(x, y, z) }
        #[no_mangle]
        pub extern "C" fn $alias(x: f64, y: f64, z: f64) -> f32 { $imp(x, y, z) }
    };
}

exp2!(fadd, f32addf64, add);
exp2!(fsub, f32subf64, sub);
exp2!(fmul, f32mulf64, mul);
exp2!(fdiv, f32divf64, div);
exp1!(fsqrt, f32sqrtf64, msqrt);
exp3!(ffma, f32fmaf64, mfma);
