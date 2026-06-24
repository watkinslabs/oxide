//! math — libm (docs/59§3, §6 G15). basic = sign/rounding/classify/fmod/
//! frexp/ldexp/modf; transcendentals + trig follow.
pub mod atrig;
pub mod basic;
#[cfg(feature = "freestanding")] pub mod float_n;
#[cfg(feature = "freestanding")] pub mod minmax_c23;
#[cfg(feature = "freestanding")] pub mod narrow;
#[cfg(feature = "freestanding")] pub mod cpi;
#[cfg(feature = "freestanding")] pub mod complex;
pub mod exp;
pub mod extra;
pub mod extras;
pub mod fma;
#[cfg(feature = "freestanding")] pub mod legacy;
pub mod round;
pub mod special;
pub mod hyper;
pub mod log;
pub mod pow;
pub mod sqrt;
pub mod trig;
