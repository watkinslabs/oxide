// Test manifest (`08§7`). Every child module lives in a file with NO target
// gate, so `cargo test -p security` really compiles and runs them — a
// `#[cfg(test)]` block inside a `#[cfg(target_os = "oxide-kernel")]` file is
// silently dropped and reported as "ok".

mod action;
mod flags;
mod install;
mod interp;
mod verifier;
