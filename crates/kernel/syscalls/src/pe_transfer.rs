//! Where a prepared PE process starts executing.
//!
//! A PE image is entered either directly or through the native bootstrap that
//! the launcher staged. The bootstrap owns the process dynamic loader, so when
//! one is staged it starts first no matter which loader prepared the image;
//! the runtime entry travels to it in the environment instead.

/// The register state a prepared PE process resumes with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeTransfer { pub entry: u64, pub stack: u64, pub argument: u64 }

/// Resolve the transfer for a prepared image. `bootstrap` is the entry and
/// stack of the staged native bootstrap when the launcher supplied one.
/// # C: O(1)
pub fn transfer(runtime: PeTransfer, bootstrap: Option<(u64, u64)>) -> PeTransfer {
    match bootstrap {
        Some((entry, stack)) => PeTransfer { entry, stack, argument: runtime.argument },
        None => runtime,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNTIME: PeTransfer = PeTransfer { entry: 0x1_7008_0e10, stack: 0x7fff_7f66_2fd8, argument: 0x1_7000_1000 };

    #[test]
    fn a_staged_bootstrap_owns_the_first_instruction() {
        let resolved = transfer(RUNTIME, Some((0x40_1000, 0x7ffe_0000)));
        assert_eq!(resolved.entry, 0x40_1000);
        assert_eq!(resolved.stack, 0x7ffe_0000);
    }

    #[test]
    fn the_runtime_startup_argument_survives_the_bootstrap() {
        assert_eq!(transfer(RUNTIME, Some((0x40_1000, 0x7ffe_0000))).argument, RUNTIME.argument);
    }

    #[test]
    fn without_a_bootstrap_the_image_is_entered_directly() {
        assert_eq!(transfer(RUNTIME, None), RUNTIME);
    }
}
