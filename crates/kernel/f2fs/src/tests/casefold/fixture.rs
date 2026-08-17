// The encodings every case folds through. A volume differs from another only
// in its flags word, so the fixtures are named for the flags.

use crate::casefold::{Casefold, ENC_NO_COMPAT_FALLBACK_FL, ENC_STRICT_MODE_FL, F2FS_ENC_UTF8_12_1};

/// A volume that tolerates a name its encoding cannot represent.
pub fn lenient() -> Casefold { Casefold::load(F2FS_ENC_UTF8_12_1, 0).unwrap() }

/// A volume that has declared such names cannot exist on it.
pub fn strict() -> Casefold {
    Casefold::load(F2FS_ENC_UTF8_12_1, ENC_STRICT_MODE_FL).unwrap()
}

/// A volume asserting no entry predates the current encoding.
pub fn no_fallback() -> Casefold {
    Casefold::load(F2FS_ENC_UTF8_12_1, ENC_NO_COMPAT_FALLBACK_FL).unwrap()
}
