use syscall::errno::Errno;

use super::{uapi, user};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct LegacyLog {
    pub buffer: u64,
    pub size: u32,
    pub level: u32,
    pub true_size_ptr: Option<u64>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct Log {
    buffer: u64,
    size: u32,
    level: u32,
    true_size_ptr: Option<u64>,
}

impl Log {
    pub(super) fn select(
        legacy: LegacyLog,
        common: Option<user::CommonAttr>,
    ) -> Result<Self, Errno> {
        validate_tuple(legacy.buffer, legacy.size, legacy.level)?;
        if let Some(common) = common {
            validate_tuple(common.log_buf, common.log_size, common.log_level)?;
            let legacy_present = legacy.buffer != 0 || legacy.size != 0 || legacy.level != 0;
            if legacy_present
                && (legacy.buffer != common.log_buf
                    || legacy.size != common.log_size
                    || legacy.level != common.log_level) {
                return Err(Errno::Einval);
            }
            if !legacy_present {
                return Ok(Self {
                    buffer: common.log_buf,
                    size: common.log_size,
                    level: common.log_level,
                    true_size_ptr: common.true_size_ptr,
                });
            }
        }
        Ok(Self {
            buffer: legacy.buffer,
            size: legacy.size,
            level: legacy.level,
            true_size_ptr: legacy.true_size_ptr,
        })
    }

    /// Finalize the verifier log before an object becomes observable.
    /// # C: O(message bytes)
    pub(super) fn finish<T>(&self, result: Result<T, Errno>) -> Result<T, Errno> {
        const FAILURE: &[u8] = b"BTF validation failed\n\0";
        const SUCCESS: &[u8] = b"\0";
        let text = if result.is_ok() { SUCCESS } else { FAILURE };
        let true_size = text.len() as u32;
        let mut final_error = None;
        if self.buffer != 0 {
            let capacity = self.size as usize;
            let source = if capacity >= text.len() {
                text
            } else if self.level & uapi::log_flags::FIXED != 0 {
                &text[..capacity]
            } else {
                &text[text.len() - capacity..]
            };
            if let Err(error) = user::write_bytes(self.buffer, source) {
                final_error = Some(error);
            } else if capacity < text.len() {
                final_error = Some(Errno::Enospc);
            }
        }
        if let Some(ptr) = self.true_size_ptr {
            if let Err(error) = user::write_bytes(ptr, &true_size.to_ne_bytes()) {
                final_error = Some(error);
            }
        }
        if let Some(error) = final_error { return Err(error); }
        result
    }
}

pub(super) fn validate_tuple(buffer: u64, size: u32, level: u32) -> Result<(), Errno> {
    if (buffer != 0) != (size != 0)
        || buffer != 0 && level == 0
        || level & !uapi::log_flags::MASK != 0
        || size > uapi::log_flags::MAX_SIZE {
        return Err(Errno::Einval);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_and_legacy_must_describe_one_log() {
        let legacy = LegacyLog {
            buffer: 1, size: 8, level: uapi::log_flags::LEVEL1, true_size_ptr: None,
        };
        let common = user::CommonAttr {
            log_buf: 2, log_size: 8, log_level: uapi::log_flags::LEVEL1,
            true_size_ptr: None,
        };
        assert_eq!(Log::select(legacy, Some(common)), Err(Errno::Einval));
    }

    #[test]
    fn count_only_log_is_valid() {
        let legacy = LegacyLog {
            buffer: 0, size: 0, level: uapi::log_flags::LEVEL1, true_size_ptr: None,
        };
        assert!(Log::select(legacy, None).is_ok());
    }

    #[test]
    fn finalization_sets_true_size_and_reports_truncation() {
        let mut buffer = [0u8; 4];
        let mut true_size = 0u32;
        let log = Log::select(LegacyLog {
            buffer: buffer.as_mut_ptr() as u64,
            size: buffer.len() as u32,
            level: uapi::log_flags::LEVEL1 | uapi::log_flags::FIXED,
            true_size_ptr: Some(&mut true_size as *mut u32 as u64),
        }, None).unwrap();
        assert_eq!(log.finish::<()>(Err(Errno::Einval)), Err(Errno::Enospc));
        assert_eq!(buffer, *b"BTF ");
        assert_eq!(true_size, b"BTF validation failed\n\0".len() as u32);
    }
}
