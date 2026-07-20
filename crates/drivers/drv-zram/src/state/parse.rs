use block::{BlockError, KResult};

pub(super) fn parse_mem_size(text: &str) -> KResult<u64> {
    let text = text.trim();
    let split = text.find(|byte: char| !byte.is_ascii_digit()).unwrap_or(text.len());
    let number = text[..split].parse::<u64>().map_err(|_| BlockError::Einval)?;
    let suffix = text[split..].trim_end_matches(['b', 'B']);
    let shift = match suffix {
        "" => 0,
        "K" | "k" => 10,
        "M" | "m" => 20,
        "G" | "g" => 30,
        "T" | "t" => 40,
        "P" | "p" => 50,
        "E" | "e" => 60,
        _ => return Err(BlockError::Einval),
    };
    number.checked_shl(shift).ok_or(BlockError::Einval)
}

/// Linux `kstrtobool` spellings accepted by zram boolean sysfs attributes.
pub(super) fn parse_linux_bool(text: &str) -> KResult<bool> {
    match text.trim() {
        "1" | "y" | "Y" | "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => Ok(true),
        "0" | "n" | "N" | "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => Ok(false),
        _ => Err(BlockError::Einval),
    }
}
