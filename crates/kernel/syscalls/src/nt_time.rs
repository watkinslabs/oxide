//! Native Windows `TIME_FIELDS` conversion over user memory.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const QPC_FREQUENCY: u64 = 10_000_000;
const NT_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const FALSE: u64 = 0;
const TRUE: u64 = 1;
const TICKS_PER_MILLISECOND: i64 = 10_000;
const TICKS_PER_SECOND: i64 = 10_000_000;
const MILLISECONDS_PER_SECOND: i64 = 1_000;
const SECONDS_PER_MINUTE: i64 = 60;
const MINUTES_PER_HOUR: i64 = 60;
const HOURS_PER_DAY: i64 = 24;
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;
const DAYS_PER_QUADRICENTENNIUM: i64 = 146_097;
const DAYS_PER_NORMAL_QUADRENNIUM: i64 = 1_461;
const YEAR_DAY_OFFSET: i64 = 1_227;
const YEAR_BASE_OFFSET: i64 = 28_188;
const YEAR_FORMULA_OFFSET: i64 = 2_442;
const MONTH_FORMULA_SCALE: i64 = 1_959;
const PERMANENT_EPOCH_DAY: i64 = 584_817;

pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::QuerySystemTime {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let value = NT_EPOCH_100NS.saturating_add(timekeeper::realtime_ns() / 100);
        if uaccess::put_user_u64(call.args.a0, value).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_SUCCESS);
    }
    if call.service == NtService::DbgUiGetThreadDebugObject {
        let Some(cur) = sched::live::current() else { return Some(0); };
        if !cur.is_nt_personality() { return Some(0); }
        return Some(0);
    }
    if call.service == NtService::DbgUiIssueRemoteBreakin {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlQueryUnbiasedInterruptTime {
        let Some(cur) = sched::live::current() else { return Some(0); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(0); }
        if uaccess::put_user_u64(call.args.a0, timekeeper::monotonic_ns() / 100).is_err() { return Some(0); }
        return Some(1);
    }
    if call.service == NtService::RtlTimeFieldsToTime { return Some(time_fields_to_time(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlTimeToTimeFields { return Some(time_to_time_fields(call.args.a0, call.args.a1)); }
    if !matches!(call.service, NtService::RtlQueryPerformanceCounter | NtService::RtlQueryPerformanceFrequency) { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let value = if call.service == NtService::RtlQueryPerformanceCounter { timekeeper::monotonic_ns() / 100 } else { QPC_FREQUENCY };
    if uaccess::put_user_u64(call.args.a0, value).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}

fn read_i16(address: u64, offset: u64) -> Option<i16> {
    let mut bytes = [0u8; 2];
    uaccess::copy_from_user(&mut bytes, address.checked_add(offset)?).ok()?;
    Some(i16::from_ne_bytes(bytes))
}

fn leap(year: i16) -> bool { year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) }

fn time_fields_to_time(fields: u64, output: u64) -> u64 {
    if fields == 0 || output == 0 { return FALSE; }
    let values = [read_i16(fields, 0), read_i16(fields, 2), read_i16(fields, 4), read_i16(fields, 6), read_i16(fields, 8), read_i16(fields, 10), read_i16(fields, 12)];
    let [Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second), Some(milliseconds)] = values else { return FALSE; };
    let month_days = [31i16, if leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if year < 1601 || month < 1 || month > 12 || day < 1 || day > month_days[(month - 1) as usize] || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59 || milliseconds < 0 || milliseconds > 999 { return FALSE; }
    let (month_number, adjusted_year) = if month < 3 { (month as i64 + 13, year as i64 - 1) } else { (month as i64 + 1, year as i64) };
    let century_leaps = (3 * (adjusted_year / 100) + 3) / 4;
    let days = (36525 * adjusted_year) / 100 - century_leaps + (1959 * month_number) / 64 + day as i64 - PERMANENT_EPOCH_DAY;
    let ticks = ((((days * HOURS_PER_DAY + hour as i64) * MINUTES_PER_HOUR + minute as i64) * SECONDS_PER_MINUTE + second as i64) * MILLISECONDS_PER_SECOND + milliseconds as i64) * TICKS_PER_MILLISECOND;
    if uaccess::put_user_u64(output, ticks as u64).is_err() { FALSE } else { TRUE }
}

fn time_to_time_fields(input: u64, fields: u64) -> u64 {
    if input == 0 || fields == 0 { return FALSE; }
    let Ok(ticks) = uaccess::get_user_u64(input) else { return FALSE; };
    let ticks = ticks as i64;
    let milliseconds = (ticks % TICKS_PER_SECOND) / TICKS_PER_MILLISECOND;
    let time = ticks / TICKS_PER_SECOND;
    let days = time / SECONDS_PER_DAY;
    let mut seconds = time % SECONDS_PER_DAY;
    let hour = seconds / SECONDS_PER_HOUR; seconds %= SECONDS_PER_HOUR;
    let minute = seconds / 60; let second = seconds % 60;
    let mut adjusted_days = days;
    let century_leaps = (3 * ((4 * adjusted_days + YEAR_DAY_OFFSET) / DAYS_PER_QUADRICENTENNIUM) + 3) / 4;
    adjusted_days += YEAR_BASE_OFFSET + century_leaps;
    let years = (20 * adjusted_days - YEAR_FORMULA_OFFSET) / DAYS_PER_NORMAL_QUADRENNIUM;
    let year_day = adjusted_days - (years * DAYS_PER_NORMAL_QUADRENNIUM) / 4;
    let month_number = (64 * year_day) / MONTH_FORMULA_SCALE;
    let (month, year) = if month_number < 14 { (month_number - 1, years + 1_524) } else { (month_number - 13, years + 1_525) };
    let day = year_day - (MONTH_FORMULA_SCALE * month_number) / 64;
    let weekday = (1 + days) % 7;
    let values = [year, month, day, hour, minute, second, milliseconds, weekday];
    let mut output = [0u8; 16];
    for (index, value) in values.into_iter().enumerate() { let Ok(value) = i16::try_from(value) else { return FALSE; }; output[index * 2..index * 2 + 2].copy_from_slice(&value.to_ne_bytes()); }
    if uaccess::copy_to_user(fields, &output).is_err() { FALSE } else { TRUE }
}
