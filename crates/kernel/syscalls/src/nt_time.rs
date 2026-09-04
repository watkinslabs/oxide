//! Native Windows `TIME_FIELDS` conversion over user memory.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
const STATUS_ALERTED: u64 = 0x0000_0101;
const STATUS_USER_APC: u64 = 0x0000_00c0;
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
const DYNAMIC_TIME_ZONE_INFORMATION_BYTES: usize = 429;
const TIME_ZONE_INFORMATION_BYTES: usize = 172;
const STATUS_PRIVILEGE_NOT_HELD: u64 = 0xc000_0061;

pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlSetTimeZoneInformation { return Some(STATUS_PRIVILEGE_NOT_HELD); }
    if call.service == NtService::RtlQueryTimeZoneInformation { return Some(query_time_zone_information(call.args.a0)); }
    if call.service == NtService::RtlQueryDynamicTimeZoneInformation { return Some(query_dynamic_time_zone_information(call.args.a0)); }
    if call.service == NtService::RtlLocalTimeToSystemTime { return Some(local_time_to_system_time(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlSystemTimeToLocalTime { return Some(system_time_to_local_time(call.args.a0, call.args.a1)); }
    if call.service == NtService::NtQueryDefaultLocale {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 > 1 || call.args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // The current NT personality is initialized from the en-US baseline;
        // the locale/NLS service can replace this once per-user LCID state is
        // owned by the environment layer.
        return Some(if uaccess::put_user_u32(call.args.a1, 0x0409).is_ok() { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER });
    }
    if call.service == NtService::NtQueryDefaultUILanguage {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let language = 0x0409u16.to_ne_bytes();
        return Some(if uaccess::copy_to_user(call.args.a0, &language).is_ok() { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER });
    }
    if call.service == NtService::NtQueryInstallUILanguage {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        return Some(if uaccess::copy_to_user(call.args.a0, &0x0409u16.to_ne_bytes()).is_ok() { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER });
    }
    if call.service == NtService::NtQueryPerformanceCounter {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        if uaccess::put_user_u64(call.args.a0, timekeeper::monotonic_ns() / 100).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        if call.args.a1 != 0 && uaccess::put_user_u64(call.args.a1, QPC_FREQUENCY).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_SUCCESS);
    }
    if call.service == NtService::NtGetTickCount {
        let Some(cur) = sched::live::current() else { return Some(0); };
        if !cur.is_nt_personality() { return Some(0); }
        return Some((timekeeper::monotonic_ns() / 1_000_000) as u32 as u64);
    }
    if call.service == NtService::NtDelayExecution {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 > 1 { return Some(STATUS_INVALID_PARAMETER); }
        let timeout = if call.args.a1 == 0 { None } else {
            match syscall::UserPtr::<i64>::new(call.args.a1) { Ok(pointer) => Some(pointer), Err(_) => return Some(STATUS_INVALID_PARAMETER) }
        };
        let table = cur.thread_group.nt_handles();
        let outcome = match crate::nt_dispatch::wait_deadline(timeout) {
            Ok(_) if call.args.a0 != 0 && cur.nt_apc_queue.request_delivery() => return Some(STATUS_USER_APC),
            Ok(0) if call.args.a0 != 0 => unsafe { sched::live::wait_event_interruptible_until_user_apc(table.waiters(), 0, || 0, || cur.nt_apc_queue.has_pending(), || false) },
            Ok(0) => unsafe { sched::live::wait_event_interruptible(table.waiters(), || false) }.into(),
            Ok(deadline) if call.args.a0 != 0 => unsafe { sched::live::wait_event_interruptible_until_user_apc(table.waiters(), deadline, timekeeper::monotonic_ns, || cur.nt_apc_queue.has_pending(), || false) },
            Ok(deadline) => unsafe { sched::live::wait_event_interruptible_until(table.waiters(), deadline, timekeeper::monotonic_ns, || false) }.into(),
            Err(status) => return Some(status),
        };
        return Some(match outcome {
            sched::NtWaitOutcome::Ready | sched::NtWaitOutcome::TimedOut => STATUS_SUCCESS,
            sched::NtWaitOutcome::UserApc => { cur.nt_apc_queue.request_delivery(); STATUS_USER_APC },
            sched::NtWaitOutcome::Interrupted => STATUS_ALERTED,
        });
    }
    if call.service == NtService::NtConvertBetweenAuxiliaryCounterAndPerformanceCounter {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(if call.args.a1 == 0 { STATUS_ACCESS_VIOLATION } else { STATUS_NOT_SUPPORTED });
    }
    if call.service == NtService::QuerySystemTime {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let value = NT_EPOCH_100NS.saturating_add(timekeeper::realtime_ns() / 100);
        if uaccess::put_user_u64(call.args.a0, value).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_SUCCESS);
    }
    if call.service == NtService::RtlGetSystemTimePrecise {
        let Some(cur) = sched::live::current() else { return Some(0); };
        if !cur.is_nt_personality() { return Some(0); }
        return Some(NT_EPOCH_100NS.saturating_add(timekeeper::realtime_ns() / 100));
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
    if call.service == NtService::RtlTimeToSecondsSince1970 { return Some(time_to_seconds_since_1970(call.args.a0, call.args.a1)); }
    if !matches!(call.service, NtService::RtlQueryPerformanceCounter | NtService::RtlQueryPerformanceFrequency) { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let value = if call.service == NtService::RtlQueryPerformanceCounter { timekeeper::monotonic_ns() / 100 } else { QPC_FREQUENCY };
    if uaccess::put_user_u64(call.args.a0, value).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}

fn query_dynamic_time_zone_information(output: u64) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || output == 0 { return STATUS_INVALID_PARAMETER; }
    let mut data = [0u8; DYNAMIC_TIME_ZONE_INFORMATION_BYTES];
    data[0..4].copy_from_slice(&crate::time_common::timezone_minuteswest().to_le_bytes());
    if uaccess::copy_to_user(output, &data).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn query_time_zone_information(output: u64) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || output == 0 { return STATUS_INVALID_PARAMETER; }
    // RTL_TIME_ZONE_INFORMATION is the 32-bit-bias form of the Windows
    // TIME_ZONE_INFORMATION structure: Bias, two 32-WCHAR names, two
    // SYSTEMTIME records, and the standard/daylight biases.
    let mut data = [0u8; TIME_ZONE_INFORMATION_BYTES];
    data[0..4].copy_from_slice(&crate::time_common::timezone_minuteswest().to_le_bytes());
    if uaccess::copy_to_user(output, &data).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn local_time_to_system_time(local: u64, system: u64) -> u64 {
    if local == 0 || system == 0 { return STATUS_INVALID_PARAMETER; }
    let Ok(value) = uaccess::get_user_u64(local) else { return STATUS_INVALID_PARAMETER; };
    let bias_ticks = (crate::time_common::timezone_minuteswest() as i64)
        .saturating_mul(60).saturating_mul(TICKS_PER_SECOND);
    let result = (value as i64).wrapping_add(bias_ticks) as u64;
    if uaccess::put_user_u64(system, result).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn system_time_to_local_time(system: u64, local: u64) -> u64 {
    if system == 0 || local == 0 { return STATUS_INVALID_PARAMETER; }
    let Ok(value) = uaccess::get_user_u64(system) else { return STATUS_INVALID_PARAMETER; };
    let bias_ticks = (crate::time_common::timezone_minuteswest() as i64)
        .saturating_mul(60).saturating_mul(TICKS_PER_SECOND);
    let result = (value as i64).wrapping_sub(bias_ticks) as u64;
    if uaccess::put_user_u64(local, result).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
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

fn time_to_seconds_since_1970(input: u64, output: u64) -> u64 {
    if input == 0 || output == 0 { return FALSE; }
    let Ok(ticks) = uaccess::get_user_u64(input) else { return FALSE; };
    let seconds = ticks / TICKS_PER_SECOND as u64;
    if seconds < NT_EPOCH_100NS / TICKS_PER_SECOND as u64 { return FALSE; }
    let unix = seconds - NT_EPOCH_100NS / TICKS_PER_SECOND as u64;
    if unix > u32::MAX as u64 || uaccess::put_user_u32(output, unix as u32).is_err() { FALSE } else { TRUE }
}
