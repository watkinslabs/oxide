use super::*;

pub(super) fn dev_create(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let name = fixed_cstr(bytes, NAME, uapi::DM_NAME_LEN)?;
    if name.is_empty() { return Err(Errno::Einval); }
    let uuid = fixed_cstr(bytes, UUID, uapi::DM_UUID_LEN)?;
    let minor = if header.flags & uapi::DM_PERSISTENT_DEV_FLAG != 0 {
        let kdev = vfs::new_decode_dev(header.dev as u32);
        if vfs::kdev_major(kdev) != crate::device::DM_MAJOR { return Err(Errno::Einval); }
        Some(vfs::kdev_minor(kdev))
    } else { None };
    let dev = registry::create(name, (!uuid.is_empty()).then_some(uuid), minor)?;
    fill_status(bytes, &dev);
    Ok(())
}

pub(super) fn dev_rename(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let new_value = variable_cstr(bytes, header.data_start, header.data_size)?.to_string();
    if new_value.is_empty() { return Err(Errno::Einval); }
    let dev = device_of(header, bytes)?;
    registry::rename(&dev, &new_value, header.flags & uapi::DM_UUID_FLAG != 0)?;
    fill_status(bytes, &dev);
    Ok(())
}

pub(super) fn dev_suspend(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let lockfs = header.flags & uapi::DM_SKIP_LOCKFS_FLAG == 0;
    let noflush = header.flags & uapi::DM_NOFLUSH_FLAG != 0;
    let dev = device_of(header, bytes)?;
    if header.flags & uapi::DM_SUSPEND_FLAG != 0 { dev.suspend(lockfs, noflush)?; }
    else { dev.resume(lockfs, noflush)?; }
    fill_status(bytes, &dev);
    Ok(())
}

pub(super) fn dev_wait(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let dev = device_of(header, bytes)?;
    if dev.event_nr() == header.event_nr {
        #[cfg(target_os = "oxide-kernel")]
        {
            // SAFETY: this is process context, the device predicate is read
            // without holding the device lock across schedule, and
            // bump_event publishes the counter before waking this list.
            unsafe {
                let _ = sched::live::wait_event_uninterruptible(
                    dev.event_waiters(), || dev.event_nr() != header.event_nr,
                );
            }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(Errno::Eagain);
    }
    fill_status(bytes, &dev);
    Ok(())
}

pub(super) fn table_load(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    if header.target_count == 0 || header.target_count > uapi::DM_MAX_TARGETS { return Err(Errno::Einval); }
    if header.data_start < DATA || header.data_start >= header.data_size { return Err(Errno::Einval); }
    let mut cursor = header.data_start;
    let resolver = BlockResolver;
    let mut builder = TableBuilder::new(header.flags & uapi::DM_READONLY_FLAG == 0);
    for number in 0..header.target_count {
        let spec_end = cursor.checked_add(TARGET_SPEC).ok_or(Errno::Einval)?;
        if spec_end > header.data_size { return Err(Errno::Einval); }
        let begin = read_u64(bytes, cursor + TARGET_SECTOR)?;
        let len = read_u64(bytes, cursor + TARGET_LENGTH)?;
        let next = usize::try_from(read_u32(bytes, cursor + TARGET_NEXT)?).map_err(|_| Errno::Einval)?;
        let type_name = fixed_cstr(bytes, cursor + TARGET_TYPE, uapi::DM_MAX_TYPE_NAME)?;
        let params = variable_cstr(bytes, spec_end, header.data_size)?;
        let target = types::get(type_name).ok_or(Errno::Einval)?;
        builder.add_target(&target, begin, len, params, &resolver)?;
        if number + 1 != header.target_count {
            if next < TARGET_SPEC || next & 7 != 0 { return Err(Errno::Einval); }
            cursor = cursor.checked_add(next).ok_or(Errno::Einval)?;
            if cursor >= header.data_size { return Err(Errno::Einval); }
        }
    }
    let dev = device_of(header, bytes)?;
    dev.load_table(alloc::sync::Arc::new(builder.complete()));
    fill_status(bytes, &dev);
    Ok(())
}

pub(super) fn table_deps(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let dev = device_of(header, bytes)?;
    let inactive = header.flags & uapi::DM_QUERY_INACTIVE_TABLE_FLAG != 0;
    let table = if inactive { dev.inactive_table() } else { dev.live_table() }.ok_or(Errno::Einval)?;
    let deps = table.devices();
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::try_from(deps.len()).map_err(|_| Errno::Einval)?);
    push_u32(&mut payload, 0);
    for dep in deps { push_u64(&mut payload, dep.devt()); }
    fill_status(bytes, &dev);
    write_payload(bytes, &payload)
}

pub(super) fn table_status(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let dev = device_of(header, bytes)?;
    let inactive = header.flags & uapi::DM_QUERY_INACTIVE_TABLE_FLAG != 0;
    let kind = if header.flags & uapi::DM_STATUS_TABLE_FLAG != 0 { StatusType::Table } else { StatusType::Info };
    let table = if inactive { dev.inactive_table() } else { dev.live_table() }.ok_or(Errno::Einval)?;
    let count = table.num_targets();
    let mut payload = Vec::new();
    for entry in table.targets() {
            let at = payload.len();
            payload.resize(at + TARGET_SPEC, 0);
            put_u64(&mut payload, at + TARGET_SECTOR, entry.begin)?;
            put_u64(&mut payload, at + TARGET_LENGTH, entry.len)?;
            write_fixed(&mut payload, at + TARGET_TYPE, uapi::DM_MAX_TYPE_NAME, entry.type_name)?;
            let body = entry.target.status(kind);
            payload.extend_from_slice(body.as_bytes());
            payload.push(0);
            let next = uapi::align8(payload.len() - at);
            payload.resize(at + next, 0);
            put_u32(&mut payload, at + TARGET_NEXT, u32::try_from(next).map_err(|_| Errno::Einval)?)?;
    }
    fill_status(bytes, &dev);
    write_payload(bytes, &payload)?;
    put_u32(bytes, TARGET_COUNT, u32::try_from(count).map_err(|_| Errno::Einval)?)
}

pub(super) fn target_msg(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    if header.data_start.checked_add(8).ok_or(Errno::Einval)? > header.data_size { return Err(Errno::Einval); }
    let sector = read_u64(bytes, header.data_start)?;
    let message = variable_cstr(bytes, header.data_start + 8, header.data_size)?;
    let args = crate::args::split_args(message);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let dev = device_of(header, bytes)?;
    let table = if header.flags & uapi::DM_QUERY_INACTIVE_TABLE_FLAG != 0 { dev.inactive_table() } else { dev.live_table() }
        .ok_or(Errno::Einval)?;
    let target = table.find_target(sector).ok_or(Errno::Einval)?;
    let reply = target.target.message(&argv)?;
    fill_status(bytes, &dev);
    if let Some(reply) = reply {
        let mut payload = reply.into_bytes();
        payload.push(0);
        write_payload(bytes, &payload)?;
        let flags = read_u32(bytes, FLAGS)? | uapi::DM_DATA_OUT_FLAG;
        put_u32(bytes, FLAGS, flags)?;
    }
    Ok(())
}

pub(super) fn set_geometry(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let data = variable_cstr(bytes, header.data_start, header.data_size)?;
    let fields: Vec<&str> = data.split_whitespace().collect();
    if fields.len() != 4 { return Err(Errno::Einval); }
    let cylinders = fields[0].parse::<u16>().map_err(|_| Errno::Einval)?;
    let heads = fields[1].parse::<u8>().map_err(|_| Errno::Einval)?;
    let sectors = fields[2].parse::<u8>().map_err(|_| Errno::Einval)?;
    let start = fields[3].parse::<u64>().map_err(|_| Errno::Einval)?;
    let dev = device_of(header, bytes)?;
    dev.set_geometry(Geometry { cylinders, heads, sectors, start })?;
    fill_status(bytes, &dev);
    clear_output(bytes)
}

pub(super) fn list_devices(bytes: &mut [u8]) -> DmResult<()> {
    let mut payload = Vec::new();
    let mut last = None;
    for dev in registry::list() {
        let at = payload.len();
        if let Some(previous) = last { put_u32(&mut payload, previous + 8, u32::try_from(at - previous).map_err(|_| Errno::Einval)?)?; }
        payload.resize(at + 12, 0);
        put_u64(&mut payload, at, registry::devt_of(&dev))?;
        let name = dev.name();
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        let tail = uapi::align8(payload.len() - at);
        payload.resize(at + tail, 0);
        last = Some(at);
    }
    write_payload(bytes, &payload)
}

pub(super) fn list_versions(bytes: &mut [u8], only: Option<&str>) -> DmResult<()> {
    let mut payload = Vec::new();
    let mut last = None;
    for target in types::list().into_iter().filter(|t| only.is_none_or(|name| name == t.name)) {
        let at = payload.len();
        if let Some(previous) = last { put_u32(&mut payload, previous, u32::try_from(at - previous).map_err(|_| Errno::Einval)?)?; }
        payload.resize(at + 16, 0);
        put_u32(&mut payload, at + 4, target.version[0])?;
        put_u32(&mut payload, at + 8, target.version[1])?;
        put_u32(&mut payload, at + 12, target.version[2])?;
        payload.extend_from_slice(target.name.as_bytes());
        payload.push(0);
        let next = uapi::align8(payload.len() - at);
        payload.resize(at + next, 0);
        last = Some(at);
    }
    write_payload(bytes, &payload)
}
