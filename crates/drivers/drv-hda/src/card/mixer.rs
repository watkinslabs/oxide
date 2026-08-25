use super::*;

fn follower_index(device: &DeviceState, nid: u8, output: bool) -> Option<usize> {
    device.master_followers.iter().position(|follower| follower.nid == nid && follower.output == output)
}

fn follower_gain(base: u8, caps: widget::AmpCaps, master: u8) -> u8 {
    let gain = i32::from(base) + i32::from(master) - i32::try_from(caps.num_steps).unwrap_or(i32::MAX);
    gain.clamp(0, i32::from(u8::MAX)) as u8
}

fn elem_get(owner: sound::SoundOwnerKey, private: u32, out: &mut sound::elem::ElemValues) -> bool {
    let (codec, nid, output, kind) = elemkey::unpack_for(private);
    if kind == ElemKind::Jack { service_jacks(owner); }
    with_device(owner, |device| match kind {
        ElemKind::Jack => {
            out[0] = i64::from(device.hda.jack_sense_for(codec, nid));
            true
        }
        ElemKind::CaptureSource => {
            out[0] = i64::from(device.hda.primary_capture_source());
            true
        }
        ElemKind::ChannelMode => {
            out[0] = i64::from(device.hda.primary_multi_io_active());
            true
        }
        ElemKind::MasterVolume => {
            out[0] = i64::from(device.master_volume);
            true
        }
        ElemKind::MasterSwitch => {
            out[0] = i64::from(!device.master_mute);
            true
        }
        ElemKind::Volume => {
            if let Some(index) = follower_index(device, nid, output) {
                let follower = &device.master_followers[index];
                out[0] = i64::from(follower.left);
                out[1] = i64::from(follower.right);
                return true;
            }
            let Some((_, left)) = device.hda.amp_read_for(codec, nid, output, 0, true) else { return false; };
            let right = device.hda.amp_read_for(codec, nid, output, 0, false).map(|(_, gain)| gain).unwrap_or(left);
            out[0] = i64::from(left);
            out[1] = i64::from(right);
            true
        }
        ElemKind::Switch => {
            if let Some(index) = follower_index(device, nid, output) {
                let follower = &device.master_followers[index];
                out[0] = i64::from(!follower.left_muted);
                out[1] = i64::from(!follower.right_muted);
                return true;
            }
            let Some((left_muted, _)) = device.hda.amp_read_for(codec, nid, output, 0, true) else { return false; };
            let right_muted = device.hda.amp_read_for(codec, nid, output, 0, false).map(|(muted, _)| muted).unwrap_or(left_muted);
            // ALSA switches are "on means audible", the inverse of the mute bit.
            out[0] = i64::from(!left_muted);
            out[1] = i64::from(!right_muted);
            true
        }
    }).unwrap_or(false)
}

fn elem_put(owner: sound::SoundOwnerKey, private: u32, values: &sound::elem::ElemValues) -> bool {
    let (codec, nid, output, kind) = elemkey::unpack_for(private);
    with_device(owner, |device| match kind {
        ElemKind::Jack => false,
        ElemKind::CaptureSource => device.hda.set_capture_source(values[0] as u32),
        ElemKind::ChannelMode => device.hda.set_multi_io(values[0] as u8),
        ElemKind::MasterVolume => {
            let volume = values[0] as u8;
            let followers = device.master_followers.clone();
            for follower in followers.iter() {
                let left = follower_gain(follower.left, follower.caps, volume);
                let right = follower_gain(follower.right, follower.caps, volume);
                if !device.hda.amp_write_for(follower.codec, follower.nid, follower.output, 0, true, false,
                                         follower.left_muted || device.master_mute, left)
                    || !device.hda.amp_write_for(follower.codec, follower.nid, follower.output, 0, false, true,
                                             follower.right_muted || device.master_mute, right) {
                    return false;
                }
            }
            device.master_volume = volume;
            true
        }
        ElemKind::MasterSwitch => {
            let master_mute = values[0] == 0;
            let followers = device.master_followers.clone();
            for follower in followers.iter() {
                let left = follower_gain(follower.left, follower.caps, device.master_volume);
                let right = follower_gain(follower.right, follower.caps, device.master_volume);
                if !device.hda.amp_write_for(follower.codec, follower.nid, follower.output, 0, true, false,
                                         follower.left_muted || master_mute, left)
                    || !device.hda.amp_write_for(follower.codec, follower.nid, follower.output, 0, false, true,
                                             follower.right_muted || master_mute, right) {
                    return false;
                }
            }
            device.master_mute = master_mute;
            true
        }
        ElemKind::Volume => {
            if let Some(index) = follower_index(device, nid, output) {
                let (caps, master, left_muted, right_muted) = {
                    let follower = &device.master_followers[index];
                    (follower.caps, device.master_volume, follower.left_muted, follower.right_muted)
                };
                let left = values[0] as u8;
                let right = values[1] as u8;
                if !device.hda.amp_write_for(codec, nid, output, 0, true, false, left_muted || device.master_mute,
                                         follower_gain(left, caps, master))
                    || !device.hda.amp_write_for(codec, nid, output, 0, false, true, right_muted || device.master_mute,
                                              follower_gain(right, caps, master)) {
                    return false;
                }
                let follower = &mut device.master_followers[index];
                follower.left = left;
                follower.right = right;
                return true;
            }
            let muted = device.hda.amp_read_for(codec, nid, output, 0, true).map(|(muted, _)| muted).unwrap_or(false);
            device.hda.amp_write_for(codec, nid, output, 0, true, false, muted, values[0] as u8)
                && device.hda.amp_write_for(codec, nid, output, 0, false, true, muted, values[1] as u8)
        }
        ElemKind::Switch => {
            if let Some(index) = follower_index(device, nid, output) {
                let left = values[0] == 0;
                let right = values[1] == 0;
                let follower = &device.master_followers[index];
                if !device.hda.amp_write_for(codec, nid, output, 0, true, false, left || device.master_mute,
                                         follower_gain(follower.left, follower.caps, device.master_volume))
                    || !device.hda.amp_write_for(codec, nid, output, 0, false, true, right || device.master_mute,
                                              follower_gain(follower.right, follower.caps, device.master_volume)) {
                    return false;
                }
                let follower = &mut device.master_followers[index];
                follower.left_muted = left;
                follower.right_muted = right;
                return true;
            }
            let gain = device.hda.amp_read_for(codec, nid, output, 0, true).map(|(_, gain)| gain).unwrap_or(0);
            device.hda.amp_write_for(codec, nid, output, 0, true, false, values[0] == 0, gain)
                && device.hda.amp_write_for(codec, nid, output, 0, false, true, values[1] == 0, gain)
        }
    }).unwrap_or(false)
}

fn elem_enum(owner: sound::SoundOwnerKey, private: u32, item: u32,
             out: &mut [u8; sound::elem::ENUM_NAME_WIDTH]) -> bool {
    let (_, _, _, kind) = elemkey::unpack_for(private);
    if kind == ElemKind::ChannelMode {
        let Some(Some((base, count))) = with_device(owner, |device| {
            let plan = device.hda.primary_plan()?;
            let route = plan.primary()?;
            let codec = device.hda.primary_codec()?;
            let base = codec.widget(route.dac).map(|w| widget::widget_channels(w.wcaps)).unwrap_or(2);
            Some((base, plan.multi_io.len()))
        }) else { return false; };
        if item as usize > count { return false; }
        let channels = base + item * 2;
        out.fill(0);
        if channels >= 10 {
            out[0] = b'0' + (channels / 10) as u8;
            out[1] = b'0' + (channels % 10) as u8;
            out[2] = b'c'; out[3] = b'h';
        } else {
            out[0] = b'0' + channels as u8;
            out[1] = b'c'; out[2] = b'h';
        }
        return true;
    }
    if kind != ElemKind::CaptureSource { return false; }
    let Some(Some(label)) = with_device(owner, |device| {
        let plan = device.hda.primary_plan()?;
        let route = plan.captures.get(item as usize)?;
        let inputs: Vec<_> = plan.captures.iter().map(|candidate| candidate.input).collect();
        let needs_location = ctlname::inputs_need_location(&inputs);
        Some(ctlname::input_label(&route.input, needs_location))
    }) else { return false; };
    out.fill(0);
    let len = label.len().min(out.len());
    out[..len].copy_from_slice(&label[..len]);
    true
}

static ELEM_OPS: sound::elem::ElemOps =
    sound::elem::ElemOps { get: elem_get, put: elem_put, enum_name: elem_enum };

fn register_amp(owner: sound::SoundOwnerKey, control: &elemkey::AmpControl) {
    let (codec, nid, output, caps) = (control.codec, control.nid, control.output, control.caps);
    if caps.num_steps != 0 && !control.volume_name.is_empty() {
        sound::elem::register(owner, sound::elem::ElemDesc {
            id: sound::elem::ElemId::mixer(&control.volume_name, 0),
            etype: sound::uapi::CTL_ELEM_TYPE_INTEGER,
            access: sound::uapi::CTL_ELEM_ACCESS_READWRITE | sound::uapi::CTL_ELEM_ACCESS_TLV_READ,
            count: 2, min: 0, max: i64::from(caps.num_steps), step: 0, items: 0,
            tlv: Some(sound::elem::DbScale {
                min_centibel: widget::amp_min_centibel(&caps),
                step_centibel: caps.step_centibel,
                mute: caps.mute,
            }),
            private: elemkey::pack_for(codec, nid, output, ElemKind::Volume),
            ops: &ELEM_OPS,
        });
    }
    if caps.mute {
        sound::elem::register(owner, sound::elem::ElemDesc {
            id: sound::elem::ElemId::mixer(&control.switch_name, 0),
            etype: sound::uapi::CTL_ELEM_TYPE_BOOLEAN,
            access: sound::uapi::CTL_ELEM_ACCESS_READWRITE,
            count: 2, min: 0, max: 1, step: 0, items: 0, tlv: None,
            private: elemkey::pack_for(codec, nid, output, ElemKind::Switch),
            ops: &ELEM_OPS,
        });
    }
}

/// Publish the card's mixer and jack controls from its routing plan.
/// # C: O(routes)
pub fn register_controls(owner: sound::SoundOwnerKey) {
    let described = with_device(owner, |device| {
        device.hda.codecs.iter().enumerate()
            .map(|(index, state)| elemkey::describe_for(index, &state.codec, &state.plan))
            .collect::<Vec<_>>()
    }).unwrap_or_default();
    let Some(controls) = described.first() else { return; };
    if let Some(master) = controls.master.as_ref() {
        with_device(owner, |device| {
            device.master_volume = master.caps.num_steps.min(u32::from(u8::MAX)) as u8;
            device.master_followers = controls.amps.iter()
                .filter(|control| control.output && !control.volume_name.is_empty())
                .filter_map(|control| {
                    let (left_muted, left) = device.hda.amp_read_for(control.codec, control.nid, control.output, 0, true)?;
                    let (right_muted, right) = device.hda.amp_read_for(control.codec, control.nid, control.output, 0, false)
                        .unwrap_or((left_muted, left));
                    Some(MasterFollower { codec: control.codec, nid: control.nid, output: control.output, caps: control.caps,
                                          left, right, left_muted, right_muted })
                }).collect();
        });
    }
    for codec_controls in described.iter() {
        for control in codec_controls.amps.iter() { register_amp(owner, control); }
    }
    if let Some(master) = controls.master.as_ref() {
        sound::elem::register(owner, sound::elem::ElemDesc {
            id: sound::elem::ElemId::mixer(b"Master Playback Volume", 0),
            etype: sound::uapi::CTL_ELEM_TYPE_INTEGER,
            access: sound::uapi::CTL_ELEM_ACCESS_READWRITE | sound::uapi::CTL_ELEM_ACCESS_TLV_READ,
            count: 1, min: 0, max: i64::from(master.caps.num_steps), step: 0, items: 0,
            tlv: Some(sound::elem::DbScale {
                min_centibel: widget::amp_min_centibel(&master.caps),
                step_centibel: master.caps.step_centibel, mute: master.caps.mute,
            }),
            private: elemkey::pack_for(master.codec, master.nid, master.output, ElemKind::MasterVolume), ops: &ELEM_OPS,
        });
        if master.caps.mute {
            sound::elem::register(owner, sound::elem::ElemDesc {
                id: sound::elem::ElemId::mixer(b"Master Playback Switch", 0),
                etype: sound::uapi::CTL_ELEM_TYPE_BOOLEAN,
                access: sound::uapi::CTL_ELEM_ACCESS_READWRITE,
                count: 1, min: 0, max: 1, step: 0, items: 0, tlv: None,
                private: elemkey::pack_for(master.codec, master.nid, master.output, ElemKind::MasterSwitch), ops: &ELEM_OPS,
            });
        }
    }
    if controls.capture_sources.len() > 1 {
        sound::elem::register(owner, sound::elem::ElemDesc {
            id: sound::elem::ElemId::mixer(&ctlname::capture_source(), 0),
            etype: sound::uapi::CTL_ELEM_TYPE_ENUMERATED,
            access: sound::uapi::CTL_ELEM_ACCESS_READWRITE,
            count: 1, min: 0, max: (controls.capture_sources.len() - 1) as i64,
            step: 0, items: controls.capture_sources.len() as u32, tlv: None,
            private: elemkey::pack(0, false, ElemKind::CaptureSource), ops: &ELEM_OPS,
        });
    }
    let has_multi_io = with_device(owner, |device| {
        device.hda.primary_plan().is_some_and(|plan| !plan.multi_io.is_empty())
    }).unwrap_or(false);
    if has_multi_io {
        let items = with_device(owner, |device| {
            device.hda.primary_plan().map(|plan| plan.multi_io.len() as u32 + 1)
        }).flatten().unwrap_or(1);
        sound::elem::register(owner, sound::elem::ElemDesc {
            id: sound::elem::ElemId::mixer(&ctlname::channel_mode(), 0),
            etype: sound::uapi::CTL_ELEM_TYPE_ENUMERATED,
            access: sound::uapi::CTL_ELEM_ACCESS_READWRITE,
            count: 1, min: 0, max: i64::from(items - 1), step: 0, items, tlv: None,
            private: elemkey::pack(0, false, ElemKind::ChannelMode), ops: &ELEM_OPS,
        });
    }
    for codec_controls in described.iter() {
      for jack in codec_controls.jacks.iter() {
        let id = sound::elem::ElemId::mixer(&jack.name, 0);
        let numid = sound::elem::register(owner, sound::elem::ElemDesc {
            id, etype: sound::uapi::CTL_ELEM_TYPE_BOOLEAN,
            access: sound::uapi::CTL_ELEM_ACCESS_READ | sound::uapi::CTL_ELEM_ACCESS_VOLATILE,
            count: 1, min: 0, max: 1, step: 0, items: 0, tlv: None,
            private: elemkey::pack_for(jack.codec, jack.pin, true, ElemKind::Jack),
            ops: &ELEM_OPS,
        });
        with_device(owner, |device| device.jack_elems.push((jack.codec, jack.pin, numid, id)));
      }
    }
}

