//! Control ranges, steps, menus, the query walk and the batch forms.

use syscall::errno::Errno;

use super::harness::{FakeCtx, Rig};
use crate::ctrl::range::{check_range, round_to_range, validate};
use crate::uapi::ctrl_ids as cid;
use crate::uapi::ioctl::*;
use crate::uapi::layout as l;
use crate::usermem::{r32, r32i, r64i, w32, w32i, w64i};

#[test]
fn snapping_rounds_to_nearest_then_clamps_then_truncates_to_the_grid() {
    // Range -64..64 step 2: every value lands on an even number in range.
    for value in -100i64..=100 {
        let snapped = round_to_range(value, -64, 64, 2);
        assert!((-64..=64).contains(&snapped), "{value} snapped out of range");
        assert_eq!((snapped - (-64)) % 2, 0, "{value} snapped off the grid");
    }
    assert_eq!(round_to_range(0, -64, 64, 2), 0);
    assert_eq!(round_to_range(1, -64, 64, 2), 2, "half a step rounds upward");
    assert_eq!(round_to_range(-1, -64, 64, 2), 0);
    assert_eq!(round_to_range(1000, -64, 64, 2), 64);
    assert_eq!(round_to_range(-1000, -64, 64, 2), -64);
    // Truncation onto the grid is the LAST step, so a maximum that is not
    // itself on the grid is not reachable: 65 with a step of 10 settles at 60.
    // A driver that wants its maximum reachable must put it on the grid.
    assert_eq!(round_to_range(65, 0, 65, 10), 60);
    assert_eq!(round_to_range(64, 0, 65, 10), 60);
    assert_eq!(round_to_range(61, 0, 65, 10), 60);
    // On a grid-aligned range the maximum is reachable.
    assert_eq!(round_to_range(70, 0, 60, 10), 60);
    assert_eq!(round_to_range(56, 0, 60, 10), 60);
    // A zero step is treated as one rather than dividing by zero.
    assert_eq!(round_to_range(37, 0, 100, 0), 37);
}

#[test]
fn a_driver_range_that_cannot_be_satisfied_is_refused() {
    // A numeric control needs a step and a default inside its range.
    assert_eq!(check_range(cid::CTRL_TYPE_INTEGER, 0, 10, 0, 5), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_INTEGER, 10, 0, 1, 5), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_INTEGER, 0, 10, 1, 11), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_INTEGER, 0, 10, 1, 5), Ok(()));
    // A boolean has no step to choose.
    assert_eq!(check_range(cid::CTRL_TYPE_BOOLEAN, 0, 1, 2, 0), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_BOOLEAN, 0, 2, 1, 0), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_BOOLEAN, 0, 1, 1, 1), Ok(()));
    // A bitmask's maximum is its legal bit set.
    assert_eq!(check_range(cid::CTRL_TYPE_BITMASK, 0, 0, 0, 0), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_BITMASK, 0, 0b111, 0, 0b1000), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_BITMASK, 0, 0b111, 0, 0b101), Ok(()));
    // A menu's skip mask only reaches the first 64 entries, and a default the
    // driver also skipped is a contradiction.
    assert_eq!(check_range(cid::CTRL_TYPE_MENU, 0, 64, 1, 0), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_MENU, 0, 3, 0b0010, 1), Err(Errno::Einval));
    assert_eq!(check_range(cid::CTRL_TYPE_MENU, 0, 3, 0b0010, 0), Ok(()));
    assert_eq!(check_range(cid::CTRL_TYPE_STRING, 0, 16, 0, 0), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_STRING, 0, 16, 1, 1), Err(Errno::Erange));
    assert_eq!(check_range(cid::CTRL_TYPE_STRING, 0, 16, 1, 0), Ok(()));
}

#[test]
fn a_menu_choice_is_refused_rather_than_clamped() {
    // An integer is a slider and is clamped.
    assert_eq!(validate(cid::CTRL_TYPE_INTEGER, 500, 0, 100, 1), Ok(100));
    // A menu index is a choice; turning "60 Hz" into "50 Hz" behind the
    // caller's back would be worse than refusing.
    assert_eq!(validate(cid::CTRL_TYPE_MENU, 4, 0, 3, 0), Err(Errno::Erange));
    assert_eq!(validate(cid::CTRL_TYPE_MENU, 2, 0, 3, 0), Ok(2));
    // An entry the driver marked unusable is EINVAL, distinct from the
    // out-of-range ERANGE.
    assert_eq!(validate(cid::CTRL_TYPE_MENU, 1, 0, 3, 0b0010), Err(Errno::Einval));
    // A boolean is normalised, a button discards its value, and a bitmask
    // drops the bits the device does not have.
    assert_eq!(validate(cid::CTRL_TYPE_BOOLEAN, 7, 0, 1, 1), Ok(1));
    assert_eq!(validate(cid::CTRL_TYPE_BUTTON, 7, 0, 0, 0), Ok(0));
    assert_eq!(validate(cid::CTRL_TYPE_BITMASK, 0b1011, 0, 0b0011, 0), Ok(0b0011));
}

#[test]
fn s_ctrl_stores_the_snapped_value_and_reports_it_back() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::CONTROL_SIZE];
    w32(&mut arg, l::CONTROL_ID, cid::CID_BRIGHTNESS);
    w32i(&mut arg, l::CONTROL_VALUE, 7);
    rig.call(VIDIOC_S_CTRL, &mut arg, &ctx).expect("set succeeds");
    assert_eq!(r32i(&arg, l::CONTROL_VALUE), 8, "7 snaps up onto the step-2 grid");
    let mut got = alloc::vec![0u8; l::CONTROL_SIZE];
    w32(&mut got, l::CONTROL_ID, cid::CID_BRIGHTNESS);
    rig.call(VIDIOC_G_CTRL, &mut got, &ctx).expect("get succeeds");
    assert_eq!(r32i(&got, l::CONTROL_VALUE), 8);
    // A control the device does not have is EINVAL on both paths.
    let mut missing = alloc::vec![0u8; l::CONTROL_SIZE];
    w32(&mut missing, l::CONTROL_ID, cid::CID_ZOOM_ABSOLUTE);
    assert_eq!(rig.call(VIDIOC_G_CTRL, &mut missing, &ctx), Err(Errno::Einval));
    assert_eq!(rig.call(VIDIOC_S_CTRL, &mut missing, &ctx), Err(Errno::Einval));
}

#[test]
fn queryctrl_describes_a_control_and_ends_the_walk_with_einval() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::QUERYCTRL_SIZE];
    w32(&mut arg, l::QUERYCTRL_ID, cid::CID_BRIGHTNESS);
    rig.call(VIDIOC_QUERYCTRL, &mut arg, &ctx).expect("query succeeds");
    assert_eq!(r32i(&arg, l::QUERYCTRL_MINIMUM), -64);
    assert_eq!(r32i(&arg, l::QUERYCTRL_MAXIMUM), 64);
    assert_eq!(r32i(&arg, l::QUERYCTRL_STEP), 2);
    assert_eq!(r32(&arg, l::QUERYCTRL_TYPE), cid::CTRL_TYPE_INTEGER);
    assert_eq!(&arg[l::QUERYCTRL_NAME..l::QUERYCTRL_NAME + 10], b"Brightness");
    // A bounded integer is a slider, whatever the driver said.
    assert!(r32(&arg, l::QUERYCTRL_FLAGS) & cid::CTRL_FLAG_SLIDER != 0);

    // The walk visits every control in id order and then stops.
    let mut id = 0u32;
    let mut seen = alloc::vec::Vec::new();
    loop {
        let mut step = alloc::vec![0u8; l::QUERYCTRL_SIZE];
        w32(&mut step, l::QUERYCTRL_ID, id | cid::CTRL_FLAG_NEXT_CTRL);
        match rig.call(VIDIOC_QUERYCTRL, &mut step, &ctx) {
            Ok(()) => { id = r32(&step, l::QUERYCTRL_ID); seen.push(id); }
            Err(e) => { assert_eq!(e, Errno::Einval); break; }
        }
        assert!(seen.len() < 64, "the walk must terminate");
    }
    assert_eq!(seen.len(), rig.device.controls.descs().len());
    let mut sorted = seen.clone();
    sorted.sort_unstable();
    assert_eq!(seen, sorted, "the walk must be in id order");
    assert!(seen.contains(&cid::CID_BRIGHTNESS));
    assert!(seen.contains(&cid::CID_EXPOSURE_AUTO));
}

#[test]
fn querymenu_names_the_entries_and_refuses_everything_else() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    for (index, name) in crate::ctrl::standard::POWER_LINE_MENU.iter().enumerate() {
        let mut arg = alloc::vec![0u8; l::QUERYMENU_SIZE];
        w32(&mut arg, l::QUERYMENU_ID, cid::CID_POWER_LINE_FREQUENCY);
        w32(&mut arg, l::QUERYMENU_INDEX, index as u32);
        rig.call(VIDIOC_QUERYMENU, &mut arg, &ctx).expect("menu entry reads");
        assert_eq!(&arg[l::QUERYMENU_NAME..l::QUERYMENU_NAME + name.len()], name.as_bytes());
    }
    // Past the last entry, and on a control that is not a menu.
    let mut past = alloc::vec![0u8; l::QUERYMENU_SIZE];
    w32(&mut past, l::QUERYMENU_ID, cid::CID_POWER_LINE_FREQUENCY);
    w32(&mut past, l::QUERYMENU_INDEX, 4);
    assert_eq!(rig.call(VIDIOC_QUERYMENU, &mut past, &ctx), Err(Errno::Einval));
    let mut wrong = alloc::vec![0u8; l::QUERYMENU_SIZE];
    w32(&mut wrong, l::QUERYMENU_ID, cid::CID_BRIGHTNESS);
    assert_eq!(rig.call(VIDIOC_QUERYMENU, &mut wrong, &ctx), Err(Errno::Einval));
}

#[test]
fn query_ext_ctrl_carries_the_range_the_legacy_form_cannot() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::QUERY_EXT_CTRL_SIZE];
    w32(&mut arg, l::QEC_ID, cid::CID_WHITE_BALANCE_TEMPERATURE);
    rig.call(VIDIOC_QUERY_EXT_CTRL, &mut arg, &ctx).expect("query succeeds");
    assert_eq!(r64i(&arg, l::QEC_MINIMUM), 2800);
    assert_eq!(r64i(&arg, l::QEC_MAXIMUM), 6500);
    assert_eq!(r64i(&arg, l::QEC_STEP), 100);
    assert_eq!(r32(&arg, l::QEC_ELEM_SIZE), 4);
    assert_eq!(r32(&arg, l::QEC_ELEMS), 1);
    assert_eq!(r32(&arg, l::QEC_NR_OF_DIMS), 0);
}

#[test]
fn an_automatic_control_makes_its_cluster_inactive() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    // Automatic exposure is the default, so its dependants must already read
    // as inactive once the mode is written.
    let mut arg = alloc::vec![0u8; l::CONTROL_SIZE];
    w32(&mut arg, l::CONTROL_ID, cid::CID_EXPOSURE_AUTO);
    w32i(&mut arg, l::CONTROL_VALUE, cid::EXPOSURE_MANUAL as i32);
    rig.call(VIDIOC_S_CTRL, &mut arg, &ctx).expect("manual mode is selected");
    let flags = rig.device.controls.flags(cid::CID_EXPOSURE_ABSOLUTE).unwrap();
    assert_eq!(flags & cid::CTRL_FLAG_INACTIVE, 0, "manual exposure activates the time");
    w32i(&mut arg, l::CONTROL_VALUE, cid::EXPOSURE_AUTO as i32);
    rig.call(VIDIOC_S_CTRL, &mut arg, &ctx).expect("automatic mode is selected");
    let flags = rig.device.controls.flags(cid::CID_EXPOSURE_ABSOLUTE).unwrap();
    assert!(flags & cid::CTRL_FLAG_INACTIVE != 0,
            "automatic exposure must grey out the exposure time");
    let priority = rig.device.controls.flags(cid::CID_EXPOSURE_AUTO_PRIORITY).unwrap();
    assert!(priority & cid::CTRL_FLAG_INACTIVE != 0, "the whole cluster follows");
}

#[test]
fn a_grabbed_control_is_ebusy_and_a_read_only_one_is_eacces() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.device.controls.set_runtime_flags(cid::CID_CONTRAST, cid::CTRL_FLAG_GRABBED, 0);
    let mut arg = alloc::vec![0u8; l::CONTROL_SIZE];
    w32(&mut arg, l::CONTROL_ID, cid::CID_CONTRAST);
    w32i(&mut arg, l::CONTROL_VALUE, 10);
    assert_eq!(rig.call(VIDIOC_S_CTRL, &mut arg, &ctx), Err(Errno::Ebusy),
               "a pinned control can be written again later, which EACCES would deny");
    // Reading it is still allowed.
    rig.call(VIDIOC_G_CTRL, &mut arg, &ctx).expect("a grabbed control still reads");
    rig.device.controls.set_runtime_flags(cid::CID_CONTRAST, 0, cid::CTRL_FLAG_GRABBED);
    rig.call(VIDIOC_S_CTRL, &mut arg, &ctx).expect("releasing it restores the write");
    // A disabled control is invisible to value access but still describable.
    rig.device.controls.set_runtime_flags(cid::CID_CONTRAST, cid::CTRL_FLAG_DISABLED, 0);
    assert_eq!(rig.call(VIDIOC_G_CTRL, &mut arg, &ctx), Err(Errno::Einval));
    let mut q = alloc::vec![0u8; l::QUERYCTRL_SIZE];
    w32(&mut q, l::QUERYCTRL_ID, cid::CID_CONTRAST);
    rig.call(VIDIOC_QUERYCTRL, &mut q, &ctx).expect("a disabled control is still described");
    assert!(r32(&q, l::QUERYCTRL_FLAGS) & cid::CTRL_FLAG_DISABLED != 0);
    rig.device.controls.set_runtime_flags(cid::CID_CONTRAST, 0, cid::CTRL_FLAG_DISABLED);
}

/// Build an extended-control batch in the caller's memory and run `cmd`
/// against it, returning the argument buffer afterwards.
fn ext_batch(rig: &Rig, ctx: &FakeCtx, cmd: u64, which: u32, entries: &[(u32, i64)])
    -> (Result<(), Errno>, alloc::vec::Vec<u8>)
{
    const BASE: u64 = 0x4000_0000;
    let mut array = alloc::vec![0u8; l::EXT_CONTROL_SIZE * entries.len().max(1)];
    for (i, (id, value)) in entries.iter().enumerate() {
        let slot = &mut array[i * l::EXT_CONTROL_SIZE..];
        w32(slot, l::EXT_CTRL_ID, *id);
        w32(slot, l::EXT_CTRL_SIZE_FIELD, 0);
        w64i(slot, l::EXT_CTRL_VALUE, *value);
    }
    ctx.user.place(BASE, array);
    let mut arg = alloc::vec![0u8; l::EXT_CONTROLS_SIZE];
    w32(&mut arg, l::EXT_CTRLS_WHICH, which);
    w32(&mut arg, l::EXT_CTRLS_COUNT, entries.len() as u32);
    crate::usermem::w64(&mut arg, l::EXT_CTRLS_CONTROLS, BASE);
    let outcome = rig.call(cmd, &mut arg, ctx);
    (outcome, arg)
}

#[test]
fn an_extended_batch_is_all_or_nothing_and_names_the_failing_entry() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let before = rig.device.controls.value(cid::CID_BRIGHTNESS).unwrap();
    // The second entry names a control the device does not have.
    let (outcome, arg) = ext_batch(&rig, &ctx, VIDIOC_S_EXT_CTRLS, cid::CTRL_WHICH_CUR_VAL,
                                   &[(cid::CID_BRIGHTNESS, 20), (cid::CID_ZOOM_ABSOLUTE, 1)]);
    assert_eq!(outcome, Err(Errno::Einval));
    assert_eq!(r32(&arg, l::EXT_CTRLS_ERROR_IDX), 1, "the failing entry is named");
    assert_eq!(rig.device.controls.value(cid::CID_BRIGHTNESS).unwrap(), before,
               "the first entry must not have been applied");

    // A batch that succeeds leaves the error index at the count.
    let (outcome, arg) = ext_batch(&rig, &ctx, VIDIOC_S_EXT_CTRLS, cid::CTRL_WHICH_CUR_VAL,
                                   &[(cid::CID_BRIGHTNESS, 20), (cid::CID_CONTRAST, 30)]);
    assert_eq!(outcome, Ok(()));
    assert_eq!(r32(&arg, l::EXT_CTRLS_ERROR_IDX), 2);
    assert_eq!(rig.device.controls.value(cid::CID_BRIGHTNESS).unwrap(), 20);
    assert_eq!(rig.device.controls.value(cid::CID_CONTRAST).unwrap(), 30);
}

#[test]
fn try_ext_ctrls_validates_without_applying() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let before = rig.device.controls.value(cid::CID_CONTRAST).unwrap();
    let (outcome, _) = ext_batch(&rig, &ctx, VIDIOC_TRY_EXT_CTRLS, cid::CTRL_WHICH_CUR_VAL,
                                 &[(cid::CID_CONTRAST, 77)]);
    assert_eq!(outcome, Ok(()));
    assert_eq!(rig.device.controls.value(cid::CID_CONTRAST).unwrap(), before,
               "trying must not change anything");
}

#[test]
fn the_which_selector_chooses_between_current_default_and_the_range_ends() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    const BASE: u64 = 0x4000_0000;
    for (which, expect) in [(cid::CTRL_WHICH_CUR_VAL, 50i64), (cid::CTRL_WHICH_DEF_VAL, 50),
                            (cid::CTRL_WHICH_MIN_VAL, 0), (cid::CTRL_WHICH_MAX_VAL, 100)] {
        let ctx = FakeCtx::new(true);
        let (outcome, _) = ext_batch(&rig, &ctx, VIDIOC_G_EXT_CTRLS, which,
                                     &[(cid::CID_CONTRAST, 0)]);
        assert_eq!(outcome, Ok(()), "which {which:#x}");
        let slot = ctx.user.peek(BASE, l::EXT_CONTROL_SIZE);
        assert_eq!(r64i(&slot, l::EXT_CTRL_VALUE), expect, "which {which:#x}");
    }
    // The request selector needs a request descriptor this device cannot
    // produce, so it is refused rather than answered with the live value.
    let (outcome, _) = ext_batch(&rig, &ctx, VIDIOC_G_EXT_CTRLS, cid::CTRL_WHICH_REQUEST_VAL,
                                 &[(cid::CID_CONTRAST, 0)]);
    assert_eq!(outcome, Err(Errno::Einval));
    // Writing a describing selector is refused before any entry is examined.
    let (outcome, _) = ext_batch(&rig, &ctx, VIDIOC_S_EXT_CTRLS, cid::CTRL_WHICH_DEF_VAL,
                                 &[(cid::CID_CONTRAST, 10)]);
    assert_eq!(outcome, Err(Errno::Einval));
}

#[test]
fn an_extended_batch_larger_than_the_cap_is_refused_before_allocating() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::EXT_CONTROLS_SIZE];
    w32(&mut arg, l::EXT_CTRLS_WHICH, cid::CTRL_WHICH_CUR_VAL);
    w32(&mut arg, l::EXT_CTRLS_COUNT, u32::MAX);
    crate::usermem::w64(&mut arg, l::EXT_CTRLS_CONTROLS, 0x4000_0000);
    assert_eq!(rig.call(VIDIOC_G_EXT_CTRLS, &mut arg, &ctx), Err(Errno::Einval));
}

#[test]
fn the_driver_is_told_about_every_change_and_nothing_else() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::CONTROL_SIZE];
    w32(&mut arg, l::CONTROL_ID, cid::CID_HFLIP);
    w32i(&mut arg, l::CONTROL_VALUE, 1);
    rig.call(VIDIOC_S_CTRL, &mut arg, &ctx).expect("set succeeds");
    rig.call(VIDIOC_S_CTRL, &mut arg, &ctx).expect("setting the same value succeeds");
    let changed = rig.ops.changed.lock().clone();
    assert_eq!(changed, alloc::vec![(cid::CID_HFLIP, 1), (cid::CID_HFLIP, 1)],
               "the driver hears both writes");
}
