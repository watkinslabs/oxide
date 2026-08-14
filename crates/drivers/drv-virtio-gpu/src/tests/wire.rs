use super::super::*;

const CTRL_HEADER_BYTES: usize = 24;
const RECT_BYTES: usize = 16;
const DISPLAY_ONE_BYTES: usize = 24;
const DISPLAY_INFO_RESPONSE_BYTES: usize =
    CTRL_HEADER_BYTES + VIRTIO_GPU_MAX_SCANOUTS * DISPLAY_ONE_BYTES;
const EDID_PAYLOAD_BYTES: usize = 1024;
const EDID_RESPONSE_METADATA_BYTES: usize = 8;
const EDID_RESPONSE_BYTES: usize =
    CTRL_HEADER_BYTES + EDID_RESPONSE_METADATA_BYTES + EDID_PAYLOAD_BYTES;
const COMMAND_BUFFER_BYTES: usize = 64;
const NODATA_COMMAND_BYTES: usize = 32;
const RESOURCE_CREATE_COMMAND_BYTES: usize = 40;
const SET_SCANOUT_COMMAND_BYTES: usize = 48;
const UPDATE_CURSOR_COMMAND_BYTES: usize = 56;
const CURSOR_POS_BYTES: usize = 16;
const PIXEL_BYTES: u32 = 4;
const UNSUPPORTED_FORMAT: u32 = 0xdead;
const BUFFER_SENTINEL: u8 = 0xaa;
const CTRL_TYPE_OFFSET: usize = 0;
const CTRL_FLAGS_OFFSET: usize = 4;
const CTRL_PAYLOAD_OFFSET: usize = CTRL_HEADER_BYTES;
const RESOURCE_FORMAT_OFFSET: usize = 28;
const RECT_WIDTH_OFFSET: usize = 32;
const RECT_HEIGHT_OFFSET: usize = 36;
const SET_SCANOUT_ID_OFFSET: usize = 40;
const SET_SCANOUT_RESOURCE_OFFSET: usize = 44;
const TEST_SCANOUT_ID: u32 = 7;
const TEST_RESOURCE_ID: u32 = 5;
const LIFETIME_RESOURCE_ID: u32 = 9;
const TEST_MODE_WIDTH: u32 = 800;
const TEST_MODE_HEIGHT: u32 = 600;
const TEST_CURSOR_WIDTH: u32 = 64;
const TEST_CURSOR_HEIGHT: u32 = 64;
const TEST_CURSOR_X: i32 = 17;
const TEST_CURSOR_Y: i32 = 23;
const TEST_CURSOR_HOT_X: i32 = 2;
const TEST_CURSOR_HOT_Y: i32 = 3;
const TEST_CURSOR_MOVE_X: i32 = 10;
const TEST_CURSOR_MOVE_Y: i32 = 20;
const CURSOR_X_OFFSET: usize = 28;
const CURSOR_Y_OFFSET: usize = 32;
const CURSOR_RESOURCE_OFFSET: usize = 40;
const CURSOR_HOT_X_OFFSET: usize = 44;
const CURSOR_HOT_Y_OFFSET: usize = 48;
const EDID_SIZE_OFFSET: usize = CTRL_HEADER_BYTES;
const EDID_DATA_OFFSET: usize = CTRL_HEADER_BYTES + EDID_RESPONSE_METADATA_BYTES;
const EDID_MAGIC: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
const TEST_HOST_FEATURES: u64 = 0b1111;
const TEST_DRIVER_FEATURES: u64 = 0b0110;

#[test]
fn ctrl_hdr_layout() {
    assert_eq!(core::mem::size_of::<VirtioGpuCtrlHdr>(), CTRL_HEADER_BYTES);
}

#[test]
fn rect_layout() {
    assert_eq!(core::mem::size_of::<VirtioGpuRect>(), RECT_BYTES);
}

#[test]
fn display_one_layout() {
    assert_eq!(core::mem::size_of::<VirtioGpuDisplayOne>(), DISPLAY_ONE_BYTES);
}

#[test]
fn resp_display_info_layout() {
    assert_eq!(
        core::mem::size_of::<VirtioGpuRespDisplayInfo>(),
        DISPLAY_INFO_RESPONSE_BYTES
    );
}

#[test]
fn resp_edid_size() {
    assert_eq!(core::mem::size_of::<VirtioGpuRespEdid>(), EDID_RESPONSE_BYTES);
}

#[test]
fn negotiate_intersects() {
    assert_eq!(
        negotiate_features(TEST_HOST_FEATURES, TEST_DRIVER_FEATURES),
        TEST_DRIVER_FEATURES,
    );
}

#[test]
fn driver_features_include_virgl_and_edid() {
    let bits = default_driver_features();
    assert!(bits & (1u64 << VIRTIO_GPU_F_VIRGL) != 0);
    assert!(bits & (1u64 << VIRTIO_GPU_F_EDID) != 0);
    assert!(bits & (1u64 << VIRTIO_F_VERSION_1) != 0);
}

#[test]
fn bpp_for_known_formats() {
    assert_eq!(
        VirtioGpuDev::bytes_per_pixel(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM),
        PIXEL_BYTES,
    );
    assert_eq!(
        VirtioGpuDev::bytes_per_pixel(VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM),
        PIXEL_BYTES,
    );
    assert_eq!(VirtioGpuDev::bytes_per_pixel(UNSUPPORTED_FORMAT), 0);
}

#[test]
fn encode_get_display_info_writes_24() {
    let mut buf = [BUFFER_SENTINEL; COMMAND_BUFFER_BYTES];
    let n = encode_get_display_info(&mut buf);
    assert_eq!(n, CTRL_HEADER_BYTES);
    assert_eq!(
        read_u32_le(&buf, CTRL_TYPE_OFFSET),
        VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
    );
    assert_eq!(read_u32_le(&buf, CTRL_FLAGS_OFFSET), 0);
    for byte in buf
        .iter()
        .take(CTRL_HEADER_BYTES)
        .skip(2 * core::mem::size_of::<u32>())
    {
        assert_eq!(*byte, 0);
    }
}

#[test]
fn encode_get_edid_writes_32_with_scanout() {
    let mut buf = [0u8; COMMAND_BUFFER_BYTES];
    let n = encode_get_edid(&mut buf, TEST_SCANOUT_ID);
    assert_eq!(n, NODATA_COMMAND_BYTES);
    assert_eq!(read_u32_le(&buf, CTRL_TYPE_OFFSET), VIRTIO_GPU_CMD_GET_EDID);
    assert_eq!(read_u32_le(&buf, CTRL_PAYLOAD_OFFSET), TEST_SCANOUT_ID);
}

#[test]
fn encode_resource_create_2d_layout() {
    let mut buf = [0u8; COMMAND_BUFFER_BYTES];
    let n = encode_resource_create_2d(
        &mut buf,
        TEST_RESOURCE_ID,
        VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
        TEST_MODE_WIDTH,
        TEST_MODE_HEIGHT,
    );
    assert_eq!(n, RESOURCE_CREATE_COMMAND_BYTES);
    assert_eq!(
        read_u32_le(&buf, CTRL_TYPE_OFFSET),
        VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
    );
    assert_eq!(read_u32_le(&buf, CTRL_PAYLOAD_OFFSET), TEST_RESOURCE_ID);
    assert_eq!(
        read_u32_le(&buf, RESOURCE_FORMAT_OFFSET),
        VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
    );
    assert_eq!(read_u32_le(&buf, RECT_WIDTH_OFFSET), TEST_MODE_WIDTH);
    assert_eq!(read_u32_le(&buf, RECT_HEIGHT_OFFSET), TEST_MODE_HEIGHT);
}

#[test]
fn encode_resource_lifetime_layouts() {
    let mut detach = [0u8; COMMAND_BUFFER_BYTES];
    let n = encode_resource_detach_backing(&mut detach, LIFETIME_RESOURCE_ID);
    assert_eq!(n, NODATA_COMMAND_BYTES);
    assert_eq!(
        read_u32_le(&detach, CTRL_TYPE_OFFSET),
        VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
    );
    assert_eq!(
        read_u32_le(&detach, CTRL_PAYLOAD_OFFSET),
        LIFETIME_RESOURCE_ID,
    );
    assert_eq!(read_u32_le(&detach, RESOURCE_FORMAT_OFFSET), 0);

    let mut unref = [0u8; COMMAND_BUFFER_BYTES];
    let n = encode_resource_unref(&mut unref, LIFETIME_RESOURCE_ID);
    assert_eq!(n, NODATA_COMMAND_BYTES);
    assert_eq!(
        read_u32_le(&unref, CTRL_TYPE_OFFSET),
        VIRTIO_GPU_CMD_RESOURCE_UNREF,
    );
    assert_eq!(
        read_u32_le(&unref, CTRL_PAYLOAD_OFFSET),
        LIFETIME_RESOURCE_ID,
    );
    assert_eq!(read_u32_le(&unref, RESOURCE_FORMAT_OFFSET), 0);
}

#[test]
fn encode_set_scanout_layout() {
    let mut buf = [0u8; COMMAND_BUFFER_BYTES];
    let n = encode_set_scanout(
        &mut buf,
        0,
        TEST_RESOURCE_ID,
        0,
        0,
        TEST_MODE_WIDTH,
        TEST_MODE_HEIGHT,
    );
    assert_eq!(n, SET_SCANOUT_COMMAND_BYTES);
    assert_eq!(
        read_u32_le(&buf, CTRL_TYPE_OFFSET),
        VIRTIO_GPU_CMD_SET_SCANOUT,
    );
    assert_eq!(read_u32_le(&buf, RECT_WIDTH_OFFSET), TEST_MODE_WIDTH);
    assert_eq!(read_u32_le(&buf, RECT_HEIGHT_OFFSET), TEST_MODE_HEIGHT);
    assert_eq!(read_u32_le(&buf, SET_SCANOUT_ID_OFFSET), 0);
    assert_eq!(
        read_u32_le(&buf, SET_SCANOUT_RESOURCE_OFFSET),
        TEST_RESOURCE_ID,
    );
}

#[test]
fn cursor_wire_layouts_and_encodings() {
    assert_eq!(core::mem::size_of::<VirtioGpuCursorPos>(), CURSOR_POS_BYTES);
    assert_eq!(
        core::mem::size_of::<VirtioGpuUpdateCursor>(),
        UPDATE_CURSOR_COMMAND_BYTES,
    );
    let mut update = [0u8; COMMAND_BUFFER_BYTES];
    assert_eq!(
        encode_update_cursor(
            &mut update,
            LIFETIME_RESOURCE_ID,
            TEST_CURSOR_WIDTH,
            TEST_CURSOR_HEIGHT,
            TEST_CURSOR_X,
            TEST_CURSOR_Y,
            TEST_CURSOR_HOT_X,
            TEST_CURSOR_HOT_Y,
        ),
        UPDATE_CURSOR_COMMAND_BYTES,
    );
    assert_eq!(
        read_u32_le(&update, CTRL_TYPE_OFFSET),
        VIRTIO_GPU_CMD_UPDATE_CURSOR,
    );
    assert_eq!(read_u32_le(&update, CTRL_PAYLOAD_OFFSET), 0);
    assert_eq!(read_u32_le(&update, CURSOR_X_OFFSET), TEST_CURSOR_X as u32);
    assert_eq!(read_u32_le(&update, CURSOR_Y_OFFSET), TEST_CURSOR_Y as u32);
    assert_eq!(
        read_u32_le(&update, CURSOR_RESOURCE_OFFSET),
        LIFETIME_RESOURCE_ID,
    );
    assert_eq!(
        read_u32_le(&update, CURSOR_HOT_X_OFFSET),
        TEST_CURSOR_HOT_X as u32,
    );
    assert_eq!(
        read_u32_le(&update, CURSOR_HOT_Y_OFFSET),
        TEST_CURSOR_HOT_Y as u32,
    );
    let mut mov = [0u8; COMMAND_BUFFER_BYTES];
    assert_eq!(
        encode_move_cursor(&mut mov, TEST_CURSOR_MOVE_X, TEST_CURSOR_MOVE_Y),
        RESOURCE_CREATE_COMMAND_BYTES,
    );
    assert_eq!(
        read_u32_le(&mov, CTRL_TYPE_OFFSET),
        VIRTIO_GPU_CMD_MOVE_CURSOR,
    );
    assert_eq!(
        read_u32_le(&mov, CURSOR_X_OFFSET),
        TEST_CURSOR_MOVE_X as u32,
    );
    assert_eq!(
        read_u32_le(&mov, CURSOR_Y_OFFSET),
        TEST_CURSOR_MOVE_Y as u32,
    );
}

#[test]
fn parse_display_info_decodes_one_enabled() {
    let mut resp = [0u8; DISPLAY_INFO_RESPONSE_BYTES];
    write_u32_le(&mut resp, CTRL_TYPE_OFFSET, VIRTIO_GPU_RESP_OK_DISPLAY_INFO);
    write_u32_le(&mut resp, CTRL_PAYLOAD_OFFSET, 0);
    write_u32_le(&mut resp, RESOURCE_FORMAT_OFFSET, 0);
    write_u32_le(&mut resp, RECT_WIDTH_OFFSET, TEST_MODE_WIDTH);
    write_u32_le(&mut resp, RECT_HEIGHT_OFFSET, TEST_MODE_HEIGHT);
    write_u32_le(&mut resp, SET_SCANOUT_ID_OFFSET, 1);
    let info = parse_display_info(&resp).unwrap();
    assert_eq!(info.count_enabled, 1);
    assert_eq!(info.modes[0].r.width, TEST_MODE_WIDTH);
    assert_eq!(info.modes[0].r.height, TEST_MODE_HEIGHT);
    assert_eq!(info.modes[0].enabled, 1);
}

#[test]
fn parse_display_info_rejects_wrong_type() {
    let mut resp = [0u8; DISPLAY_INFO_RESPONSE_BYTES];
    write_u32_le(&mut resp, CTRL_TYPE_OFFSET, VIRTIO_GPU_RESP_ERR_UNSPEC);
    let result = parse_display_info(&resp);
    assert!(matches!(result, Err(Error::BadResp(VIRTIO_GPU_RESP_ERR_UNSPEC))));
}

#[test]
fn parse_edid_decodes_block() {
    let mut resp = [0u8; EDID_RESPONSE_BYTES];
    write_u32_le(&mut resp, CTRL_TYPE_OFFSET, VIRTIO_GPU_RESP_OK_EDID);
    write_u32_le(&mut resp, EDID_SIZE_OFFSET, EDID_MAGIC.len() as u32);
    resp[EDID_DATA_OFFSET..EDID_DATA_OFFSET + EDID_MAGIC.len()]
        .copy_from_slice(&EDID_MAGIC);
    let edid = parse_edid_bytes(&resp).unwrap();
    assert_eq!(edid, &EDID_MAGIC);
}

#[test]
fn parse_nodata_accepts_any_ok() {
    let mut resp = [0u8; CTRL_HEADER_BYTES];
    write_u32_le(&mut resp, CTRL_TYPE_OFFSET, VIRTIO_GPU_RESP_OK_NODATA);
    assert!(parse_nodata_resp(&resp).is_ok());
    write_u32_le(
        &mut resp,
        CTRL_TYPE_OFFSET,
        VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
    );
    assert!(parse_nodata_resp(&resp).is_err());
}
