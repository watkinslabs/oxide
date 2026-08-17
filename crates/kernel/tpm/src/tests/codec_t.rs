// Command encoding and response framing. The expected buffers are written
// out byte for byte: a builder that emits a field in the wrong place, in the
// wrong width, or in the wrong byte order produces a different string here.

use alloc::vec;
use alloc::vec::Vec;

use super::support::{hex, response};
use crate::alg::Alg;
use crate::codec::cmds;
use crate::codec::{CmdBuf, CodecError, Reader, Response};
use crate::limits::TPM_BUFSIZE;
use crate::rc::Rc;
use crate::uapi::{
    HEADER_SIZE, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_TOTAL_COMMANDS, TPM2_RC_FAILURE, TPM2_RC_TESTING,
    TPM2_ST_NO_SESSIONS, TPM2_ST_SESSIONS, TPM2_SU_CLEAR, TPM2_SU_STATE,
};

#[test]
fn pcr_read_encodes_the_selection_bitmap() {
    let got = cmds::pcr_read(Alg::Sha256, 3).unwrap();
    assert_eq!(got, hex("8001000000140000017e00000001000b03080000"));
}

#[test]
fn pcr_selection_sets_one_bit_in_the_right_byte() {
    assert_eq!(cmds::pcr_select(0).unwrap(), [0x01, 0x00, 0x00]);
    assert_eq!(cmds::pcr_select(7).unwrap(), [0x80, 0x00, 0x00]);
    assert_eq!(cmds::pcr_select(8).unwrap(), [0x00, 0x01, 0x00]);
    assert_eq!(cmds::pcr_select(23).unwrap(), [0x00, 0x00, 0x80]);
    assert_eq!(cmds::pcr_select(24), Err(CodecError::BadArgument("pcr index")));
}

#[test]
fn pcr_extend_carries_a_password_authorisation_area() {
    let d = [0u8; 32];
    let got = cmds::pcr_extend(3, &[(Alg::Sha256.id(), &d[..])]).unwrap();
    let mut want = hex("80020000004100000182000000030000000940000009000000000000000001000b");
    want.extend_from_slice(&d);
    assert_eq!(got, want);
}

#[test]
fn pcr_extend_refuses_a_digest_of_the_wrong_width() {
    let short = [0u8; 20];
    assert_eq!(cmds::pcr_extend(3, &[(Alg::Sha256.id(), &short[..])]), Err(CodecError::BadArgument("digest length")));
    let d = [0u8; 32];
    assert_eq!(cmds::pcr_extend(3, &[(0xABCD, &d[..])]), Err(CodecError::BadArgument("unknown algorithm")));
    assert_eq!(cmds::pcr_extend(24, &[(Alg::Sha256.id(), &d[..])]), Err(CodecError::BadArgument("pcr index")));
    assert_eq!(cmds::pcr_extend(3, &[]), Err(CodecError::BadArgument("no digests")));
}

#[test]
fn fixed_commands_encode_exactly() {
    assert_eq!(cmds::get_random(20).unwrap(), hex("80010000000c0000017b0014"));
    assert_eq!(cmds::self_test(false).unwrap(), hex("80010000000b0000014300"));
    assert_eq!(cmds::self_test(true).unwrap(), hex("80010000000b0000014301"));
    assert_eq!(cmds::startup(TPM2_SU_CLEAR).unwrap(), hex("80010000000c000001440000"));
    assert_eq!(cmds::shutdown(TPM2_SU_STATE).unwrap(), hex("80010000000c000001450001"));
    assert_eq!(cmds::flush_context(0x8000_0000).unwrap(), hex("80010000000e0000016580000000"));
    assert_eq!(cmds::context_save(0x8000_0001).unwrap(), hex("80010000000e0000016280000001"));
    assert_eq!(cmds::get_capability(TPM2_CAP_TPM_PROPERTIES, TPM2_PT_TOTAL_COMMANDS, 1).unwrap(),
               hex("8001000000160000017a000000060000012900000001"));
}

#[test]
fn random_byte_counts_are_bounded() {
    assert_eq!(cmds::get_random(0), Err(CodecError::BadArgument("random byte count")));
    assert_eq!(cmds::get_random(129), Err(CodecError::BadArgument("random byte count")));
    assert!(cmds::get_random(128).is_ok());
}

#[test]
fn a_command_that_outgrows_the_transport_buffer_is_refused_not_truncated() {
    let mut b = CmdBuf::with_limit(TPM2_ST_NO_SESSIONS, 0x11F, 16);
    b.bytes(&[0u8; 4]);
    assert!(!b.overflowed());
    b.bytes(&[0u8; 8]);
    assert!(b.overflowed());
    assert_eq!(b.finish(), Err(CodecError::Overflow { limit: 16 }));
    // The default limit is the device buffer.
    let mut big = CmdBuf::new(TPM2_ST_NO_SESSIONS, 0x11F);
    big.bytes(&vec![0u8; TPM_BUFSIZE]);
    assert_eq!(big.finish(), Err(CodecError::Overflow { limit: TPM_BUFSIZE }));
}

#[test]
fn the_header_length_tracks_every_append() {
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, 0x11F);
    b.u32(1).u16(2).u8(3);
    let out = b.finish().unwrap();
    assert_eq!(out.len(), HEADER_SIZE + 7);
    assert_eq!(&out[2..6], &(out.len() as u32).to_be_bytes());
}

#[test]
fn handles_are_counted() {
    let mut b = CmdBuf::new(TPM2_ST_SESSIONS, 0x11F);
    assert_eq!(b.handles(), 0);
    b.handle(0x4000_0001).handle(0x8000_0000);
    assert_eq!(b.handles(), 2);
}

#[test]
fn a_response_shorter_than_a_header_is_rejected() {
    for n in 0..HEADER_SIZE {
        let buf = vec![0u8; n];
        assert_eq!(Response::parse(&buf).err(), Some(CodecError::ShortHeader { got: n }));
    }
}

#[test]
fn a_length_field_that_disagrees_with_the_buffer_is_rejected() {
    let mut r = response(TPM2_ST_NO_SESSIONS, 0, &[1, 2, 3, 4]);
    // Declared longer than the buffer: a body parser would read past the end.
    r[2..6].copy_from_slice(&1000u32.to_be_bytes());
    assert_eq!(Response::parse(&r).err(), Some(CodecError::LengthMismatch { declared: 1000, actual: 14 }));
    // Declared shorter than the buffer: trailing bytes would be attributed to
    // this response.
    r[2..6].copy_from_slice(&12u32.to_be_bytes());
    assert_eq!(Response::parse(&r).err(), Some(CodecError::LengthMismatch { declared: 12, actual: 14 }));
    // Declared shorter than the header itself.
    r[2..6].copy_from_slice(&4u32.to_be_bytes());
    assert_eq!(Response::parse(&r).err(), Some(CodecError::LengthUnderHeader { declared: 4 }));
}

#[test]
fn an_unknown_tag_is_rejected() {
    let mut r = response(TPM2_ST_NO_SESSIONS, 0, &[]);
    r[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    assert_eq!(Response::parse(&r).err(), Some(CodecError::BadTag(0x1234)));
}

#[test]
fn a_failing_response_code_cannot_be_read_as_success() {
    for raw in [TPM2_RC_FAILURE, TPM2_RC_TESTING, 0x18B, 1] {
        let r = response(TPM2_ST_NO_SESSIONS, raw, &[0; 4]);
        let rsp = Response::parse(&r).unwrap();
        assert_eq!(rsp.rc(), Rc::new(raw));
        assert_eq!(rsp.ok(), Err(CodecError::Device(Rc::new(raw))));
        assert!(rsp.reader().is_err(), "0x{raw:X} must not yield a body reader");
    }
    let good = response(TPM2_ST_NO_SESSIONS, 0, &[0; 4]);
    assert!(Response::parse(&good).unwrap().ok().is_ok());
}

#[test]
fn a_session_tagged_response_hides_its_parameter_size() {
    let mut body = Vec::new();
    body.extend_from_slice(&4u32.to_be_bytes());
    body.extend_from_slice(&[9, 8, 7, 6]);
    let r = response(TPM2_ST_SESSIONS, 0, &body);
    let rsp = Response::parse(&r).unwrap();
    assert_eq!(rsp.parameters().unwrap(), &[9, 8, 7, 6]);
    let r0 = response(TPM2_ST_NO_SESSIONS, 0, &[9, 8, 7, 6]);
    assert_eq!(Response::parse(&r0).unwrap().parameters().unwrap(), &[9, 8, 7, 6]);
}

#[test]
fn a_session_tagged_response_with_a_lying_parameter_size_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&64u32.to_be_bytes());
    body.extend_from_slice(&[9, 8]);
    let r = response(TPM2_ST_SESSIONS, 0, &body);
    assert_eq!(Response::parse(&r).unwrap().parameters().err(), Some(CodecError::Truncated { need: 64, have: 2 }));
}

#[test]
fn pcr_read_response_parses() {
    let mut body = Vec::new();
    body.extend_from_slice(&7u32.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&Alg::Sha256.id().to_be_bytes());
    body.push(3);
    body.extend_from_slice(&[0x08, 0, 0]);
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&32u16.to_be_bytes());
    body.extend_from_slice(&[0xAB; 32]);
    let r = response(TPM2_ST_NO_SESSIONS, 0, &body);
    let rsp = Response::parse(&r).unwrap();
    let out = cmds::parse_pcr_read(&rsp).unwrap();
    assert_eq!(out.update_counter, 7);
    assert_eq!(out.alg_id, Alg::Sha256.id());
    assert_eq!(out.digest, &[0xAB; 32]);
}

#[test]
fn a_truncated_pcr_read_response_is_rejected_not_padded() {
    let mut body = Vec::new();
    body.extend_from_slice(&7u32.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&Alg::Sha256.id().to_be_bytes());
    body.push(3);
    body.extend_from_slice(&[0x08, 0, 0]);
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&32u16.to_be_bytes());
    body.extend_from_slice(&[0xAB; 8]);
    let r = response(TPM2_ST_NO_SESSIONS, 0, &body);
    let rsp = Response::parse(&r).unwrap();
    assert_eq!(cmds::parse_pcr_read(&rsp).err(), Some(CodecError::Truncated { need: 32, have: 8 }));
}

#[test]
fn random_response_parses_and_bounds_itself() {
    let mut body = Vec::new();
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&[1, 2, 3, 4]);
    let r = response(TPM2_ST_NO_SESSIONS, 0, &body);
    assert_eq!(cmds::parse_get_random(&Response::parse(&r).unwrap()).unwrap(), &[1, 2, 3, 4]);

    let mut lying = Vec::new();
    lying.extend_from_slice(&64u16.to_be_bytes());
    lying.extend_from_slice(&[1, 2, 3, 4]);
    let r = response(TPM2_ST_NO_SESSIONS, 0, &lying);
    assert_eq!(cmds::parse_get_random(&Response::parse(&r).unwrap()).err(),
               Some(CodecError::Truncated { need: 64, have: 4 }));
}

#[test]
fn capability_response_parses() {
    let mut body = Vec::new();
    body.push(0);
    body.extend_from_slice(&TPM2_CAP_TPM_PROPERTIES.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&TPM2_PT_TOTAL_COMMANDS.to_be_bytes());
    body.extend_from_slice(&99u32.to_be_bytes());
    let r = response(TPM2_ST_NO_SESSIONS, 0, &body);
    let rsp = Response::parse(&r).unwrap();
    let mut out = cmds::parse_get_capability(&rsp).unwrap();
    assert!(!out.more_data);
    assert_eq!(out.capability, TPM2_CAP_TPM_PROPERTIES);
    assert_eq!(out.reader.u32().unwrap(), 1);
    assert_eq!(out.reader.u32().unwrap(), TPM2_PT_TOTAL_COMMANDS);
    assert_eq!(out.reader.u32().unwrap(), 99);
    assert!(out.reader.is_empty());
}

#[test]
fn a_response_handle_is_read_ahead_of_the_parameters() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x8000_0002u32.to_be_bytes());
    body.extend_from_slice(&[0xEE; 4]);
    let r = response(TPM2_ST_NO_SESSIONS, 0, &body);
    let rsp = Response::parse(&r).unwrap();
    assert_eq!(cmds::parse_handle(&rsp).unwrap(), 0x8000_0002);
    assert_eq!(rsp.parameters_after(1).unwrap(), &[0xEE; 4]);
}

#[test]
fn the_reader_never_walks_past_its_buffer() {
    let buf = [1u8, 2, 3];
    let mut r = Reader::new(&buf);
    assert_eq!(r.u8().unwrap(), 1);
    assert_eq!(r.u16().unwrap(), 0x0203);
    assert_eq!(r.u8().err(), Some(CodecError::Truncated { need: 1, have: 0 }));
    let mut r = Reader::new(&buf);
    assert_eq!(r.u32().err(), Some(CodecError::Truncated { need: 4, have: 3 }));
    assert_eq!(r.remaining(), 3);
}
