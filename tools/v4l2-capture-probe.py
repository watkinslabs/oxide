#!/usr/bin/env python3
"""One real capture through /dev/video0, from inside the guest.

Node presence proves publication and nothing else. This drives the whole
path an application drives — QUERYCAP, format negotiation, buffer
allocation, mmap, queue, stream on, blocking dequeue — and reports the
frame's payload and the first bytes of the mapped page, so a completed
buffer is evidence rather than an inference.

Typed into the guest's debug shell by tools/boot-smoke-v4l2.sh.
"""
import fcntl, mmap, struct, sys

QUERYCAP = 0x80685600
G_FMT = 0xC0D05604
REQBUFS = 0xC0145608
QUERYBUF = 0xC0585609
QBUF = 0xC058560F
DQBUF = 0xC0585611
STREAMON = 0x40045612
STREAMOFF = 0x40045613
CAPTURE, MMAP_MEM = 1, 1


def fail(why):
    print("v4l2_probe: FAIL - %s" % why)
    sys.exit(1)


try:
    fd = open("/dev/video0", "rb+", buffering=0)
except Exception as e:
    fail("open /dev/video0: %s" % e)

cap = bytearray(104)
fcntl.ioctl(fd, QUERYCAP, cap, True)
driver = bytes(cap[0:16]).split(b"\0")[0].decode()
card = bytes(cap[16:48]).split(b"\0")[0].decode()
caps, devcaps = struct.unpack_from("<II", cap, 84)
print("v4l2_probe: driver=%s card=%s caps=%#x device_caps=%#x" % (driver, card, caps, devcaps))
if not devcaps & 0x1:
    fail("device does not report capture")
if not devcaps & 0x4000000:
    fail("device does not report streaming")

fmt = bytearray(208)
struct.pack_into("<I", fmt, 0, CAPTURE)
fcntl.ioctl(fd, G_FMT, fmt, True)
w, h, pixfmt, _field, bpl, sizeimage = struct.unpack_from("<IIIIII", fmt, 8)
print("v4l2_probe: fmt=%dx%d fourcc=%s bytesperline=%d sizeimage=%d"
      % (w, h, struct.pack("<I", pixfmt).decode("ascii", "replace"), bpl, sizeimage))
if sizeimage == 0:
    fail("format has no image size")

req = bytearray(20)
struct.pack_into("<III", req, 0, 2, CAPTURE, MMAP_MEM)
fcntl.ioctl(fd, REQBUFS, req, True)
count = struct.unpack_from("<I", req, 0)[0]
print("v4l2_probe: reqbufs count=%d" % count)
if count < 1:
    fail("no buffers allocated")

maps = []
for i in range(count):
    b = bytearray(88)
    struct.pack_into("<II", b, 0, i, CAPTURE)
    struct.pack_into("<I", b, 60, MMAP_MEM)
    fcntl.ioctl(fd, QUERYBUF, b, True)
    offset = struct.unpack_from("<I", b, 64)[0]
    length = struct.unpack_from("<I", b, 72)[0]
    if length < sizeimage:
        fail("buffer %d is %d bytes for a %d-byte image" % (i, length, sizeimage))
    try:
        maps.append(mmap.mmap(fd.fileno(), length, mmap.MAP_SHARED,
                              mmap.PROT_READ, offset=offset))
    except Exception as e:
        fail("mmap buffer %d at offset %#x: %s" % (i, offset, e))
    fcntl.ioctl(fd, QBUF, b, True)
print("v4l2_probe: mapped and queued %d buffers" % count)

fcntl.ioctl(fd, STREAMON, struct.pack("<i", CAPTURE))
print("v4l2_probe: streaming")

seen = 0
for _ in range(3):
    d = bytearray(88)
    struct.pack_into("<II", d, 0, 0, CAPTURE)
    struct.pack_into("<I", d, 60, MMAP_MEM)
    fcntl.ioctl(fd, DQBUF, d, True)
    index, = struct.unpack_from("<I", d, 0)
    bytesused, flags = struct.unpack_from("<II", d, 8)
    seq, = struct.unpack_from("<I", d, 56)
    tv_sec, tv_usec = struct.unpack_from("<qq", d, 24)
    head = maps[index][:8].hex()
    nonzero = any(maps[index][:sizeimage:997])
    print("v4l2_probe: frame index=%d bytesused=%d seq=%d flags=%#x ts=%d.%06d head=%s nonzero=%s"
          % (index, bytesused, seq, flags, tv_sec, tv_usec, head, nonzero))
    if bytesused == 0:
        fail("frame %d carried no payload" % seq)
    if not flags & 0x4:
        fail("frame %d came back without the done flag" % seq)
    if not nonzero:
        fail("frame %d is entirely zero — nothing was written into the buffer" % seq)
    seen += 1
    fcntl.ioctl(fd, QBUF, d, True)

fcntl.ioctl(fd, STREAMOFF, struct.pack("<i", CAPTURE))
print("v4l2_probe: PASS - %d frames captured" % seen)
