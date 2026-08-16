// One writer for `struct snd_pcm_info`, shared by the control node's
// SNDRV_CTL_IOCTL_PCM_INFO and by each substream's SNDRV_PCM_IOCTL_INFO, so
// the two can never disagree about a card's device identity.

use crate::uapi::*;

/// Subdevices this core publishes per PCM device.
const SUBDEVICES: u32 = 1;

/// Fill `snd_pcm_info` for device 0, subdevice 0 of `card`. # C: O(struct size)
pub(crate) fn write(b: &UserBuf, card: u32, stream: i32, id: &[u8], name: &[u8]) {
    b.zero(0, PCM_INFO_SIZE);
    b.w32(PI_DEVICE, 0);
    b.w32(PI_SUBDEVICE, 0);
    b.w32(PI_STREAM, stream as u32);
    b.w32(PI_CARD, card);
    b.wstr(PI_ID, id, 64);
    b.wstr(PI_NAME, name, 80);
    b.wstr(PI_SUBNAME, b"subdevice #0", 32);
    b.w32(PI_SUBDEVICES_COUNT, SUBDEVICES);
    b.w32(PI_SUBDEVICES_AVAIL, SUBDEVICES);
}
