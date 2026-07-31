// A `/dev/snd/*` node is identified by the `SndData` its inode owns, never by
// the tag in its inode NUMBER. Gating on the tag first and reading the backend
// state second CONSUMED the ioctl with EINVAL for any inode that merely carried
// the tag — an errno the dispatch chain reads as "answered", so the stage that
// actually owned the command never ran.

use alloc::sync::Arc;
use vfs::pseudo_ino::SOUND;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, Ino, InodeBuilder, InodeRef};

use crate::device::{handle_ioctl, make_snd_inode, snd_data_of, MINOR_CONTROL, MINOR_MIXER,
                    MINOR_PCM_C, MINOR_PCM_P};
use crate::uapi::CTL_MAGIC;

/// A card number high enough not to collide with a published card.
const TEST_CARD: u32 = 0x7f;
/// `SNDRV_CTL_IOCTL_CARD_INFO` shape: group `CTL_MAGIC`, command 0x01.
const CTL_REQUEST: u64 = (CTL_MAGIC << 8) | 0x01;

struct ForeignState;

fn foreign_inode(ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0), default_inode_ops(), default_file_ops())
        .private(Arc::new(ForeignState))
        .build()
}

fn bare_inode(ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0), default_inode_ops(), default_file_ops())
        .build()
}

#[test]
fn published_sound_numbers_fall_inside_the_sound_region() {
    for minor in [MINOR_CONTROL, MINOR_PCM_P, MINOR_PCM_C, MINOR_MIXER] {
        for card in [0u32, TEST_CARD] {
            let ino = make_snd_inode(super::key(0x7f00), card, minor).ino();
            assert!(SOUND.contains(ino), "{ino:#x} outside {}", SOUND.name());
        }
    }
}

#[test]
fn a_real_sound_inode_resolves_to_its_own_owner_card_and_minor() {
    let owner = super::key(0x7f01);
    let inode = make_snd_inode(owner, TEST_CARD, MINOR_PCM_P);
    let data = snd_data_of(&inode).expect("sound node resolves");
    assert_eq!(data.owner, owner);
    assert_eq!(data.card, TEST_CARD);
    assert_eq!(data.minor, MINOR_PCM_P);
}

#[test]
fn an_inode_carrying_the_sound_tag_without_backend_state_falls_through() {
    // The defect: EINVAL here is an ANSWER, and it stopped the dispatch chain
    // before the stage that owns the command. Declining is the only correct
    // reply from a handler that does not recognise the file.
    for ino in [SOUND.start(), SOUND.start() | MINOR_PCM_P, SOUND.end()] {
        assert!(snd_data_of(&bare_inode(ino)).is_none(), "{ino:#x}");
        assert_eq!(handle_ioctl(&bare_inode(ino), CTL_REQUEST, 0), None, "{ino:#x}");
    }
}

#[test]
fn a_foreign_inode_reusing_a_sound_number_is_declined() {
    let real = make_snd_inode(super::key(0x7f02), 0, MINOR_CONTROL);
    assert!(snd_data_of(&real).is_some());
    let stranger = foreign_inode(real.ino());
    assert!(snd_data_of(&stranger).is_none());
    assert_eq!(handle_ioctl(&stranger, CTL_REQUEST, 0), None);
}

#[test]
fn a_sound_inode_outside_the_region_still_resolves() {
    // Identity follows the state, not the number: renumbering the region
    // cannot make a real sound node stop being one.
    let inode = make_snd_inode(super::key(0x7f03), 0, MINOR_MIXER);
    assert!(snd_data_of(&inode).is_some());
    assert!(snd_data_of(&foreign_inode(0)).is_none());
    assert_eq!(handle_ioctl(&foreign_inode(0), CTL_REQUEST, 0), None);
}
