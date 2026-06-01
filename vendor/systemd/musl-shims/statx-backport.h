/* statx backport for the old aarch64-linux-musl-cross toolchain whose
 * musl <sys/stat.h> predates musl 1.2.0 (no struct statx). systemd 259's
 * musl shim (src/include/musl/sys/stat.h) #include_next's the toolchain's
 * <sys/stat.h> then uses struct statx unconditionally. build.sh appends
 * this to the arm toolchain's sys/stat.h when struct statx is absent.
 * Definitions match musl 1.2.x (and the kernel UAPI struct statx). */
#ifndef __OXIDE_STATX_BACKPORT
#define __OXIDE_STATX_BACKPORT
#include <stdint.h>
struct statx_timestamp { int64_t tv_sec; uint32_t tv_nsec; int32_t __statx_timestamp_pad1[1]; };
struct statx {
	uint32_t stx_mask;
	uint32_t stx_blksize;
	uint64_t stx_attributes;
	uint32_t stx_nlink;
	uint32_t stx_uid;
	uint32_t stx_gid;
	uint16_t stx_mode;
	uint16_t __statx_pad1[1];
	uint64_t stx_ino;
	uint64_t stx_size;
	uint64_t stx_blocks;
	uint64_t stx_attributes_mask;
	struct statx_timestamp stx_atime;
	struct statx_timestamp stx_btime;
	struct statx_timestamp stx_ctime;
	struct statx_timestamp stx_mtime;
	uint32_t stx_rdev_major;
	uint32_t stx_rdev_minor;
	uint32_t stx_dev_major;
	uint32_t stx_dev_minor;
	uint64_t stx_mnt_id;
	uint64_t __statx_pad2;
	uint64_t __pad1[12];
};
int statx(int, const char *, int, unsigned, struct statx *);
#define STATX_TYPE         0x00000001U
#define STATX_MODE         0x00000002U
#define STATX_NLINK        0x00000004U
#define STATX_UID          0x00000008U
#define STATX_GID          0x00000010U
#define STATX_ATIME        0x00000020U
#define STATX_MTIME        0x00000040U
#define STATX_CTIME        0x00000080U
#define STATX_INO          0x00000100U
#define STATX_SIZE         0x00000200U
#define STATX_BLOCKS       0x00000400U
#define STATX_BASIC_STATS  0x000007ffU
#define STATX_BTIME        0x00000800U
#define STATX_MNT_ID       0x00001000U
#define AT_STATX_SYNC_AS_STAT 0x0000
#define AT_STATX_FORCE_SYNC   0x2000
#define AT_STATX_DONT_SYNC    0x4000
#endif
