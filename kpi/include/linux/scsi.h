#ifndef OXIDE_LINUX_SCSI_H
#define OXIDE_LINUX_SCSI_H

#include <linux/types.h>

#define SCSI_SENSE_BUFFERSIZE 96
#define TYPE_DISK 0x00
#define TYPE_TAPE 0x01
#define TYPE_ROM  0x05
#define TYPE_RAID 0x0c
#define TYPE_ZBC  0x14

struct scsi_lun {
    u8 scsi_lun[8];
};

extern const unsigned char scsi_command_size_tbl[8];
extern const char * const scsi_device_type[32];

void int_to_scsilun(u64 lun, struct scsi_lun *scsilun);
bool scsi_build_sense_buffer(int desc, u8 *buf, u8 key, u8 asc, u8 ascq);
void scsi_set_sense_information(u8 *buf, int buflen, u64 info);

static inline unsigned int scsi_command_size(const unsigned char *cmnd)
{
    return scsi_command_size_tbl[cmnd[0] >> 5];
}

#endif
