#ifndef OXIDE_LINUX_INPUT_H
#define OXIDE_LINUX_INPUT_H

#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/input-event-codes.h>
#include <linux/types.h>

#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(nr) (((nr) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#endif

#define BUS_HOST        0x19
#define BUS_VIRTUAL     0x06
#define INPUT_MAJOR     13

struct input_id {
    __u16 bustype;
    __u16 vendor;
    __u16 product;
    __u16 version;
};

struct input_absinfo {
    __s32 value;
    __s32 minimum;
    __s32 maximum;
    __s32 fuzz;
    __s32 flat;
    __s32 resolution;
};

struct input_event {
    long tv_sec;
    long tv_usec;
    __u16 type;
    __u16 code;
    __s32 value;
};

struct input_dev {
    const char *name;
    const char *phys;
    const char *uniq;
    struct input_id id;
    struct device dev;
    void *private_data;
    unsigned long propbit[BITS_TO_LONGS(INPUT_PROP_CNT)];
    unsigned long evbit[BITS_TO_LONGS(EV_CNT)];
    unsigned long keybit[BITS_TO_LONGS(KEY_CNT)];
    unsigned long relbit[BITS_TO_LONGS(REL_CNT)];
    unsigned long absbit[BITS_TO_LONGS(ABS_CNT)];
    unsigned long mscbit[BITS_TO_LONGS(MSC_CNT)];
    unsigned long ledbit[BITS_TO_LONGS(LED_CNT)];
    unsigned long sndbit[BITS_TO_LONGS(SND_CNT)];
    unsigned long ffbit[BITS_TO_LONGS(FF_CNT)];
    unsigned long swbit[BITS_TO_LONGS(SW_CNT)];
    struct input_absinfo absinfo[ABS_CNT];
    unsigned long key[BITS_TO_LONGS(KEY_CNT)];
    unsigned long led[BITS_TO_LONGS(LED_CNT)];
    unsigned long snd[BITS_TO_LONGS(SND_CNT)];
    unsigned long sw[BITS_TO_LONGS(SW_CNT)];
    unsigned int evdev_id;
    unsigned int registered;
    unsigned int oxide_key;
};

struct input_dev *input_allocate_device(void);
void input_free_device(struct input_dev *dev);
int input_register_device(struct input_dev *dev);
void input_unregister_device(struct input_dev *dev);
void input_set_capability(struct input_dev *dev, unsigned int type, unsigned int code);
void input_set_abs_params(struct input_dev *dev, unsigned int axis, int min, int max, int fuzz, int flat);
void input_event(struct input_dev *dev, unsigned int type, unsigned int code, int value);
void input_report_key(struct input_dev *dev, unsigned int code, int value);
void input_report_abs(struct input_dev *dev, unsigned int code, int value);
void input_report_rel(struct input_dev *dev, unsigned int code, int value);
void input_sync(struct input_dev *dev);
void input_set_drvdata(struct input_dev *dev, void *data);
void *input_get_drvdata(struct input_dev *dev);

#endif
