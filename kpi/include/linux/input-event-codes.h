#ifndef OXIDE_LINUX_INPUT_EVENT_CODES_H
#define OXIDE_LINUX_INPUT_EVENT_CODES_H

#define EV_SYN          0x00
#define EV_KEY          0x01
#define EV_REL          0x02
#define EV_ABS          0x03
#define EV_MSC          0x04
#define EV_SW           0x05
#define EV_LED          0x11
#define EV_SND          0x12
#define EV_REP          0x14
#define EV_FF           0x15
#define EV_PWR          0x16
#define EV_MAX          0x1f
#define EV_CNT          (EV_MAX + 1)

#define SYN_REPORT      0
#define SYN_CONFIG      1
#define SYN_MT_REPORT   2
#define SYN_DROPPED     3

#define KEY_A           30
#define KEY_B           48
#define KEY_C           46
#define KEY_ENTER       28
#define KEY_ESC         1
#define BTN_LEFT        0x110
#define BTN_RIGHT       0x111
#define KEY_MAX         0x2ff
#define KEY_CNT         (KEY_MAX + 1)

#define REL_X           0x00
#define REL_Y           0x01
#define REL_WHEEL       0x08
#define REL_MAX         0x0f
#define REL_CNT         (REL_MAX + 1)

#define ABS_X           0x00
#define ABS_Y           0x01
#define ABS_Z           0x02
#define ABS_RX          0x03
#define ABS_RY          0x04
#define ABS_RZ          0x05
#define ABS_PRESSURE    0x18
#define ABS_MT_SLOT     0x2f
#define ABS_MT_TOUCH_MAJOR 0x30
#define ABS_MT_TRACKING_ID 0x39
#define ABS_MT_TOOL_Y   0x3d
#define ABS_MAX         0x3f
#define ABS_CNT         (ABS_MAX + 1)

#define MSC_MAX         0x07
#define MSC_CNT         (MSC_MAX + 1)

#define SW_MAX          0x11
#define SW_CNT          (SW_MAX + 1)

#define LED_NUML        0x00
#define LED_CAPSL       0x01
#define LED_SCROLLL     0x02
#define LED_MAX         0x0f
#define LED_CNT         (LED_MAX + 1)

#define SND_MAX         0x07
#define SND_CNT         (SND_MAX + 1)

#define REP_DELAY       0
#define REP_PERIOD      1
#define REP_MAX         1
#define REP_CNT         (REP_MAX + 1)

#define FF_MAX          0x7f
#define FF_CNT          (FF_MAX + 1)

#define INPUT_PROP_POINTER 0x00
#define INPUT_PROP_DIRECT  0x01
#define INPUT_PROP_MAX     0x1f
#define INPUT_PROP_CNT     (INPUT_PROP_MAX + 1)

#endif
