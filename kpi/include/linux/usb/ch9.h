#ifndef OXIDE_LINUX_USB_CH9_H
#define OXIDE_LINUX_USB_CH9_H

#include <linux/types.h>

#define USB_DIR_OUT             0x00
#define USB_DIR_IN              0x80
#define USB_TYPE_STANDARD       0x00
#define USB_TYPE_CLASS          0x20
#define USB_TYPE_VENDOR         0x40
#define USB_RECIP_DEVICE        0x00
#define USB_RECIP_INTERFACE     0x01
#define USB_DT_DEVICE           0x01
#define USB_DT_CONFIG           0x02
#define USB_DT_STRING           0x03
#define USB_DT_INTERFACE        0x04
#define USB_DT_ENDPOINT         0x05
#define USB_ENDPOINT_XFER_CONTROL 0
#define USB_ENDPOINT_XFER_ISOC    1
#define USB_ENDPOINT_XFER_BULK    2
#define USB_ENDPOINT_XFER_INT     3
#define USB_ENDPOINT_XFERTYPE_MASK 3

struct usb_device_descriptor {
    __u8 bLength;
    __u8 bDescriptorType;
    __u16 bcdUSB;
    __u8 bDeviceClass;
    __u8 bDeviceSubClass;
    __u8 bDeviceProtocol;
    __u8 bMaxPacketSize0;
    __u16 idVendor;
    __u16 idProduct;
    __u16 bcdDevice;
    __u8 iManufacturer;
    __u8 iProduct;
    __u8 iSerialNumber;
    __u8 bNumConfigurations;
};

struct usb_endpoint_descriptor {
    __u8 bLength;
    __u8 bDescriptorType;
    __u8 bEndpointAddress;
    __u8 bmAttributes;
    __u16 wMaxPacketSize;
    __u8 bInterval;
};

struct usb_interface_descriptor {
    __u8 bLength;
    __u8 bDescriptorType;
    __u8 bInterfaceNumber;
    __u8 bAlternateSetting;
    __u8 bNumEndpoints;
    __u8 bInterfaceClass;
    __u8 bInterfaceSubClass;
    __u8 bInterfaceProtocol;
    __u8 iInterface;
};

#endif
