#ifndef OXIDE_LINUX_USB_H
#define OXIDE_LINUX_USB_H

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/usb/ch9.h>

#define USB_DEVICE_ID_MATCH_VENDOR        0x0001
#define USB_DEVICE_ID_MATCH_PRODUCT       0x0002
#define USB_DEVICE_ID_MATCH_DEV_LO        0x0004
#define USB_DEVICE_ID_MATCH_DEV_HI        0x0008
#define USB_DEVICE_ID_MATCH_DEV_CLASS     0x0010
#define USB_DEVICE_ID_MATCH_DEV_SUBCLASS  0x0020
#define USB_DEVICE_ID_MATCH_DEV_PROTOCOL  0x0040
#define USB_DEVICE_ID_MATCH_INT_CLASS     0x0080
#define USB_DEVICE_ID_MATCH_INT_SUBCLASS  0x0100
#define USB_DEVICE_ID_MATCH_INT_PROTOCOL  0x0200
#define USB_DEVICE(vend, prod) \
    .match_flags = USB_DEVICE_ID_MATCH_VENDOR | USB_DEVICE_ID_MATCH_PRODUCT, \
    .idVendor = (vend), .idProduct = (prod)
#define USB_INTERFACE_INFO(cl, sc, pr) \
    .match_flags = USB_DEVICE_ID_MATCH_INT_CLASS | USB_DEVICE_ID_MATCH_INT_SUBCLASS | USB_DEVICE_ID_MATCH_INT_PROTOCOL, \
    .bInterfaceClass = (cl), .bInterfaceSubClass = (sc), .bInterfaceProtocol = (pr)

#define USB_CLASS_PER_INTERFACE 0
#define USB_CLASS_HID           3
#define USB_SPEED_UNKNOWN       0
#define USB_SPEED_LOW           1
#define USB_SPEED_FULL          2
#define USB_SPEED_HIGH          3
#define URB_NO_TRANSFER_DMA_MAP 0x0004
#define USB_PIPE_DIR_SHIFT      7
#define USB_PIPE_DIR_IN         (USB_DIR_IN << USB_PIPE_DIR_SHIFT)

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "oxide"
#endif

struct usb_device;
struct usb_interface;
struct urb;

struct usb_host_interface {
    struct usb_interface_descriptor desc;
    struct usb_endpoint_descriptor *endpoint;
    const unsigned char *extra;
    int extralen;
};

struct usb_device {
    struct device dev;
    struct usb_device_descriptor descriptor;
    int devnum;
    int speed;
    int maxchild;
    void *driver_data;
    unsigned int refcnt;
};

struct usb_interface {
    struct device dev;
    struct usb_host_interface *altsetting;
    struct usb_host_interface *cur_altsetting;
    unsigned int num_altsetting;
    struct usb_device *usb_dev;
    void *intfdata;
    unsigned int registered;
    struct usb_driver *driver;
};

struct usb_driver {
    const char *name;
    int (*probe)(struct usb_interface *intf, const struct usb_device_id *id);
    void (*disconnect)(struct usb_interface *intf);
    const struct usb_device_id *id_table;
};

struct urb {
    struct usb_device *dev;
    unsigned int pipe;
    int status;
    unsigned int transfer_flags;
    void *transfer_buffer;
    int transfer_buffer_length;
    int actual_length;
    unsigned char *setup_packet;
    void *context;
    void (*complete)(struct urb *urb);
    int interval;
    int number_of_packets;
};

int __usb_register_driver(struct usb_driver *driver, struct module *owner, const char *mod_name);
int usb_register_driver(struct usb_driver *driver);
#define usb_register_driver(driver, owner, mod_name) __usb_register_driver((driver), (owner), (mod_name))
#define usb_register(driver) __usb_register_driver((driver), THIS_MODULE, KBUILD_MODNAME)
#define module_usb_driver(__usb_driver) \
    module_driver(__usb_driver, usb_register, usb_deregister)
void usb_deregister(struct usb_driver *driver);
struct urb *usb_alloc_urb(int iso_packets, gfp_t mem_flags);
void usb_free_urb(struct urb *urb);
int usb_submit_urb(struct urb *urb, gfp_t mem_flags);
void usb_kill_urb(struct urb *urb);
int usb_unlink_urb(struct urb *urb);
int usb_control_msg(struct usb_device *dev, unsigned int pipe, __u8 request, __u8 requesttype, __u16 value, __u16 index, void *data, __u16 size, int timeout);
int usb_bulk_msg(struct usb_device *dev, unsigned int pipe, void *data, int len, int *actual_length, int timeout);
int usb_interrupt_msg(struct usb_device *dev, unsigned int pipe, void *data, int len, int *actual_length, int timeout);
void *usb_alloc_coherent(struct usb_device *dev, size_t size, gfp_t mem_flags, dma_addr_t *dma);
void usb_free_coherent(struct usb_device *dev, size_t size, void *addr, dma_addr_t dma);
void *usb_buffer_alloc(struct usb_device *dev, size_t size, gfp_t mem_flags, dma_addr_t *dma);
void usb_buffer_free(struct usb_device *dev, size_t size, void *addr, dma_addr_t dma);
void usb_set_intfdata(struct usb_interface *intf, void *data);
void *usb_get_intfdata(struct usb_interface *intf);
struct usb_device *usb_get_dev(struct usb_device *dev);
void usb_put_dev(struct usb_device *dev);
struct usb_interface *usb_get_intf(struct usb_interface *intf);
void usb_put_intf(struct usb_interface *intf);
const struct usb_device_id *usb_match_id(struct usb_interface *intf, const struct usb_device_id *id);
struct usb_interface *usb_find_interface(struct usb_driver *driver, int minor);

static inline struct usb_device *interface_to_usbdev(struct usb_interface *intf)
{
    return intf ? intf->usb_dev : (struct usb_device *)0;
}

static inline unsigned int usb_sndctrlpipe(struct usb_device *dev, unsigned int endpoint)
{
    (void)dev; return endpoint;
}

static inline unsigned int usb_rcvctrlpipe(struct usb_device *dev, unsigned int endpoint)
{
    (void)dev; return endpoint | USB_PIPE_DIR_IN;
}

static inline unsigned int usb_sndbulkpipe(struct usb_device *dev, unsigned int endpoint)
{
    (void)dev; return endpoint;
}

static inline unsigned int usb_rcvbulkpipe(struct usb_device *dev, unsigned int endpoint)
{
    (void)dev; return endpoint | USB_PIPE_DIR_IN;
}

static inline unsigned int usb_sndintpipe(struct usb_device *dev, unsigned int endpoint)
{
    (void)dev; return endpoint;
}

static inline unsigned int usb_rcvintpipe(struct usb_device *dev, unsigned int endpoint)
{
    (void)dev; return endpoint | USB_PIPE_DIR_IN;
}

static inline int usb_pipein(unsigned int pipe)
{
    return (pipe & USB_PIPE_DIR_IN) != 0;
}

static inline int usb_endpoint_dir_in(const struct usb_endpoint_descriptor *epd)
{
    return (epd->bEndpointAddress & USB_DIR_IN) != 0;
}

static inline int usb_endpoint_dir_out(const struct usb_endpoint_descriptor *epd)
{
    return (epd->bEndpointAddress & USB_DIR_IN) == 0;
}

static inline int usb_endpoint_xfer_bulk(const struct usb_endpoint_descriptor *epd)
{
    return (epd->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK;
}

static inline int usb_endpoint_xfer_int(const struct usb_endpoint_descriptor *epd)
{
    return (epd->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_INT;
}

static inline int usb_endpoint_is_bulk_in(const struct usb_endpoint_descriptor *epd)
{
    return usb_endpoint_xfer_bulk(epd) && usb_endpoint_dir_in(epd);
}

static inline int usb_endpoint_is_bulk_out(const struct usb_endpoint_descriptor *epd)
{
    return usb_endpoint_xfer_bulk(epd) && usb_endpoint_dir_out(epd);
}

static inline int usb_endpoint_is_int_in(const struct usb_endpoint_descriptor *epd)
{
    return usb_endpoint_xfer_int(epd) && usb_endpoint_dir_in(epd);
}

static inline int usb_endpoint_is_int_out(const struct usb_endpoint_descriptor *epd)
{
    return usb_endpoint_xfer_int(epd) && usb_endpoint_dir_out(epd);
}

static inline void usb_fill_control_urb(struct urb *urb, struct usb_device *dev, unsigned int pipe,
    unsigned char *setup_packet, void *transfer_buffer, int buffer_length,
    void (*complete_fn)(struct urb *), void *context)
{
    urb->dev = dev;
    urb->pipe = pipe;
    urb->setup_packet = setup_packet;
    urb->transfer_buffer = transfer_buffer;
    urb->transfer_buffer_length = buffer_length;
    urb->complete = complete_fn;
    urb->context = context;
}

static inline void usb_fill_bulk_urb(struct urb *urb, struct usb_device *dev, unsigned int pipe,
    void *transfer_buffer, int buffer_length, void (*complete_fn)(struct urb *), void *context)
{
    urb->dev = dev;
    urb->pipe = pipe;
    urb->transfer_buffer = transfer_buffer;
    urb->transfer_buffer_length = buffer_length;
    urb->complete = complete_fn;
    urb->context = context;
}

static inline void usb_fill_int_urb(struct urb *urb, struct usb_device *dev, unsigned int pipe,
    void *transfer_buffer, int buffer_length, void (*complete_fn)(struct urb *), void *context, int interval)
{
    usb_fill_bulk_urb(urb, dev, pipe, transfer_buffer, buffer_length, complete_fn, context);
    urb->interval = interval;
}

#endif
