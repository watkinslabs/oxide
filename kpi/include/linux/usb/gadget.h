#ifndef OXIDE_LINUX_USB_GADGET_H
#define OXIDE_LINUX_USB_GADGET_H

#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/usb/ch9.h>

#define USB_SPEED_SUPER      4
#define USB_SPEED_SUPER_PLUS 5
#define USB_STATE_NOTATTACHED 0
#define USB_STATE_ATTACHED    1
#define USB_STATE_POWERED     2
#define USB_STATE_DEFAULT     3
#define USB_STATE_ADDRESS     4
#define USB_STATE_CONFIGURED  5

struct usb_ep;
struct usb_request;
struct usb_gadget;
struct usb_gadget_driver;
struct usb_ss_ep_comp_descriptor;

struct usb_ep_caps {
    u8 type_control;
    u8 type_iso;
    u8 type_bulk;
    u8 type_int;
    u8 dir_in;
    u8 dir_out;
};

struct usb_ep_ops {
    int (*enable)(struct usb_ep *ep, const struct usb_endpoint_descriptor *desc);
    int (*disable)(struct usb_ep *ep);
    struct usb_request *(*alloc_request)(struct usb_ep *ep, gfp_t gfp_flags);
    void (*free_request)(struct usb_ep *ep, struct usb_request *req);
    int (*queue)(struct usb_ep *ep, struct usb_request *req, gfp_t gfp_flags);
    int (*dequeue)(struct usb_ep *ep, struct usb_request *req);
};

struct usb_ep {
    const char *name;
    const struct usb_ep_ops *ops;
    struct list_head ep_list;
    struct usb_ep_caps caps;
    u16 maxpacket;
    u16 maxpacket_limit;
    u16 max_streams;
    u8 enabled;
    u8 address;
    const struct usb_endpoint_descriptor *desc;
    void *driver_data;
};

struct usb_request {
    void *buf;
    dma_addr_t dma;
    unsigned int length;
    unsigned int actual;
    int status;
    u8 zero;
    u8 short_not_ok;
    u8 no_interrupt;
    void (*complete)(struct usb_ep *ep, struct usb_request *req);
    void *context;
    struct list_head list;
};

struct usb_ctrlrequest {
    __u8 bRequestType;
    __u8 bRequest;
    __u16 wValue;
    __u16 wIndex;
    __u16 wLength;
};

struct usb_gadget {
    const void *ops;
    struct usb_ep *ep0;
    struct list_head ep_list;
    int speed;
    int max_speed;
    int state;
    const char *name;
    struct device dev;
    u8 is_selfpowered;
    u8 deactivated;
    u8 connected;
    u8 remote_wakeup;
    u32 vbus_draw_ma;
    struct usb_gadget_driver *driver;
};

struct usb_gadget_driver {
    const char *function;
    int max_speed;
    int (*bind)(struct usb_gadget *gadget, struct usb_gadget_driver *driver);
    void (*unbind)(struct usb_gadget *gadget);
    int (*setup)(struct usb_gadget *gadget, const struct usb_ctrlrequest *ctrl);
    void (*disconnect)(struct usb_gadget *gadget);
    void (*suspend)(struct usb_gadget *gadget);
    void (*resume)(struct usb_gadget *gadget);
    void (*reset)(struct usb_gadget *gadget);
    struct device_driver *driver;
};

struct usb_request *usb_ep_alloc_request(struct usb_ep *ep, gfp_t gfp_flags);
void usb_ep_free_request(struct usb_ep *ep, struct usb_request *req);
int usb_ep_queue(struct usb_ep *ep, struct usb_request *req, gfp_t gfp_flags);
int usb_ep_dequeue(struct usb_ep *ep, struct usb_request *req);
int usb_gadget_register_driver_owner(struct usb_gadget_driver *driver, struct module *owner);
#define usb_gadget_register_driver(driver) usb_gadget_register_driver_owner((driver), THIS_MODULE)
void usb_gadget_unregister_driver(struct usb_gadget_driver *driver);
int usb_gadget_activate(struct usb_gadget *gadget);
int usb_gadget_deactivate(struct usb_gadget *gadget);
int usb_gadget_set_selfpowered(struct usb_gadget *gadget);
int usb_gadget_clear_selfpowered(struct usb_gadget *gadget);
int usb_gadget_set_remote_wakeup(struct usb_gadget *gadget, int enabled);
int usb_gadget_vbus_draw(struct usb_gadget *gadget, unsigned int ma);
void usb_gadget_set_state(struct usb_gadget *gadget, int state);
int usb_gadget_check_config(struct usb_gadget *gadget);
int usb_gadget_ep_match_desc(struct usb_gadget *gadget, struct usb_ep *ep,
    const struct usb_endpoint_descriptor *desc,
    const struct usb_ss_ep_comp_descriptor *ep_comp);
const char *usb_speed_string(int speed);

static inline void usb_ep_set_maxpacket_limit(struct usb_ep *ep, unsigned int maxpacket_limit)
{
    ep->maxpacket_limit = (u16)maxpacket_limit;
}

static inline void usb_ep_set_drvdata(struct usb_ep *ep, void *data)
{
    ep->driver_data = data;
}

static inline void *usb_ep_get_drvdata(const struct usb_ep *ep)
{
    return ep->driver_data;
}

#endif
