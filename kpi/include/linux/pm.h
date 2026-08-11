#ifndef OXIDE_LINUX_PM_H
#define OXIDE_LINUX_PM_H

#include <linux/types.h>

struct device;
struct wakeup_source;
struct wake_irq;
struct pm_subsys_data;
struct dev_pm_qos;
struct list_head;
typedef struct { int counter; } atomic_t;

#define PM_EVENT_ON 0x0000
#define PM_EVENT_FREEZE 0x0001
#define PM_EVENT_SUSPEND 0x0002
#define PM_EVENT_HIBERNATE 0x0004
#define PM_EVENT_RESUME 0x0010
#define PM_EVENT_THAW 0x0020
#define PM_EVENT_RESTORE 0x0040

typedef struct pm_message {
    int event;
} pm_message_t;

#define PMSG_ON ((pm_message_t){ PM_EVENT_ON })
#define PMSG_FREEZE ((pm_message_t){ PM_EVENT_FREEZE })
#define PMSG_SUSPEND ((pm_message_t){ PM_EVENT_SUSPEND })
#define PMSG_HIBERNATE ((pm_message_t){ PM_EVENT_HIBERNATE })
#define PMSG_RESUME ((pm_message_t){ PM_EVENT_RESUME })
#define PMSG_THAW ((pm_message_t){ PM_EVENT_THAW })
#define PMSG_RESTORE ((pm_message_t){ PM_EVENT_RESTORE })

#define RPM_ACTIVE 0
#define RPM_RESUMING 1
#define RPM_SUSPENDED 2
#define RPM_SUSPENDING 3

struct dev_pm_info {
    pm_message_t power_state;
    bool can_wakeup:1;
    bool async_suspend:1;
    bool in_dpm_list:1;
    bool is_prepared:1;
    bool is_suspended:1;
    bool is_noirq_suspended:1;
    bool is_late_suspended:1;
    bool no_pm:1;
    bool early_init:1;
    bool direct_complete:1;
    unsigned char __power_flags_pad[2];
    u32 driver_flags;
    u32 lock;
    struct list_head *entry_words[2];
    unsigned char completion[32];
    struct wakeup_source *wakeup;
    bool work_in_progress;
    unsigned char __runtime_prefix[143];
    atomic_t usage_count;
    atomic_t child_count;
    unsigned char disable_depth:3;
    bool idle_notification:1;
    bool request_pending:1;
    bool deferred_resume:1;
    bool needs_force_resume:1;
    bool runtime_auto:1;
    bool ignore_children:1;
    bool no_callbacks:1;
    bool irq_safe:1;
    bool use_autosuspend:1;
    bool timer_autosuspends:1;
    bool memalloc_noio:1;
    u32 links_count;
    int request;
    int runtime_status;
    int last_status;
    int runtime_error;
    int autosuspend_delay;
    u32 __runtime_pad;
    u64 last_busy;
    u64 active_time;
    u64 suspended_time;
    u64 accounting_timestamp;
    struct pm_subsys_data *subsys_data;
    void (*set_latency_tolerance)(struct device *, s32);
    struct dev_pm_qos *qos;
    bool detach_power_off:1;
    unsigned char __tail[7];
};

struct dev_pm_ops {
    int (*prepare)(struct device *dev);
    void (*complete)(struct device *dev);
    int (*suspend)(struct device *dev);
    int (*resume)(struct device *dev);
    int (*freeze)(struct device *dev);
    int (*thaw)(struct device *dev);
    int (*poweroff)(struct device *dev);
    int (*restore)(struct device *dev);
    int (*suspend_late)(struct device *dev);
    int (*resume_early)(struct device *dev);
    int (*runtime_suspend)(struct device *dev);
    int (*runtime_resume)(struct device *dev);
    int (*runtime_idle)(struct device *dev);
};

#define SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
    .suspend = (suspend_fn), .resume = (resume_fn), \
    .freeze = (suspend_fn), .thaw = (resume_fn), \
    .poweroff = (suspend_fn), .restore = (resume_fn)

#define SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
    .runtime_suspend = (suspend_fn), \
    .runtime_resume = (resume_fn), \
    .runtime_idle = (idle_fn)

#define SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
    const struct dev_pm_ops name = { SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) }

#define DEFINE_SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
    SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn)

#define UNIVERSAL_DEV_PM_OPS(name, suspend_fn, resume_fn, idle_fn) \
    const struct dev_pm_ops name = { \
        SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn), \
        SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn), \
    }

int dev_pm_suspend(struct device *dev);
int dev_pm_resume(struct device *dev);

#endif
