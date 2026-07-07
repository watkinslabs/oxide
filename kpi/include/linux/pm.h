#ifndef OXIDE_LINUX_PM_H
#define OXIDE_LINUX_PM_H

#include <linux/types.h>

struct device;

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
    int runtime_status;
    int disable_depth;
    int usage_count;
    int runtime_error;
    int autosuspend_delay;
    unsigned long last_busy;
    bool use_autosuspend;
    bool can_wakeup;
    bool wakeup_enabled;
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
