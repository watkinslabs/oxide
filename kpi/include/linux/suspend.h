#ifndef OXIDE_LINUX_SUSPEND_H
#define OXIDE_LINUX_SUSPEND_H

#include <linux/pm.h>

typedef int suspend_state_t;

#define PM_SUSPEND_ON 0
#define PM_SUSPEND_TO_IDLE 1
#define PM_SUSPEND_STANDBY 2
#define PM_SUSPEND_MEM 3
#define PM_SUSPEND_MAX 4

#endif
