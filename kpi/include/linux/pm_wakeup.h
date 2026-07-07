#ifndef OXIDE_LINUX_PM_WAKEUP_H
#define OXIDE_LINUX_PM_WAKEUP_H

#include <linux/device.h>

int device_init_wakeup(struct device *dev, bool enable);
void device_set_wakeup_capable(struct device *dev, bool capable);
bool device_can_wakeup(struct device *dev);
bool device_may_wakeup(struct device *dev);
int device_wakeup_enable(struct device *dev);
int device_wakeup_disable(struct device *dev);
void pm_wakeup_event(struct device *dev, unsigned int msec);
void pm_stay_awake(struct device *dev);
void pm_relax(struct device *dev);

#endif
