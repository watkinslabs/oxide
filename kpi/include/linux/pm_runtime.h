#ifndef OXIDE_LINUX_PM_RUNTIME_H
#define OXIDE_LINUX_PM_RUNTIME_H

#include <linux/device.h>
#include <linux/pm.h>

void pm_runtime_enable(struct device *dev);
void pm_runtime_disable(struct device *dev);
bool pm_runtime_enabled(struct device *dev);
int pm_runtime_get_sync(struct device *dev);
int pm_runtime_put(struct device *dev);
int pm_runtime_put_sync(struct device *dev);
int pm_runtime_put_noidle(struct device *dev);
void pm_runtime_get_noresume(struct device *dev);
int pm_runtime_get_if_in_use(struct device *dev);
int __pm_runtime_idle(struct device *dev, int rpmflags);
int __pm_runtime_resume(struct device *dev, int rpmflags);
int pm_runtime_resume(struct device *dev);
int pm_runtime_suspend(struct device *dev);
void pm_runtime_set_active(struct device *dev);
void pm_runtime_set_suspended(struct device *dev);
bool pm_runtime_active(struct device *dev);
bool pm_runtime_suspended(struct device *dev);
#define pm_runtime_status_suspended(dev) pm_runtime_suspended(dev)
void pm_runtime_forbid(struct device *dev);
void pm_runtime_allow(struct device *dev);
void pm_runtime_mark_last_busy(struct device *dev);
unsigned long pm_runtime_autosuspend_expiration(struct device *dev);
void pm_runtime_set_autosuspend_delay(struct device *dev, int delay);
void pm_runtime_use_autosuspend(struct device *dev);
void pm_runtime_dont_use_autosuspend(struct device *dev);
int pm_schedule_suspend(struct device *dev, unsigned int delay);

#endif
