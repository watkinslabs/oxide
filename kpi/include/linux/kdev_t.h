#ifndef OXIDE_LINUX_KDEV_T_H
#define OXIDE_LINUX_KDEV_T_H

#include <linux/types.h>

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1U)
#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev) & MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | ((mi) & MINORMASK))

#endif
