#ifndef OXIDE_LINUX_BUILD_BUG_H
#define OXIDE_LINUX_BUILD_BUG_H

#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int:(-!!(e)); })))
#define BUILD_BUG_ON(e) ((void)sizeof(char[1 - 2 * !!(e)]))
#define static_assert _Static_assert

#endif
