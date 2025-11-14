#pragma once

#include <stdbool.h>

bool dk_login_fifo_init(const char *path);

bool dk_login_wait_by_fifo(const char *path);

bool dk_login_notify_by_fifo(const char *path);

#ifdef __cplusplus
}
#endif
