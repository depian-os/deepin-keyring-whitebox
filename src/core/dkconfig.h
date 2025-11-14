#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool dk_config_set_enable(const char *workDir, bool enable);
bool dk_config_set_is_wb_data(const char *workDir, bool isWbData);
bool dk_config_enable(const char *workDir);
bool dk_config_is_wb_data(const char *workDir);

bool dk_config_writefile(const char *workDir);
bool dk_config_readfile(const char *workDir);

#ifdef __cplusplus
}
#endif
