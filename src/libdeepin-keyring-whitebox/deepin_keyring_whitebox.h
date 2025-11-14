#ifndef _DEEPIN_KEYRING_WHITEBOX_H_
#define _DEEPIN_KEYRING_WHITEBOX_H_

#include <pwd.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool deepin_keyring_client_start_deepin_keyring_whitebox(const struct passwd *pwd, const char *password, char *const argument[], char *const *envList);

bool deepin_keyring_file_get_workdir(const char *userHome, char **workDir);
bool deepin_keyring_config_enable(const char *workDir);
bool deepin_keyring_config_is_wb_data(const char *workDir);

#ifdef __cplusplus
}
#endif

#endif
