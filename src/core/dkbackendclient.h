#pragma once

#include <pwd.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

char *const *dk_client_start_args_of_lightdm();
char *const *dk_client_start_args_of_dpa();
char *const *dk_client_start_args_of_dpa_to_wb();
char *const *dk_client_start_args_of_dpa_to_user();

bool dk_client_start_deepin_keyring_whitebox(const struct passwd *pwd, const char *password, char *const argument[], char *const *envList);

#ifdef __cplusplus
}
#endif
