#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// pam方案稳定的话，去掉了dbus接口，减少对libsecret和glib的依赖
// bool gnome_keyring_change_pw_by_dbus(const char *currentKey, const char *newKey);
bool gnome_keyring_change_pw_by_pam(const char *username, char *currentKey, char *newKey);

#ifdef __cplusplus
}
#endif
