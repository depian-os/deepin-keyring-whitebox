#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool dk_crypt_deepin_wb_encrypt(const char *in, const char *key, char **out);
bool dk_crypt_sm4_crypt(const char *in, const char *key, int mode, char *out);

#ifdef __cplusplus
}
#endif
