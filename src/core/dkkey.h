#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool dk_key_generate_random_key(char **key);

bool dk_key_salt_decrypt(char *iodineSaltEnc, char *salt);

bool dk_key_whitebox_encrypt(const char *data, const char *key, char **dataEnc);
bool dk_key_whitebox_decrypt(const char *dataEnc, const char *key, char **data);

bool dk_key_get_salt(const char *workDir, char **salt);
bool dk_key_get_masterkey(const char *workDir, char **masterkey);

bool dk_key_generate_iodinesalt(const char *key, char **salt, char **saltEncHex);

bool dk_key_init_salt(const char *workDir, char **saltOut);
bool dk_key_init_masterkey(const char *workDir, const char *salt, char **masterKey);
bool dk_key_init(const char *workDir);

#ifdef __cplusplus
}
#endif
