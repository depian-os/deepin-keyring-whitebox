#include "dkcrypt.h"

#include "dklog.h"

#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

const char *keyring_crypto_lib_path = "/usr/lib/libkeyringcrypto.so";
typedef unsigned char *(*DDE_KEYRING_CRYPT_WB_ENCRYPT)(unsigned char *IN, unsigned char *key);
typedef void (*DDE_KEYRING_CRYPT_SM4)(unsigned char *IN, unsigned char *key, int mode, unsigned char *OUT);

bool dk_crypt_deepin_wb_encrypt(const char *in, const char *key, char **out)
{
    void *handle = dlopen(keyring_crypto_lib_path, RTLD_NOW);
    if (!handle) {
        DK_LOG(LOG_ERR, "failed to dlopen libkeyringcrypto.");
        return false;
    }

    DDE_KEYRING_CRYPT_WB_ENCRYPT func = (DDE_KEYRING_CRYPT_WB_ENCRYPT)dlsym(handle, "deepin_wb_encrypt");
    if (!func) {
        DK_LOG(LOG_ERR, "failed to dlsym deepin_wb_encrypt.");
        return false;
    }
    unsigned char *ret = func((unsigned char *)in, (unsigned char *)key);
    if (ret == NULL) {
        return false;
    }
    *out = (char *)ret;

    return true;
}

bool dk_crypt_sm4_crypt(const char *in, const char *key, int mode, char *out)
{
    void *handle = dlopen(keyring_crypto_lib_path, RTLD_NOW);
    if (!handle) {
        DK_LOG(LOG_ERR, "failed to dlopen libkeyringcrypto.");
        return false;
    }
    DDE_KEYRING_CRYPT_SM4 func_sm4 = (DDE_KEYRING_CRYPT_SM4)dlsym(handle, "sm4_crypt");
    if (!func_sm4) {
        DK_LOG(LOG_ERR, "failed to dlsym sm4_crypt.");
        return false;
    }

    func_sm4((unsigned char *)in, (unsigned char *)key, mode, (unsigned char *)out);
    return true;
}
