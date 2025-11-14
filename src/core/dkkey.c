#include "dkkey.h"

#include "common.h"
#include "dkcrypt.h"
#include "dklog.h"

#include <dlfcn.h>
#include <time.h>
#include <unistd.h>

bool dk_key_generate_random_key(char **key)
{
    static int inited = 0;
    static char *str = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t len = strlen(str);
    char *tkey = dalloc(MASTER_KEY_LEN + 1);

    if (!inited) {
        inited = 1;
        srand((unsigned)time(NULL));
    }

    for (int i = 0; i < MASTER_KEY_LEN; i++) {
        tkey[i] = str[rand() % len];
    }
    tkey[MASTER_KEY_LEN] = '\0';
    *key = tkey;
    return true;
}

bool dk_key_salt_decrypt(char *iodineSaltEnc, char *salt)
{
    unsigned int len = 0;
    char iodineSaltEncHex[VALID_ALL_LENGTH + 1] = { 0 };
    hex_decode_string(iodineSaltEnc, (unsigned char *)iodineSaltEncHex, &len);
    iodineSaltEncHex[VALID_ALL_LENGTH] = '\0';

    char iodineEnc[VALID_LENGTH + 1] = { 0 };
    char saltEnc[VALID_LENGTH + 1] = { 0 };
    memcpy(iodineEnc, iodineSaltEncHex, VALID_LENGTH);
    iodineEnc[VALID_LENGTH] = '\0';
    memcpy(saltEnc, iodineSaltEncHex + VALID_LENGTH, VALID_LENGTH);
    saltEnc[VALID_LENGTH] = '\0';

    char iodine[VALID_LENGTH + 1] = { 0 };
    char saltData[VALID_LENGTH + 1] = { 0 };
    char zkey[VALID_LENGTH] = { 0 };

    // dec iodine
    if (!dk_crypt_sm4_crypt(iodineEnc, zkey, DECRYPT_MODE, iodine)) {
        return false;
    }
    iodine[VALID_LENGTH] = '\0';
    DK_LOG_PRIVATE(LOG_INFO, "iodine:%s, len:%ld", iodine, strlen(iodine));

    // dec salt
    if (!dk_crypt_sm4_crypt(saltEnc, iodine, DECRYPT_MODE, saltData)) {
        return false;
    }
    saltData[VALID_LENGTH] = '\0';
    DK_LOG_PRIVATE(LOG_INFO, "saltData:%s, len:%ld", saltData, strlen(saltData));

    memcpy(salt, saltData, VALID_LENGTH + 1);

    return true;
}

bool dk_key_whitebox_encrypt(const char *data, const char *key, char **dataEnc)
{
    return dk_crypt_deepin_wb_encrypt(data, key, dataEnc);
}

bool dk_key_masterkey_decrypt(const char *keyEnc, const char *salt, char **masterkey)
{
    char *mkey = NULL;
    bool success = false;
    do {
        mkey = dalloc(MAX_BUF_SIZE);
        memset(mkey, 0, MAX_BUF_SIZE);
        if (!dk_crypt_sm4_crypt(keyEnc, salt, DECRYPT_MODE, mkey)) {
            break;
        }
        *masterkey = mkey;
        success = true;
    } while (0);

    if (!success) {
        if (mkey != NULL) {
            free(mkey);
        }
    }

    return success;
}

bool dk_key_get_salt(const char *workDir, char **salt)
{
    char *saltPath = NULL;
    char *saltEncHex = NULL;
    char *saltdata = NULL;
    bool success = false;

    do {
        saltPath = dalloc(MAX_FILENAME_LENGTH);
        int retSize = snprintf(saltPath, MAX_FILENAME_LENGTH, "%s%s", workDir, "/skey");
        if (retSize < 0) {
            break;
        }
        if (!get_file_data(saltPath, VALID_ENC_LINE, &saltEncHex)) {
            break;
        }
        DK_LOG_PRIVATE(LOG_INFO, "saltEncHex:%s, len:%ld", saltEncHex, strlen(saltEncHex));
        saltdata = dalloc(VALID_LENGTH + 1);
        if (!dk_key_salt_decrypt(saltEncHex, saltdata)) {
            break;
        }
        *salt = saltdata;
        DK_LOG_PRIVATE(LOG_INFO, "salt:%s, len:%ld", saltdata, strlen(saltdata));
        success = true;
    } while (0);

    if (saltPath != NULL) {
        free(saltPath);
    }
    if (saltEncHex != NULL) {
        free(saltEncHex);
    }
    if (!success) {
        if (saltdata != NULL) {
            free(saltdata);
        }
    }

    return success;
}

bool dk_key_get_masterkey(const char *workDir, char **masterkey)
{
    char *keyPath = NULL;
    char *filedata = NULL;
    char *salt = NULL;
    char *mkey = NULL;
    bool success = false;

    do {
        keyPath = dalloc(MAX_FILENAME_LENGTH);
        int retSize = snprintf(keyPath, MAX_FILENAME_LENGTH, "%s%s", workDir, "/mkey");
        if (retSize < 0) {
            break;
        }
        filedata = read_file_data(keyPath);
        if (filedata == NULL) {
            break;
        }

        if (!dk_key_get_salt(workDir, &salt)) {
            break;
        }
        if (!dk_key_masterkey_decrypt(filedata, salt, &mkey)) {
            break;
        }
        *masterkey = mkey;
        success = true;
    } while (0);

    if (keyPath != NULL) {
        free(keyPath);
    }
    if (filedata != NULL) {
        free(filedata);
    }
    if (salt != NULL) {
        free(salt);
    }
    if (!success) {
        if (mkey != NULL) {
            free(mkey);
        }
    }

    return success;
}

// to generate iodine or salt, the difference between them is that the key is different
bool dk_key_generate_iodinesalt(const char *key, char **data, char **dataEncHex)
{
    char *tmpData = NULL;
    char *tmpDataEnc = NULL;
    char *tmpDataEncHex = NULL;
    bool success = false;
    // 算法因素，会随机生成长度不对的数据，此情况重新生成
    for (int i = 0; i < 1000; i++) {
        dk_key_generate_random_key(&tmpData);
        if (tmpData == NULL) {
            break;
        }
        DK_LOG_PRIVATE(LOG_INFO, "tmpData:%s, len:%ld", tmpData, strlen(tmpData));
        // enc data
        if (!dk_key_whitebox_encrypt(tmpData, key, &tmpDataEnc)) {
            break;
        }
        if (tmpDataEnc == NULL) {
            break;
        }
        if (strlen(tmpDataEnc) == MASTER_KEY_LEN) {
            hex_encode_to_string((unsigned char *)tmpDataEnc, strlen(tmpDataEnc), &tmpDataEncHex);
            DK_LOG_PRIVATE(LOG_INFO, "to generate data:%s, data-len:%ld, data-hex:%s, data-hex-len:%ld", tmpData, strlen(tmpData), tmpDataEncHex, strlen(tmpDataEncHex));
            if (strlen(tmpDataEncHex) == MASTER_KEY_LEN * 2) {
                success = true;
                break;
            }
        }
        DK_LOG_PRIVATE(LOG_INFO, "tmpData len error, to re-generate it.");
        if (tmpData != NULL) {
            free(tmpData);
            tmpData = NULL;
        }
        if (tmpDataEnc != NULL) {
            free(tmpDataEnc);
            tmpDataEnc = NULL;
        }
        if (tmpDataEncHex != NULL) {
            free(tmpDataEncHex);
            tmpDataEncHex = NULL;
        }
    }

    if (tmpData == NULL || tmpDataEnc == NULL || tmpDataEncHex == NULL) {
        success = false;
    }
    if (success) {
        free(tmpDataEnc);
        *data = tmpData;
        *dataEncHex = tmpDataEncHex;
    } else {
        if (tmpData != NULL) {
            free(tmpData);
        }
        if (tmpDataEnc != NULL) {
            free(tmpDataEnc);
        }
        if (tmpDataEncHex != NULL) {
            free(tmpDataEncHex);
        }
    }
    return success;
}

bool dk_key_init_salt(const char *workDir, char **saltOut)
{
    // UFILE
    char *saltPath = dalloc(MAX_FILENAME_LENGTH);
    char *salt = NULL;
    char *iodine = NULL;
    char *saltEncHex = NULL;
    char *iodineEncHex = NULL;
    int pathSize = -1;
    bool ret = false;

    do {
        pathSize = snprintf(saltPath, MAX_FILENAME_LENGTH, "%s/skey", workDir);
        if (pathSize < 0) {
            break;
        }
        if (0 != access(saltPath, F_OK)) {
            // 新建
            FILE *fp = NULL;
            bool createSuccess = false;
            do {
                fp = fopen(saltPath, "w");
                if (fp == NULL) {
                    break;
                }
                char zkey[VALID_LENGTH] = { 0 };
                if (!dk_key_generate_iodinesalt(zkey, &iodine, &iodineEncHex)) {
                    break;
                }
                if (!dk_key_generate_iodinesalt(iodine, &salt, &saltEncHex)) {
                    break;
                }

                size_t writeSize = fwrite((const void *)iodineEncHex, 1, strlen(iodineEncHex), fp);
                if (writeSize != strlen(iodineEncHex)) {
                    break;
                }
                writeSize = fwrite("\n", 1, 1, fp);
                if (writeSize != 1) {
                    break;
                }
                writeSize = fwrite((const void *)saltEncHex, 1, strlen(saltEncHex), fp);
                if (writeSize != strlen(saltEncHex)) {
                    break;
                }
                createSuccess = true;
                *saltOut = salt;
                salt = NULL;
            } while (0);
            if (fp != NULL) {
                fclose(fp);
            }
            if (!createSuccess) {
                if (0 == access(saltPath, F_OK)) {
                    DK_LOG(LOG_ERR, "create failed and to delete %s", saltPath);
                    remove(saltPath);
                }
                break;
            }
        } else {
            // 如果存在，则读取
            if (!dk_key_get_salt(workDir, saltOut)) {
                break;
            }
        }
        ret = true;
    } while (0);

    if (saltPath != NULL) {
        free(saltPath);
    }

    if (salt != NULL) {
        free(salt);
    }
    if (iodine != NULL) {
        free(iodine);
    }
    if (saltEncHex != NULL) {
        free(saltEncHex);
    }
    if (iodineEncHex != NULL) {
        free(iodineEncHex);
    }
    return ret;
}

bool dk_key_init_masterkey(const char *workDir, const char *salt, char **masterKey)
{
    char *masterKeyPath = dalloc(MAX_FILENAME_LENGTH);
    char *keyData = NULL;
    char *keyEnc = NULL;
    int masterKeyPathSize = -1;
    bool ret = false;

    do {
        masterKeyPathSize = snprintf(masterKeyPath, MAX_FILENAME_LENGTH, "%s/mkey", workDir);
        if (masterKeyPathSize < 0) {
            break;
        }
        if (0 != access(masterKeyPath, F_OK)) {
            // 新建
            FILE *fp = NULL;
            bool createSuccess = false;
            do {
                fp = fopen(masterKeyPath, "w");
                if (fp == NULL) {
                    break;
                }
                dk_key_generate_random_key(&keyData);
                DK_LOG_PRIVATE(LOG_INFO, "generate masterkey:%s", keyData);
                // enc master_key
                if (!dk_key_whitebox_encrypt(keyData, salt, &keyEnc)) {
                    break;
                }
                size_t len = 0;
                if (keyEnc) {
                    len = strlen(keyEnc);
                }
                if (len <= 0) {
                    break;
                }
                fwrite((const void *)keyEnc, 1, len + 1, fp);
                *masterKey = keyData;
                keyData = NULL;
                createSuccess = true;
            } while (0);
            if (fp != NULL) {
                fclose(fp);
            }
            if (!createSuccess) {
                if (0 == access(masterKeyPath, F_OK)) {
                    DK_LOG(LOG_WARNING, "create failed and to delete %s", masterKeyPath);
                    remove(masterKeyPath);
                }
                break;
            }
        }
        ret = true;
    } while (0);

    if (masterKeyPath != NULL) {
        free(masterKeyPath);
    }
    if (keyEnc != NULL) {
        free(keyEnc);
    }
    if (keyData != NULL) {
        free(keyData);
    }
    return ret;
}

bool dk_key_init(const char *workDir)
{
    char *salt = NULL;
    char *masterKey = NULL;

    do {
        if (0 != access(workDir, F_OK)) {
            break;
        }
        if (!dk_key_init_salt(workDir, &salt)) {
            break;
        }
        // masterkey
        if (!dk_key_init_masterkey(workDir, salt, &masterKey)) {
            break;
        }
    } while (0);

    if (salt != NULL) {
        free(salt);
    }

    if (masterKey != NULL) {
        free(masterKey);
    }

    return true;
}