/*
 * Copyright (C) 2021 ~ 2022 Deepin Technology Co., Ltd.
 *
 * Author:     weizhixiang <weizhixiang@uniontech.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"

#include "dklog.h"

void *dalloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        abort();
    }
    return p;
}

// 读取全部文件内容
char *read_file_data(const char *filename)
{
    char *data = NULL;
    FILE *pf = NULL;

    do {
        pf = fopen(filename, "r");
        if (pf == NULL) {
            break;
        }
        fseek(pf, 0, SEEK_END);
        long size = ftell(pf);
        if (size == 0) {
            break;
        }
        data = (char *)malloc(size + 1);
        rewind(pf);
        fread(data, sizeof(char), size, pf);
        data[size] = '\0';

    } while (0);

    if (pf != NULL) {
        fclose(pf);
    }

    return data;
}

// 读取文件多行内容
bool get_file_data(char *file, int line, char **out)
{

    FILE *fp = NULL;
    char *tempOut = NULL;
    bool success = false;
    do {
        if (file == NULL || out == NULL) {
            break;
        }
        char data[line][MAX_BUF_SIZE];
        tempOut = malloc(MAX_BUF_SIZE);
        memset(tempOut, 0, MAX_BUF_SIZE);
        int i = 0;
        if ((fp = fopen(file, "rb")) == NULL) {
            break;
        }
        bool readSuccess = true;
        for (i = 0; i < line; i++) {
            memset(data[i], 0, MAX_BUF_SIZE);
            if (fscanf(fp, "%s\n", data[i]) == EOF) {
                DK_LOG(LOG_ERR, "fscanf error");
                readSuccess = false;
                break;
            }
        }
        if (!readSuccess) {
            break;
        }
        for (i = 0; i < line; i++) {
            if (data[i]) {
                size_t len = strlen(data[i]);
                memcpy(tempOut + len * i, data[i], len);
            }
        }
        success = true;
    } while (0);

    if (success) {
        *out = tempOut;
    } else {
        free(tempOut);
    }

    if (fp != NULL) {
        fclose(fp);
    }

    return success;
}

int hex_encode_to_string(unsigned char *in, unsigned int inlen, char **out)
{
    char *tout = malloc(inlen * 2 + 1);
    memset(tout, 0, inlen * 2 + 1);
    char strBuf[33] = { 0 };
    char pbuf[32];
    unsigned int i = 0;
    for (i = 0; i < inlen; i++) {
        sprintf(pbuf, "%02X", in[i]);
        strncat(strBuf, pbuf, 2);
    }
    strncpy(tout, strBuf, inlen * 2);
    *out = tout;
    return inlen * 2;
}

int hex_decode_string(char *in, unsigned char *out, unsigned int *outlen)
{
    if (!in) {
        return -1;
    }

    char *p = in;
    char high = 0, low = 0;
    size_t inlen = 0, cnt = 0;
    inlen = strlen(p);
    while (cnt < (inlen / 2)) {
        high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
        low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p)-48 - 7 : *(p)-48;
        out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
        p++;
        cnt++;
    }
    if (inlen % 2 != 0) {
        out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
    }

    if (outlen != NULL) {
        *outlen = inlen / 2 + inlen % 2;
    }
    return inlen / 2 + inlen % 2;
}

int copy_by_fileio(const char *src_file_name, const char *dest_file_name)
{
    int fd1 = open(dest_file_name, O_WRONLY | O_CREAT, 0600);
    if (fd1 == -1) {
        DK_LOG(LOG_ERR, "fopen dest file %s failed.", dest_file_name);
        return -1;
    }
    int fd2 = open(src_file_name, O_RDONLY | S_IROTH);
    if (fd2 == -1) {
        DK_LOG(LOG_ERR, "fopen src %s failed.", src_file_name);
        return -1;
    }
    char *buffer = (char *)malloc(2 * sizeof(char));
    int len = 0;
    ssize_t k = 0;
    do {
        memset(buffer, 0, 2 * sizeof(char));
        k = read(fd2, buffer, 1);
        if (k <= 0) {
            break;
        }
        write(fd1, buffer, 1);
        len++;
    } while (k > 0);
    free(buffer);
    close(fd1);
    close(fd2);
    return len;
}

bool arg_parse(int argc, char *argv[], argHandler *argh)
{
    if (argh == NULL || argc <= 0) {
        return false;
    }
    argh->len = 0;
    argh->arg = NULL;
    char *argTemp = NULL;
    for (int i = 1; i < argc; i++) {
        if (argTemp != NULL) {
            free(argTemp);
        }
        argTemp = (char *)malloc(strlen(argv[i]) + 1);
        strncpy(argTemp, argv[i], strlen(argv[i]));
        argTemp[strlen(argv[i])] = '\0';
        if (strncmp(argTemp, "--", 2) != 0) {
            DK_LOG(LOG_WARNING, "invalid param.");
            continue;
        }
        char *key = strtok(argTemp, "=");
        if (key == NULL) {
            DK_LOG(LOG_ERR, "invalid param:no key.");
            continue;
        }
        argInfo *arg = (argInfo *)dalloc(sizeof(argInfo));
        strncpy(arg->key, key, MAX_BUF_SIZE);
        char *value = strtok(NULL, "=");
        if (value != NULL) {
            strncpy(arg->value, value, MAX_BUF_SIZE);
        }
        if (argh->arg == NULL) {
            arg->next = NULL;
            argh->arg = arg;
        } else {
            arg->next = argh->arg;
            argh->arg = arg;
        }
        argh->len++;
    }
    if (argTemp != NULL) {
        free(argTemp);
    }
    return true;
}

bool arg_has_key(argHandler *argh, const char *key)
{
    if (argh == NULL || key == NULL) {
        return false;
    }
    bool isFind = false;
    argInfo *arg = argh->arg;
    while (arg != NULL) {
        if (strcmp(arg->key, key) == 0) {
            isFind = true;
            break;
        }
        arg = arg->next;
    }
    return isFind;
}

bool arg_get_value(argHandler *argh, const char *key, char **value)
{
    if (argh == NULL || key == NULL || value == NULL) {
        return false;
    }
    bool isFind = false;
    argInfo *arg = argh->arg;
    while (arg != NULL) {
        if (strcmp(arg->key, key) == 0) {
            isFind = true;
            if (arg->value != NULL) {
                char *v = dalloc(MAX_BUF_SIZE);
                strncpy(v, arg->value, MAX_BUF_SIZE);
                *value = v;
            }
            break;
        }
        arg = arg->next;
    }
    return isFind;
}

bool arg_clean(argHandler *argh)
{
    if (argh == NULL) {
        return true;
    }
    argInfo *arg = argh->arg;
    argh->arg = NULL;
    while (arg != NULL) {
        argInfo *temparg = arg->next;
        free(arg);
        arg = temparg;
    }
    return true;
}