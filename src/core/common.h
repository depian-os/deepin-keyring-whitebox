#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_FILENAME_LENGTH 256
#define MASTER_KEY_LEN 16
#define MAX_BUF_SIZE 256

#define ENCRYPT_MODE 1
#define DECRYPT_MODE 0

#define VALID_LENGTH 16
#define VALID_ENC_LINE 2
#define VALID_ALL_LENGTH (VALID_LENGTH * VALID_ENC_LINE)

#define STDIN 0
#define STDOUT 1
#define STDERR 2
#define READ_END 0
#define WRITE_END 1

#define UNUSED_VALUE(a) ((void)(a))

typedef struct _argInfo
{
    char key[MAX_BUF_SIZE];
    char value[MAX_BUF_SIZE];
    struct _argInfo *next;
} argInfo;

typedef struct _argHandler
{
    int len;
    argInfo *arg;
} argHandler;

void *dalloc(size_t size);
char *read_file_data(const char *filename);
bool get_file_data(char *file, int line, char **out);
int copy_by_fileio(const char *src_file_name, const char *dest_file_name);

bool arg_parse(int argc, char *argv[], argHandler *argh);
bool arg_has_key(argHandler *argh, const char *key);
bool arg_get_value(argHandler *argh, const char *key, char **value);
bool arg_clean(argHandler *argh);

int hex_decode_string(char *in, unsigned char *out, unsigned int *outlen);
int hex_encode_to_string(unsigned char *in, unsigned int inlen, char **out);

#ifdef __cplusplus
}
#endif
