#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
const char *dk_file_get_workdir_name();

bool dk_file_get_workdir(const char *userHome, char **workDir);
bool dk_file_workdir_init(const char *userHome, const unsigned int uid, const unsigned int gid, char **workDir);

bool dk_file_md5_exist(const char *workDir, int *isExist);
bool dk_file_md5_gen(const char *workDir, const char *fileDir, const char *fileName, int uid, int gid);
bool dk_file_md5_init(const char *workDir, int uid, int gid);

#ifdef __cplusplus
}
#endif
