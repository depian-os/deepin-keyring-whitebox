#include "dkfile.h"

#include "common.h"
#include "dklog.h"

#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const char *dk_file_get_workdir_name()
{
    return "deepin-keyrings-wb";
}

bool dk_file_get_workdir(const char *userHome, char **workDir)
{
    char *filedir = NULL;
    bool success = false;

    do {
        if (userHome == NULL) {
            break;
        }
        filedir = dalloc(MAX_FILENAME_LENGTH);
        int size = -1;
        if (userHome[strlen(userHome) - 1] == '/') {
            size = snprintf(filedir, MAX_FILENAME_LENGTH, "%s%s%s", userHome, ".local/share/", dk_file_get_workdir_name());
        } else {
            size = snprintf(filedir, MAX_FILENAME_LENGTH, "%s%s%s", userHome, "/.local/share/", dk_file_get_workdir_name());
        }
        if (size < 0) {
            break;
        }
        *workDir = filedir;
        success = true;
    } while (0);

    if (!success) {
        if (filedir != NULL) {
            free(filedir);
        }
    }
    return success;
}

bool dk_file_md5_exist(const char *workDir, int *isExist)
{
    char *md5Path = NULL;
    bool success = false;
    do {
        *isExist = 0;
        md5Path = dalloc(MAX_FILENAME_LENGTH);
        int md5PathSize = snprintf(md5Path, MAX_FILENAME_LENGTH, "%s/md5", workDir);
        if (md5PathSize < 0) {
            break;
        }
        if (0 == access(md5Path, F_OK)) {
            *isExist = 1;
        }
        success = true;
    } while (0);

    if (md5Path != NULL) {
        free(md5Path);
    }
    return success;
}

bool dk_file_md5_init(const char *workDir, int uid, int gid)
{
    char *md5Dir = NULL;
    bool success = false;
    do {
        md5Dir = dalloc(MAX_FILENAME_LENGTH);
        int md5DirSize = snprintf(md5Dir, MAX_FILENAME_LENGTH, "%s/md5", workDir);
        if (md5DirSize < 0) {
            break;
        }
        if (0 != access(md5Dir, F_OK)) {
            int mkret = mkdir(md5Dir, 0700);
            if (mkret < 0) {
                DK_LOG(LOG_ERR, "creat workDir(%s) error.", md5Dir);
                break;
            }
            DK_LOG(LOG_INFO, "deepin keyring md5 dir create:%s", md5Dir);
            chown(md5Dir, uid, gid);
        }
        success = true;
    } while (0);

    if (md5Dir != NULL) {
        free(md5Dir);
    }
    return success;
}

bool dk_file_md5_gen(const char *workDir, const char *fileDir, const char *fileName, int uid, int gid)
{
    UNUSED_VALUE(uid);
    UNUSED_VALUE(gid);

    char *md5File = NULL;
    char *md5Cmd = NULL;
    bool success = false;
    do {
        md5File = dalloc(MAX_FILENAME_LENGTH);
        int md5FileSize = snprintf(md5File, MAX_FILENAME_LENGTH, "%s/md5/%s.md5", workDir, fileName);
        if (md5FileSize < 0) {
            break;
        }
        md5Cmd = dalloc(MAX_FILENAME_LENGTH * 2);
        int md5CmdSize = snprintf(md5Cmd, MAX_FILENAME_LENGTH * 2, "md5sum %s/%s > %s", fileDir, fileName, md5File);
        if (md5CmdSize < 0) {
            break;
        }
        system(md5Cmd);
        success = true;
    } while (0);

    if (md5File != NULL) {
        free(md5File);
    }
    if (md5Cmd != NULL) {
        free(md5Cmd);
    }

    return success;
}

bool dk_file_workdir_init(const char *userHome, const unsigned int uid, const unsigned int gid, char **workDir)
{
    DK_LOG(LOG_INFO, "deepin keyring workdir init.");
    if (userHome == NULL) {
        DK_LOG(LOG_ERR, "param error.");
        return false;
    }
    // login
    char *orgPath = NULL;
    char *md5Path = NULL;
    DIR *orgDirp = NULL;
    bool ret = false;
    do {
        if (!dk_file_get_workdir(userHome, workDir) || *workDir == NULL) {
            DK_LOG(LOG_ERR, "get workdir error.");
            break;
        }
        int isLoginExist = 0;
        dk_file_md5_exist(*workDir, &isLoginExist);
        if (isLoginExist == 1) {
            // 存在则不再做数据迁移，暂时不做md检验
            ret = true;
            break;
        }
        DK_LOG(LOG_INFO, "deepin keyring to sync keyring data.");
        // 创建workDir
        if (0 != access(*workDir, F_OK)) {
            int mkret = mkdir(*workDir, 0700);
            if (mkret < 0) {
                DK_LOG(LOG_ERR, "creat workDir(%s) error.", *workDir);
                break;
            }
            DK_LOG(LOG_INFO, "deepin keyring work dir create:%s", *workDir);
            chown(*workDir, uid, gid);
        }
        // 迁移
        if (!dk_file_md5_init(*workDir, uid, gid)) {
            DK_LOG(LOG_ERR, "dk file md5 init failed!");
            break;
        }

        orgPath = dalloc(MAX_FILENAME_LENGTH);
        int orgPathSize = -1;
        if (userHome[strlen(userHome) - 1] == '/') {
            orgPathSize = snprintf(orgPath, MAX_FILENAME_LENGTH, "%s%s", userHome, ".local/share/keyrings");
        } else {
            orgPathSize = snprintf(orgPath, MAX_FILENAME_LENGTH, "%s%s", userHome, "/.local/share/keyrings");
        }
        if (orgPathSize < 0) {
            break;
        }
        orgDirp = opendir(orgPath);
        if (orgDirp == NULL) {
            DK_LOG(LOG_WARNING, "can not to open old keyrings dir(%s).", orgPath);
            break;
        }

        struct dirent *orgFile = NULL;
        const char *keystoreFileName = "user.keystore";
        const char *keyringFileSuffix = ".keyring";
        size_t kfsLen = strlen(keyringFileSuffix);
        while ((orgFile = readdir(orgDirp)) != NULL) {
            if (orgFile->d_type != DT_REG) {
                continue;
            }
            if (strcmp(orgFile->d_name, keystoreFileName) == 0 || strcmp(orgFile->d_name + strlen(orgFile->d_name) - kfsLen, keyringFileSuffix) == 0) {
                int filePathSize = -1;
                char *orgFilePath = dalloc(MAX_FILENAME_LENGTH);
                char *dstFilePath = dalloc(MAX_FILENAME_LENGTH);
                do {
                    filePathSize = snprintf(orgFilePath, MAX_FILENAME_LENGTH, "%s/%s", orgPath, orgFile->d_name);
                    if (filePathSize < 0) {
                        break;
                    }
                    filePathSize = snprintf(dstFilePath, MAX_FILENAME_LENGTH, "%s/%s", *workDir, orgFile->d_name);
                    if (filePathSize < 0) {
                        break;
                    }
                    DK_LOG(LOG_INFO, "cp %s to %s", orgFilePath, dstFilePath);
                    copy_by_fileio(orgFilePath, dstFilePath);
                    chown(dstFilePath, uid, gid);
                    dk_file_md5_gen(*workDir, orgPath, orgFile->d_name, uid, gid);
                } while (0);
                free(orgFilePath);
                free(dstFilePath);
            }
        }
        ret = true;
    } while (0);

    if (orgPath != NULL) {
        free(orgPath);
    }
    if (md5Path != NULL) {
        free(md5Path);
    }
    if (orgDirp != NULL) {
        closedir(orgDirp);
    }

    return ret;
}
