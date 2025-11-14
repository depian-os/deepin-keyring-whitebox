#include "dkconfig.h"

#include "common.h"
#include "dklog.h"

static bool s_enable = false;
static bool s_isWbData = false;

bool dk_config_writefile(const char *workDir)
{
    char *filePath = dalloc(MAX_FILENAME_LENGTH);
    int filePathSize = -1;
    FILE *fp = NULL;
    bool ret = false;
    do {
        filePathSize = snprintf(filePath, MAX_FILENAME_LENGTH, "%s/status", workDir);
        DK_LOG(LOG_INFO, "write file:%s", filePath);
        if (filePathSize < 0) {
            break;
        }
        fp = fopen(filePath, "w");
        if (fp == NULL) {
            break;
        }
        if (s_enable) {
            fputc('1', fp);
        } else {
            fputc('0', fp);
        }
        if (s_isWbData) {
            fputc('1', fp);
        } else {
            fputc('0', fp);
        }
        ret = true;
    } while (0);

    if (filePath != NULL) {
        free(filePath);
    }
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}

bool dk_config_readfile(const char *workDir)
{
    char *filePath = dalloc(MAX_FILENAME_LENGTH);
    int filePathSize = -1;
    FILE *fp = NULL;
    bool ret = false;

    do {
        filePathSize = snprintf(filePath, MAX_FILENAME_LENGTH, "%s/status", workDir);
        if (filePathSize < 0) {
            break;
        }
        fp = fopen(filePath, "r");
        if (fp == NULL) {
            DK_LOG(LOG_WARNING, "can not to open config(%s).", filePath);
            break;
        }
        char enable = (char)fgetc(fp);
        char iswb = (char)fgetc(fp);
        if (enable == '1') {
            s_enable = true;
        } else {
            s_enable = false;
        }
        if (iswb == '1') {
            s_isWbData = true;
        } else {
            s_isWbData = false;
        }
        ret = true;
    } while (0);

    if (filePath != NULL) {
        free(filePath);
    }
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}

bool dk_config_set_enable(const char *workDir, bool enable)
{
    if (enable != s_enable) {
        s_enable = enable;
        dk_config_writefile(workDir);
    }
    return true;
}

bool dk_config_set_is_wb_data(const char *workDir, bool isWbData)
{
    if (isWbData != s_isWbData) {
        s_isWbData = isWbData;
        dk_config_writefile(workDir);
    }
    return true;
}

bool dk_config_enable(const char *workDir)
{
    dk_config_readfile(workDir);
    DK_LOG(LOG_DEBUG, "is enable: %d", s_enable);
    return s_enable;
}

bool dk_config_is_wb_data(const char *workDir)
{
    dk_config_readfile(workDir);
    DK_LOG(LOG_DEBUG, "is whitebox data: %d", s_isWbData);
    return s_isWbData;
}