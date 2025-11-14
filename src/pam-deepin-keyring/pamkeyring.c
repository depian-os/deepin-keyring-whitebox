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
#include "dkbackendclient.h"
#include "dkconfig.h"
#include "dkfile.h"
#include "dkkey.h"
#include "dklog.h"

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <sys/syslog.h>

#include <pwd.h>

const char *USER_PASSWORD = "user-password";

static void cleanup_data(pam_handle_t *pamh, void *data, int pam_end_status)
{
    UNUSED_VALUE(pamh);
    UNUSED_VALUE(pam_end_status);
    char *d = (char *)data;
    if (d == NULL) {
        return;
    }
    memset(d, 0, strlen(d));
    free(d);
}

// 如果需要修改密码，那么需要在session阶段进行，不然缺少session级环境变量
static bool delay_to_change_password_at_session(pam_handle_t *pamh, const char *pw)
{
    if (pamh == NULL || pw == NULL) {
        return false;
    }
    int ret = pam_set_data(pamh, USER_PASSWORD, strdup(pw), cleanup_data);
    if (ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "will to pam_set_data error : %d", ret);
        return false;
    }
    return true;
}

// 功能描述：
// 此处运行在gnome-keyring的pam_sm_authenticate的之前，提供一些给gnome-keyring的数据。
// 这些数据是gnome-keyring机制原有就需要的，所以gnome-keyring对此处的操作无感，gnome-keyring不关心是否白盒，原用户密码方案和白盒方案，gnome-keyring一样的处理
// 1，切换keyring工作目录
// 2, 根据白盒状态，选择性进行替换用户密码为白盒密码
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    UNUSED_VALUE(flags);
    UNUSED_VALUE(argc);
    UNUSED_VALUE(argv);
    dk_log_init(LOG_AUTH, "pam-deepin-keyring-whitebox");
    pam_syslog(pamh, LOG_INFO, "start pam_sm_authenticate");

    int ret = PAM_SERVICE_ERR;
    char *workDir = NULL;
    char *fileenv = NULL;
    char *masterkey = NULL;

    do {
        const char *username = NULL;
        if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "failed to get user");
            break;
        }
        struct passwd *pwd = NULL;
        pwd = getpwnam(username);
        if (!pwd) {
            pam_syslog(pamh, LOG_ERR, "failed to getpwnam");
            break;
        }

        int initRet = dk_file_workdir_init(pwd->pw_dir, pwd->pw_uid, pwd->pw_gid, &workDir);
        if (initRet < 0 || workDir == NULL) {
            pam_syslog(pamh, LOG_ERR, "failed to get workdir");
            break;
        }
        fileenv = dalloc(MAX_BUF_SIZE);
        int fileEnvLen = snprintf(fileenv, MAX_BUF_SIZE, "GNOME_KEYRING_CUSTOM_LOCAL_PATH=%s", workDir);
        if (fileEnvLen <= 0 || fileEnvLen >= MAX_BUF_SIZE) {
            pam_syslog(pamh, LOG_ERR, "invalid local path env length.");
            break;
        }
        pam_putenv(pamh, fileenv);
        pam_syslog(pamh, LOG_INFO, "work dir env: %s", fileenv);

        bool isWbData = dk_config_is_wb_data(workDir);
        pam_syslog(pamh, LOG_INFO, "whitebox is wb data: %d", isWbData);
        if (!isWbData) {
            // 非白盒加密，给gnomekeyring提供用户密码（原流程）
        } else {
            // 白盒加密，给gnomekeyring提供白盒密码MasterKey
            dk_key_get_masterkey(workDir, &masterkey);
            if (masterkey == NULL) {
                pam_syslog(pamh, LOG_ERR, "can not to get master key.");
                break;
            }
            DK_LOG_PRIVATE(LOG_INFO, "[key:%s, keylen=%ld", masterkey, strlen(masterkey));
            pam_set_item(pamh, PAM_AUTHTOK, masterkey);
        }
        // gnome-keyring只支持在session之后修改加密方式，因此延迟进行
        char *org = NULL;
        pam_get_item(pamh, PAM_AUTHTOK, (const void **)&org);
        if (org != NULL) {
            DK_LOG_PRIVATE(LOG_INFO, "userKey :%s", org);
            delay_to_change_password_at_session(pamh, org);
        } else {
            pam_syslog(pamh, LOG_INFO, "userKey is empty.");
            delay_to_change_password_at_session(pamh, "");
        }
        ret = PAM_SUCCESS;
    } while (0);

    if (fileenv != NULL) {
        free(fileenv);
    }
    if (workDir != NULL) {
        free(workDir);
    }
    if (masterkey != NULL) {
        free(masterkey);
    }

    return ret;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    UNUSED_VALUE(pamh);
    UNUSED_VALUE(flags);
    UNUSED_VALUE(argc);
    UNUSED_VALUE(argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    UNUSED_VALUE(flags);
    UNUSED_VALUE(argc);
    UNUSED_VALUE(argv);
    pam_syslog(pamh, LOG_INFO, "start pam_sm_open_session");

    char *workDir = NULL;
    int ret = PAM_SYSTEM_ERR;
    do {
        const char *username = NULL;
        if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "failed to get user");
            break;
        }
        struct passwd *pwd = NULL;
        pwd = getpwnam(username);
        if (!pwd) {
            pam_syslog(pamh, LOG_ERR, "failed to getpwnam");
            break;
        }
        const char *password = NULL;
        pam_get_data(pamh, USER_PASSWORD, (const void **)&password);
        if (password != NULL) {
            // 在auth阶段尝试初始化过一次workdir，在session再次初始化是因为部分场景（如域管新用户首次登录），auth阶段的初始化会失败
            // 如果auth阶段初始化成功，这里再次初始化也就只做了下判断了，不会重复初始化
            int initRet = dk_file_workdir_init(pwd->pw_dir, pwd->pw_uid, pwd->pw_gid, &workDir);
            if (initRet < 0 || workDir == NULL) {
                pam_syslog(pamh, LOG_ERR, "session failed to get workdir");
                break;
            }
            dk_client_start_deepin_keyring_whitebox(pwd, password, dk_client_start_args_of_lightdm(), (char *const *)pam_getenvlist(pamh));
        }
        ret = PAM_SUCCESS;
    } while (0);

    if (workDir != NULL) {
        free(workDir);
    }

    return ret;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    UNUSED_VALUE(pamh);
    UNUSED_VALUE(flags);
    UNUSED_VALUE(argc);
    UNUSED_VALUE(argv);
    return PAM_SUCCESS;
}

// 功能描述：
// 调用pam库的pam_chauthtok会连续调用两次pam_sm_chauthtok，一次前置校验，一次实际操作
// 独立gnome-keyring的pam_sm_chauthtok无法完成修改keyring密码，gnome-keyring依赖前置数据，没有前置数据的话前置校验会失败，直接return PAM_IGNORE，什么都不做
// passwd命令，随用户密码修改keyring密码，passwd命令实现填充前置数据，完成前置校验
// 白盒方案，不需要修改用户密码，所以由此处来完成填充前置数据，完成前置校验
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    UNUSED_VALUE(argc);
    UNUSED_VALUE(argv);
    pam_syslog(pamh, LOG_INFO, "start pam_sm_chauthtok");

    if (flags & PAM_PRELIM_CHECK) {
        pam_syslog(pamh, LOG_INFO, "deepin keyring pam_sm_chauthtok by PAM_PRELIM_CHECK");
        return PAM_SUCCESS;
    } else if (flags & PAM_UPDATE_AUTHTOK) {
        pam_syslog(pamh, LOG_INFO, "deepin keyring pam_sm_chauthtok by PAM_UPDATE_AUTHTOK");
        int updateRet = PAM_SYSTEM_ERR;
        do {
            const struct pam_conv *pconv = NULL;
            int ret = pam_get_item(pamh, PAM_CONV, (const void **)&pconv);
            if (ret != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_ERR, "pam module get conv item error: %s!", strerror(-ret));
                updateRet = ret;
                break;
            }
            if (!pconv || !pconv->appdata_ptr) {
                pam_syslog(pamh, LOG_ERR, "pam module pconv or pconv->conv is nullptr, error!");
                break;
            }
            char **pw = (char **)pconv->appdata_ptr;
            char *org = *pw;
            char *master = *(++pw);
            if (org == NULL || master == NULL) {
                pam_syslog(pamh, LOG_ERR, "pam module pconv or pconv->conv is nullptr, error!");
                break;
            }
            DK_LOG_PRIVATE(LOG_INFO, "org-len:%ld, new-len:%ld", strlen(org), strlen(master));
            ret = pam_set_item(pamh, PAM_AUTHTOK, master);
            if (ret != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_INFO, "[pam_sm_open_session] pam_set_data old failed:%s", pam_strerror(NULL, ret));
                updateRet = ret;
                break;
            }
            ret = pam_set_item(pamh, PAM_OLDAUTHTOK, org);
            if (ret != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_INFO, "[pam_sm_open_session] pam_set_data failed:%s", pam_strerror(NULL, ret));
                updateRet = ret;
                break;
            }
            updateRet = PAM_SUCCESS;
        } while (0);
        return updateRet;
    } else {
        pam_syslog(pamh, LOG_INFO, "deepin keyring pam_sm_chauthtok, PAM_IGNORE");
        return PAM_IGNORE;
    }
}
