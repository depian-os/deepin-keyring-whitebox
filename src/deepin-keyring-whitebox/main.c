
#include "common.h"
#include "dkconfig.h"
#include "dkfile.h"
#include "dkkey.h"
#include "dklog.h"
#include "dklogin.h"
#include "gnomekeyringclient.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

const int CHANGE_PASSWORD_NONE = 100;
const int CHANGE_PASSWORD_TO_WHITEBOX = 101;
const int CHANGE_PASSWORD_TO_USER = 102;

const char *argPWSourcePipe = "pipe";
const char *argPWSourceCmd = "cmd";
const char *argPWTypeAuto = "auto";
const char *argPWTypeForce = "force";
const char *argPWTypeToWB = "to_wb";
const char *argPWTypeToUser = "to_user";
const char *argWaitAutostart = "autostart";

static bool is_udcp()
{
    gid_t gids[128];
    int len = getgroups(128, gids);
    if (len <= 0) {
        return false;
    }
    bool isUdcp = false;
    for (int i = 0; i < len; i++) {
        struct group *g = getgrgid(gids[i]);
        if (g == NULL) {
            continue;
        }
        if (strcmp(g->gr_name, "udcp") == 0) {
            isUdcp = true;
            break;
        }
    }
    return isUdcp;
}

static bool is_quick_login()
{
    char *value = getenv("DDE_QUICKLOGIN");
    if (value == NULL) {
        return false;
    }
    if (strcmp(value, "true") != 0) {
        return false;
    }
    return true;
}

static bool is_config_auto_open_whitebox()
{
    bool enable = false;

    const char *cmd = "dde-dconfig --get -a org.deepin.dde.keyring -r org.deepin.dde.keyring.whitebox -k autoOpenWhitebox";
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        DK_LOG(LOG_WARNING, "unable to open pipe !");
        return enable;
    }

    const char *flag = "true";
    char buf[strlen(flag) + 1];
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strcmp(buf, flag) == 0) {
            enable = true;
        }
    }

    pclose(fp);

    DK_LOG(LOG_INFO, "auto open whitebox: %d", enable);
    return enable;
}

static int check_change_password_type(const char *workDir, const char *argValuePWType)
{
    int type = CHANGE_PASSWORD_NONE;
    bool wbEnable = dk_config_enable(workDir);
    bool isWbData = dk_config_is_wb_data(workDir);

    if (strcmp(argValuePWType, argPWTypeAuto) == 0) {
        if (wbEnable && !isWbData) {
            type = CHANGE_PASSWORD_TO_WHITEBOX;
        } else if (!wbEnable && isWbData) {
            type = CHANGE_PASSWORD_TO_USER;
        } else if (!wbEnable && !isWbData) {
            // 初始状态，此时进行一些需要自动开启白盒的场景的检测
            if (is_quick_login()) {
                type = CHANGE_PASSWORD_TO_WHITEBOX;
            } else if (is_udcp()) {
                // 域管用户，如果没有开启白盒，则自动开启白盒
                type = CHANGE_PASSWORD_TO_WHITEBOX;
            } else if (is_config_auto_open_whitebox()) {
                // autoOpenWhitebox配置开启，则自动开启白盒
                type = CHANGE_PASSWORD_TO_WHITEBOX;
            }
        }
    } else if (strcmp(argValuePWType, argPWTypeForce) == 0) {
        // force方式一定是会切换的，只关心切换的方向
        if (isWbData) {
            type = CHANGE_PASSWORD_TO_USER;
        } else {
            type = CHANGE_PASSWORD_TO_WHITEBOX;
        }
    } else if (strcmp(argValuePWType, argPWTypeToWB) == 0) {
        // 不是白盒密码加密切换到白盒密码加密
        if (!isWbData) {
            type = CHANGE_PASSWORD_TO_WHITEBOX;
        }
    } else if (strcmp(argValuePWType, argPWTypeToUser) == 0) {
        // 不是用户密码加密切换到用户密码加密
        if (isWbData) {
            type = CHANGE_PASSWORD_TO_USER;
        }
    }
    return type;
}

static char *read_password_by_caller()
{
    char *buf = dalloc(MAX_BUF_SIZE);
    char *ret = dalloc(MAX_BUF_SIZE);
    memset(ret, 0, MAX_BUF_SIZE);
    ssize_t r = 0, len = 0;
    bool success = false;

    DK_LOG(LOG_INFO, "ready to read password from caller.");
    for (;;) {
        memset(buf, 0, MAX_BUF_SIZE);
        r = read(STDIN, buf, MAX_BUF_SIZE);
        if (r < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            DK_LOG(LOG_ERR, "error to read, %s", strerror(errno));
            break;
        } else if (r == 0 || len > MAX_BUF_SIZE) {
            success = true;
            DK_LOG(LOG_INFO, "success to read.");
            break;
        } else {
            len = len + r;
            strncat(ret, buf, r);
        }
    }
    if (buf != NULL) {
        free(buf);
    }
    if (!success) {
        if (ret != NULL) {
            free(ret);
            ret = NULL;
        }
    }
    return ret;
}

static void printHelp()
{
    // TODO
}

static bool opt_search(argHandler *argh)
{
    dk_log_set_stdout(true);
    DK_LOG(LOG_INFO, "opt-search run...");
    const char *argOptSearchWBEnable = "enable";           // 白盒是否开启
    const char *argOptSearchWBEncryptType = "encrypttype"; // keyring加密方式：白盒密码、用户密码
    char *argValueOpt = NULL;
    char *workDir = NULL;
    bool success = false;
    do {
        if (!arg_get_value(argh, "--opt-search", &argValueOpt)) {
            DK_LOG(LOG_ERR, "error to get opt value.");
            break;
        }
        if (argValueOpt == NULL) {
            DK_LOG(LOG_ERR, "error, opt value is null.");
            break;
        }
        struct passwd *pwd = getpwuid(getuid());
        if (pwd == NULL) {
            DK_LOG(LOG_ERR, "error to getpwuid, %s", strerror(errno));
            break;
        }
        if (!dk_file_get_workdir(pwd->pw_dir, &workDir) || workDir == NULL) {
            DK_LOG(LOG_ERR, "error to call dk_file_get_workdir.");
            break;
        }
        DK_LOG(LOG_INFO, "workDir:%s", workDir);
        if (strcmp(argValueOpt, argOptSearchWBEnable) == 0) {
            if (dk_config_enable(workDir)) {
                DK_LOG(LOG_INFO, "whitebox enable.");
            } else {
                DK_LOG(LOG_INFO, "whitebox disable.");
            }
        } else if (strcmp(argValueOpt, argOptSearchWBEncryptType) == 0) {
            if (dk_config_is_wb_data(workDir)) {
                DK_LOG(LOG_INFO, "whitebox encrypt.");
            } else {
                DK_LOG(LOG_INFO, "no whitebox encrypt.");
            }
        }
        success = true;
    } while (0);
    if (argValueOpt != NULL) {
        free(argValueOpt);
    }
    if (workDir != NULL) {
        free(workDir);
    }
    return success;
}

static bool opt_changepw(argHandler *argh)
{
    DK_LOG(LOG_INFO, "opt-changepw run...");
    // --pw-source：指定获取密码的方式, "pipe"、"cmd"
    bool argPWSource = arg_has_key(argh, "--pw-source");
    // --pw-type：force代表一定会改密码，auto代表会根据环境检测判断是否要改密码
    bool argPWType = arg_has_key(argh, "--pw-type");
    // --wait：可选选项，开启则会延迟进行操作, 目前用于session创建之前启动时，带wait延后处理
    bool argWait = arg_has_key(argh, "--wait");

    char *argValuePWSource = NULL;
    char *argValuePWType = NULL;
    char *argValueWait = NULL;
    char *password = NULL;
    char *masterkey = NULL;
    char *workDir = NULL;
    bool success = false;
    do {
        if (!argPWSource || !argPWType) {
            DK_LOG(LOG_ERR, "error, pw param is empty.");
            break;
        }
        if (!arg_get_value(argh, "--pw-source", &argValuePWSource)) {
            DK_LOG(LOG_ERR, "error to get --pw-source param value.");
            break;
        }
        if (argValuePWSource == NULL) {
            DK_LOG(LOG_ERR, "error, --pw-source value is null.");
            break;
        }
        if (!arg_get_value(argh, "--pw-type", &argValuePWType)) {
            DK_LOG(LOG_ERR, "error to get --pw-type param value.");
            break;
        }
        if (argValuePWType == NULL) {
            DK_LOG(LOG_ERR, "error, --pw-type value is null.");
            break;
        }
        struct passwd *pwd = getpwuid(getuid());
        if (pwd == NULL) {
            DK_LOG(LOG_ERR, "error to getpwuid, %s", strerror(errno));
            break;
        }
        if (!dk_file_get_workdir(pwd->pw_dir, &workDir) || workDir == NULL) {
            DK_LOG(LOG_ERR, "error to call dk_file_get_workdir.");
            break;
        }
        DK_LOG(LOG_INFO, "workDir:%s", workDir);

        if (!dk_key_init(workDir)) {
            DK_LOG(LOG_ERR, "error to call dk_key_init.");
            break;
        }

        if (strcmp(argValuePWSource, argPWSourcePipe) == 0) {
            password = read_password_by_caller();
        } else if (strcmp(argValuePWSource, argPWSourceCmd) == 0) {
            // 命令行切换白盒密码方法，无此需求，用于调试或者..?
#ifdef DK_DEBUG_MODE
            dk_log_set_stdout(true);
            password = getpass("Input your password:");
#endif
        }
        if (password == NULL) {
            DK_LOG(LOG_ERR, "error: no passwd input.");
            break;
        }
        DK_LOG_PRIVATE(LOG_INFO, "password:%s", password);
        // lightdm等场景，session未创建时，gnome-keyring不支持修改密码，因此需要wait
        if (argWait) {
            DK_LOG(LOG_INFO, "waiting for notify...");
            if (!dk_login_wait_by_fifo(workDir)) {
                DK_LOG(LOG_ERR, "wait error.");
                break;
            }
            DK_LOG(LOG_INFO, "wait success and continue.");
        }
        int changeType = check_change_password_type(workDir, argValuePWType);
        if (changeType == CHANGE_PASSWORD_NONE) {
            DK_LOG(LOG_INFO, "not need to change pw.");
            break;
        }
        if (!dk_key_get_masterkey(workDir, &masterkey)) {
            DK_LOG(LOG_ERR, "dk_key_get_masterkey error.");
            break;
        }
        DK_LOG_PRIVATE(LOG_INFO, "opt_changepw masterkey:%s", masterkey);
        if (changeType == CHANGE_PASSWORD_TO_USER) {
            DK_LOG(LOG_INFO, "will change to user password");
            bool changeRet = gnome_keyring_change_pw_by_pam(pwd->pw_name, masterkey, password);
            if (!changeRet) {
                DK_LOG(LOG_ERR, "change to userpw error.");
                break;
            }
            // 修改keyring加密方式会自动修改keyring白盒开启状态，不然对不上导致解锁数据失败
            // pam-deepin-keyring中会检验开启状态和数据加密方式，不一致则会调用本程序调整加密方式使其一致
            // 原则：白盒开启状态决定数据加密方式，修改数据加密方式影响白盒开启状态
            if (!dk_config_set_enable(workDir, false)) {
                DK_LOG(LOG_ERR, "dk_config_set_enable error.");
                break;
            }
            if (!dk_config_set_is_wb_data(workDir, false)) {
                DK_LOG(LOG_ERR, "dk_config_set_is_wb_data error.");
                break;
            }
        } else if (changeType == CHANGE_PASSWORD_TO_WHITEBOX) {
            DK_LOG(LOG_INFO, "will change to whitebox password");
            bool changeRet = gnome_keyring_change_pw_by_pam(pwd->pw_name, password, masterkey);
            if (!changeRet) {
                DK_LOG(LOG_WARNING, "change to mkey error by user key, and to try empty key.");
                bool changeEmptyRet = gnome_keyring_change_pw_by_pam(pwd->pw_name, "", masterkey);
                if (!changeEmptyRet) {
                    DK_LOG(LOG_ERR, "failed to change mkey by empty key and user key.");
                    break;
                }
            }
            if (!dk_config_set_enable(workDir, true)) {
                DK_LOG(LOG_ERR, "dk_config_set_enable error.");
                break;
            }
            if (!dk_config_set_is_wb_data(workDir, true)) {
                DK_LOG(LOG_ERR, "dk_config_set_is_wb_data error.");
                break;
            }
        } else {
            DK_LOG(LOG_ERR, "invalid change password type.");
            break;
        }
        success = true;
    } while (0);

    if (argValuePWSource != NULL) {
        free(argValuePWSource);
    }
    if (argValuePWType != NULL) {
        free(argValuePWType);
    }
    if (password != NULL) {
        free(password);
    }
    if (argValueWait != NULL) {
        free(argValueWait);
    }
    if (masterkey != NULL) {
        free(masterkey);
    }
    if (workDir != NULL) {
        free(workDir);
    }
    return success;
}

static bool opt_client(argHandler *argh)
{
    DK_LOG(LOG_INFO, "opt-client run...");
    const char *argOptClientWaitFifoNotify = "waitfifonotify";
    char *argValueOpt = NULL;
    char *workDir = NULL;
    bool success = false;
    do {
        if (!arg_get_value(argh, "--opt-client", &argValueOpt)) {
            break;
        }
        if (argValueOpt == NULL) {
            break;
        }
        struct passwd *pwd = getpwuid(getuid());
        if (pwd == NULL) {
            DK_LOG(LOG_ERR, "error to getpwuid, %s", strerror(errno));
            break;
        }
        if (!dk_file_get_workdir(pwd->pw_dir, &workDir) || workDir == NULL) {
            DK_LOG(LOG_ERR, "error to dk_file_get_workdir");
            break;
        }
        DK_LOG(LOG_INFO, "workDir:%s", workDir);
        if (strcmp(argValueOpt, argOptClientWaitFifoNotify) == 0) {
            if (!dk_login_notify_by_fifo(workDir)) {
                break;
            }
        } else {
            break;
        }
        success = true;
    } while (0);
    if (argValueOpt != NULL) {
        free(argValueOpt);
    }
    if (workDir != NULL) {
        free(workDir);
    }
    return success;
}

// 白盒主程序，运行此程序的场景：
// 场景1, 由core/dkbackupclient.h中的dk_client_start_deepin_keyring_whitebox()函数拉起来，
//       白盒主程以子进程方式运行，该场景用于触发安全不泄密的方式(密码通过父子进程传递)把keyring切换到白盒方案
// 场景2，autostart/deepin-keyring-whitebox-notify.desktop拉起
//       该场景用于发送notify，对应--opt-client参数
// 场景3，在命令行直接运行
//       该场景目前没需求，更多的是用于方便调试，或者为后续拓展需求留个方便的方法
//       对应参数，--opt-search - 用于在命令行查询白盒状态（是否开启、是否加密等）
//       对应参数，--opt-changepw - 用于支持通过命令行直接在白盒方案和原方案间切换
int main(int argc, char *argv[])
{
    dk_log_init(LOG_DAEMON, "deepin-keyring-whitebox");
    DK_LOG(LOG_INFO, "start(%d, %d).", getpid(), getppid());

    argHandler argh;
    arg_parse(argc, argv, &argh);

    bool argHelp = arg_has_key(&argh, "--help");
    // --opt-x：必须指定, 包含,
    // --opt-search
    // --opt-changepw
    bool argOptSearch = arg_has_key(&argh, "--opt-search");
    bool argOptChangePW = arg_has_key(&argh, "--opt-changepw");
    bool argOptClient = arg_has_key(&argh, "--opt-client");

    do {
        if (argHelp) {
            printHelp();
            break;
        }
        if (!argOptSearch && !argOptChangePW && !argOptClient) {
            printHelp();
            break;
        }
        if (argOptSearch) {
            opt_search(&argh);
        } else if (argOptChangePW) {
            opt_changepw(&argh);
        } else if (argOptClient) {
            opt_client(&argh);
        }
    } while (0);

    arg_clean(&argh);
    DK_LOG(LOG_INFO, "end.");
    return 0;
}
