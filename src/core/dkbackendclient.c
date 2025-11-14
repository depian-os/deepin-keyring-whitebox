#include "dkbackendclient.h"

#include "common.h"
#include "dklog.h"

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static int fd_write_string(int fd, const char *buf)
{
    size_t bytes = 0;
    ssize_t res = 0;
    size_t len = strlen(buf);

    while (bytes < len) {
        res = write(fd, buf + bytes, len - bytes);
        if (res < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                return -1;
            }
        } else {
            bytes += res;
        }
    }

    return 0;
}

char *const *dk_client_start_args_of_lightdm()
{
    static char *args[] = { "deepin-keyring-whitebox", "--opt-changepw", "--pw-source=pipe", "--pw-type=auto", "--wait=autostart", NULL };
    return args;
}

char *const *dk_client_start_args_of_dpa()
{
    static char *args[] = { "deepin-keyring-whitebox", "--opt-changepw", "--pw-source=pipe", "--pw-type=force", NULL };
    return args;
}

char *const *dk_client_start_args_of_dpa_to_wb()
{
    static char *args[] = { "deepin-keyring-whitebox", "--opt-changepw", "--pw-source=pipe", "--pw-type=to_wb", NULL };
    return args;
}

char *const *dk_client_start_args_of_dpa_to_user()
{
    static char *args[] = { "deepin-keyring-whitebox", "--opt-changepw", "--pw-source=pipe", "--pw-type=to_user", NULL };
    return args;
}

static int setup_deepin_keyring_whitebox(const struct passwd *pwd, int inp[2], char *const argument[], char *const *envList)
{
    if (inp[READ_END] <= 0 || inp[WRITE_END] <= 0 || pwd == NULL) {
        DK_LOG(LOG_ERR, "error: invalid param.");
        return -1;
    }

    if (dup2(inp[READ_END], STDIN) < 0) {
        return -1;
    }
    close(inp[READ_END]);
    close(inp[WRITE_END]);

    DK_LOG(LOG_INFO, "run %s by %s, uid:%d", argument[0], pwd->pw_name, pwd->pw_uid);
    // lightdm阶段，此时子进程所属不是即将登录用户的，因此需要修改，保证execv拉起的进程属于用户
    if (setgid(pwd->pw_gid) < 0 || setuid(pwd->pw_uid) < 0 || setegid(pwd->pw_gid) < 0 || seteuid(pwd->pw_uid) < 0) {
        DK_LOG(LOG_ERR, "couldn't setup deepin-keyring-whitebox: %s", strerror(errno));
        return -1;
    }
    pid_t pid = -1;
    switch (pid = fork()) {
    case -1:
        DK_LOG(LOG_ERR, "couldn't fork for deepin-keyring-whitebox.");
        break;
    case 0:
        // 子进程，由于父进程很快退出，实际执行的deepin-keyring-whitebox进程会变成孤儿进程，由1来回收，避免出现僵尸进程
        if (envList != NULL) {
            execvpe(argument[0], argument, envList);
        } else {
            execvp(argument[0], argument);
        }
        DK_LOG(LOG_ERR, "error: never run here.%s", strerror(errno));
        exit(0);
        break;
    default:
        // 父进程，该进程会很快退出，被dk_client_start_deepin_keyring_whitebox()的调用者用waitpid回收
        break;
    };
    DK_LOG(LOG_INFO, "start %s pid %d", argument[0], pid);

    return 0;
}

bool dk_client_start_deepin_keyring_whitebox(const struct passwd *pwd, const char *password, char *const argument[], char *const *envList)
{
    struct sigaction defsact, oldsact;
    pid_t pid = 0;

    int inp[2] = { -1, -1 };

    memset(&defsact, 0, sizeof(defsact));
    memset(&oldsact, 0, sizeof(oldsact));
    defsact.sa_handler = SIG_DFL;
    sigaction(SIGCHLD, &defsact, &oldsact);

    if (pipe(inp) < 0) {
        return false;
    }
    switch (pid = fork()) {
    case -1:
        DK_LOG(LOG_ERR, "couldn't fork for deepin-keyring-whitebox.");
        break;
    case 0:
        setup_deepin_keyring_whitebox(pwd, inp, argument, envList);
        DK_LOG(LOG_INFO, "temp process exit");
        _exit(0); // waitpid for here
        DK_LOG(LOG_WARNING, "temp process can not run here");
        break;
    default:
        break;
    };
    DK_LOG(LOG_INFO, "start temp process pid %d", pid);
    close(inp[READ_END]);
    inp[READ_END] = -1;
    if (password) {
        fd_write_string(inp[WRITE_END], password);
    }

    close(inp[WRITE_END]);

    DK_LOG(LOG_INFO, "wait temp process pid %d", pid);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        DK_LOG(LOG_ERR, "waitpid error %d", pid);
    }

    sigaction(SIGCHLD, &oldsact, NULL);

    DK_LOG(LOG_INFO, "start deepin keyring whitebox end.");

    return true;
}
