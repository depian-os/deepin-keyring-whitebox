#include "dklogin.h"

#include "common.h"
#include "dklog.h"

#include <dlfcn.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

const char *READY = "ready";

static bool dk_login_fifo_path(const char *path, char **wfifoPath)
{
    char *filePath = dalloc(MAX_FILENAME_LENGTH);
    bool success = true;
    int filePathSize = snprintf(filePath, MAX_FILENAME_LENGTH, "%s/wfifo", path);
    if (filePathSize < 0) {
        free(filePath);
        success = false;
    } else {
        *wfifoPath = filePath;
        success = true;
    }
    return success;
}

bool dk_login_fifo_init(const char *wfifoPath)
{
    if (mkfifo(wfifoPath, 0700) < 0) {
        if (errno != EEXIST) {
            DK_LOG(LOG_ERR, "error to mkfifo");
            return false;
        }
    }
    return true;
}

bool dk_login_fifo_clean(const char *wfifoPath)
{
    if (wfifoPath == NULL) {
        return false;
    }
    if (0 == access(wfifoPath, F_OK)) {
        DK_LOG(LOG_INFO, "clean %s", wfifoPath);
        remove(wfifoPath);
    }
    return true;
}

bool dk_login_wait_by_fifo(const char *path)
{
    char *wfifoPath = NULL;
    bool success = false;
    int fdRead = -1;

    do {
        if (!dk_login_fifo_path(path, &wfifoPath) || wfifoPath == NULL) {
            break;
        }
        if (!dk_login_fifo_init(wfifoPath)) {
            break;
        }
        fdRead = open(wfifoPath, O_RDONLY | O_NONBLOCK);
        if (fdRead <= 0) {
            DK_LOG(LOG_ERR, "error to open fifo.");
            break;
        }
        struct timeval timeout = { 180, 0 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fdRead, &rfds);
        int selectRet = select(fdRead + 1, &rfds, NULL, NULL, &timeout);
        if (selectRet < 0) {
            // select 连接失败
            DK_LOG(LOG_ERR, "select failure.");
            break;
        } else if (selectRet == 0) {
            // 超时
            DK_LOG(LOG_ERR, "select timeout.");
            break;
        } else {
            if (FD_ISSET(fdRead, &rfds)) {
                char buf[MAX_BUF_SIZE];
                ssize_t len = read(fdRead, buf, MAX_BUF_SIZE);
                buf[len] = '\0';
                DK_LOG(LOG_DEBUG, "read %d bytes:%s", len, buf);
                if (strcmp(buf, READY) != 0) {
                    break;
                }
            } else {
                DK_LOG(LOG_ERR, "select error fd.");
                break;
            }
        }
        success = true;
    } while (0);

    if (fdRead > 0) {
        close(fdRead);
    }

    if (!dk_login_fifo_clean(wfifoPath)) {
        DK_LOG(LOG_ERR, "clean error.");
    }

    if (wfifoPath != NULL) {
        free(wfifoPath);
    }

    return success;
}

bool dk_login_notify_by_fifo(const char *path)
{
    char *wfifoPath = NULL;
    bool success = false;
    int fdWrite = -1;

    do {
        if (!dk_login_fifo_path(path, &wfifoPath) || wfifoPath == NULL) {
            break;
        }
        fdWrite = open(wfifoPath, O_WRONLY);
        if (fdWrite <= 0) {
            DK_LOG(LOG_WARNING, "error to open fifo.");
            break;
        }
        ssize_t len = write(fdWrite, READY, strlen(READY));
        DK_LOG(LOG_DEBUG, "notify write %d", len);
        success = true;
    } while (0);

    if (wfifoPath != NULL) {
        free(wfifoPath);
    }
    if (fdWrite > 0) {
        close(fdWrite);
    }
    return success;
}
