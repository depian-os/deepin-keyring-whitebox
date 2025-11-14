#include "dklog.h"

#include "common.h"

#include <stdarg.h>
#include <stdio.h>

// syslog日志
const int DK_LOG_TYPE_SYSLOG = 0;
// syslog私有日志，cmake -DCMAKE_BUILD_TYPE=Debug才开启。这里的Debug是程序状态，和syslog中的日志等级的Debug不是一个概念
const int DK_LOG_TYPE_PRIVATE = 1;

static int s_facility = 0;
static char *s_id = NULL;
static bool s_isPrintStdout = false;

bool dk_log_init(const int facility, const char *id)
{
    if (id == NULL) {
        return false;
    }
    if (s_id != NULL) {
        free(s_id);
        s_id = NULL;
    }
    s_id = dalloc(strlen(id) + 1);
    memset(s_id, 0, strlen(id) + 1);
    strncpy(s_id, id, strlen(id));
    s_facility = facility;
    return true;
}

void dk_log_set_stdout(bool isPrintStdout)
{
    s_isPrintStdout = isPrintStdout;
}

void dk_log_print(int type, int priority, const char *function, const int line, const char *format, ...)
{
    if (s_facility < 0) {
        return;
    }
#ifndef DK_DEBUG_MODE
    if (type == DK_LOG_TYPE_PRIVATE) {
        return;
    }
#else
    UNUSED_VALUE(type);
#endif
    va_list ap;
    va_start(ap, format);
    if (s_id != NULL) {
        openlog(s_id, LOG_PID, s_facility);
    } else {
        openlog("deepin-keyring-whitebox", LOG_PID, LOG_DAEMON);
    }
    do {
        char buf[1024] = { 0 };
        int len = snprintf(buf, 1024, "[%s:%d]", function, line);
        if (len < 0) {
            syslog(LOG_ERR, "dk_log_print error: len invalid.");
            break;
        }
        vsnprintf(buf + len, 1024 - len, format, ap);
        syslog(priority, buf);
        // vsyslog(format, ap);
        if (s_isPrintStdout) {
            printf("%s\n", buf);
            // vprintf(format, ap);
            // printf("\n");
        }
    } while (0);
    closelog();
    va_end(ap);
}
