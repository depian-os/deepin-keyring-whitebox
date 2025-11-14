#pragma once

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <sys/syslog.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
syslog - priority, see syslog.h
LOG_EMERG 系统不可用
LOG_ALERT 消息需立即处理
LOG_CRIT 重要情况
LOG_ERR 错误
LOG_WARNING 警告
LOG_NOTICE 正常情况，但较为重要
LOG_INFO 信息
LOG_DEBUG 调试信息

syslog - facility, see syslog.h
LOG_DAEMON 独立进程用这个
LOG_AUTH PAM用这个
*/

// dk_log_init 可选，不指定会使用默认方式
bool dk_log_init(const int facility, const char *id);
void dk_log_set_stdout(bool isPrintStdout);
void dk_log_print(int type, int priority, const char *function, const int line, const char *format, ...);

#define DK_LOG(priority, text, ...) dk_log_print(0, priority, __FUNCTION__, __LINE__, text, ##__VA_ARGS__)
#define DK_LOG_PRIVATE(priority, text, ...) dk_log_print(1, priority, __FUNCTION__, __LINE__, text, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
