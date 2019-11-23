#ifndef LOG_H
#define LOG_H
#include <syslog.h>
#include <stdio.h>
#include <string.h>

#define LOGE(fmt, ...) syslog(LOG_ERR, "[%s.%d]: " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define LOGW(fmt, ...) syslog(LOG_WARNING, "[%s.%d]: " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define LOGD(fmt, ...) syslog(LOG_DEBUG, "[%s.%d]: " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define LOGI(fmt, ...) syslog(LOG_INFO, "[%s.%d]: " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)

#endif // LOG_H
