#ifndef LOG_H
#define LOG_H

#include <string.h>

typedef enum {
	LOG_LEVEL_DEBUG = 0,
	LOG_LEVEL_INFO,
	LOG_LEVEL_WARN,
	LOG_LEVEL_ERR,
	LOG_LEVEL_FATAL,
} LogLevel;

#define LOG_DBG(fmt, ...) \
    log_msg(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    log_msg(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    log_msg(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)

#define LOG_ERR(fmt, ...) \
    log_msg(LOG_LEVEL_ERR, fmt, ##__VA_ARGS__)

#define LOG_FATAL(fmt, ...) do { \
    log_msg(LOG_LEVEL_FATAL, fmt, ##__VA_ARGS__); \
    __builtin_unreachable(); \
} while (0)


void log_init(void);
void log_set_level(LogLevel lvl);

__attribute__((format(printf, 2, 3)))
void log_msg(LogLevel lvl, const char *fmt, ...);
__attribute__((format(printf, 2, 3)))
void log_printf(LogLevel lvl, const char *fmt, ...);

#endif /* !LOG_H */
