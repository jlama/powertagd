#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#include "log.h"
#include "util.h"

//#define LOG_TIMESTAMP 1

// Default log level.
static LogLevel g_level = LOG_LEVEL_INFO;
static struct timespec ts_start;

void log_init(void)
{
	assert(clock_gettime(CLOCK_REALTIME, &ts_start) == 0);
}

void log_set_level(LogLevel lvl)
{
	g_level = lvl;
}

static void vlog(LogLevel level, const char *fmt, va_list ap)
{
	if (level < g_level)
		return;

	/*
	 * Use stderr for logging, and stdout for PowerTags reports.
	 */
	FILE *out = stderr;
	//FILE *out = (level >= LOG_LEVEL_WARN) ? stderr : stdout;

#ifdef LOG_TIMESTAMP
	struct timespec now, diff;
	assert(clock_gettime(CLOCK_REALTIME, &now) == 0);
	timespecsub(&now, &ts_start, &diff);

	fprintf(out, "%4ld.%03d ", diff.tv_sec, (int)(diff.tv_nsec / 1e6));
#endif

	switch (level) {
	case LOG_LEVEL_DEBUG:
		fprintf(out, "\033[0;30m[ DBG] ");
		break;
	case LOG_LEVEL_INFO:
		fprintf(out, "[INFO] ");
		break;
	case LOG_LEVEL_WARN:
		fprintf(out, "\033[0;33m[WARN] ");
		break;
	case LOG_LEVEL_ERR:
		fprintf(out, "\033[0;31m[ ERR] ");
		break;
	case LOG_LEVEL_FATAL:
		fprintf(out, "\033[1;31m[CRIT] ");
		break;
	default:
		assert(0 && "invalid log level");
	}

	vfprintf(out, fmt, ap);
	fprintf(out, "\033[0m\n");

	if (level == LOG_LEVEL_FATAL)
		exit(1);
}

void log_msg(LogLevel level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(level, fmt, ap);
	va_end(ap);
}

void log_vprintf(LogLevel level, const char *fmt, va_list ap)
{
	if (level < g_level)
		return;

	FILE *out = (level >= LOG_LEVEL_WARN) ? stderr : stdout;
	vfprintf(out, fmt, ap);
}

void log_printf(LogLevel level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_vprintf(level, fmt, ap);
	va_end(ap);
}
