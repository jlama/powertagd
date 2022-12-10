#ifndef ASH_H
#define ASH_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

typedef ssize_t (*ash_read_func_t)(uint8_t *buf, size_t len, int timeout_ms);
typedef ssize_t (*ash_write_func_t)(const uint8_t *buf, size_t len);

void ash_init(ash_read_func_t read_fn, ash_write_func_t write_fn);
bool ash_reset_ncp(void);

size_t ash_available_frames(void);

ssize_t ash_read(uint8_t *out, size_t len, int timeout_ms);
void ash_write(const uint8_t *data, size_t len, int timeout_ms);

#endif
