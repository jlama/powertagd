#ifndef SERIAL_H
#define SERIAL_H

#include <sys/types.h>
#include <stdint.h>

void serial_open(const char *dev, unsigned int baud);
void serial_close(void);

size_t serial_available(void);

ssize_t serial_read(uint8_t *buf, size_t len, int timeout_ms);
ssize_t serial_write(const uint8_t *buf, size_t len);

#endif
