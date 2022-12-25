#include <sys/ioctl.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include "serial.h"
#include "log.h"

static int _fd = -1;

void serial_open(const char *dev, speed_t baud)
{
	assert(baud > 0);

	LOG_INFO("tty: opening '%s' at %d bauds", dev, (int)baud);
	int fd = open(dev, O_RDWR | O_NOCTTY /*| O_NONBLOCK*/);
	if (fd == -1)
		LOG_FATAL("tty: open '%s' failed: %s", dev, strerror(errno));

	struct termios opts;
	if (tcgetattr(fd, &opts) == -1)
		err(1, "tcgetattr");

	// Set up raw mode / no echo / binary
	opts.c_cflag |= CLOCAL | CREAD;
	opts.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL | ISIG | IEXTEN);

	opts.c_oflag &= ~(OPOST);
	opts.c_iflag &= ~(INLCR | IGNCR | ICRNL | IGNBRK);

	opts.c_cflag &= ~CSIZE; // 8 bits
	opts.c_cflag |= CS8;
	opts.c_cflag &= ~(CSTOPB); // 1 stop bit
	opts.c_cflag &= ~(PARENB | PARODD); // No parity

	// Software flow control
	opts.c_iflag |= IXON | IXOFF;
	//opts.c_iflag &= ~(IXON | IXOFF | IXANY); no software flow control
	opts.c_cflag &= ~(CRTSCTS); // no hardware flow control

	// Make read(2) non-blocking. We can still use poll/select to ensure data
	// is available before reading.
	opts.c_cc[VMIN] = 1;
	opts.c_cc[VTIME] = 0;

	switch (baud) {
		case 4800:   cfsetospeed(&opts, B4800);   break;
		case 9600:   cfsetospeed(&opts, B9600);   break;
		case 19200:  cfsetospeed(&opts, B19200);  break;
		case 38400:  cfsetospeed(&opts, B38400);  break;
		case 115200: cfsetospeed(&opts, B115200); break;
		default:
			LOG_WARN("warning: baud rate %u is not supported, using 9600.\n", baud);
			cfsetospeed(&opts, B115200);
			break;
	}
	cfsetispeed(&opts, cfgetospeed(&opts));

	// Activate settings
	if (tcsetattr(fd, TCSANOW, &opts) == -1)
		LOG_FATAL("tty: configuration failed");
	LOG_DBG("tty: link configured");

#if defined(__APPLE__)
#include <IOKit/serial/ioss.h>
	LOG_DBG("tty: setting baud rate to %d", (int)baud);
	if (ioctl(fd, IOSSIOSPEED, &baud, 1) == -1)
		err(1, "ioctl(IOSSIOSPEED)");

#elif defined(__linux__)
    // Nothing specific to do for linux
#else
	#error "Serial not supported on this platform"
#endif

	tcflush(fd, TCIOFLUSH);
	tcdrain(fd);
	_fd = fd;
}

void serial_close(void)
{
	close(_fd);
}

/* Return the number of bytes available in the input buffer. */
size_t serial_available(void)
{
	int bytes = 0;
	if (ioctl(_fd, FIONREAD, &bytes) == -1)
		LOG_WARN("tty: ioctl(FIONREAD) failed");
	return bytes;
}

ssize_t serial_read(uint8_t *buf, size_t len, int timeout_ms)
{
	assert(len > 0);

	struct pollfd fds;
	fds.fd = _fd;
	fds.events = POLLIN;

	int r = poll(&fds, 1, timeout_ms);
	if (r == -1)
		LOG_FATAL("serial_read: poll failed: %s", strerror(errno));
	if (r == 0)
		return 0;

	ssize_t sz = read(_fd, buf, len);
	if (sz == -1)
		LOG_FATAL("serial_read failed: %s", strerror(errno));
	if (sz == 0) {
		LOG_FATAL("serial_read: unexpected EOF");
		serial_close();
	}

	return sz;
}

ssize_t serial_write(const uint8_t *buf, size_t len)
{
	assert(len > 0);

	ssize_t sz = write(_fd, buf, len);
	if (sz == -1)
		LOG_FATAL("serial_write failed: %s", strerror(errno));

	//LOG_DBG("tty: wrote %d bytes", (int)sz);
	return sz;
}
