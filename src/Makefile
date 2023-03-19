DESTDIR ?= /usr/local
COMMON_SRCS := \
	ash.c \
	crc-ccitt.c \
	ezsp.c \
	ezsp_types.c \
	gp.c \
	log.c \
	serial.c \
	powertag.c \
	zcl.c

POWERTAGD_SRCS   := $(COMMON_SRCS) powertagd.c
POWERTAGCTL_SRCS := $(COMMON_SRCS) powertagctl.c

HDRS := $(wildcard *.h)
POWERTAGD_OBJS   := $(POWERTAGD_SRCS:.c=.o)
POWERTAGCTL_OBJS := $(POWERTAGCTL_SRCS:.c=.o)

CRYPTO_SRCS := $(wildcard crypto/*.c)
CRYPTO_OBJS := $(CRYPTO_SRCS:.c=.o)

RELEASE ?= 0
ifeq ($(RELEASE), 1)
	CFLAGS := -O2
else
	CFLAGS := -g -O1 -fno-omit-frame-pointer
endif
CFLAGS += -Wall -Wno-unused-function
#CFLAGS += -Wextra -fsanitize=address

#CFLAGS += -DENABLE_MQTT
#LDFLAGS := -lmosquitto

all: powertagd powertagctl

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

libcrypto.a: $(CRYPTO_OBJS)
	ar rcs $@ $^

test_crypto: libcrypto.a crypto/test_crypto.c
	$(CC) $(CFLAGS) crypto/test_crypto.c libcrypto.a -o $@

powertagd: $(POWERTAGD_OBJS) $(HDRS) libcrypto.a
	$(CC) $(CFLAGS) $(POWERTAGD_OBJS) libcrypto.a -lpthread $(LDFLAGS) -o $@

powertagctl: $(POWERTAGCTL_OBJS) $(HDRS) libcrypto.a
	$(CC) $(CFLAGS) $(POWERTAGCTL_OBJS) libcrypto.a $(LDFLAGS) -o $@

install: powertagd powertagctl
	install -m755 $^ $(DESTDIR)/bin/

clean:
	rm -f *.o crypto/*.o
	rm -f libcrypto.a
	rm -f powertagd powertagctl test_crypto

.PHONY: all install clean
