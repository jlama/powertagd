SRCS := \
	ash.c \
	crc-ccitt.c \
	ezsp.c \
	ezsp_types.c \
	gp.c \
	log.c \
	serial.c \
	powertagd.c \
	zcl.c

HDRS := $(wildcard *.h)
OBJS := $(SRCS:.c=.o)

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

all: powertagd

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

libcrypto.a: $(CRYPTO_OBJS)
	ar rcs $@ $^

test_crypto: libcrypto.a crypto/test_crypto.c
	$(CC) $(CFLAGS) crypto/test_crypto.c libcrypto.a -o $@

powertagd: $(OBJS) $(HDRS) libcrypto.a
	$(CC) $(CFLAGS) $(OBJS) libcrypto.a $(LDFLAGS) -o $@

clean:
	rm -f *.o crypto/*.o
	rm -f libcrypto.a
	rm -f powertagd test_crypto

.PHONY: all clean
