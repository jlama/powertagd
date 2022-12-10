#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "ash.h"
#include "crc-ccitt.h"
#include "log.h"
#include "util.h"

/*
 * ASH frame format.
 * |--------------|------------------|-----------|----------|
 * | Control Byte | Data             | CRC       | End Byte |
 * | (1 byte)     | (0 to 128 bytes) | (2 bytes) | 0x7E     |
 * |--------------|------------------|-----------|----------|
 *
 * The CRC (CCITT-FALSE variant, initialized with 0xffff) is computed from all
 * preceding bytes.
 *
 * For more details, see UG101 documentation from Silicon Labs.
 */

#define ASH_MAX_PAYLOAD_SIZE 128

/* ASH frame, without any pseudo-randomization and byte-stuffing. */
typedef struct {
	uint8_t cb; // Control Byte
	uint8_t data[ASH_MAX_PAYLOAD_SIZE];
	size_t len; // data size
} AshFrame;

#define ASH_CANCEL_BYTE     0x1A
#define ASH_ENDFRAME_BYTE   0x7E
#define ASH_ESCAPE_BYTE     0x7D
#define ASH_SUBSTITUTE_BYTE 0x18
#define ASH_XON_BYTE        0x11
#define ASH_XOFF_BYTE       0x13

/*
 * Control byte format, depending on frame type:
 * ------------------------------------------------------------
 * | Frame Type | Sent By   | Control Byte bits               |
 * |            |           |  b7  b6  b5  b4  b3  b2  b1  b0 |
 * ------------------------------------------------------------
 * | DATA       | NCP, Host |  0   --seqNum-- reTx --ackNum-- |
 * | ACK        | NCP, Host |  1   0   0   0  nRdy --ackNum-- |
 * | NAK        | NCP, Host |  1   0   1   0  nRdy --ackNum-- |
 * | RESET      | Host      |  1   1   0   0   0   0   0   0  |
 * | RESET ACK  | NCP       |  1   1   0   0   0   0   0   1  |
 * | ERROR      | NCP       |  1   1   0   0   0   0   1   0  |
 * ------------------------------------------------------------
 * See UG101, section 2.1 - Control Byte.
 */
enum {
	ASH_CB_DATA      = 0x00, // To be OR'ed with reTx, frameNum and ackNum
	ASH_CB_ACK       = 0x90, // To be OR'ed with nRdy and ackNum
	ASH_CB_NAK       = 0xB0, // To be OR'ed with nRdy and ackNum
	ASH_CB_RESET     = 0xC0,
	ASH_CB_RESET_ACK = 0xC1, // Data field size: 2 bytes
	ASH_CB_ERROR     = 0xC2, // Data field size: 2 bytes

	// Frame has been sent again. Only valid for DATA frames.
	ASH_CB_FLAG_RETX      = 0x08,
	// Host is not ready to received callbacks.
	// Only valid for ACK and NAK frames sent by host.
	ASH_CB_FLAG_NOT_READY = 0x08,
};

// ASH reset codes.
enum {
	ASH_RESET_UNKNOWN       = 0x00,
	ASH_RESET_EXTERNAL      = 0x01,
	ASH_RESET_POWERON       = 0x02,
	ASH_RESET_WATCHDOG      = 0x03,
	ASH_RESET_ASSERT        = 0x06,
	ASH_RESET_BOOTLOADER    = 0x09,
	ASH_RESET_SOFTWARE      = 0x0B,
	ASH_RESET_ACK_TIMEOUT   = 0x51,
	ASH_RESET_CHIP_SPECIFIC = 0x80,
};

// Parser errors.
enum {
	ASH_ERR_EMPTY         = -1,
	ASH_ERR_TRUNCATED     = -2,
	ASH_ERR_CRC           = -3,
	ASH_ERR_BAD_DATA_SIZE = -4,
	ASH_ERR_BAD_ACK_NUM   = -5,
	ASH_ERR_INVALID_FRAME = -6,
	ASH_ERR_UNKNOWN_FRAME = -7,
};

typedef enum {
	ASH_TX_IDLE = 0,
	ASH_TX_WAITING_ACK,
	ASH_TX_ACK, // Frame was ACKed by NCP
	ASH_TX_NAK, // Frame was NAKed by NCP
} AshTxStatus;

static const uint8_t ash_frame_reset[5] = {
	ASH_CANCEL_BYTE, ASH_CB_RESET, 0x38, 0xbc, ASH_ENDFRAME_BYTE,
};

typedef struct ash_queue {
	size_t capacity;
	size_t count;
	size_t head, tail;
	AshFrame *frames;
} ash_queue_t;

typedef enum {
	ASH_STATE_DISCONNECTED = 0,
	ASH_STATE_RESET,
	ASH_STATE_CONNECTED,
	ASH_STATE_FAILED,
} AshState;

typedef struct {
	AshState state;
	uint8_t tx_frame_seq;  /* Sequence number of the next frame we will send */
	uint8_t rx_frame_seq;  /* Sequence number of the last frame we received + 1 */
	uint8_t last_ack_num;  /* Last ACK number received */

	bool reject_rx_frames; /* Reject incoming frames until we see a valid one. */

	/* Buffer for incoming frame. */
	uint8_t inbuf[512];
	size_t inlen;
	/* Set when encoutering a ASH_SUBSTITUTE_BYTE. */
	bool discard_frame;

	/* Pending RX frames */
	ash_queue_t rx_queue;
	/* Last sent frame */
	AshFrame *tx_frame;
	AshTxStatus tx_status;

	ash_read_func_t  read_fn;
	ash_write_func_t write_fn;
} ash_stream_t;

static ash_stream_t ctx;


static inline uint8_t cb_frame_num(uint8_t cb)
{
	return ((cb >> 4) & 0x7);
}

static inline uint8_t cb_ack_num(uint8_t cb)
{
	return ((cb & 0x0f) & 0x7);
}

static inline uint16_t ash_crc(const uint8_t *buf, size_t len)
{
	return crc_ccitt_false(0xffff, buf, len);
}

static inline uint16_t ash_crc_frame(uint8_t cb, const uint8_t *buf, size_t len)
{
	uint16_t res = crc_ccitt_false_byte(0xffff, cb);
	return crc_ccitt_false(res, buf, len);
}

static const char *resetcode_to_str(uint8_t code)
{
	switch (code) {
	case ASH_RESET_UNKNOWN:
		return "unknown";
	case ASH_RESET_EXTERNAL:
		return "external";
	case ASH_RESET_POWERON:
		return "power-on";
	case ASH_RESET_WATCHDOG:
		return "watchdog";
	case ASH_RESET_ASSERT:
		return "assertion";
	case ASH_RESET_BOOTLOADER:
		return "bootloader";
	case ASH_RESET_SOFTWARE:
		return "software";
	case ASH_RESET_ACK_TIMEOUT:
		return "ack timeout";
	case ASH_RESET_CHIP_SPECIFIC:
		return "chip-specific";
	}
	return "??";
}

static size_t add_byte_stuffing(uint8_t *src, size_t slen, uint8_t *dst, size_t dlen)
{
	assert(dlen >= slen);
	size_t i = 0, j = 0;

	for (; i < slen; i++) {
		assert(j+2 < dlen);

		switch (src[i]) {
		case ASH_ENDFRAME_BYTE:
			dst[j++] = ASH_ESCAPE_BYTE;
			dst[j++] = 0x5E;
			break;
		case ASH_ESCAPE_BYTE:
			dst[j++] = ASH_ESCAPE_BYTE;
			dst[j++] = 0x5D;
			break;
		case ASH_XON_BYTE:
			dst[j++] = ASH_ESCAPE_BYTE;
			dst[j++] = 0x31;
			break;
		case ASH_XOFF_BYTE:
			dst[j++] = ASH_ESCAPE_BYTE;
			dst[j++] = 0x33;
			break;
		case ASH_SUBSTITUTE_BYTE:
			dst[j++] = ASH_ESCAPE_BYTE;
			dst[j++] = 0x38;
			break;
		case ASH_CANCEL_BYTE:
			dst[j++] = ASH_ESCAPE_BYTE;
			dst[j++] = 0x3A;
			break;
		default:
			dst[j++] = src[i];
			break;
		}
	}
	return j;
}

static size_t remove_byte_stuffing(uint8_t *buf, size_t len)
{
	bool escape = false;
	size_t i = 0, j = 0;

	for (; i < len; i++) {
		if (escape) {
			escape = false;
			if ((buf[i] & 0x20) == 0)
				buf[j++] = buf[i] | 0x20;
			else
				buf[j++] = buf[i] & 0xDF;
		} else {
			if (buf[i] == ASH_ESCAPE_BYTE)
				escape = true;
			else // Copy non-stuffed byte as-is
				buf[j++] = buf[i];
		}
	}
	return j;
}

static void randomize_data(uint8_t *dst, const uint8_t *src, size_t len)
{
	uint8_t lfsr_byte = 0x42;
	for (size_t i = 0; i < len; i++) {
		dst[i] = src[i] ^lfsr_byte;
		/* Compute the next LFSR byte */
		if (lfsr_byte & 0x01)
			lfsr_byte = (lfsr_byte >> 1) ^ 0xb8;
		else
			lfsr_byte = (lfsr_byte >> 1);
	}
}

static int cb_frame_type(uint8_t cb)
{
	if ((cb & 0x80) == 0)
		return ASH_CB_DATA;
	if ((cb & 0x60) == 0)
		return ASH_CB_ACK;
	if ((cb & 0x60) == 0x20)
		return ASH_CB_NAK;

	if (cb == ASH_CB_RESET || cb == ASH_CB_RESET_ACK || cb == ASH_CB_ERROR)
		return cb;

	return -1;
}

static void log_frame(LogLevel lvl, uint8_t *buf, size_t len)
{
	char str[512] = {0};
	FILE *fp = fmemopen(str, sizeof(str), "w");
	assert(fp != NULL);

	while (len > 0) {
		fprintf(fp, "[");
		for (int i = 0; len > 0 && i < 16; i++) {
			fprintf(fp, " %02X", *buf);
			buf++, len--;
		}
		fprintf(fp, " ]");
		rewind(fp);
		log_msg(lvl, "ash:   %s", str);
	}

	fclose(fp);
}

static void ash_queue_init(ash_queue_t *queue, size_t num_frames)
{
	queue->frames = calloc(num_frames, sizeof(AshFrame));
	if (queue->frames == NULL)
		LOG_FATAL("ash: calloc failed: %s", strerror(errno));
	queue->capacity = num_frames;
	queue->count = 0;
	queue->head = queue->tail = 0;
}

static void ash_queue_clear(ash_queue_t *queue)
{
	queue->head = queue->tail = 0;
	queue->count = 0;
}

static bool ash_queue_push(ash_queue_t *queue, AshFrame *frame)
{
	if (queue->count == queue->capacity)
		return false;

	memcpy(&queue->frames[queue->head], frame, sizeof(*frame));
	queue->head = (queue->head + 1) % queue->capacity;
	queue->count++;
	return true;
}

static AshFrame *ash_queue_pop(ash_queue_t *queue)
{
	if (queue->head == queue->tail)
		return NULL;

	AshFrame *frame = &queue->frames[queue->tail];
	queue->tail = (queue->tail + 1) % queue->capacity;
	queue->count--;
	return frame;
}

static size_t ash_queue_count(ash_queue_t *queue)
{
	return queue->count;
}

static void ash_send_frame(AshFrame *frame, bool resend)
{
	uint8_t buf[512]; // Should be enough for the worst case byte stuffing.
	size_t len;
	bool is_data = (cb_frame_type(frame->cb) == ASH_CB_DATA);

	// Always send the most recent ack num
	frame->cb |= (ctx.rx_frame_seq & 0x7);
	if (is_data && resend)
		frame->cb |= ASH_CB_FLAG_RETX;
	// Calculate CRC
	uint16_t crc16 = ash_crc_frame(frame->cb, frame->data, frame->len);

	len = add_byte_stuffing(&frame->cb, 1, buf, sizeof(buf));
	len += add_byte_stuffing(frame->data, frame->len, buf+len, sizeof(buf)-len);

	uint8_t crc[2];
	crc[0] = crc16 >> 8;
	crc[1] = crc16 & 0xFF;
	len += add_byte_stuffing(crc, 2, buf+len, sizeof(buf)-len);

	buf[len++] = ASH_ENDFRAME_BYTE;

	if (is_data) {
		ctx.tx_frame = frame;
		ctx.tx_status = ASH_TX_WAITING_ACK;
	}

	if (ctx.write_fn(buf, len) != len)
		LOG_FATAL("ash: write failed: %s", strerror(errno));
}

static void ash_send_ack(void)
{
	assert(ctx.state == ASH_STATE_CONNECTED);
	LOG_DBG("ash: sending ACK for frame %d", ctx.rx_frame_seq);

	AshFrame ack;
	ack.cb = ASH_CB_ACK;
	ack.len = 0;
	ash_send_frame(&ack, false);
}

static bool ash_validate_ack_num(uint8_t cb)
{
	bool valid = false;
	uint8_t ack_num = cb_ack_num(cb);
	uint8_t next_ack_num = ctx.tx_frame_seq;

	/*
	 * A valid ack_num is a number between the last received ack_num and the
	 * last transmitted frame_num+1, both limits inclusive.
	 */
	if (next_ack_num > ctx.last_ack_num)
		valid = (ack_num >= ctx.last_ack_num && ack_num <= next_ack_num);
	else
		valid = (ack_num <= ctx.last_ack_num && ack_num >= next_ack_num);

	if (!valid) {
		LOG_WARN("ash: got invalid ACK num %d (last ack: %d, next ack: %d)",
		    ack_num, ctx.last_ack_num, next_ack_num);
		// TODO: set reject condition
	}

	ctx.last_ack_num = ack_num;
	return valid;
}

/*
 * Decode and validate a raw ASH frame.
 */
static int ash_decode_frame(uint8_t *buf, size_t len, AshFrame *frame)
{
	if (len == 0) {
		LOG_WARN("ash: got empty frame");
		return ASH_ERR_EMPTY;
	}

	len = remove_byte_stuffing(buf, len);

	/* Smallest valid frame is Control Byte + CRC (ignoring End Frame byte) */
	if (len < 3) {
		LOG_ERR("ash: got truncated frame");
		return ASH_ERR_TRUNCATED;
	}

	// Check CRC
	if (ash_crc(buf, len) != 0) {
		LOG_ERR("ash: got corrupted frame: (expected CRC: 0x%04x, got: 0x%02x%02x)",
		    ash_crc(buf, len-2), buf[len-2], buf[len-1]);
		log_frame(LOG_LEVEL_ERR, buf, len);
		return ASH_ERR_CRC;
	}
	// Ignore trailing CRC bytes from now on
	len -= 2;

	// Control byte
	uint8_t cb = buf[0];
	buf++, len--;

	frame->cb = cb;
	frame->len = 0;

	switch (cb_frame_type(cb)) {
	case ASH_CB_DATA:
		if (len == 0) {
			LOG_ERR("ash: got empty data frame");
			return ASH_ERR_BAD_DATA_SIZE;
		}

		randomize_data(frame->data, buf, len);
		frame->len = len;

		LOG_DBG("ash: got data frame %d:", cb_frame_num(frame->cb));
		log_frame(LOG_LEVEL_DEBUG, frame->data, frame->len);
		break;

	case ASH_CB_ACK:
		if (len != 0) {
			LOG_ERR("ash: ACK frame cannot contain data!");
			return ASH_ERR_BAD_DATA_SIZE;
		}
		LOG_DBG("ash: got ACK frame");
		break;

	case ASH_CB_NAK:
		if (len != 0) {
			LOG_ERR("ash: NAK frame cannot contain data!");
			return ASH_ERR_BAD_DATA_SIZE;
		}
		LOG_DBG("ash: got NAK frame");
		break;

	case ASH_CB_RESET_ACK:
		if (len != 2) {
			LOG_ERR("ash: RSTACK frame must have 2 data bytes (got %zu)", len);
			return ASH_ERR_BAD_DATA_SIZE;
		}
		frame->data[0] = buf[0];
		frame->data[1] = buf[1];
		frame->len = 2;
		break;

	case ASH_CB_ERROR:
		if (len != 2) {
			LOG_ERR("ash: ERROR frame must have 2 data bytes (got %zu)", len);
			return ASH_ERR_BAD_DATA_SIZE;
		}
		frame->data[0] = buf[0];
		frame->data[1] = buf[1];
		frame->len = 2;
		break;

	default:
		// Unknown frame
		LOG_ERR("ash: got unknown frame (control byte: 0x%02X)", cb);
		return ASH_ERR_UNKNOWN_FRAME;
	}

	return 0;
}

/* Return true if we processed a valid DATA or RSTACK frame. */
static bool ash_process_frame(uint8_t *buf, size_t len, AshFrame *frame)
{
	int err = ash_decode_frame(buf, len, frame);
	if (err != 0) {
		if (err == ASH_ERR_EMPTY)
			return false;

		if (ctx.state == ASH_STATE_CONNECTED) {
			if (!ctx.reject_rx_frames) {
				LOG_ERR("ash: got invalid frame, entering reject condition");
				ctx.reject_rx_frames = true;
				// TODO
				// send NAK
			}
		}
		return false;
	}

	uint8_t frame_type = cb_frame_type(frame->cb);

	if (ctx.state == ASH_STATE_DISCONNECTED) {
		LOG_WARN("ash: unexpected frame received while in disconnected state, discarding");
		return false;
	}
	if (ctx.state == ASH_STATE_RESET && frame_type != ASH_CB_RESET_ACK) {
		LOG_WARN("ash: unexpected non-RSTACK frame after reset, aborting");
		return false;
	}

	switch (frame_type) {
	case ASH_CB_ACK:
		if (!ash_validate_ack_num(frame->cb)) {
			//ash_try_recover();
		}
		if (ctx.tx_status == ASH_TX_WAITING_ACK)
			ctx.tx_status = ASH_TX_ACK;
		else
			LOG_ERR("ash: got unsolicited ACK");
		return false;

	case ASH_CB_NAK:
		if (!ash_validate_ack_num(frame->cb)) {

		}
		if (ctx.tx_status == ASH_TX_WAITING_ACK)
			ctx.tx_status = ASH_TX_NAK;
		else
			LOG_WARN("ash: got NAK but no data was sent, ignoring");
		return false;

	case ASH_CB_RESET_ACK:
		if (ctx.state != ASH_STATE_RESET) {
			LOG_WARN("ash: unexpected RSTACK frame - reset reason: %s",
			    resetcode_to_str(buf[1]));
			return false;
		}
		LOG_DBG("ash: got RSTACK - version: 0x%02X, reason: 0x%02X (%s)",
		    buf[0], buf[1], resetcode_to_str(buf[1]));
		return true;

	case ASH_CB_ERROR:
		LOG_FATAL("ash: got ERROR frame: %s", resetcode_to_str(buf[1]));
		ctx.state = ASH_STATE_FAILED;
		return false;

	default:
		break;
	}

	assert(frame_type == ASH_CB_DATA);
	bool retransmitted = (frame->cb & ASH_CB_FLAG_RETX);
	LOG_DBG("ash: got %sdata frame (%zu bytes)",
	     retransmitted ? "retransmitted " : "", frame->len);

	if (!ash_validate_ack_num(frame->cb)) {
		// TODO
	}

	// Update the next ackNum we need to sent.
	uint8_t last_rx_frame_seq = ctx.rx_frame_seq;
	ctx.rx_frame_seq = (cb_frame_num(frame->cb) + 1) & 0x7;

	if (last_rx_frame_seq == ctx.rx_frame_seq) {
		if (retransmitted)
			LOG_DBG("ash: dropping retransmitted frame - already processed");
		else
			LOG_WARN("ash: got duplicate frame?!");
		ash_send_ack();
		return false;
	}

	uint8_t expected_frame_seq = (last_rx_frame_seq + 1) & 0x7;
	// Check for out-of-sequence frame. This probably mean a RX frame was lost.
	if (ctx.rx_frame_seq != expected_frame_seq) {
		// Silently discard if we are already in reject mode.
		if (ctx.reject_rx_frames) {
			LOG_DBG("ash: reject mode already set - dropping frame");
			return false;
		}
		LOG_WARN("ash: got out-of-sequence frame (got: %d, expected: %d)",
		    ctx.rx_frame_seq, expected_frame_seq);
		ctx.reject_rx_frames = true;
		return false;
	}

	if (ctx.tx_status == ASH_TX_WAITING_ACK)
		ctx.tx_status = ASH_TX_ACK;

	ash_send_ack();
	return true;
}

static inline void clear_incoming_frame(void)
{
	ctx.inlen = 0;
	ctx.discard_frame = false;
}

/*
 * Read and parse incoming ASH frames.
 * Return a parsed frame, or NULL is none were read.
 *
 * If the timeout is 0, ash_read_frame() will return a pending frame (if any).
 */
static AshFrame *ash_read_frame(bool ack_only, int timeout_ms)
{
	/* Check for already processed frames first. */
	AshFrame *frame = ash_queue_pop(&ctx.rx_queue);
	if (frame != NULL)
		return frame;
	/* A zero timeout can be used for getting pending frames. */
	if (timeout_ms == 0)
		return NULL;

	/*
	 * No pending frames, try to read from remote.
	 * If we couldn't read a complete frame, we try reading again until
	 * the specified timeout has elapsed.
	 */
	uint8_t buf[256];
	ssize_t r;
	int elapsed_ms = 0;
	struct timespec ts_start, ts_now;

	assert(clock_gettime(CLOCK_MONOTONIC, &ts_start) == 0);

read_again:
	r = ctx.read_fn(buf, sizeof(buf), timeout_ms);
	if (r <= 0)
		return NULL;

	assert(clock_gettime(CLOCK_MONOTONIC, &ts_now) == 0);
	elapsed_ms = timespec_diff(&ts_start, &ts_now);

	if (ctx.inlen + r > sizeof(ctx.inbuf))
		LOG_FATAL("ash: input buffer overflow");

	for (size_t i = 0; i < (size_t)r; i++) {
		switch (buf[i]) {
		case ASH_ENDFRAME_BYTE:
			/*
			 * Received an end-of-frame marker. If we didn't encounter a
			 * SUBSTITUTE byte before, try processing it.
			 */
			if (!ctx.discard_frame) {
				AshFrame frame;
				if (ash_process_frame(ctx.inbuf, ctx.inlen, &frame)) {
					if (!ash_queue_push(&ctx.rx_queue, &frame))
						LOG_FATAL("ash: RX queue is full. Should not happen!");
				}
			}
			clear_incoming_frame();
			break;

		case ASH_CANCEL_BYTE:
			/*
			 * Terminate a frame in progress. All data received since the
			 * previous frame is discarded.
			 */
			clear_incoming_frame();
			break;

		case ASH_SUBSTITUTE_BYTE:
			/*
			 * A SUBSTITUTE byte might be sent from the NCP when a low-level
			 * communication occurs in the UART. All data up to the next
			 * received end-of-frame marker should be discarded.
			 */
			ctx.discard_frame = true;
			break;

		case ASH_XON_BYTE:
			//LOG_WARN("ash: got XON byte. Now what?");
			break;
		case ASH_XOFF_BYTE:
			LOG_WARN("ash: got XOFF byte. Implement TX pausing!");
			break;

		default:
			ctx.inbuf[ctx.inlen++] = buf[i];
			break;
		}
	}

	if (ack_only)
		return NULL;

	frame = ash_queue_pop(&ctx.rx_queue);
	if (frame == NULL) {
		if (elapsed_ms < timeout_ms)
			goto read_again;
		else
			return NULL;
	}
	return frame;
}

void ash_init(ash_read_func_t read_fn, ash_write_func_t write_fn)
{
	ctx.state = ASH_STATE_DISCONNECTED;
	ctx.read_fn = read_fn;
	ctx.write_fn = write_fn;

	ash_queue_init(&ctx.rx_queue, 8);
}

/*
 * Send a reset request to the NCP. Always valid even if the NCP is in
 * failed state.
 * When the NCP resets for whatever reason, it sends a RSTACK frame to the host.
 */
bool ash_reset_ncp(void)
{
	ctx.tx_frame_seq = 0;
	ctx.rx_frame_seq = 0;
	ctx.last_ack_num = 0;
	ctx.reject_rx_frames = false;

	ctx.tx_frame = NULL;
	ctx.tx_status = ASH_TX_IDLE;

	clear_incoming_frame();
	ash_queue_clear(&ctx.rx_queue);

	ctx.state = ASH_STATE_RESET;
	LOG_DBG("ash: sending RESET");
	ctx.write_fn(ash_frame_reset, sizeof(ash_frame_reset));

	/* State is changed to CONNECTED if a valid RSTACK has been received. */
	AshFrame *frame = ash_read_frame(false, 5000);
	if (frame == NULL) {
		LOG_ERR("ash: reset failed: no reply");
		return false;
	}

	assert(frame->cb == ASH_CB_RESET_ACK);
	assert(frame->len == 2);
	uint8_t version = frame->data[0];
	if (version != 2) {
		LOG_ERR("ash: unsupported protocol version 0x%02X", version);
		return false;
	}

	ctx.state = ASH_STATE_CONNECTED;
	LOG_INFO("ash: connected to NCP");
	return true;
}

size_t ash_available_frames(void)
{
	return ash_queue_count(&ctx.rx_queue);
}

/*
 * Read and process incoming ASH frames.
 * Return the size of the payload, or 0 is none were read.
 */
ssize_t ash_read(uint8_t *out, size_t len, int timeout_ms)
{
	assert(out != NULL);
	assert(len > 0);

	AshFrame *f = ash_read_frame(false, timeout_ms);
	if (f == NULL)
		return 0;

	assert(len >= f->len);
	memcpy(out, f->data, f->len);
	return f->len;
}

void ash_write(const uint8_t *data, size_t len, int timeout_ms)
{
	assert(len > 0 && len <= ASH_MAX_PAYLOAD_SIZE);
	assert(ctx.state == ASH_STATE_CONNECTED);

	if (ash_queue_count(&ctx.rx_queue) != 0)
		LOG_FATAL("ash: RX queue must be empty before sending!");

	AshFrame frame;
	frame.cb = (uint8_t)(ctx.tx_frame_seq << 4);
	ctx.tx_frame_seq = (ctx.tx_frame_seq + 1) & 0x7;

	randomize_data(frame.data, data, len);
	frame.len = len;

	LOG_DBG("ash: sending data frame %d", cb_frame_num(frame.cb));
	ash_send_frame(&frame, false);

	int retries = 0;
	int elapsed_ms;
	struct timespec ts_start, ts_now;

try_again:
	elapsed_ms = 0;
	assert(clock_gettime(CLOCK_MONOTONIC, &ts_start) == 0);

	while (1) {
		(void)ash_read_frame(true, timeout_ms - elapsed_ms);

		if (ctx.tx_status == ASH_TX_ACK) {
			ctx.tx_status = ASH_TX_IDLE;
			return;
		}

		assert(clock_gettime(CLOCK_MONOTONIC, &ts_now) == 0);
		elapsed_ms = timespec_diff(&ts_start, &ts_now);
		if (elapsed_ms >= timeout_ms)
			break;

		if (ctx.tx_status == ASH_TX_NAK) {
			LOG_WARN("ash: got NAK, resending...");
			retries++;
			ash_send_frame(&frame, true);
		}
	}

	if (ctx.tx_status == ASH_TX_WAITING_ACK) {
		if (retries < 3) {
			LOG_WARN("ash: no ACK reply, resending frame %d", cb_frame_num(frame.cb));
			retries++;
			ash_send_frame(&frame, true);
			goto try_again;
		}
		LOG_FATAL("ash: tx frame %d timed out: no ACK reply from NCP",
		    cb_frame_num(frame.cb));
	} else if (ctx.tx_status == ASH_TX_NAK)
		LOG_FATAL("ash: NAK reply for TX frame %d after %d retries",
		    cb_frame_num(frame.cb), retries);

	// Should not happen
	abort();
}
