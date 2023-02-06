#ifndef EZSP_H
#define EZSP_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include "ezsp_types.h"

// Supported EZSP protocols.
#define EZSP_MIN_VER 8
#define EZSP_MAX_VER 9

#define EZSP_TIMEOUT 3000

#define EZSP_FRAME_ID_ANY 0xffff

/* Frame Control Low Byte */
#define EZSP_CBLOW_OVERFLOW         0x01
#define EZSP_CBLOW_TRUNCATED        0x02
#define EZSP_CBLOW_CALLBACK_PENDING 0x04
#define EZSP_CBLOW_REPLY            0x80

#define EZSP_CBLOW_CALLBACK_TYPE(cblo)     ((cblo & 0x18) >> 3)
#define EZSP_CBLOW_IS_CALLBACK(cblo)       (EZSP_CBLOW_CALLBACK_TYPE(cblo) != 0)
#define EZSP_CBLOW_IS_ASYNC_CALLBACK(cblo) (EZSP_CBLOW_CALLBACK_TYPE(cblo) == 0x2)

#define EZSP_HEADER_SIZE 5
typedef struct {
	uint8_t seq_num;
	uint8_t cb_lo;
	uint8_t cb_hi;
	uint16_t frame_id;
} EzspHeader;

typedef struct {
	EzspHeader hdr;
	uint8_t data[128];
	uint8_t len;
} EzspFrame;

typedef struct {
	EmberStatus es;
	uint8_t data[128];
	uint8_t len;
} EzspXncpReply;

typedef struct {
	uint8_t ep_num;
	uint16_t profile_id;
	uint16_t device_id;
	uint8_t app_flags;
	uint8_t in_cluster_count;
	uint8_t out_cluster_count;
	uint16_t in_clusters[16];
	uint16_t out_clusters[16];
} EzspEndpoint;


typedef ssize_t (*ezsp_read_func_t)(uint8_t *buf, size_t len, int timeout_ms);
typedef void (*ezsp_write_func_t)(const uint8_t *buf, size_t len, int timeout_ms);
typedef bool (*ezsp_callback_func_t)(const EzspFrame *frame);

bool ezsp_init(ezsp_read_func_t read_fn, ezsp_write_func_t write_fn, ezsp_callback_func_t cb_fn);
bool ezsp_stack_init(void);

bool ezsp_get_config(EzspConfigId cid, uint16_t *value);
bool ezsp_set_config(EzspConfigId cid, uint16_t value);

bool ezsp_network_init(EmberStatus *es);
bool ezsp_network_status(EmberNwkStatus *ens);
bool ezsp_network_create(uint16_t *pan_id, uint8_t channel, uint8_t tx_power);

uint8_t ezsp_nwk_radio_channel(void);

bool ezsp_start_energy_scan(uint32_t channel_mask);

void ezsp_send_frame(uint16_t frame_id, uint8_t *buf, size_t len);
void ezsp_send_xncp_frame(uint8_t *buf, uint8_t len);

ssize_t ezsp_read_frame(uint16_t fid, EzspFrame *frame, int timeout_ms);
bool ezsp_read_reply_status(uint16_t expected_fid, uint8_t *es);
bool ezsp_read_xncp_reply(EzspXncpReply *r);

bool ezsp_read_callbacks(int timeout_ms);

#endif // EZSP_H
