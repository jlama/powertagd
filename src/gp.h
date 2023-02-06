#ifndef GP_H
#define GP_H

#include "ezsp.h"

// Schneider Electric
#define MFR_ID_SCHNEIDER 0x105e

enum {
	GPF_CMD_COMMISSIONING   = 0xE0,
	GPF_CMD_DECOMMISSIONING = 0xE1,
	GPF_CMD_SUCCESS         = 0xE2,
	GPF_CMD_CHANNEL_REQUEST = 0xE3,

	GPF_CMD_MANUFACTURER_ATTRIBUTE_REPORTING     = 0xA1,
	GPF_CMD_MANUFACTURER_MULTI_CLUSTER_REPORTING = 0xA3,
	GPF_CMD_READ_ATTRIBUTES_REPLY                = 0xA5,
	// Specific to PowerTags, in reply to a GPF_CMD_WRITE_ATTRIBUTES command.
	GPF_CMD_WRITE_ATTRIBUTES_ACK                 = 0xA7,

	// GPDF commands sent to GPD
	GPF_CMD_COMMISSIONING_REPLY = 0xF0,
	GPF_CMD_WRITE_ATTRIBUTES    = 0xF1,
	GPF_CMD_READ_ATTRIBUTES     = 0xF2,
	GPF_CMD_CHANNEL_CONFIG      = 0xF3,
};

typedef uint32_t GpSrcId;

#define GP_APP_SOURCE_ID    0x00
#define GP_APP_IEEE_ADDRESS 0x02

typedef struct __attribute__((packed)) {
	union {
		EmberEUI64 ieee_addr;
		GpSrcId src_id;
	} id;
	uint8_t app_id;    // 0x0 for source ID, 0x2 for IEEE address.
	uint8_t endpoint;  // GPD endpoint.
} GpAddr;

typedef uint8_t GpSecurityLevel;
enum {
	GP_SECURITY_LEVEL_NONE = 0x00,
	/* 1 LSB of Frame Counter + short (2B) MIC only */
	GP_SECURITY_LEVEL_1LSB_FC_SHORT_MIC = 0x01,
	/* 4 Byte Frame Counter + 4 Byte MIC */
	GP_SECURITY_LEVEL_FC_MIC = 0x02,
	/* 4 Byte Frame Counter + 4 Byte MIC + encryption */
	GP_SECURITY_LEVEL_FC_MIC_ENCRYPTED = 0x03,
};

typedef uint8_t GpKeyType;
enum {
	GP_KEY_TYPE_NONE        = 0x00,
	GP_KEY_TYPE_ZB_NWK      = 0x01, /* shared key */
	GP_KEY_TYPE_GPD_GROUP   = 0x02, /* shared key */
	GP_KEY_TYPE_NWK_DERIVED = 0x03, /* shared key */
	GP_KEY_TYPE_GPD_OOB     = 0x04, /* individual key */
	GP_KEY_TYPE_GPD_DERIVED = 0x07, /* individual key */
};

/* Received GP frame. */
typedef struct {
	uint8_t gpd_link;
	uint8_t seq_num;
	GpAddr addr;
	GpSecurityLevel sec_lvl;
	GpKeyType key_type;
	uint8_t auto_commissioning;
	uint8_t bidirectional_info;
	uint32_t sec_frame_counter;
	uint8_t cmd_id;
	uint32_t mic;
	uint8_t proxy_table_idx;
	uint8_t payload_len;
	uint8_t payload[128];
} GpFrame;

#define GPF_RX_AFTER_TX(gpf) (gpf->bidirectional_info & 0x1)

typedef uint8_t GpSinkType;
enum {
	GP_SINK_TYPE_FULL_UNICAST = 0,
	GP_SINK_TYPE_D_GROUPCAST,
	GP_SINK_TYPE_GROUPCAST,
	GP_SINK_TYPE_LW_UNICAST,
	GP_SINK_TYPE_SINK_GROUPLIST,

	GP_SINK_TYPE_UNUSED = 0xFF,
};

typedef struct __attribute__((packed)) {
	EmberEUI64 sink_eui;
	EmberNodeId sink_node_id;
} GpSinkAddr;

typedef struct __attribute__((packed)) {
	uint16_t group_id;
	uint16_t alias;
} GpSinkGroup;

typedef struct __attribute__((packed)) {
	GpSinkType type;
	union {
		GpSinkAddr unicast;
		GpSinkGroup groupcast;
		GpSinkGroup group_list;
	} target;
} GpSinkListEntry;

typedef struct __attribute__((packed)) {
	uint8_t status;
	uint32_t options;
	GpAddr gpd;
	uint8_t device_id;
	GpSinkListEntry sink_list[2];
	EmberNodeId assigned_alias;
	uint8_t groupcast_radius;
	uint8_t security_options;
	uint32_t sec_frame_counter;
	EmberKey gpd_key;
} GpSinkTableEntry;

typedef bool (*GpCallbackHandler)(const GpFrame *frame);

void gp_init(EmberKey *gpd_key, GpCallbackHandler cbfn);

bool gp_sink_init(void);
bool gp_sink_find_entry(GpSrcId id, uint8_t *index);
#define gp_sink_allocate_entry gp_sink_find_entry

void gp_set_allow_commissioning(bool v);

bool gp_parse_frame(const uint8_t *buf, uint8_t len, GpFrame *gpf);
bool gp_process_raw_frame(const uint8_t *buf, uint8_t len);

bool gp_send(GpSrcId addr, uint8_t cmd_id, uint8_t *buf, uint8_t len);
bool gp_send_raw_frame(GpFrame *f);

GpSrcId gpf_source_id(const GpFrame *gpf);

#endif
