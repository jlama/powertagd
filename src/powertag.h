#ifndef POWERTAG_H
#define POWERTAG_H

#include "ezsp.h"
#include "gp.h"
#include "util.h"

// Default serial speed
#define BAUDRATE 115200

// Schneider-specific cluster ID for PowerTags attributes below.
#define ZCL_CLUSTER_POWERTAG   0xff14
#define ZCL_CLUSTER_POWERTAG_2 0xff15

// ZCL attributes specific to Schneider Powertags.
enum {
	ZCL_POWERTAG_REPORT_INTERVAL   = 0x0000, // Report interval in seconds, type: uint16, cluster ID: 0xff15

	ZCL_POWERTAG_BREAKER_CAPACITY  = 0x0300, // in Amps, type: uint16
	ZCL_POWERTAG_MOUNT_POSITION    = 0x0700, // 0 = downstream, 1 = upstream, type: 8-bit bitmap
	/*
	 * TODO: 0x0701 - not sure what this is...
	 * This is sent as a "Write Attribute" command by the Wiser gateway
	 * shortly after commissioning a PowerTag, with cluster ID 0xff14 and a
	 * 8-bit bitmap value of 0x01.
	 * At first I thought it was used to reset counters, but after testing,
	 * it's not...
	 */
};

// Custom EZSP xNCP commands.
enum {
	XNCP_CMD_INIT_MULTI_RAIL = 0x0e,
	XNCP_CMD_SET_GP_KEY      = 0x0f,
	XNCP_CMD_GET_GP_KEY      = 0x1f,
	XNCP_CMD_PUSH_TX_QUEUE   = 0xa0,
	XNCP_CMD_CLEAR_TX_QUEUE  = 0xa1,
};

bool xncp_init(void);
bool xncp_get_gp_key(EmberKey *gp_key);
bool xncp_set_gp_key(EmberKey *key);

bool powertag_net_init(GpCallbackHandler gp_cb);

#endif
