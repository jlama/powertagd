#include <unistd.h>

#include "powertag.h"
#include "log.h"

bool xncp_init(void)
{
	uint8_t cmd = XNCP_CMD_INIT_MULTI_RAIL;
	ezsp_send_xncp_frame(&cmd, 1);

	EzspXncpReply reply;
	if (!ezsp_read_xncp_reply(&reply))
		return false;
	if (reply.es != EMBER_SUCCESS) {
		LOG_ERR("powertagd: failed to initialize xNCP multi-rail");
		return false;
	}

	LOG_DBG("powertagd: xncp initialized");
	return true;
}

/*
 * Retrieve the GP key from NCP.
 */
bool xncp_get_gp_key(EmberKey *gp_key)
{
	uint8_t cmd = XNCP_CMD_GET_GP_KEY;
	ezsp_send_xncp_frame(&cmd, 1);

	EzspXncpReply reply;
	if (!ezsp_read_xncp_reply(&reply))
		return false;
	if (reply.es != EMBER_SUCCESS) {
		LOG_ERR("powertagd: failed to retrieve GP key");
		return false;
	}
	if (reply.len != 16) {
		LOG_ERR("powertagd: bad XNCP_CMD_GET_GP_KEY reply: expected 16 bytes, got %u", reply.len);
		return false;
	}

	memcpy(gp_key->data, reply.data, 16);
	return true;
}

/*
 * Store the GP key in the NCP.
 */
bool xncp_set_gp_key(EmberKey *key)
{
	uint8_t cmd[1+EMBER_KEY_LEN];
	cmd[0] = XNCP_CMD_SET_GP_KEY;
	memcpy(cmd+1, key->data, EMBER_KEY_LEN);
	ezsp_send_xncp_frame(cmd, sizeof(cmd));

	EzspXncpReply reply;
	if (!ezsp_read_xncp_reply(&reply))
		return false;
	if (reply.es != EMBER_SUCCESS) {
		LOG_ERR("powertagd: failed to set GP key");
		return false;
	}

	LOG_DBG("powertagd: GP key set to 0x%s", key2str(key->data));
	return true;
}

/* Bring network up and initialize Green Power stack with the key stored in the NCP. */
bool powertag_net_init(GpCallbackHandler gp_cb)
{
	/*
	 * Try joining an existing network.
	 */
	EmberStatus es;
	if (!ezsp_network_init(&es))
		return false;
	if (es == EMBER_NOT_JOINED) {
		LOG_ERR("%s: no network found, you need to create one first", getprogname());
		return false;
	}
	usleep(500*1000);

	EmberKey gpd_key = {0};

	if (!xncp_init())
		return false;
	if (!xncp_get_gp_key(&gpd_key))
		return false;
	if (ember_key_is_null(&gpd_key)) {
		LOG_ERR( "%s: no GP key has been configured yet", getprogname());
		LOG_INFO("%s: run 'powertagctl set-gp-key <key>' to set one", getprogname());
		return false;
	}

	gp_init(&gpd_key, gp_cb);
	// At the moment we don't use the built-in sink capabilities of the NCP,
	// we handle the decryption/encryption of GP frames ourselves.
	//gp_sink_init();

	return true;
}
