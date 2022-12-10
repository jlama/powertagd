#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "ezsp.h"
#include "log.h"
#include "util.h"

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htole16(x) OSSwapHostToLittleInt16(x)
#endif

typedef struct {
	uint8_t major;
	uint8_t minor;
	uint8_t rev;
	uint8_t bugfix;
} EzspVersion;

typedef struct {
	size_t capacity;
	size_t count;
	size_t head, tail;
	EzspFrame *frames;
} ezsp_queue_t;

struct ezsp_ctx {
	uint8_t version; // EZSP protocol version
	uint8_t seq_num;
	EmberStatus stack_state;

	ezsp_read_func_t read_fn;
	ezsp_write_func_t write_fn;

	ezsp_callback_func_t cb_handler;

	// Callbacks FIFO queue
	ezsp_queue_t cb_queue;

	EmberNodeType node_type;
	EmberNwkConfig nwk_config;
};
static struct ezsp_ctx ctx;


static void ezsp_queue_init(ezsp_queue_t *queue, size_t num_frames)
{
	queue->frames = calloc(num_frames, sizeof(EzspFrame));
	if (queue->frames == NULL)
		LOG_FATAL("ezsp: calloc failed: %s", strerror(errno));
	queue->capacity = num_frames;
	queue->count = 0;
	queue->head = queue->tail = 0;
}

static void ezsp_queue_clear(ezsp_queue_t *queue)
{
	queue->head = queue->tail = 0;
	queue->count = 0;
}

static bool ezsp_queue_push(ezsp_queue_t *queue, EzspFrame *frame)
{
	if (queue->count == queue->capacity)
		return false;

	memcpy(&queue->frames[queue->head], frame, sizeof(*frame));
	queue->head = (queue->head + 1) % queue->capacity;
	queue->count++;
	return true;
}

static EzspFrame *ezsp_queue_pop(ezsp_queue_t *queue)
{
	if (queue->head == queue->tail)
		return NULL;

	EzspFrame *frame = &queue->frames[queue->tail];
	queue->tail = (queue->tail + 1) % queue->capacity;
	queue->count--;
	return frame;
}

static size_t ezsp_queue_count(ezsp_queue_t *queue)
{
	return queue->count;
}

static void ezsp_dbg_frame(EzspHeader *hdr, uint8_t *buf, size_t len, bool is_rx)
{
	assert(hdr != NULL);

	if (len == 0) {
		LOG_DBG("ezsp: %s %s frame (empty)",
		    (is_rx) ? "got" : "sending", ezsp_cmd_id_to_str(hdr->frame_id));
		return;
	}

	LOG_DBG("ezsp: %s %s frame (%zu bytes):",
	    (is_rx) ? "got" : "sending", ezsp_cmd_id_to_str(hdr->frame_id), len);

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
		LOG_DBG("ezsp:   %s", str);
	}

	fclose(fp);
}

void ezsp_send_frame(uint16_t frame_id, uint8_t *buf, size_t len)
{
	assert(len + EZSP_HEADER_SIZE <= 128);
	uint8_t frame[len + EZSP_HEADER_SIZE];

	frame[0] = ctx.seq_num++;
	frame[1] = 0x00;
	frame[2] = 0x01; // Set frame format v1
	u16_to_mem(frame_id, frame+3);

	if (len > 0)
		memcpy(frame+5, buf, len);

	EzspHeader hdr = {
		.seq_num = frame[0],
		.cb_lo = frame[1],
		.cb_hi = frame[2],
		.frame_id = frame_id,
	};
	ezsp_dbg_frame(&hdr, buf, len, false);
	ctx.write_fn(frame, sizeof(frame), EZSP_TIMEOUT);
}

void ezsp_send_xncp_frame(uint8_t *buf, uint8_t len)
{
	uint8_t frame[len+1];
	frame[0] = len;
	memcpy(frame+1, buf, len);
	ezsp_send_frame(EZSP_CUSTOM_FRAME, frame, len+1);
}

static bool ezsp_parse_frame(uint8_t *buf, size_t len, EzspFrame *outf)
{
	assert(outf != NULL);
	if (len < EZSP_HEADER_SIZE) {
		LOG_ERR("ezsp: got truncated frame (%zu bytes)", len);
		return false;
	}

	outf->hdr = (EzspHeader){
		.seq_num = buf[0],
		.cb_lo = buf[1],
		.cb_hi = buf[2],
		.frame_id = u16_from_mem(buf + 3),
	};

	uint8_t cblo = buf[1];
	if (cblo & EZSP_CBLOW_TRUNCATED) {
		LOG_ERR("ezsp: got truncated frame!");
		return false;
	}
	if (cblo & EZSP_CBLOW_OVERFLOW) {
		LOG_ERR("ezsp: NCP is out of memory!");
		return false;
	}
	if (!(cblo & EZSP_CBLOW_REPLY)) {
		LOG_ERR("ezsp: received frame is not a reply!");
		return false;
	}
	if (EZSP_CBLOW_IS_CALLBACK(cblo))
		LOG_DBG("ezsp: got callback frame %s", ezsp_cmd_id_to_str(outf->hdr.frame_id));

	ezsp_dbg_frame(&outf->hdr, buf+EZSP_HEADER_SIZE, len-EZSP_HEADER_SIZE, true);

	memcpy(outf->data, buf+EZSP_HEADER_SIZE, len-EZSP_HEADER_SIZE);
	outf->len = len - EZSP_HEADER_SIZE;
	return true;
}

static void ezsp_parse_stack_version(uint16_t ver, EzspVersion *ev)
{
	ev->major  = (uint8_t)(ver >> 8) >> 4;
	ev->minor  = (uint8_t)(ver >> 8) & 0x0f;
	ev->rev    = (uint8_t)(ver & 0xff) >> 4;
	ev->bugfix = (uint8_t)(ver & 0xff) & 0x0f;
}

static bool ezsp_negotiate_version(void)
{
	uint8_t vercmd[] = {ctx.seq_num++, 0x00, EZSP_VERSION, EZSP_MAX_VER};
	ctx.write_fn(vercmd, sizeof(vercmd), EZSP_TIMEOUT);

	uint8_t buf[128];
	size_t len = ctx.read_fn(buf, sizeof(buf), EZSP_TIMEOUT);
	if (len == 0)
		LOG_ERR("ezsp: no reply to EZSP_VERSION");
	if (len != 7)
		LOG_ERR("ezsp: got truncated EZSP_VERSION reply");

	uint8_t protver = buf[3];
	uint8_t stack_type = buf[4];
	LOG_DBG("ezsp: got EZSP_VERSION reply: [%02X %02X %02X %02X]",
		protver, stack_type, buf[5], buf[6]);

	if (protver != EZSP_MAX_VER) {
		if (protver > EZSP_MAX_VER || protver < EZSP_MIN_VER) {
			LOG_ERR("ezsp: unsupported protocol version %d", protver);
			return false;
		}
		// FIXME
		LOG_ERR("ezsp: protocol version supported but not handled");
		return false;
	}

	if (stack_type != 2) {
		LOG_ERR("ezsp: unsupported stack type %d", stack_type);
		return false;
	}

	uint16_t stackver = u16_from_mem(buf + 5);
	EzspVersion ver;
	ezsp_parse_stack_version(stackver, &ver);
	LOG_INFO("ezsp: EZSPv%d, stack type 2 (mesh), version %d.%d.%d.%d",
	    protver, ver.major, ver.minor, ver.rev, ver.bugfix);

	ctx.version = protver;
	return true;
}

static bool ezsp_get_xncp_info(void)
{
	ezsp_send_frame(EZSP_GET_XNCP_INFO, NULL, 0);

	EzspFrame reply;
	if (ezsp_read_frame(EZSP_GET_XNCP_INFO, &reply, EZSP_TIMEOUT) <= 0) {
		LOG_ERR("ezsp: no reply to EZSP_GET_XNCP_INFO");
		return false;
	}
	if (reply.len != 1 && reply.len != 5) {
		LOG_ERR("ezsp: wrong size for EZSP_GET_XNCP_INFO reply");
		return false;
	}
	if (reply.data[0] != EMBER_SUCCESS) {
		LOG_DBG("ezsp: NCP is not running the xNCP library");
		return false;
	}

	uint16_t mfr_id = u16_from_mem(reply.data + 1);
	uint16_t ver_id = u16_from_mem(reply.data + 3);
	LOG_INFO("ezsp: xNCP manufacturer: 0x%04x, version: 0x%04x", mfr_id, ver_id);
	return true;
}

/*
 * Configure endpoint information on the NCP. The NCP does not remember these
 * settings after a reset.
 * Endpoints can be added by the Host after the NCP has reset. Once the status
 * of the stack changes to EMBER_NETWORK_UP, endpoints can no longer be added.
 */
static bool ezsp_add_endpoint(EzspEndpoint *ep)
{
	size_t len = 8 + (ep->in_cluster_count * 2) + (ep->out_cluster_count * 2);
	uint8_t buf[len];

	buf[0] = ep->ep_num;
	u16_to_mem(ep->profile_id, buf+1);
	u16_to_mem(ep->device_id, buf+3);
	buf[5] = ep->app_flags;
	buf[6] = ep->in_cluster_count;
	buf[7] = ep->out_cluster_count;

	for (size_t i = 0; i < ep->in_cluster_count; i++)
		u16_to_mem(ep->in_clusters[i], buf + 8 + (i * 2));
	for (size_t i = 0; i < ep->out_cluster_count; i++)
		u16_to_mem(ep->out_clusters[i], buf + 8 + (ep->in_cluster_count * 2) + (i * 2));

	ezsp_send_frame(EZSP_ADD_ENDPOINT, buf, len);

	EzspStatus es;
	if (!ezsp_read_reply_status(EZSP_ADD_ENDPOINT, &es))
		return false;
	if (es != EZSP_SUCCESS) {
		LOG_ERR("ezsp: failed to add endpoint: %s", ezsp_status_to_str(es));
		return false;
	}
	return true;
}

bool ezsp_get_config(EzspConfigId cid, uint16_t *value)
{
	LOG_DBG("ezsp: requesting config value for %s", ezsp_config_id_to_str(cid));
	uint8_t id = cid;
	ezsp_send_frame(EZSP_GET_CONFIG_VALUE, &id, 1);

	EzspFrame reply;
	if (ezsp_read_frame(EZSP_GET_CONFIG_VALUE, &reply, EZSP_TIMEOUT) <= 0) {
		LOG_ERR("ezsp: no reply to EZSP_GET_CONFIG_VALUE");
		return false;
	}
	if (reply.len != 1 && reply.len != 3) {
		LOG_ERR("ezsp: wrong size for EZSP_GET_CONFIG_VALUE reply");
		return false;
	}
	if (reply.data[0] != EZSP_SUCCESS) {
		LOG_ERR("ezsp: unrecognized config ID %s", ezsp_config_id_to_str(cid));
		return false;
	}

	*value = u16_from_mem(reply.data + 1);
	return true;
}

bool ezsp_set_config(EzspConfigId cid, uint16_t value)
{
	uint16_t old_value;
	if (!ezsp_get_config(cid, &old_value))
		return false;

	if (old_value == value) {
		LOG_DBG("ezsp: config %s already set to %u", ezsp_config_id_to_str(cid), value);
		return true;
	}

	LOG_DBG("ezsp: updating config %s from %u to %u",
	    ezsp_config_id_to_str(cid), old_value, value);

	uint8_t buf[3];
	buf[0] = cid;
	u16_to_mem(value, buf+1);
	ezsp_send_frame(EZSP_SET_CONFIG_VALUE, buf, sizeof(buf));

	EzspStatus es;
	if (!ezsp_read_reply_status(EZSP_SET_CONFIG_VALUE, &es))
		return false;
	if (es != EZSP_SUCCESS) {
		LOG_ERR("ezsp: failed to set config ID %s: %s",
		    ezsp_config_id_to_str(cid), ezsp_status_to_str(es));
		return false;
	}

	return true;
}

static bool ezsp_get_policy(EzspPolicyId pid, uint8_t *value)
{
	LOG_DBG("ezsp: requesting policy value %s", ezsp_policy_id_to_str(pid));

	uint8_t id = pid;
	ezsp_send_frame(EZSP_GET_POLICY, &id, 1);

	EzspFrame reply;
	if (ezsp_read_frame(EZSP_GET_POLICY, &reply, EZSP_TIMEOUT) <= 0) {
		LOG_ERR("ezsp: no reply to EZSP_GET_POLICY");
		return false;
	}
	if (reply.len != 1 && reply.len != 2) {
		LOG_ERR("ezsp: wrong size for EZSP_GET_POLICY reply");
		return false;
	}
	if (reply.data[0] != EZSP_SUCCESS) {
		LOG_ERR("ezsp: unrecognized policy ID %s", ezsp_policy_id_to_str(pid));
		return false;
	}

	*value = reply.data[1];
	return true;
}

static bool ezsp_set_policy(EzspPolicyId id, uint8_t value)
{
	LOG_DBG("ezsp: changing policy %s to %u", ezsp_policy_id_to_str(id), value);

	uint8_t buf[2] = {id, value};
	ezsp_send_frame(EZSP_SET_POLICY, buf, 2);

	EzspStatus es;
	if (!ezsp_read_reply_status(EZSP_SET_POLICY, &es))
		return false;
	if (es != EZSP_SUCCESS) {
		LOG_ERR("ezsp: failed to set policy ID %s: %s",
		    ezsp_policy_id_to_str(id), ezsp_status_to_str(es));
		return false;
	}

	return true;
}

static bool ezsp_set_value(EzspValueId id, uint8_t *value, size_t len)
{
	assert(len <= 32);

	uint8_t cmd[len+2];
	cmd[0] = id;
	cmd[1] = (uint8_t)len;
	memcpy(cmd+2, value, len);

	ezsp_send_frame(EZSP_SET_VALUE, cmd, sizeof(cmd));

	EzspStatus es;
	if (!ezsp_read_reply_status(EZSP_SET_VALUE, &es))
		return false;
	if (es != EZSP_SUCCESS) {
		LOG_ERR("ezsp: EZSP_SET_VALUE failed: %s", ezsp_status_to_str(es));
		return false;
	}
	return true;
}

static bool ezsp_enable_async_callbacks(bool enable)
{
	LOG_DBG("ezsp: %s async callbacks", (enable) ? "enabling" : "disabling");
	uint8_t value = !enable;
	return ezsp_set_value(EZSP_VALUE_UART_SYNCH_CALLBACKS, &value, 1);
}

bool ezsp_stack_init(void)
{
	/*
	 * Configure stack defaults.
	 */
	struct {
		EzspConfigId id;
		uint16_t value;
	} defaults[] = {
		{EZSP_CONFIG_NEIGHBOR_TABLE_SIZE, 16},
		{EZSP_CONFIG_APS_UNICAST_MESSAGE_COUNT, 10},
		{EZSP_CONFIG_BINDING_TABLE_SIZE, 0},
		{EZSP_CONFIG_ADDRESS_TABLE_SIZE, 8},
		{EZSP_CONFIG_MULTICAST_TABLE_SIZE, 8},
		{EZSP_CONFIG_ROUTE_TABLE_SIZE, 8},
		{EZSP_CONFIG_DISCOVERY_TABLE_SIZE, 8},
		{EZSP_CONFIG_STACK_PROFILE, 2},
		{EZSP_CONFIG_SECURITY_LEVEL, 5},
		{EZSP_CONFIG_MAX_HOPS, 15},
		{EZSP_CONFIG_MAX_END_DEVICE_CHILDREN, 32},
		{EZSP_CONFIG_INDIRECT_TRANSMISSION_TIMEOUT, 3000},
		{EZSP_CONFIG_END_DEVICE_POLL_TIMEOUT, 5},
		{EZSP_CONFIG_TX_POWER_MODE, 0},
		{EZSP_CONFIG_DISABLE_RELAY, 0},
		{EZSP_CONFIG_TRUST_CENTER_ADDRESS_CACHE_SIZE, 0},
		{EZSP_CONFIG_SOURCE_ROUTE_TABLE_SIZE, 0},
		{EZSP_CONFIG_FRAGMENT_WINDOW_SIZE, 0},
		{EZSP_CONFIG_FRAGMENT_DELAY_MS, 0},
		{EZSP_CONFIG_KEY_TABLE_SIZE, 10},
		{EZSP_CONFIG_APS_ACK_TIMEOUT, 1600},
		{EZSP_CONFIG_BEACON_JITTER_DURATION, 3},
		{EZSP_CONFIG_END_DEVICE_BIND_TIMEOUT, 60},
		{EZSP_CONFIG_PAN_ID_CONFLICT_REPORT_THRESHOLD, 1},
		{EZSP_CONFIG_REQUEST_KEY_TIMEOUT, 0},
		{EZSP_CONFIG_APPLICATION_ZDO_FLAGS, 0},
		{EZSP_CONFIG_BROADCAST_TABLE_SIZE, 15},
		{EZSP_CONFIG_MAC_FILTER_TABLE_SIZE, 0},
		{EZSP_CONFIG_SUPPORTED_NETWORKS, 1},
		{EZSP_CONFIG_SEND_MULTICASTS_TO_SLEEPY_ADDRESS, 0},
		{EZSP_CONFIG_ZLL_GROUP_ADDRESSES, 0},
		{EZSP_CONFIG_MTORR_FLOW_CONTROL, 1},
		{EZSP_CONFIG_RETRY_QUEUE_SIZE, 8},
		{EZSP_CONFIG_NEW_BROADCAST_ENTRY_THRESHOLD, 10},
		{EZSP_CONFIG_BROADCAST_MIN_ACKS_NEEDED, 1},

		// Use all remain memory for in/out radio packets
		{EZSP_CONFIG_PACKET_BUFFER_COUNT, 0xFF},
	};

	size_t defaults_count = sizeof(defaults) / sizeof(defaults[0]);
	for (size_t i = 0; i < defaults_count; i++) {
		if (!ezsp_set_config(defaults[i].id, defaults[i].value))
			return false;
	}

	/*
	 * Configure policies.
	 */
	struct {
		EzspPolicyId id;
		uint16_t value;
	} policies[] = {
		{EZSP_TRUST_CENTER_POLICY, EZSP_ALLOW_PRECONFIGURED_KEY_JOINS},
		{EZSP_TC_KEY_REQUEST_POLICY, EZSP_DENY_TC_KEY_REQUESTS},
		{EZSP_MESSAGE_CONTENTS_IN_CALLBACK_POLICY, EZSP_MESSAGE_TAG_ONLY_IN_CALLBACK},
		{EZSP_BINDING_MODIFICATION_POLICY, EZSP_CHECK_BINDING_MODIFICATIONS_ARE_VALID_ENDPOINT_CLUSTERS},
		{EZSP_POLL_HANDLER_POLICY, EZSP_POLL_HANDLER_IGNORE},
	};

	size_t policies_count = sizeof(policies) / sizeof(policies[0]);
	for (size_t i = 0; i < policies_count; i++) {
		if (!ezsp_set_policy(policies[i].id, policies[i].value))
			return false;
	}

	/*
	 * Add gateway endpoint.
	 */
	enum zb_public_profile_id {
		ZB_PROFILE_ID_INDUSTRIAL_PLANT_MONITORING = 0x0101,
		ZB_PROFILE_ID_HOME_AUTOMATION = 0x0104,
	};
	enum zb_generic_device_id {
		ZB_DEVICE_ID_ON_OFF_SWITCH        = 0x0000,
		ZB_DEVICE_ID_LEVEL_CONTROL_SWITCH = 0x0001,
		ZB_DEVICE_ID_ON_OFF_OUTPUT        = 0x0002,
		ZB_DEVICE_ID_LEVEL_CONTROL_OUTPUT = 0x0003,
		ZB_DEVICE_ID_SCENE_SELECTOR       = 0x0004,
		ZB_DEVICE_ID_CONFIG_TOOL          = 0x0005,
		ZB_DEVICE_ID_REMOTE_CONTROL       = 0x0006,
		ZB_DEVICE_ID_COMBINED_INTERFACE   = 0x0007,
		ZB_DEVICE_ID_RANGE_EXTENDER       = 0x0008,
		ZB_DEVICE_ID_MAINS_POWER_OUTLET   = 0x0009,
	};

	EzspEndpoint gwep = {0};
	gwep.ep_num = 1;
	gwep.profile_id = ZB_PROFILE_ID_HOME_AUTOMATION;
	gwep.device_id = ZB_DEVICE_ID_COMBINED_INTERFACE;
	gwep.in_cluster_count = 1;
	gwep.out_cluster_count = 1;
	gwep.in_clusters[0] = 0;
	gwep.out_clusters[0] = 0;

	LOG_INFO("ezsp: registering gateway endpoint");
	if (!ezsp_add_endpoint(&gwep)) {
		LOG_ERR("ezsp: could not register gateway endpoint");
		return false;
	}

	/*
	 * Add Green Power endpoint.
	 *
	 * The GP cluster has a Cluster ID of 0x0021.
	 * This cluster must be implemented on the reserved GP endpoint, 242,
	 * using a Profile ID of 0xA1E0.
	 */
#define ZGP_ENDPOINT   242
#define ZGP_PROFILE_ID 0xA1E0
#define ZGP_CLUSTER_ID 0x0021
	enum zgp_device_id {
		ZGP_DEVICE_ID_PROXY              = 0x0060,
		ZGP_DEVICE_ID_PROXY_MIN          = 0x0061,
		ZGP_DEVICE_ID_TARGET_PLUS        = 0x0062,
		ZGP_DEVICE_ID_TARGET             = 0x0063,
		ZGP_DEVICE_ID_COMMISSIONING_TOOL = 0x0064,
		ZGP_DEVICE_ID_COMBO              = 0x0065,
		ZGP_DEVICE_ID_COMBO_MIN          = 0x0066,
	};

	EzspEndpoint gpep = {0};
	gpep.ep_num = ZGP_ENDPOINT;
	gpep.profile_id = ZGP_PROFILE_ID;
	gpep.device_id = ZGP_DEVICE_ID_COMBO_MIN;
	gpep.in_cluster_count = 1;
	gpep.out_cluster_count = 1;
	gpep.in_clusters[0] = ZGP_CLUSTER_ID;
	gpep.out_clusters[0] = ZGP_CLUSTER_ID;

	LOG_INFO("ezsp: registering Green Power endpoint");
	if (!ezsp_add_endpoint(&gpep)) {
		LOG_ERR("ezsp: could not register Green Power endpoint");
		return false;
	}

	return true;
}

bool ezsp_network_status(EmberNwkStatus *ns)
{
	LOG_DBG("ezsp: requesting network status");
	ezsp_send_frame(EZSP_NETWORK_STATE, NULL, 0);

	if (!ezsp_read_reply_status(EZSP_NETWORK_STATE, ns))
		return false;

	LOG_DBG("ezsp: network status: 0x%02x", *ns);
	return true;
}

static bool ezsp_network_config(EmberNodeType *nt, EmberNwkConfig *nc)
{
	assert(nt != NULL && nc != NULL);

	ezsp_send_frame(EZSP_GET_NETWORK_PARAMETERS, NULL, 0);

	EzspFrame reply;
	if (ezsp_read_frame(EZSP_GET_NETWORK_PARAMETERS, &reply, EZSP_TIMEOUT) <= 0) {
		LOG_ERR("ezsp: no reply to EZSP_GET_NETWORK_PARAMETERS");
		return false;
	}
	if (reply.len != 1 && reply.len != (2 + sizeof(*nc))) {
		LOG_ERR("ezsp: wrong size for EZSP_GET_NETWORK_PARAMETERS reply (got %u, expected %zu)", reply.len, (2 + sizeof(*nc)));
		return false;
	}
	if (reply.data[0] != EMBER_SUCCESS) {
		LOG_ERR("ezsp: EZSP_GET_NETWORK_PARAMETERS failed: %s", ember_status_to_str(reply.data[0]));
		return false;
	}

	uint8_t *buf = reply.data + 1;
	*nt = buf[0];

	memcpy(nc->extended_pan_id, buf+1, sizeof(nc->extended_pan_id));
	buf += 9;
	nc->pan_id = u16_from_mem(buf);
	nc->radio_tx_power = buf[2];
	nc->radio_channel = buf[3];
	nc->join_method = buf[4];
	nc->nwk_manager_id = u16_from_mem(buf + 5);
	nc->nwk_update_id = buf[7];
	nc->channels = u32_from_mem(buf + 8);

	return true;
}

static bool ezsp_radio_config()
{
	ezsp_send_frame(EZSP_GET_RADIO_PARAMETERS, NULL, 0);
	// TODO
	return false;
}

bool ezsp_network_init(EmberStatus *es)
{
	assert(es != NULL);

	uint8_t opt = 0x00; // EmberNetworkInitStruct
	ezsp_send_frame(EZSP_NETWORK_INIT, &opt, 1);
	if (!ezsp_read_reply_status(EZSP_NETWORK_INIT, es))
		return false;

	if (*es == EMBER_NOT_JOINED)
		return true;
	if (*es != EMBER_SUCCESS) {
		LOG_ERR("ezsp: EZSP_NETWORK_INIT failed: %s", ember_status_to_str(*es));
		return false;
	}

	assert(*es == EMBER_SUCCESS);

	LOG_INFO("ezsp: initializing network...");
	if (!ezsp_read_callbacks(EZSP_TIMEOUT)) {
		LOG_ERR("ezsp: network still not up");
		return false;
	}
	if (ctx.stack_state != EMBER_NETWORK_UP) {
		LOG_ERR("ezsp: failed to initialize network");
		return false;
	}

	if (!ezsp_network_config(&ctx.node_type, &ctx.nwk_config))
		return false;

	LOG_INFO("ezsp: network joined as %s node on channel %d (PAN: 0x%04x, TX power: %d dBm)",
	    ember_node_type_to_str(ctx.node_type), ctx.nwk_config.radio_channel,
	    ctx.nwk_config.pan_id, ctx.nwk_config.radio_tx_power);
	return true;
}

bool ezsp_init(ezsp_read_func_t readfn, ezsp_write_func_t writefn, ezsp_callback_func_t cbfn)
{
	ctx.seq_num = 0;
	ctx.stack_state = EMBER_NETWORK_CLOSED;
	ezsp_queue_init(&ctx.cb_queue, 16);

	ctx.read_fn = readfn;
	ctx.write_fn = writefn;
	ctx.cb_handler = cbfn;

	if (!ezsp_negotiate_version())
		return false;

	ezsp_get_xncp_info();
	return true;
}

ssize_t ezsp_read_frame(uint16_t expected_fid, EzspFrame *frame, int timeout_ms)
{
	uint8_t buf[sizeof(EzspFrame)];
	ssize_t r;
	int elapsed_ms = 0;
	struct timespec ts_start, ts_now;

	assert(clock_gettime(CLOCK_MONOTONIC, &ts_start) == 0);

	while (elapsed_ms < timeout_ms) {
		r = ctx.read_fn(buf, sizeof(buf), timeout_ms - elapsed_ms);
		if (r <= 0)
			return r;

		if (!ezsp_parse_frame(buf, r, frame))
			return -1;

		if (frame->hdr.frame_id == expected_fid)
			return r;
		if (expected_fid == EZSP_FRAME_ID_ANY)
			return r;

		assert(clock_gettime(CLOCK_MONOTONIC, &ts_now) == 0);
		elapsed_ms = timespec_diff(&ts_start, &ts_now);

		if (EZSP_CBLOW_IS_CALLBACK(frame->hdr.cb_lo)) {
			LOG_DBG("ezsp: queueing callback frame %s", ezsp_cmd_id_to_str(frame->hdr.frame_id));
			ezsp_queue_push(&ctx.cb_queue, frame);
		} else
			LOG_ERR("ezsp: expected %s frame, got %s",
			    ezsp_cmd_id_to_str(expected_fid), ezsp_cmd_id_to_str(frame->hdr.frame_id));
	}

	return 0;
}

bool ezsp_read_reply_status(uint16_t expected_fid, uint8_t *es)
{
	assert(es != NULL);
	EzspFrame reply;

	if (ezsp_read_frame(expected_fid, &reply, EZSP_TIMEOUT) <= 0) {
		LOG_ERR("ezsp: no reply to %s", ezsp_cmd_id_to_str(expected_fid));
		return false;
	}
	if (reply.len != 1) {
		LOG_ERR("ezsp: wrong size for %s reply: expected 1 status byte",
		    ezsp_cmd_id_to_str(expected_fid));
		return false;
	}

	*es = reply.data[0];
	return true;
}

bool ezsp_read_xncp_reply(EzspXncpReply *r)
{
	assert(r != NULL);
	EzspFrame reply;

	if (ezsp_read_frame(EZSP_CUSTOM_FRAME, &reply, EZSP_TIMEOUT) <= 0) {
		LOG_ERR("ezsp: no reply to %s", ezsp_cmd_id_to_str(EZSP_CUSTOM_FRAME));
		return false;
	}
	if (reply.len < 1) {
		LOG_ERR("ezsp: wrong size for %s reply: expected at least 1B",
		    ezsp_cmd_id_to_str(EZSP_CUSTOM_FRAME));
		return false;
	}

	r->es = reply.data[0];
	if (reply.len > 1) {
		// reply.data[1] is payload size, skip
		memcpy(r->data, reply.data+2, reply.len-2);
		r->len = reply.len-2;
	} else {
		r->len = 0;
	}
	return true;
}

static bool ezsp_handle_callback(EzspFrame *frame)
{
	LOG_DBG("ezsp: got %s callback", ezsp_cmd_id_to_str(frame->hdr.frame_id));

	switch (frame->hdr.frame_id) {
	case EZSP_STACK_STATUS_HANDLER:
		if (frame->len != 1) {
			LOG_ERR("ezsp: wrong size for %s callback: expected 1B, got %u",
			    ezsp_cmd_id_to_str(frame->hdr.frame_id), frame->len);
			return false;
		}
		ctx.stack_state = frame->data[0];
		LOG_INFO("ezsp: stack state changed to %s", ember_status_to_str(ctx.stack_state));
		break;

	case EZSP_ENERGY_SCAN_RESULT_HANDLER: {
		if (frame->len != 2) {
			LOG_ERR("ezsp: wrong size for %s callback: expected 2 bytes, got %u",
			    ezsp_cmd_id_to_str(frame->hdr.frame_id), frame->len);
			return false;
		}
		uint8_t channel = frame->data[0];
		int8_t rssi = frame->data[1];
		printf("Energy scan result: channel %d: %d dBm\n", channel, rssi);
		break;
	}

	case EZSP_SCAN_COMPLETE_HANDLER: {
		if (frame->len != 2) {
			LOG_ERR("ezsp: wrong size for %s callback: expected 2 bytes, got %u",
			    ezsp_cmd_id_to_str(frame->hdr.frame_id), frame->len);
			return false;
		}

		EmberStatus es = frame->data[1];
		uint8_t channel = frame->data[0]; // Undefined if es == EMBER_SUCCESS
		if (es != EMBER_SUCCESS)
			LOG_ERR("ezsp: energy scan error: channel %d: %s", channel, ember_status_to_str(es));

		if (ctx.cb_handler != NULL)
			ctx.cb_handler(frame);
		break;
	}

	default:
		if (ctx.cb_handler == NULL || !ctx.cb_handler(frame)) {
			LOG_ERR("ezsp: unhandled callback %s", ezsp_cmd_id_to_str(frame->hdr.frame_id));
			return false;
		}
		break;
	}
	return true;
}

bool ezsp_read_callbacks(int timeout_ms)
{
	// Process pending callbacks first
	while (ezsp_queue_count(&ctx.cb_queue) > 0) {
		EzspFrame *f = ezsp_queue_pop(&ctx.cb_queue);
		assert(f != NULL);
		if (!ezsp_handle_callback(f))
			return false;
	}

	EzspFrame frame;
	do {
		if (ezsp_read_frame(EZSP_FRAME_ID_ANY, &frame, timeout_ms) <= 0)
			return false;

		if (!EZSP_CBLOW_IS_CALLBACK(frame.hdr.cb_lo)) {
			LOG_ERR("ezsp: expected callback frame, got %s",
			    ezsp_cmd_id_to_str(frame.hdr.frame_id));
			return false;
		}

		if (!ezsp_handle_callback(&frame))
			return false;
	} while ((frame.hdr.cb_lo & EZSP_CBLOW_CALLBACK_PENDING));

	return true;
}

/*
 * Start scanning the specified radio channels for RSSI values.
 *
 * channel_mask: bits set as 1 indicate that this particular channel should be
 *   scanned. For example, a channel_mask value of 0x00000001 would indicate
 *   that only channel 0 should be scanned.
 *   Valid channels range from 11 to 26 inclusive. This translates to a channel
 *   mask value of 0x07FFF800. A value of 0 is reinterpreted as the mask
 *   for all channels.
 */
bool ezsp_start_energy_scan(uint32_t channel_mask)
{
	uint8_t buf[6];

	buf[0] = EZSP_ENERGY_SCAN;
	if (channel_mask == 0)
		channel_mask = 0x07FFF800; // scan all channels (11 to 26)
	u32_to_mem(channel_mask, buf+1);
	buf[5] = 3; // Scan duration. Must be between [0..14] inclusive.

	ezsp_send_frame(EZSP_START_SCAN, buf, sizeof(buf));

	if (ctx.version == 9) { // EZSP v9
		EzspFrame reply;
		if (ezsp_read_frame(EZSP_START_SCAN, &reply, EZSP_TIMEOUT) <= 0) {
			LOG_ERR("ezsp: no reply to EZSP_START_SCAN");
			return false;
		}
		if (reply.len != 4) {
			LOG_ERR("ezsp: wrong size for EZSP_START_SCAN reply");
			return false;
		}

		uint32_t status = u32_from_mem(reply.data); // sl_status_t
		if (status != 0) {
			LOG_ERR("ezsp: EZSP_START_SCAN failed: 0x%04X", status);
			return false;
		}
	} else if (ctx.version == 8) { // EZSP v8
		EmberStatus es;
		if (!ezsp_read_reply_status(EZSP_START_SCAN, &es))
			return false;
		if (es != EMBER_SUCCESS) {
			LOG_ERR("ezsp: EZSP_START_SCAN failed: %s", ember_status_to_str(es));
			return false;
		}
	} else {
		LOG_ERR("ezsp: energy scan not supported with EZSP v%d", ctx.version);
		return false;
	}

	return true;
}

/*
 * Create a new network and become the coordinator.
 *
 * valid channels: [11, 26]
 * tx_power: max +20 dBm.
 */
bool ezsp_network_create(uint16_t *pan_id, uint8_t channel, uint8_t tx_power)
{
	assert(channel >= 11 && channel <= 26);
	assert(tx_power <= 20);

	EmberStatus es;

	// Clear any existing keys.
	ezsp_send_frame(EZSP_CLEAR_KEY_TABLE, NULL, 0);
	if (!ezsp_read_reply_status(EZSP_CLEAR_KEY_TABLE, &es))
		return false;
	if (es != EMBER_SUCCESS) {
		LOG_ERR("ezsp: EZSP_CLEAR_KEY_TABLE failed: %s", ember_status_to_str(es));
		return false;
	}

	// Configure initial security state.
	EmberInitialSecurityState sec_state = {0};
	sec_state.flags = EMBER_HAVE_PRECONFIGURED_KEY | EMBER_HAVE_NETWORK_KEY |
	    EMBER_REQUIRE_ENCRYPTED_KEY | EMBER_TRUST_CENTER_GLOBAL_LINK_KEY;
	sec_state.flags = htole16(sec_state.flags);

	// Preconfigured key, defined by the ZigBee Alliance.
	uint8_t zigbee_ha_key[EMBER_KEY_LEN] = {
		0x5A, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6C,
		0x6C, 0x69, 0x61, 0x6E, 0x63, 0x65, 0x30, 0x39,
	};
	memcpy(sec_state.pc_key, zigbee_ha_key, sizeof(zigbee_ha_key));

	// Generate random network key.
	arc4random_buf(sec_state.nwk_key, sizeof(sec_state.nwk_key));

	ezsp_send_frame(EZSP_SET_INITIAL_SECURITY_STATE, (void *)&sec_state, sizeof(sec_state));
	if (!ezsp_read_reply_status(EZSP_SET_INITIAL_SECURITY_STATE, &es))
		return false;
	if (es != EMBER_SUCCESS) {
		LOG_ERR("ezsp: EZSP_SET_INITIAL_SECURITY_STATE failed: %s", ember_status_to_str(es));
		return false;
	}

	/*
	 * Configure new network.
	 */
	EmberNwkConfig conf = {0};
	// Generate random PAN ID if requested
	if (*pan_id == 0)
		*pan_id = arc4random() & 0xffff;
	conf.pan_id = htole16(*pan_id);
	conf.radio_channel = channel;
	conf.radio_tx_power = tx_power;
	conf.join_method = 0x0; // EMBER_USE_MAC_ASSOCIATION
	// All remaining params should be 0

	ezsp_send_frame(EZSP_FORM_NETWORK, (void *)&conf, sizeof(conf));
	if (!ezsp_read_reply_status(EZSP_FORM_NETWORK, &es))
		return false;
	if (es != EMBER_SUCCESS) {
		LOG_ERR("ezsp: EZSP_FORM_NETWORK failed: %s", ember_status_to_str(es));
		return false;
	}

	LOG_DBG("ezsp: network created: PAN 0x%04x, channel %d", *pan_id, channel);
	return true;
}

uint8_t ezsp_nwk_radio_channel(void)
{
	return ctx.nwk_config.radio_channel;
}
