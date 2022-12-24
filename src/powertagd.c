#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "ash.h"
#include "gp.h"
#include "log.h"
#include "serial.h"
#include "util.h"
#include "zcl.h"
#include "crypto/aes.h"

// Default serial speed
#define BAUDRATE 115200

// ZCL attributes specific to Schneider Powertags.
enum {
	ZCL_SCHNEIDER_BREAKER_CAPACITY  = 0x0300, // in Amps, type: 16-bit unsigned int
	ZCL_SCHNEIDER_POWERTAG_POSITION = 0x0700, // 0 = downstream, 1 = upstream - type: 8-bit bitmap
};

// Custom EZSP xNCP commands.
enum {
	XNCP_CMD_INIT_MULTI_RAIL = 0x0e,
	XNCP_CMD_SET_GP_KEY      = 0x0f,
	XNCP_CMD_GET_GP_KEY      = 0x1f,
};


#ifdef ENABLE_MQTT
#include <mosquitto.h>

static struct mosquitto *mosq;
static volatile bool mosq_connected = false;

/* Callback called when the client receives a CONNACK message from the broker. */
static void mosq_on_connect(struct mosquitto *mosq, void *obj, int reason_code)
{
	if (reason_code != 0) {
		/* If the connection fails for any reason, we don't want to keep on
		 * retrying in this example, so disconnect. Without this, the client
		 * will attempt to reconnect. */
		mosquitto_disconnect(mosq);
		LOG_FATAL("could not connect to MQTT broker: %s", mosquitto_connack_string(reason_code));
	}

	mosq_connected = true;
}

static int mqtt_client_init(void)
{
	mosquitto_lib_init();
	/*
	 * Create a new MQTT client.
	 * id = NULL -> ask the broker to generate a client id for us
	 * clean session = true -> the broker should remove old sessions when we connect
	 * obj = NULL -> we aren't passing any of our private data for callbacks
	 */
	mosq = mosquitto_new(NULL, true, NULL);
	if (mosq == NULL) {
		LOG_FATAL("mosquitto_new() failed: out of memory");
		return 1;
	}

	/* Configure callbacks. This should be done before connecting ideally. */
	mosquitto_connect_callback_set(mosq, mosq_on_connect);
	//mosquitto_publish_callback_set(mosq, on_publish);

	/*
	 * Connect on port 1883, with a keepalive of 60 seconds.
	 * This call makes the socket connection only, it does not complete the MQTT
	 * CONNECT/CONNACK flow, you should use mosquitto_loop_start() or
	 * mosquitto_loop_forever() for processing net traffic.
	 */
	int rc = mosquitto_connect(mosq, "127.0.0.1", 1883, 60);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_destroy(mosq);
		LOG_ERR("could not connect to MQTT broker: %s", mosquitto_strerror(rc));
		return 1;
	}

	/* Run the network loop in a background thread, this call returns quickly. */
	rc = mosquitto_loop_start(mosq);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_destroy(mosq);
		LOG_ERR("mosquitto_loop_start() failed: %s", mosquitto_strerror(rc));
		return 1;
	}

	while (mosq_connected != 1)
		usleep(500000);
	LOG_INFO("Connected to MQTT broker");
	return 0;
}

static void mqtt_close(void)
{
	mosquitto_lib_cleanup();
}
#endif /* ENABLE_MQTT */


static void ezsp_energy_scan_completed(EmberStatus es)
{
	exit((es == EMBER_SUCCESS) ? 0 : 1);
}

static bool handle_rx_gp_frame(const EzspFrame *frame)
{
	EmberStatus es;

	if (frame->len < 1) {
		LOG_ERR("ezsp: bad size for EZSP_GP_INCOMING_MESSAGE_HANDLER: %u", frame->len);
		return false;
	}

	es = frame->data[0];
	switch (es) {
	case EMBER_UNPROCESSED:
		LOG_DBG("ezsp: got unprocessed GP frame: %s", ember_status_to_str(es));
		break;
	case EMBER_NO_SECURITY:
	case EMBER_SUCCESS:
		break;
	default:
		LOG_ERR("ezsp: error receiving GP frame: %s", ember_status_to_str(es));
		return false;
	}

	return gp_process_raw_frame((frame->data)+1, frame->len-1);
}

static bool handle_gp_sent_callback(const EzspFrame *frame)
{
	if (frame->len != 2) {
		LOG_ERR("gp: bad size for EZSP_GP_SENT_HANDLER: %u", frame->len);
		return false;
	}

	EmberStatus es = frame->data[0];
	uint8_t gpep = frame->data[1];

	if (es != EMBER_SUCCESS) {
		LOG_ERR("gp: failed to send frame %d: %s", gpep, ember_status_to_str(es));
		return false;
	}

	LOG_DBG("gp: frame %d successfully sent", gpep);
	return true;
}

static bool handle_raw_tx_complete_callback(const EzspFrame *frame)
{
	if (frame->len < 1) {
		LOG_ERR("ezsp: bad size for EZSP_RAW_TRANSMIT_COMPLETE_HANDLER: %u", frame->len);
		return false;
	}

	EmberStatus es = frame->data[0];
	if (es != EMBER_SUCCESS) {
		LOG_ERR("ezsp: failed to send raw frame: %s", ember_status_to_str(es));
		return false;
	}
	return true;
}

static bool ezsp_callback_handler(const EzspFrame *frame)
{
	switch (frame->hdr.frame_id) {
	case EZSP_SCAN_COMPLETE_HANDLER:
		ezsp_energy_scan_completed(frame->data[1]);
		break;

	case EZSP_GP_INCOMING_MESSAGE_HANDLER:
		(void)handle_rx_gp_frame(frame);
		break;

	case EZSP_GP_SENT_HANDLER:
		(void)handle_gp_sent_callback(frame);
		break;

	case EZSP_RAW_TRANSMIT_COMPLETE_HANDLER:
		(void)handle_raw_tx_complete_callback(frame);
		break;

	default:
		return false;
	}
	return true;
}

static void process_basic_cluster_report(ZclAttrList *list, FILE *fp)
{
	assert(fp != NULL);

	if (list->count == 0) {
		LOG_ERR("process_basic_cluster_report: no attributes");
		return;
	}

	for (int i = 0; i < list->count; i++) {
		ZclAttr *attr = &list->attrs[i];
		fprintf(fp, "%s=%s,",
		    zcl_attr_name(ZCL_CLUSTER_BASIC, attr->id),
		    zcl_attr_format_value(attr));
	}

	//LOG_INFO("[0x%08x] Basic: %s", src, str);
}

static void process_metering_cluster_report(ZclAttrList *list, FILE *fp)
{
	assert(fp != NULL);

	uint32_t multiplier = 1;
	uint32_t divisor = 1;

	if (list->count == 0) {
		LOG_ERR("process_metering_cluster_report: no attributes");
		return;
	}

	// Get multiplier and divisor first, if they exist
	for (int i = 0; i < list->count; i++) {
		ZclAttr *attr = &list->attrs[i];

		switch (attr->id) {
		case ZCL_METERING_MULTIPLIER:
			multiplier = attr->value.u64;
			break;
		case ZCL_METERING_DIVISOR:
			divisor = attr->value.u64;
			break;
		}
	}

	for (int i = 0; i < list->count; i++) {
		ZclAttr *attr = &list->attrs[i];

		switch (attr->id) {
		case ZCL_METERING_UNIT_MEASURE:
			LOG_WARN("unsupported ZCL_METERING_UNIT_MEASURE");
			continue;
		case ZCL_METERING_MULTIPLIER:
		case ZCL_METERING_DIVISOR:
			continue;
		default:
			break;
		}

		const char *name = zcl_attr_name(ZCL_CLUSTER_METERING, attr->id);
		if (*name == '\0') {
			fprintf(fp, "0x%04x=%s,",
			    attr->id, zcl_attr_format_value(attr)/*, zcl_attr_type_name(attr->orig_type)*/);
			continue;
		}

		if (attr->orig_type == ZCL_ATTR_TYPE_U48) {
			fprintf(fp, "%s=%.2f,",
			    name, attr->value.u64 * multiplier / (float)divisor);
		} else {
			fprintf(fp, "%s=%s,",
			    name, zcl_attr_format_value(attr));
		}
	}

	//LOG_INFO("[0x%08x] Metering: %s", src, str);
}

static void process_electrical_meas_cluster_report(ZclAttrList *list, FILE *fp)
{
	assert(fp != NULL);

#if 0
	uint16_t freq_mul = 1, freq_div = 1;
	uint32_t nps_power_mul = 1, nps_power_div = 1;
#endif
	uint16_t voltage_mul = 1, voltage_div = 1;
	uint16_t current_mul = 1, current_div = 1;
	uint16_t power_mul   = 1, power_div   = 1;

	if (list->count == 0) {
		LOG_ERR("process_electrical_meas_cluster_report: no attributes");
		return;
	}

	// Get multipliers and divisors first, if they exist
	for (int i = 0; i < list->count; i++) {
		ZclAttr *attr = &list->attrs[i];
		switch (attr->id) {
#if 0
		case ZCL_EMR_FREQUENCY_MULTIPLIER:
			freq_mul = attr->value.u64;
			break;
		case ZCL_EMR_FREQUENCY_DIVISOR:
			freq_div = attr->value.u64;
			break;
		case ZCL_EMR_POWER_MULTIPLIER:
			nps_power_mul = attr->value.u64;
			break;
		case ZCL_EMR_POWER_DIVISOR:
			nps_power_div = attr->value.u64;
			break;
#endif
		case ZCL_EMR_AC_VOLTAGE_MULTIPLIER:
			voltage_mul = attr->value.u64;
			break;
		case ZCL_EMR_AC_VOLTAGE_DIVISOR:
			voltage_div = attr->value.u64;
			break;
		case ZCL_EMR_AC_CURRENT_MULTIPLIER:
			current_mul = attr->value.u64;
			break;
		case ZCL_EMR_AC_CURRENT_DIVISOR:
			current_div = attr->value.u64;
			break;
		case ZCL_EMR_AC_POWER_MULTIPLIER:
			power_mul = attr->value.u64;
			break;
		case ZCL_EMR_AC_POWER_DIVISOR:
			power_div = attr->value.u64;
			break;
		}
	}

	for (int i = 0; i < list->count; i++) {
		ZclAttr *attr = &list->attrs[i];

		switch (attr->id) {
		case ZCL_EMR_FREQUENCY_MULTIPLIER:
		case ZCL_EMR_FREQUENCY_DIVISOR:
		case ZCL_EMR_POWER_MULTIPLIER:
		case ZCL_EMR_POWER_DIVISOR:
		case ZCL_EMR_AC_VOLTAGE_MULTIPLIER:
		case ZCL_EMR_AC_VOLTAGE_DIVISOR:
		case ZCL_EMR_AC_CURRENT_MULTIPLIER:
		case ZCL_EMR_AC_CURRENT_DIVISOR:
		case ZCL_EMR_AC_POWER_MULTIPLIER:
		case ZCL_EMR_AC_POWER_DIVISOR:
			continue;

		case ZCL_EMR_AC_P1_LINE_CURRENT:
		case ZCL_EMR_AC_P1_RMS_CURRENT:
		case ZCL_EMR_AC_P2_LINE_CURRENT:
		case ZCL_EMR_AC_P2_RMS_CURRENT:
		case ZCL_EMR_AC_P3_LINE_CURRENT:
		case ZCL_EMR_AC_P3_RMS_CURRENT:
			attr->value.flt = attr->value.u64 * current_mul / (float)current_div;
			attr->type = ZCL_ATTR_TYPE_FLOAT_32;
			break;

		case ZCL_EMR_AC_P1_RMS_VOLTAGE:
		case ZCL_EMR_AC_P2_RMS_VOLTAGE:
		case ZCL_EMR_AC_P3_RMS_VOLTAGE:
		case ZCL_EMR_AC_VOLTAGE_PHASE_AB:
		case ZCL_EMR_AC_VOLTAGE_PHASE_BC:
		case ZCL_EMR_AC_VOLTAGE_PHASE_CA:
			attr->value.flt = attr->value.u64 * voltage_mul / (float)voltage_div;
			attr->type = ZCL_ATTR_TYPE_FLOAT_32;
			break;

		default:
			break;
		}

		const char *name = zcl_attr_name(ZCL_CLUSTER_ELECTRICAL_MEASUREMENTS, attr->id);
		if (*name == '\0') {
			fprintf(fp, "0x%04x=%s,",
			    attr->id, zcl_attr_format_value(attr)/*, zcl_attr_type_name(attr->orig_type)*/);
			continue;
		}

		fprintf(fp, "%s=%s,",
		    name, zcl_attr_format_value(attr));
	}

	//LOG_INFO("[0x%08x] Electrical Measurements: %s", src, str);
}

static bool gpf_process_mfr_specific_reporting(const GpFrame *f)
{
	LOG_DBG("gp: got MFR_ATTRIBUTE_REPORTING frame");

	time_t timestamp = time(NULL);
	GpSrcId srcid = gpf_source_id(f);
	const uint8_t *buf = f->payload;
	uint8_t len = f->payload_len;

	if (len < 4) {
		LOG_ERR("gp: MFR_ATTRIBUTE_REPORTING frame: payload too small");
		return false;
	}

	uint16_t mfr_id = u16_from_mem(buf);
	uint16_t cluster_id = u16_from_mem(buf+2);
	buf += 4, len -= 4;

	if (mfr_id != MFR_ID_SCHNEIDER) {
		LOG_WARN("gp: report from unknown mfr id 0x%04x, ignoring", mfr_id);
		return true;
	}

	if (len < 3) {
		LOG_ERR("gp: MFR_ATTRIBUTE_REPORTING frame: no attributes");
		return false;
	}

	ZclAttrList *list = zcl_parse_attr_list(buf, len);
	if (list == NULL)
		return false;

	char str[1024] = {0};
	FILE *fp = fmemopen(str, sizeof(str), "w");

	switch (cluster_id) {
	case ZCL_CLUSTER_BASIC:
		process_basic_cluster_report(list, fp);
		break;
	case ZCL_CLUSTER_METERING:
		process_metering_cluster_report(list, fp);
		break;
	case ZCL_CLUSTER_ELECTRICAL_MEASUREMENTS:
		process_electrical_meas_cluster_report(list, fp);
		break;

	default:
		LOG_WARN("gp: MFR_ATTRIBUTE_REPORTING: unknown cluster ID 0x%04x", cluster_id);
		return false;
	}

	zcl_attr_list_free(list);
	fclose(fp);

	if (str[0] == '\0')
		return false;

	// Drop last comma
	len = strlen(str);
	if (str[len-1] == ',')
		str[len-1] = '\0';

	printf("powertag,id=0x%08x %s %lu\n", srcid, str, timestamp);
	return true;
}

static bool gpf_process_mfr_multi_cluster_reporting(const GpFrame *f)
{
	LOG_DBG("gp: got MFR_MULTI_CLUSTER_REPORTING frame");

	// TODO
	return true;
}

static bool gp_callback_handler(const GpFrame *f)
{
	switch (f->cmd_id) {
	case GPF_CMD_MANUFACTURER_ATTRIBUTE_REPORTING:
		return gpf_process_mfr_specific_reporting(f);
	case GPF_CMD_MANUFACTURER_MULTI_CLUSTER_REPORTING:
		return gpf_process_mfr_multi_cluster_reporting(f);
	}
	return false;
}

/*
 * Check whether a key is all zeros.
 */
static inline bool ember_key_is_null(EmberKey *key)
{
	static EmberKey zero_key = {0};
	return (memcmp(key->data, zero_key.data, sizeof(zero_key.data)) == 0);
}

/*
 * Retrieve the GP key from NCP.
 */
static bool xncp_get_gp_key(EmberKey *gp_key)
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
static bool xncp_set_gp_key(EmberKey *key)
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

static bool xncp_init(void)
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

static void usage(void)
{
	printf("usage: powertagd [-qv] [-d device] [cmd]\n\n");
	printf("commands:\n");
	printf("    create <channel> [txpower]   Create a new network\n");
	printf("    leave                        Leave the ZigBee network and clear keys\n");
	printf("    scan                         Scan ZigBee channels\n");
	printf("    info                         Print ZigBee network informations\n\n");

	printf("    set-gp-key <key>             Set the GP security key (from a 16-bytes hex string)\n");
	printf("    get-gp-key                   Print the GP security key\n");
	exit(1);
}

enum {
	CMD_DEFAULT = 0,
	CMD_CREATE_NET,
	CMD_LEAVE_NET,
	CMD_SCAN_NET,
	CMD_PRINT_INFOS,
	CMD_SET_GP_KEY,
	CMD_GET_GP_KEY,
};

static int parse_cmd_arg(const char *name)
{
	if (name == NULL || *name == 0)
		return CMD_DEFAULT;

	struct {
		const char *name;
		int cmd;
	} cmd_table[] = {
		{ "create", CMD_CREATE_NET },
		{ "leave",  CMD_LEAVE_NET },
		{ "scan",   CMD_SCAN_NET },
		{ "info",   CMD_PRINT_INFOS },
		{ "set-gp-key", CMD_SET_GP_KEY },
		{ "get-gp-key", CMD_GET_GP_KEY },
		{ NULL, 0 },
	};
	for (unsigned i = 0; cmd_table[i].name != NULL; i++) {
		if (strcmp(name, cmd_table[i].name) == 0)
			return cmd_table[i].cmd;
	}
	return -1;
}

int main(int argc, char **argv)
{
	const char *serialdev = NULL;
	int verbosity = 1;
	int cmd = CMD_DEFAULT;

	int ch;
	while ((ch = getopt(argc, argv, "d:qv")) != -1) {
		switch (ch) {
		case 'q':
			verbosity = 0;
			break;
		case 'v':
			verbosity = 2;
			break;
		case 'd':
			serialdev = optarg;
			break;
		default:
			usage();
			// NOTREACHED
		}
	}
	argv += optind;
	argc -= optind;

	if (serialdev == NULL) {
		warnx("no serial device specified (-d)");
		usage();
	}

	if (argc > 0) {
		cmd = parse_cmd_arg(*argv);
		if (cmd == -1)
			errx(1, "unknown command '%s'", *argv);
		argv++, argc--;
	}

	log_init();
	switch (verbosity) {
	case 0:
		log_set_level(LOG_LEVEL_WARN);
		break;
	case 1:
		log_set_level(LOG_LEVEL_INFO);
		break;
	case 2:
		log_set_level(LOG_LEVEL_DEBUG);
		break;
	}
	// Line-buffered stdout
	setlinebuf(stdout);

	serial_open(serialdev, BAUDRATE);

	ash_init(serial_read, serial_write);
	if (!ash_reset_ncp())
		LOG_FATAL("ash: could not connect to NCP");

	if (!ezsp_init(ash_read, ash_write, ezsp_callback_handler))
		LOG_FATAL("EZSP initialization failed");

	if (cmd == CMD_GET_GP_KEY) {
		EmberKey gp_key;
		if (!xncp_get_gp_key(&gp_key))
			return 1;
		printf("GP key: 0x%s\n", key2str(gp_key.data));
		return 0;
	}
	if (cmd == CMD_SET_GP_KEY) {
		if (argc < 1)
			errx(1, "set-gp-key requires an argument");
		EmberKey gp_key;
		if (hex2bin(*argv, gp_key.data, EMBER_KEY_LEN) != EMBER_KEY_LEN)
			errx(1, "set-gp-key: invalid key format");
		printf("Setting GP key to 0x%s\n", key2str(gp_key.data));
		return !xncp_set_gp_key(&gp_key);
	}

	/*
	 * The ZigBee stack needs to be initialized for the other commands.
	 */
	if (!ezsp_stack_init())
		return 1;

	if (cmd == CMD_SCAN_NET) {
		printf("Starting energy scan...\n");
		if (!ezsp_start_energy_scan(0)) {
			printf("Energy scan failed!\n");
			return 1;
		}
		while (1)
			ezsp_read_callbacks(1500);
		// NOT REACHED
	}
	if (cmd == CMD_CREATE_NET) {
		uint8_t channel = 11;
		uint8_t txpower = 0;

		if (argc < 1) {
			warnx("create: invalid arguments");
			printf("usage: powertagd create <channel> [tx_power]\n");
			exit(1);
		}

		channel = strtol(argv[0], NULL, 10);
		if (channel < 11 || channel > 26)
			errx(1, "create: invalid channel '%s'. Must be between 11 and 26.", argv[0]);

		if (argc > 1) {
			txpower = strtol(argv[1], NULL, 10);
			if (txpower < 0 || txpower > 20)
				errx(1, "create: invalid TX power '%s'. Must be between 0 and +20 dBm.", argv[1]);
		}

		uint16_t pan_id = 0;
		if (!ezsp_network_create(&pan_id, channel, txpower))
			return 1;

		printf("ZigBee network successfully created!\n");
		printf("    channel:  %d\n", channel);
		printf("    TX power: +%d dBm\n", txpower);
		printf("    PAN id:   0x%04x\n", pan_id);

		// Generate random GP key.
		EmberKey gp_key;
		arc4random_buf(gp_key.data, sizeof(gp_key.data));
		return !xncp_set_gp_key(&gp_key);
	}

	/*
	 * Try joining an existing network.
	 */
	EmberStatus es;
	if (!ezsp_network_init(&es))
		return false;
	if (es == EMBER_NOT_JOINED) {
		LOG_ERR("powertagd: no network found, you need to create one first");
		return 1;
	}
	usleep(500*1000);

	if (cmd == CMD_PRINT_INFOS) {
		// TODO
		return 0;
	}

#ifdef ENABLE_MQTT
	if (mqtt_client_init() != 0)
		return 1;
#endif

	/* Initialize Green Power stack with the key stored in the NCP. */
	EmberKey gpd_key = {0};
	if (!xncp_init())
		return 1;
	if (!xncp_get_gp_key(&gpd_key))
		return 1;
	if (ember_key_is_null(&gpd_key)) {
		LOG_ERR( "powertagd: no GP key has been configured yet");
		LOG_INFO("powertagd: run 'powertagd set-gp-key <key>' to set one");
		return 1;
	}
	gp_init(&gpd_key, gp_callback_handler);

	// At the moment we don't use the built-in sink capabilities of the NCP,
	// we handle the decryption/encryption of GP frames ourselves.
	//gp_sink_init();

	gp_set_allow_commissioning(true);

	while (1) {
		ezsp_read_callbacks(3000);
	}

	serial_close();
#ifdef ENABLE_MQTT
	mqtt_close();
#endif
	return 0;
}
