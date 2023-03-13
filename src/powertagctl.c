#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "ash.h"
#include "log.h"
#include "serial.h"
#include "zcl.h"
#include "crypto/aes.h"
#include "powertag.h"

/*
* Verbosity:
 *   0 = quiet
 *   1 = normal
 *   2 = debug
 */
static int verbose = 1;

// The device id of the PowerTag being configured.
static GpSrcId powertag_dev = 0;
// Set to 1 after receiving a WRITE_ACK or READ_REPLY reply from powertag_dev.
static bool powertag_did_reply = false;
// The reply received from powertag_dev for a WRITE_ACK or READ_REPLY cmd.
static GpFrame powertag_reply;


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
		LOG_DBG("ezsp: got unprocessed GP frame (%s)", ember_status_to_str(es));
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

static bool gp_callback_handler(const GpFrame *f)
{
	GpSrcId srcid = gpf_source_id(f);

	switch (f->cmd_id) {
	case GPF_CMD_MANUFACTURER_ATTRIBUTE_REPORTING:
	case GPF_CMD_MANUFACTURER_MULTI_CLUSTER_REPORTING:
		break;
	case GPF_CMD_WRITE_ATTRIBUTES_ACK:
		if (powertag_dev != srcid) {
			LOG_ERR("gp: 0x%02x: got unexpected write ack", srcid);
			return false;
		}
		LOG_DBG("gp: 0x%02x: got write ack", srcid);
		powertag_did_reply = true;
		memcpy(&powertag_reply, f, sizeof(*f));
		break;
	case GPF_CMD_READ_ATTRIBUTES_REPLY:
		if (powertag_dev != srcid) {
			LOG_ERR("gp: 0x%02x: got unexpected read reply", srcid);
			return false;
		}
		powertag_did_reply = true;
		memcpy(&powertag_reply, f, sizeof(*f));
		break;
	}
	return true;
}

/*
 * Queue an identify request for the given PowerTag device ID.
 */
static bool powertag_queue_identify(GpSrcId devid)
{
	static uint8_t identify_frame[10] = {
		GPF_CMD_WRITE_ATTRIBUTES, 0x00 /* Options field */,
		ZCL_CLUSTER_IDENTIFY & 0xff, ZCL_CLUSTER_IDENTIFY >> 8, /* Cluster ID */
		5,          /* Record length */
		0x00, 0x00, /* Attribute ID (ZCL_IDENTIFY_TIME) */
		ZCL_ATTR_TYPE_U16, /* Data type */
		0x0a, 0x00, /* 10s identify time (uint16) */
	};

	uint8_t cmd[1+5+sizeof(identify_frame)];
	cmd[0] = XNCP_CMD_PUSH_TX_QUEUE;
	cmd[1] = GP_APP_SOURCE_ID;
	u32_to_mem(devid, cmd+2);
	memcpy(cmd+6, identify_frame, sizeof(identify_frame));

	LOG_DBG("0x%02x: queuing identify cmd", devid);
	ezsp_send_xncp_frame(cmd, sizeof(cmd));

	EzspXncpReply reply;
	if (!ezsp_read_xncp_reply(&reply))
		return false;
	if (reply.es != EMBER_SUCCESS) {
		LOG_ERR("0x%02x: failed queuing identify cmd", devid);
		return false;
	}

	LOG_DBG("0x%02x: queued identify cmd", devid);
	return true;
}

/*
 * Queue a read request to retrieve the PowerTag mounting position
 * (upstream or downstream).
 */
static bool powertag_queue_read_mount_position(GpSrcId devid)
{
	static uint8_t read_frame[9] = {
		GPF_CMD_READ_ATTRIBUTES, 0x02, /* Options field (manufacturer field present) */
		MFR_ID_SCHNEIDER     & 0xff, MFR_ID_SCHNEIDER     >> 8, /* Manufacturer ID */
		ZCL_CLUSTER_POWERTAG & 0xff, ZCL_CLUSTER_POWERTAG >> 8, /* Cluster ID */
		2, /* Record length */
		ZCL_POWERTAG_MOUNT_POSITION & 0xff, ZCL_POWERTAG_MOUNT_POSITION >> 8, /* Attribute ID */
	};

	uint8_t cmd[1+5+sizeof(read_frame)];
	cmd[0] = XNCP_CMD_PUSH_TX_QUEUE;
	cmd[1] = GP_APP_SOURCE_ID;
	u32_to_mem(devid, cmd+2);
	memcpy(cmd+6, read_frame, sizeof(read_frame));

	ezsp_send_xncp_frame(cmd, sizeof(cmd));

	EzspXncpReply reply;
	if (!ezsp_read_xncp_reply(&reply))
		return false;
	if (reply.es != EMBER_SUCCESS) {
		LOG_ERR("0x%02x: failed queuing identify frame", devid);
		return false;
	}

	LOG_DBG("0x%02x: queued identify frame", devid);
	return true;
}

/*
 * Queue a write request to set the PowerTag mounting position
 * (upstream or downstream).
 */
static bool powertag_queue_write_mount_position(GpSrcId devid, uint8_t pos)
{
	static uint8_t write_frame[11] = {
		GPF_CMD_WRITE_ATTRIBUTES, 0x02, /* Options field (manufacturer field present) */
		MFR_ID_SCHNEIDER     & 0xff, MFR_ID_SCHNEIDER     >> 8, /* Manufacturer ID */
		ZCL_CLUSTER_POWERTAG & 0xff, ZCL_CLUSTER_POWERTAG >> 8, /* Cluster ID */
		4, /* Record length */
		ZCL_POWERTAG_MOUNT_POSITION & 0xff, ZCL_POWERTAG_MOUNT_POSITION >> 8, /* Attribute ID */
		ZCL_ATTR_TYPE_BITMAP_8, /* Data type */
		0, /* Value */
	};

	uint8_t cmd[1+5+sizeof(write_frame)];
	cmd[0] = XNCP_CMD_PUSH_TX_QUEUE;
	cmd[1] = GP_APP_SOURCE_ID;
	u32_to_mem(devid, cmd+2);
	memcpy(cmd+6, write_frame, sizeof(write_frame));
	cmd[sizeof(cmd)-1] = pos;

	ezsp_send_xncp_frame(cmd, sizeof(cmd));

	EzspXncpReply reply;
	if (!ezsp_read_xncp_reply(&reply))
		return false;
	if (reply.es != EMBER_SUCCESS) {
		LOG_ERR("0x%02x: failed queuing identify frame", devid);
		return false;
	}

	LOG_DBG("0x%02x: queued identify frame", devid);
	return true;
}

static bool powertag_wait_reply(int timeout_ms)
{
	struct timespec start, now;
	assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);

	// Reset flag
	powertag_did_reply = false;

	while (!powertag_did_reply) {
		ezsp_read_callbacks(3000);

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (timespec_diff(&start, &now) > timeout_ms)
			break;
	}

	return powertag_did_reply;
}

static void usage(void)
{
	printf("Usage: powertagctl [-qv] [-d device] <cmd>\n\n");
	printf("Network commands:\n");
	printf("    create <channel> [txpower]   Create a new network\n");
	printf("    leave                        Leave the ZigBee network and clear keys\n");
	printf("    scan                         Scan all ZigBee channels\n");
	printf("    set-gp-key <key>             Set the GP security key (from a 16-bytes hex string)\n");
	printf("    get-gp-key                   Print the GP security key\n\n");

	printf("PowerTag commands:\n");
	printf("    pair                         Allow pairing of PowerTags\n");
	printf("    identify <dev>               Blink the PowerTag during 10s\n");
	printf("    invert-flow <dev>            Invert the PowerTag current flow direction\n");
	exit(1);
}

enum {
	CMD_DEFAULT = 0,
	CMD_CREATE_NET,
	CMD_LEAVE_NET,
	CMD_SCAN_NET,
	CMD_SET_GP_KEY,
	CMD_GET_GP_KEY,
	CMD_PAIR,
	CMD_IDENTIFY,
	CMD_INVERT_FLOW,
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
		{ "set-gp-key", CMD_SET_GP_KEY },
		{ "get-gp-key", CMD_GET_GP_KEY },
		{ "pair", CMD_PAIR },
		{ "identify", CMD_IDENTIFY },
		{ "invert-flow", CMD_INVERT_FLOW },
		{ NULL, 0 },
	};
	for (unsigned i = 0; cmd_table[i].name != NULL; i++) {
		if (strcmp(name, cmd_table[i].name) == 0)
			return cmd_table[i].cmd;
	}
	return -1;
}

int cmd_get_gp_key(void)
{
	EmberKey gp_key;
	if (!xncp_get_gp_key(&gp_key))
		return 1;

	if (verbose)
		printf("GP key: %s\n", key2str(gp_key.data));
	else
		printf("%s\n", key2str(gp_key.data));
	return 0;
}

int cmd_set_gp_key(int argc, char **argv)
{
	if (argc < 1)
		errx(1, "set-gp-key requires an argument");

	EmberKey gp_key;
	if (hex2bin(*argv, gp_key.data, EMBER_KEY_LEN) != EMBER_KEY_LEN)
		errx(1, "set-gp-key: invalid key format");

	printf("Setting GP key to %s\n", key2str(gp_key.data));
	return !xncp_set_gp_key(&gp_key);
}

int cmd_scan_net(void)
{
	printf("Starting energy scan...\n");
	if (!ezsp_start_energy_scan(0)) {
		printf("Energy scan failed!\n");
		return 1;
	}

	struct timespec start, now;
	assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);

	while (1) {
		ezsp_read_callbacks(1500);

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (timespec_diff(&start, &now) > 10000) // 10s timeout
			break;
	}

	// Should not be reached.
	LOG_FATAL("unexpected error during network scan!");
	return 1;
}

int cmd_create_net(int argc, char **argv)
{
	uint8_t channel = 11;
	uint8_t txpower = 0;

	if (argc < 1) {
		warnx("create: invalid arguments");
		fprintf(stderr, "usage: powertagctl create <channel> [tx_power]\n");
		return 1;
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
	// HACK: wait for network to be UP.
	sleep(1);

	// Generate random GP key.
	printf("Generating GreenPower key...\n");
	EmberKey gp_key;
	arc4random_buf(gp_key.data, sizeof(gp_key.data));
	return !xncp_set_gp_key(&gp_key);
}

int cmd_enable_pairing(void)
{
	gp_set_allow_commissioning(true);
	LOG_INFO("PowerTags can now be commissioned!");
	while (1)
		ezsp_read_callbacks(3000);
	return 0;
}

int cmd_identify(int argc, char **argv)
{
	if (argc != 1)
		errx(1, "identify: no device id specified");

	uint8_t buf[4];
	if (hex2bin(*argv, buf, sizeof(buf)) != sizeof(buf))
		errx(1, "identify: invalid device id");

	powertag_dev = ntohl(u32_from_mem(buf));
	if (!powertag_queue_identify(powertag_dev))
		return 1;

	if (!powertag_wait_reply(10000)) {
		LOG_ERR("Could not find PowerTag 0x%02x. Is it on and commissioned?", powertag_dev);
		return 1;
	}

	LOG_INFO("PowerTag 0x%02x is now blinking rapidly", powertag_dev);
	return 0;
}

int cmd_invert_flow(int argc, char **argv)
{
	if (argc != 1)
		errx(1, "invert-flow: no device id specified");

	uint8_t dev[4];
	if (hex2bin(*argv, dev, sizeof(dev)) != sizeof(dev))
		errx(1, "invert-flow: invalid device id");

	powertag_dev = ntohl(u32_from_mem(dev));
	if (!powertag_queue_read_mount_position(powertag_dev))
		return 1;

	if (!powertag_wait_reply(10000)) {
		LOG_ERR("Could not find PowerTag 0x%02x. Is it on and commissioned?", powertag_dev);
		return 1;
	}

	GpFrame *f = &powertag_reply;
	if (f->cmd_id != GPF_CMD_READ_ATTRIBUTES_REPLY) {
		LOG_ERR("invert-flow: expected %02x cmd reply, got %02x", GPF_CMD_READ_ATTRIBUTES_REPLY, f->cmd_id);
		return 1;
	}

	const uint8_t *buf = f->payload;
	uint8_t len = f->payload_len;
	if (len < 11) {
		LOG_ERR("invert-flow: short reply (%u bytes)", len);
		return 1;
	}
	uint8_t opts = buf[0];
	if (opts != 0x2) {
		LOG_ERR("invert-flow: got reply with bad option field");
		return 1;
	}
	// Skip options & manufacturer field
	buf += 3, len -= 3;

	uint16_t cluster_id = u16_from_mem(buf);
	buf += 2, len -= 2;
	if (cluster_id != ZCL_CLUSTER_POWERTAG) {
		LOG_ERR("invert-flow: got reply with bad cluster id (%04x)", cluster_id);
		return 1;
	}
	// Skip attribute list len
	buf++, len--;
	uint16_t attr_id = u16_from_mem(buf);
	buf += 2, len -= 2;
	uint8_t ok = buf[0];
	uint8_t data_type = buf[1];
	uint8_t dir = buf[2];

	if (attr_id != ZCL_POWERTAG_MOUNT_POSITION || ok != 0 ||
	    data_type != ZCL_ATTR_TYPE_BITMAP_8 || dir > 1) {
		LOG_ERR("invert-flow: got bad reply");
		return 1;
	}

	LOG_INFO("PowerTag 0x%04x: changing flow direction to %s",
	    powertag_dev, (dir == 0) ? "upstream" : "downstream");
	if (!powertag_queue_write_mount_position(powertag_dev, !dir))
		return 1;

	if (!powertag_wait_reply(10000)) {
		LOG_ERR("Could not find PowerTag 0x%02x. Is it on and commissioned?", powertag_dev);
		return 1;
	}
	if (powertag_reply.cmd_id != GPF_CMD_WRITE_ATTRIBUTES_ACK) {
		LOG_ERR("Failed to change flow direction for PowerTag 0x%02x", powertag_dev);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *serialdev = NULL;
	int cmd = CMD_DEFAULT;

	int ch;
	while ((ch = getopt(argc, argv, "d:qv")) != -1) {
		switch (ch) {
		case 'q':
			verbose = 0;
			break;
		case 'v':
			verbose = 2;
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

	if (argc < 1)
		errx(1, "no command given");

	cmd = parse_cmd_arg(*argv);
	if (cmd == -1)
		errx(1, "unknown command '%s'", *argv);
	argv++, argc--;

	log_init();
	switch (verbose) {
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

	switch (cmd) {
	case CMD_GET_GP_KEY:
		return cmd_get_gp_key();
	case CMD_SET_GP_KEY:
		return cmd_set_gp_key(argc, argv);
	default:
		break;
	}

	/*
	 * The ZigBee stack needs to be initialized for all other commands.
	 */
	if (!ezsp_stack_init())
		return 1;

	switch (cmd) {
	case CMD_SCAN_NET:
		return cmd_scan_net();
	case CMD_CREATE_NET:
		return cmd_create_net(argc, argv);
	default:
		break;
	}

	/* Bring up network for remaining commands. */
	if (!powertag_net_init(gp_callback_handler))
		return 1;

	switch (cmd) {
	case CMD_PAIR:
		return cmd_enable_pairing();
	case CMD_IDENTIFY:
		return cmd_identify(argc, argv);
	case CMD_INVERT_FLOW:
		return cmd_invert_flow(argc, argv);
	default:
		break;
	}

	serial_close();
	return 0;
}
