#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include "ash.h"
#include "log.h"
#include "serial.h"
#include "zcl.h"
#include "crypto/aes.h"
#include "powertag.h"

enum {
	OUTPUT_FILE     = 0,
	OUTPUT_INFLUXDB = 1,
};

static int output_type = OUTPUT_FILE;
static FILE *output_file = NULL;

static struct {
	const char *url;
	const char *org;
	const char *bucket;
	const char *token;
	char hostname[128];
	struct sockaddr_in addr;
} influx_opts;

/*
 * InfluxDB metrics are written in batch every 30s.
 * We assume the buffer is large enough to store all PowerTag reports for
 * this time frame.
 */
#define INFLUXDB_BATCH_INTERVAL 30
static struct {
	pthread_t tid;
	pthread_mutex_t lock; // To synchronize access to the following fields.
	char data[128*1024];
	size_t size;          // Total record size in data.
	unsigned int nrec;    // Number of records in data.
} influx_ctx;


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


static void *influx_thread(void *arg)
{
#define MAX_RETRY 3
	int retries = 0;
	char reply[512];
	struct timespec ts_last, ts_now;

	clock_gettime(CLOCK_MONOTONIC, &ts_last);

	while (1) {
		sleep(3);
		clock_gettime(CLOCK_MONOTONIC, &ts_now);
		int elapsed_ms = timespec_diff(&ts_last, &ts_now);
		if (elapsed_ms < (INFLUXDB_BATCH_INTERVAL*1000))
			continue;

		ts_last = ts_now;
		pthread_mutex_lock(&influx_ctx.lock);

		if (influx_ctx.size == 0) {
			pthread_mutex_unlock(&influx_ctx.lock);
			continue;
		}

		LOG_DBG("influxdb: connecting to %s...", influx_opts.hostname);
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			LOG_FATAL("influxdb: cannot create socket: %s", strerror(errno));
		if (connect(fd, (struct sockaddr *)&influx_opts.addr, sizeof(influx_opts.addr)) < 0) {
			if (retries >= MAX_RETRY)
				LOG_FATAL("influxdb: could not connect after %d retries, aborting", retries);

			LOG_ERR("influxdb: failed to connect: %s", strerror(errno));
			retries++;
			pthread_mutex_unlock(&influx_ctx.lock);
			continue;
		}
		retries = 0;

		int res = dprintf(fd,
		    "POST /api/v2/write?org=%s&bucket=%s&precision=s HTTP/1.1\r\n"
		    "Host: %s\r\n"
		    "Authorization: Token %s\r\n"
		    "Content-Type: text/plain; charset=utf-8\r\n"
		    "Accept: application/json\r\n"
		    "Content-Length: %zu\r\n\r\n",
		    influx_opts.org, influx_opts.bucket,
		    influx_opts.hostname,
		    influx_opts.token,
		    influx_ctx.size);
		if (res < 0)
			LOG_FATAL("influxdb: write: %s", strerror(errno));

		char *buf = influx_ctx.data;
		size_t total = influx_ctx.size;
		size_t sent = 0;
		do {
			ssize_t wr = write(fd, buf+sent, total-sent);
			if (wr < 0)
				LOG_FATAL("influxdb: write: %s", strerror(errno));
			if (wr == 0)
				break;
			sent += wr;
		} while (sent < total);

		// Reset data and release lock
		unsigned int nrec = influx_ctx.nrec;
		influx_ctx.size = 0;
		influx_ctx.nrec = 0;
		pthread_mutex_unlock(&influx_ctx.lock);

		// Read reply
		total = sizeof(reply) - 1;
		size_t received = 0;
		do {
			ssize_t rd = read(fd, reply+received, total-received);
			if (rd < 0)
				LOG_FATAL("influxdb: read: %s", strerror(errno));
			if (rd >= 20)
				break;
			received += rd;
		} while (received < total);

		static char *http_ok = "HTTP/1.1 204";
		if (strncmp(reply, http_ok, strlen(http_ok)) != 0) {
			char *nl = strchr(reply, '\r');
			if (nl != NULL)
				LOG_ERR("influxdb: server error: %.*s", (int)(nl-reply), reply);
			else
				LOG_ERR("influxdb: unknown server error");
		} else {
			LOG_DBG("influxdb: wrote %u records", nrec);
		}

		close(fd);
	}

	return NULL;
}

static void write_influxdb(const char *fmt, va_list ap)
{
	pthread_mutex_lock(&influx_ctx.lock);

	char *buf = influx_ctx.data + influx_ctx.size;
	int res = vsprintf(buf, fmt, ap);
	assert(res > 0);
	influx_ctx.size += res;
	influx_ctx.nrec++;

	pthread_mutex_unlock(&influx_ctx.lock);
}

static void write_report(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	switch (output_type) {
	case OUTPUT_FILE:
		vfprintf(output_file, fmt, ap);
		break;
	case OUTPUT_INFLUXDB:
		write_influxdb(fmt, ap);
		break;
	}
	va_end(ap);
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
		const char *name = zcl_attr_name(ZCL_CLUSTER_BASIC, attr->id);
		/*
		 * Some PowerTags firmwares report a bunch of non-standard attributes.
		 * Just ignore them.
		 */
		if (name == NULL)
			LOG_DBG("zcl basic cluster: unknown attribute 0x%04x", attr->id);
		else
			fprintf(fp, "%s=%s,", name, zcl_attr_format_value(attr));
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

		case ZCL_METERING_POWER_FACTOR:
			// Newer PowerTag firmwares send -128 as power factor value when no
			// current is flowing, probably to mean invalid value.
			if (attr->value.i64 == -128)
				attr->value.i64 = 100;
			break;
		default:
			break;
		}

		const char *name = zcl_attr_name(ZCL_CLUSTER_METERING, attr->id);
		if (name == NULL) {
			fprintf(fp, "0x%04x=%s,", attr->id, zcl_attr_format_value(attr));
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

	uint16_t freq_mul = 1, freq_div = 1;
#if 0
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

		case ZCL_EMR_FREQUENCY_MULTIPLIER:
			freq_mul = attr->value.u64;
			break;
		case ZCL_EMR_FREQUENCY_DIVISOR:
			freq_div = attr->value.u64;
			break;
#if 0
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

		case ZCL_EMR_AC_FREQUENCY:
			attr->value.flt = attr->value.u64 * freq_mul / (float)freq_div;
			attr->type = ZCL_ATTR_TYPE_FLOAT_32;
			break;

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
		if (name == NULL) {
			fprintf(fp, "0x%04x=%s,", attr->id, zcl_attr_format_value(attr));
			continue;
		}

		fprintf(fp, "%s=%s,", name, zcl_attr_format_value(attr));
	}

	//LOG_INFO("[0x%08x] Electrical Measurements: %s", src, str);
}

static void process_powertag_cluster_report(ZclAttrList *list, FILE *fp)
{
	assert(fp != NULL);

	if (list->count == 0) {
		LOG_ERR("process_powertag_cluster_report: no attributes");
		return;
	}

	for (int i = 0; i < list->count; i++) {
		ZclAttr *attr = &list->attrs[i];
		const char *name = NULL;
		switch (attr->id) {
		case ZCL_POWERTAG_BREAKER_CAPACITY:
			name = "breaker_capacity";
			break;
		case ZCL_POWERTAG_MOUNT_POSITION:
			name = "mount_position";
			break;
		default:
			break;
		}

		if (name == NULL)
			LOG_DBG("PowerTag cluster: unknown attribute 0x%04x", attr->id);
		else
			fprintf(fp, "%s=%s,", name, zcl_attr_format_value(attr));
	}
}

static void gpf_process_mfr_specific_reporting(const GpFrame *f)
{
	LOG_DBG("gp: got MFR_ATTRIBUTE_REPORTING frame");

	time_t timestamp = time(NULL);
	GpSrcId srcid = gpf_source_id(f);
	const uint8_t *buf = f->payload;
	uint8_t len = f->payload_len;

	if (len < 4) {
		LOG_ERR("gp: MFR_ATTRIBUTE_REPORTING frame: payload too small");
		return;
	}

	uint16_t mfr_id = u16_from_mem(buf);
	uint16_t cluster_id = u16_from_mem(buf+2);
	buf += 4, len -= 4;

	if (mfr_id != MFR_ID_SCHNEIDER) {
		LOG_WARN("gp: report from unknown mfr id 0x%04x, ignoring", mfr_id);
		return;
	}

	if (len < 3) {
		LOG_ERR("gp: MFR_ATTRIBUTE_REPORTING frame: no attributes");
		return;
	}

	ZclAttrList *list = zcl_parse_attr_list(buf, len);
	if (list == NULL)
		return;

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
	case ZCL_CLUSTER_POWERTAG:
		process_powertag_cluster_report(list, fp);
		break;
	// This cluster only contains the "report interval" attribute, ignore it.
	case ZCL_CLUSTER_POWERTAG_2:
		return;

	default:
		LOG_WARN("gp: MFR_ATTRIBUTE_REPORTING: unknown cluster ID 0x%04x", cluster_id);
		return;
	}

	zcl_attr_list_free(list);
	fclose(fp);

	if (str[0] == '\0')
		return;

	// Drop last comma
	len = strlen(str);
	if (str[len-1] == ',')
		str[len-1] = '\0';

	write_report("powertag,id=0x%08x %s %lu\n", srcid, str, timestamp);
}

static void gpf_process_mfr_multi_cluster_reporting(const GpFrame *f)
{
	LOG_DBG("gp: got MFR_MULTI_CLUSTER_REPORTING frame");

	// TODO
}

static bool gp_callback_handler(const GpFrame *f)
{
	switch (f->cmd_id) {
	case GPF_CMD_MANUFACTURER_ATTRIBUTE_REPORTING:
		gpf_process_mfr_specific_reporting(f);
		break;
	case GPF_CMD_MANUFACTURER_MULTI_CLUSTER_REPORTING:
		gpf_process_mfr_multi_cluster_reporting(f);
		break;
	default:
		return false;
	}
	return true;
}

static int parse_output_arg(const char *arg)
{
	if (strcmp(arg, "influxdb") == 0)
		return OUTPUT_INFLUXDB;

	if (strcmp(arg, "-") == 0 || strcmp(arg, "stdout") == 0) {
		output_file = stdout;
		return OUTPUT_FILE;
	}

	output_file = fopen(arg, "a");
	if (output_file == NULL)
		err(1, "%s", arg);

	return OUTPUT_FILE;
}

static void usage(void)
{
	printf("Usage: powertagd [-qv] [-d device] [-o output]\n");
	exit(1);
}

enum {
	INFLUX_URL = 1000,
	INFLUX_ORG,
	INFLUX_BUCKET,
	INFLUX_TOKEN,
};

static struct option long_opts[] = {
	{"dev",      required_argument, NULL, 'd'},
	{"output",   required_argument, NULL, 'o'},
	{"quiet",    no_argument, NULL, 'q'},
	{"verbose",  no_argument, NULL, 'q'},

	// InfluxDB options
	{"url",    required_argument, NULL, INFLUX_URL},
	{"org",    required_argument, NULL, INFLUX_ORG},
	{"bucket", required_argument, NULL, INFLUX_BUCKET},
	{"token",  required_argument, NULL, INFLUX_TOKEN},

	{NULL, 0, NULL, 0}
};

int main(int argc, char **argv)
{
	const char *serialdev = NULL;
	int verbose = 1;

	int ch;
	while ((ch = getopt_long(argc, argv, "d:o:qv", long_opts, NULL)) != -1) {
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
		case 'o':
			output_type = parse_output_arg(optarg);
			break;

		// InfluxDB options
		case INFLUX_URL:
			influx_opts.url = optarg;
			break;
		case INFLUX_ORG:
			influx_opts.org = optarg;
			break;
		case INFLUX_BUCKET:
			influx_opts.bucket = optarg;
			break;
		case INFLUX_TOKEN:
			influx_opts.token = optarg;
			break;
		default:
			usage();
			// NOTREACHED
		}
	}
	argv += optind;
	argc -= optind;

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

	if (output_file == NULL)
		output_file = stdout;

	if (serialdev == NULL) {
		warnx("no serial device specified (-d)");
		usage();
	}
	if (output_type == OUTPUT_INFLUXDB) {
		if (!influx_opts.url)
			errx(1, "influxdb output requires --url option");
		if (!influx_opts.org)
			errx(1, "influxdb output requires --org option");
		if (!influx_opts.bucket)
			errx(1, "influxdb output requires --bucket option");
		if (!influx_opts.token)
			errx(1, "influxdb output requires --token option");

		// Parse URL. It should look like http://host:port
		const char *url = influx_opts.url;
		char *hostname = influx_opts.hostname;
		int port = 8086; // Default InfluxDB port.

		const char *protocol = "http://";
		if (strncmp(url, protocol, strlen(protocol)) != 0)
			errx(1, "invalid influxdb url '%s'", url);

		// Skip prefix
		url += strlen(protocol);
		char *colon = strrchr(url, ':');
		if (colon) {
			memcpy(hostname, url, colon-url);
			hostname[colon-url] = '\0';
			port = atoi(colon + 1);
		} else {
			memcpy(hostname, url, strlen(url));
			hostname[strlen(url)] = '\0';
		}

		struct hostent *he = gethostbyname(hostname);
		if (he == NULL)
			err(1, "gethostbyname");

		memset(&influx_opts.addr, 0, sizeof(influx_opts.addr));
		influx_opts.addr.sin_family = AF_INET;
		influx_opts.addr.sin_port = htons(port);
		memcpy(&influx_opts.addr.sin_addr.s_addr, he->h_addr, he->h_length);

		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(influx_opts.addr.sin_addr), ip, INET_ADDRSTRLEN);
		LOG_INFO("InfluxDB host: %s:%i", ip, port);

		int r = pthread_mutex_init(&influx_ctx.lock, NULL);
		if (r != 0)
			err(1, "pthread_mutex_init");
		r = pthread_create(&influx_ctx.tid, NULL, &influx_thread, NULL);
		if (r != 0)
			err(1, "pthread_create");
	}

	serial_open(serialdev, BAUDRATE);
	ash_init(serial_read, serial_write);
	if (!ash_reset_ncp())
		LOG_FATAL("ash: could not connect to NCP");

	/*
	 * Initialize the ZigBee stack and try joining an existing network.
	 */
	if (!ezsp_init(ash_read, ash_write, ezsp_callback_handler))
		LOG_FATAL("EZSP initialization failed");
	if (!ezsp_stack_init())
		return 1;
	if (!powertag_net_init(gp_callback_handler))
		return 1;

#ifdef ENABLE_MQTT
	if (mqtt_client_init() != 0)
		return 1;
#endif

	while (1) {
		ezsp_read_callbacks(3000);
	}

	serial_close();
#ifdef ENABLE_MQTT
	mqtt_close();
#endif
	return 0;
}
