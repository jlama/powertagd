/*
 * ZigBee Green Power implementation for Schneider PowerTag.
 */

#include <assert.h>
#include <stdio.h>

#include "gp.h"
#include "log.h"
#include "util.h"
#include "crypto/aes.h"

#define GP_NONCE_SIZE 13
typedef struct {
	uint8_t data[GP_NONCE_SIZE];
} gp_nonce_t;

/* Options byte in GP Commissioning frames (2nd payload byte). */
#define GPF_COMMISSIONING_OPT_MAC_SEQ_CAP  0x01
#define GPF_COMMISSIONING_OPT_RX_ON_CAP    0x02
#define GPF_COMMISSIONING_OPT_HAS_APP_INFO 0x04
#define GPF_COMMISSIONING_OPT_PANID_REQ    0x10
#define GPF_COMMISSIONING_OPT_GP_KEY_REQ   0x20
#define GPF_COMMISSIONING_OPT_FIXED_LOC    0x40
#define GPF_COMMISSIONING_OPT_EXTENDED     0x80

/* Extended options byte in GP Commissioning frames (if present). */
#define GPF_COMMISSIONING_EXTOPT_SEC_LVL_CAP         0x03 // mask (GpSecurityLevel)
#define GPF_COMMISSIONING_EXTOPT_KEY_TYPE            0x1C // mask (GpKeyType)
#define GPF_COMMISSIONING_EXTOPT_HAS_GPD_KEY         0x20
#define GPF_COMMISSIONING_EXTOPT_GPD_ENC_KEY         0x40
#define GPF_COMMISSIONING_EXTOPT_HAS_GPD_OUT_COUNTER 0x80

/* App info byte in GP Commissioning frames (if present). */
#define GPF_COMMISSIONING_APPINFO_MFR_ID       0x01
#define GPF_COMMISSIONING_APPINFO_MODEL_ID     0x02
#define GPF_COMMISSIONING_APPINFO_GPD_CMDS     0x04
#define GPF_COMMISSIONING_APPINFO_CLUSTER_LIST 0x08

/* Options byte in GP Commissioning Reply frame. */
#define GPF_COMMISSIONING_REPLY_OPT_PANID_PRESENT    0x01
#define GPF_COMMISSIONING_REPLY_OPT_SEC_KEY_PRESENT  0x02
#define GPF_COMMISSIONING_REPLY_OPT_GPD_KEY_ENC      0x04
#define GPF_COMMISSIONING_REPLY_OPT_SEC_LVL          0x18 // mask
#define GPF_COMMISSIONING_REPLY_OPT_SEC_LVL_SHIFT    3
#define GPF_COMMISSIONING_REPLY_OPT_KEY_TYPE         0xE0 // mask
#define GPF_COMMISSIONING_REPLY_OPT_KEY_TYPE_SHIFT   5


struct gp_ctx {
	EmberKey gpd_key;

	bool gp_allow_commissioning;

	uint8_t next_gpep_handle; // index in tx_queue, from 0 to 7
	//uint8_t tx_queue[8];

	GpCallbackHandler cb_fn;
};
static struct gp_ctx ctx;


static void gp_addr_from_src_id(GpSrcId srcid, GpAddr *addr)
{
	addr->id.src_id = srcid;
	addr->app_id = GP_APP_SOURCE_ID;
	addr->endpoint = 0;
}

static void gp_addr_serialize(GpAddr *addr, uint8_t *buf)
{
	buf[0] = addr->app_id;
	if (addr->app_id == GP_APP_SOURCE_ID) {
		u32_to_mem(addr->id.src_id, buf+1);
		u32_to_mem(addr->id.src_id, buf+5);
	} else if (addr->app_id == GP_APP_IEEE_ADDRESS) {
		u64_to_mem(addr->id.ieee_addr, buf+1);
	} else {
		LOG_FATAL("gp_addr_serialize: invalid app_id 0x%02X", addr->app_id);
	}
	buf[9] = addr->endpoint;
}

/*
 * WARNING: EZSPv8 uses an EmberGpAddress struct with app_id as its first field.
 */
static void gp_addr_deserialize(const uint8_t *buf, GpAddr *addr)
{
	addr->app_id = buf[0];
	addr->endpoint = buf[9];

	if (addr->app_id == GP_APP_SOURCE_ID) {
		addr->id.src_id = u32_from_mem(buf+1);
	} else if (addr->app_id == GP_APP_IEEE_ADDRESS) {
		addr->id.ieee_addr = u64_from_mem(buf+1);
	} else {
		LOG_ERR("gp_addr_deserialize: invalid app_id 0x%02X", addr->app_id);
		addr->id.src_id = 0;
		addr->app_id = GP_APP_SOURCE_ID;
	}
}

GpSrcId gpf_source_id(const GpFrame *gpf)
{
	assert(gpf->addr.app_id == GP_APP_SOURCE_ID);
	return gpf->addr.id.src_id;
}

static void gp_log_frame(LogLevel lvl, GpFrame *f)
{
	char autocom = (f->auto_commissioning) ? 'Y' : 'N';
	char rx_after_tx = (f->bidirectional_info & 0x1) ? 'Y' : 'N';

	if (f->addr.app_id == GP_APP_SOURCE_ID)
		log_msg(lvl, "gp:   [%d] src_id: 0x%04x, link: %d, auto_commissioning: %c, rx_after_tx: %c",
		    f->seq_num, gpf_source_id(f), f->gpd_link, autocom, rx_after_tx);
	else
		log_msg(lvl, "gp:   [%d] ieee_id: 0x%08llX, link: %d, auto_commissioning: %c, rx_after_tx: %c",
		    f->seq_num, (unsigned long long)f->addr.id.ieee_addr, f->gpd_link, autocom, rx_after_tx);

	log_msg(lvl, "gp:   [%d] security_lvl: 0x%02X, key_type: 0x%02X, frame_counter: %d, mic: 0x%04x",
	    f->seq_num, f->sec_lvl, f->key_type, f->sec_frame_counter, f->mic);
	log_msg(lvl, "gp:   [%d] cmd: 0x%02X, payload_len: %d%s",
	    f->seq_num, f->cmd_id, f->payload_len, (f->payload_len > 0) ? ", payload:" : "");

	if (f->payload_len == 0)
		return;

	char str[512] = {0};
	FILE *fp = fmemopen(str, sizeof(str), "w");
	assert(fp != NULL);

	uint8_t *buf = f->payload;
	size_t len = f->payload_len;
	while (len > 0) {
		fprintf(fp, "[");
		for (int i = 0; len > 0 && i < 16; i++) {
			fprintf(fp, " %02X", *buf);
			buf++, len--;
		}
		fprintf(fp, " ]");
		rewind(fp);
		log_msg(lvl, "gp:        %s", str);
	}

	fclose(fp);
}

/*
 * Warning: to be able to use the NCP GP sink, the table must be configured
 * in firmware to be > 0.
 */
bool gp_sink_init(void)
{
	uint16_t proxy_table_size, sink_table_size;

	if (!ezsp_get_config(EZSP_CONFIG_GP_PROXY_TABLE_SIZE, &proxy_table_size))
		return false;
	if (!ezsp_get_config(EZSP_CONFIG_GP_SINK_TABLE_SIZE, &sink_table_size))
		return false;

	LOG_INFO("gp: proxy table size: %d", proxy_table_size);
	LOG_INFO("gp: sink table size: %d", sink_table_size);
	if (sink_table_size == 0) {
		LOG_ERR("gp: firmware has no GP sink table");
		return false;
	}

	LOG_DBG("gp: initializing GP sink table...");
	ezsp_send_frame(EZSP_GP_SINK_TABLE_INIT, NULL, 0);
	EzspFrame reply;
	ezsp_read_frame(EZSP_GP_SINK_TABLE_INIT, &reply, EZSP_TIMEOUT);

	return true;
}

bool gp_sink_find_entry(GpSrcId id, uint8_t *index)
{
	assert(index != NULL);

	GpAddr addr = {0};
	addr.id.src_id = id;
	addr.app_id = GP_APP_SOURCE_ID;

	uint8_t buf[sizeof(addr)];
	gp_addr_serialize(&addr, buf);

	ezsp_send_frame(EZSP_GP_SINK_TABLE_FIND_OR_ALLOCATE_ENTRY, buf, sizeof(buf));
	if (!ezsp_read_reply_status(EZSP_GP_SINK_TABLE_FIND_OR_ALLOCATE_ENTRY, index))
		return false;
	if (*index == 0xff) {
		LOG_ERR("gp: failed to allocate GP sink entry for source id 0x%08X", id);
		return false;
	}
	return true;
}

void gp_init(EmberKey *gpd_key, GpCallbackHandler cbfn)
{
	memcpy(&ctx.gpd_key, gpd_key, sizeof(*gpd_key));

	ctx.gp_allow_commissioning = false;
	ctx.next_gpep_handle = 0;
	ctx.cb_fn = cbfn;
}

void gp_set_allow_commissioning(bool v)
{
	ctx.gp_allow_commissioning = v;
}

bool gp_send(GpSrcId src_id, uint8_t cmd_id, uint8_t *data, uint8_t len)
{
	assert(len <= 128);

#define GP_SEND_TIMEOUT_MS    100
#define GP_SEND_BUF_BASE_SIZE (2 + sizeof(GpAddr) + 5)

	uint8_t buf[GP_SEND_BUF_BASE_SIZE + len];

	buf[0] = 1; // Action to perform on GP TX queue: 1 to add, 0 to remove.
	buf[1] = 1; // use Clear Channel Assessment

	GpAddr addr;
	gp_addr_from_src_id(src_id, &addr);
	gp_addr_serialize(&addr, buf+2);

	buf[12] = cmd_id;
	buf[13] = len;
	memcpy(buf+14, data, len);

	buf[14+len] = ctx.next_gpep_handle;
	ctx.next_gpep_handle = (ctx.next_gpep_handle + 1) & 0x7;
	// TX timeout in ms
	u16_to_mem(GP_SEND_TIMEOUT_MS, buf+15+len);

	ezsp_send_frame(EZSP_GP_SEND, buf, sizeof(buf));

	EmberStatus es;
	if (!ezsp_read_reply_status(EZSP_GP_SEND, &es))
		return false;
	if (es != EMBER_SUCCESS) {
		LOG_ERR("gp: failed to send cmd 0x%02X to GPD 0x%08X", cmd_id, src_id);
		return false;
	}
	return true;
}

bool gp_parse_frame(const uint8_t *buf, uint8_t len, GpFrame *gpf)
{
	assert(len > 0);
	assert(gpf != NULL);

	if (len < 27) {
		LOG_ERR("gp: got truncated GP frame (%u bytes)", len);
		return false;
	}

	gpf->gpd_link = buf[0];
	gpf->seq_num = buf[1];
	gp_addr_deserialize(buf+2, &gpf->addr);

	gpf->sec_lvl = buf[12];
	gpf->key_type = buf[13];
	gpf->auto_commissioning = buf[14];
	gpf->bidirectional_info = buf[15];
	gpf->sec_frame_counter = u32_from_mem(buf+16);
	gpf->cmd_id = buf[20];
	gpf->mic = u32_from_mem(buf+21);
	gpf->proxy_table_idx = buf[25];
	gpf->payload_len = buf[26];

	len -= 27;
	if (len != gpf->payload_len) {
		LOG_ERR("gp: bad GP payload size (expected %d, got %u)", gpf->payload_len, len);
		return false;
	}
	memcpy(gpf->payload, buf+27, gpf->payload_len);

	gp_log_frame(LOG_LEVEL_DEBUG, gpf);
	return true;
}

static bool gp_handle_commissioning_frame(GpFrame *gpf)
{
	LOG_INFO("gp: got commissioning frame from GPD 0x%04x", gpf_source_id(gpf));

	// Sanity checks
	if (!ctx.gp_allow_commissioning) {
		static bool warned_commissioning_disabled = false;
		if (!warned_commissioning_disabled) {
			LOG_WARN("gp: commissioning disabled, ignoring commissioning request");
			warned_commissioning_disabled = true;
		}
		return false;
	}
	if (gpf->auto_commissioning) {
		LOG_ERR("gp: got bad commissioning frame: auto-commissioning field should be 0");
		return false;
	}
	if (!GPF_RX_AFTER_TX(gpf)) {
		LOG_WARN("gp: GPD 0x%04x does not expect a reply to its commissioning frame",
		    gpf_source_id(gpf));
		return true;
	}
	if (gpf->payload_len < 2) {
		LOG_ERR("gp: got bad commissioning frame: too short payload");
		return false;
	}

	uint8_t *buf = gpf->payload;
	size_t len = gpf->payload_len;

	uint8_t device_id = buf[0];
	uint8_t options = buf[1];
	buf += 2, len -= 2;

	uint8_t ext_options = 0;
	if (options & GPF_COMMISSIONING_OPT_EXTENDED) {
		// Extended field is present
		if (len == 0) {
			LOG_ERR("gp: bad commissioning frame: no extended options");
			return false;
		}
		ext_options = *buf;
		buf++, len--;
	}

	bool has_gpd_key = (ext_options & GPF_COMMISSIONING_EXTOPT_HAS_GPD_KEY);
	bool is_gpd_key_encrypted = (ext_options & GPF_COMMISSIONING_EXTOPT_GPD_ENC_KEY);
	bool has_counter = (ext_options & GPF_COMMISSIONING_EXTOPT_HAS_GPD_OUT_COUNTER);
	bool has_app_info = (options & GPF_COMMISSIONING_OPT_HAS_APP_INFO);

	uint8_t gpd_key[EMBER_KEY_LEN] = {0};
	uint32_t gpd_key_mic = 0;
	uint32_t gpd_counter = 0;
	uint16_t mfr_id = 0, model_id = 0;

	if (has_gpd_key) {
		if (len < EMBER_KEY_LEN) {
			LOG_ERR("gp: bad commissioning frame: no GPD key");
			return false;
		}
		memcpy(gpd_key, buf, EMBER_KEY_LEN);
		buf += EMBER_KEY_LEN, len -= EMBER_KEY_LEN;

		if (is_gpd_key_encrypted) {
			if (len < 4) {
				LOG_ERR("gp: bad commissioning frame: no GPD key MIC");
				return false;
			}
			gpd_key_mic = u32_from_mem(buf);
			buf += 4, len -= 4;
		}
	}
	if (has_counter) {
		if (len < 4) {
			LOG_ERR("gp: bad commissioning frame: no GPD counter");
			return false;
		}
		gpd_counter = u32_from_mem(buf);
		buf += 4, len -= 4;
	}
	if (has_app_info) {
		if (len < 1) {
			LOG_ERR("gp: bad commissioning frame: no App Info field");
			return false;
		}

		uint8_t appinfo = *buf;
		buf++, len--;

		if (appinfo & GPF_COMMISSIONING_APPINFO_MFR_ID) {
			if (len < 2) {
				LOG_ERR("gp: bad commissioning frame: no manufacturer ID");
				return false;
			}

			mfr_id = u16_from_mem(buf);
			buf += 2, len -= 2;
		}

		if (appinfo & GPF_COMMISSIONING_APPINFO_MODEL_ID) {
			if (len < 2) {
				LOG_ERR("gp: bad commissioning frame: no model ID");
				return false;
			}

			model_id = u16_from_mem(buf);
			buf += 2, len -= 2;
		}

		// Recent PowerTags include App Info GPD_CMDS and CLUSTER_LIST fields.
		// Just ignore them.
	}

	LOG_INFO("gp: Starting commissioning for GPD 0x%04x", gpf_source_id(gpf));
	LOG_INFO("gp:   Device ID: 0x%02x%s", device_id, (device_id == 0xfe) ? " (Manufacturer Specific)" : "");

	if (mfr_id != 0) {
		if (mfr_id == MFR_ID_SCHNEIDER)
			LOG_INFO("gp:   Manufacturer ID: %s (0x%04x)", "Schneider Electric", MFR_ID_SCHNEIDER);
		else
			LOG_INFO("gp:   Manufacturer ID: 0x%04x", mfr_id);
	}
	if (model_id != 0) {
		switch (model_id) {
		default:
			LOG_INFO("gp:   Model ID: 0x%04x", model_id);
			break;
		}
	}

	LOG_DBG("gp:   Options:");
	LOG_DBG("gp:       MAC Sequence number capability: %s",
	    (options & GPF_COMMISSIONING_OPT_MAC_SEQ_CAP) ? "YES" : "NO");
	LOG_DBG("gp:       RX On capability: %s",
	    (options & GPF_COMMISSIONING_OPT_RX_ON_CAP) ? "YES" : "NO");
	LOG_DBG("gp:       PAN id request: %s",
	    (options & GPF_COMMISSIONING_OPT_PANID_REQ) ? "YES" : "NO");
	LOG_DBG("gp:       App Info field: %s",
	    (options & GPF_COMMISSIONING_OPT_HAS_APP_INFO) ? "YES" : "NO");
	LOG_DBG("gp:       Security Key request: %s",
	    (options & GPF_COMMISSIONING_OPT_GP_KEY_REQ) ? "YES" : "NO");
	LOG_DBG("gp:       Fixed Location: %s",
	    (options & GPF_COMMISSIONING_OPT_FIXED_LOC) ? "YES" : "NO");
	LOG_DBG("gp:       Extended options field: %s",
	    (options & GPF_COMMISSIONING_OPT_EXTENDED) ? "YES" : "NO");

	uint8_t sec_lvl = 0;
	if (ext_options != 0) {
		sec_lvl = (ext_options & GPF_COMMISSIONING_EXTOPT_SEC_LVL_CAP);
		LOG_DBG("gp:   Extended options:");
		LOG_DBG("gp:       Security level capabilities: 0x%x", sec_lvl);
		LOG_DBG("gp:       Key type: 0x%x",
		    (ext_options & GPF_COMMISSIONING_EXTOPT_KEY_TYPE));
		LOG_DBG("gp:       GPD Key present: %s",
		    (ext_options & GPF_COMMISSIONING_EXTOPT_HAS_GPD_KEY) ? "YES" : "NO");
		LOG_DBG("gp:       GPD Key Encryption: %s",
		    (ext_options & GPF_COMMISSIONING_EXTOPT_GPD_ENC_KEY) ? "YES" : "NO");
		LOG_DBG("gp:       GPD Outgoing Counter present: %s",
		    (ext_options & GPF_COMMISSIONING_EXTOPT_HAS_GPD_OUT_COUNTER) ? "YES" : "NO");
	}

	if (has_gpd_key)
		LOG_DBG("gp:   GPD Security Key: %s", key2str(gpd_key));
	if (has_counter)
		LOG_DBG("gp:   GPD Outgoing Counter: %d", gpd_counter);

	// Recent PowerTags provide a default key. We ignore it and use our own
	// key instead.
#if 0
	if (has_gpd_key || (ext_options & GPF_COMMISSIONING_EXTOPT_GPD_ENC_KEY)) {
		LOG_ERR("gp: unsupported commissioning with GPD key");
		return false;
	}
#endif
	if (sec_lvl == GP_SECURITY_LEVEL_1LSB_FC_SHORT_MIC) {
		LOG_ERR("gp: unsupported commissioning security level 0x01");
		return false;
	}

	// Max possible reply payload
	uint8_t reply[1 + 2 + 16 + 4]; // Options + PAN id + Sec Key + MIC
	buf = reply, len = 0;

	uint8_t reply_opts = 0;
	bool need_panid = (options & GPF_COMMISSIONING_OPT_PANID_REQ);
	bool need_sec_key = (options & GPF_COMMISSIONING_OPT_GP_KEY_REQ);

	if (need_panid)
		reply_opts |= GPF_COMMISSIONING_REPLY_OPT_PANID_PRESENT;
	if (need_sec_key) {
		reply_opts |= GPF_COMMISSIONING_REPLY_OPT_SEC_KEY_PRESENT;
		reply_opts |= (ext_options & GPF_COMMISSIONING_EXTOPT_SEC_LVL_CAP) << GPF_COMMISSIONING_REPLY_OPT_SEC_LVL_SHIFT;
		reply_opts |= GP_KEY_TYPE_GPD_GROUP << GPF_COMMISSIONING_REPLY_OPT_KEY_TYPE_SHIFT;
	}
	// Note: if 'GPD key encryption' bit is set, a 4-byte MIC should be
	// appended to the frame. However this is not supported at the moment.

	buf[0] = reply_opts;
	buf++, len++;

	//if (need_panid) {
	//	u16_to_mem(panid, buf);
	//	buf += 2, len += 2;
	//}
	if (need_sec_key) {
		memcpy(buf, ctx.gpd_key.data, 16);
		buf += 16, len += 16;
	}
	// if (need_mic) {
	//	u32_to_mem(mic, buf);
	//	buf += 4, len += 4;
	//}

	LOG_DBG("gp: sending commissioning reply to 0x%04x", gpf_source_id(gpf));
	return gp_send(gpf_source_id(gpf), GPF_CMD_COMMISSIONING_REPLY, reply, len);
}

static bool gp_process_insecure_frame(GpFrame *gpf)
{
	switch (gpf->cmd_id) {
	case GPF_CMD_CHANNEL_REQUEST:
		// Ignore Channel Requests, they are handled in firmware.
		return true;
	case GPF_CMD_COMMISSIONING:
		return gp_handle_commissioning_frame(gpf);
	}

	LOG_WARN("gp: unsupported insecure GPF with cmd id 0x%02X", gpf->cmd_id);
	return false;
}

static void gp_compute_nonce(GpSrcId srcid, uint32_t frame_counter,
    bool is_rx, gp_nonce_t *nonce)
{
	/* For outgoing frames, the first 4 bytes shall be zero. */
	if (is_rx)
		u32_to_mem(srcid, nonce->data);
	else
		u32_to_mem(0, nonce->data);
	u32_to_mem(srcid, nonce->data+4);

	/* Security frame counter. */
	u32_to_mem(frame_counter, nonce->data+8);
	/* Security control byte. Predefined value. */
	nonce->data[12] = 0x05;
}

bool gp_send_raw_frame(GpFrame *f)
{
	uint8_t buf[128];
	/* Reserve first byte for frame size */
	int len = 1;

	/* IEEE 802.15.4 layer */
	buf[len++] = 0x01;
	buf[len++] = 0x08;
	buf[len++] = 0; // MAC sequence number. EZSP will overwrite this with a valid number.
	u16_to_mem(0xffff, buf+len); // Destination PAN
	u16_to_mem(0xffff, buf+len+2); // Destination
	len += 4;

	uint8_t header_offset = len;
	uint8_t nwk_fc = 0x8c;    // NWK FC (Frame type 0, Protocol v3, Extended FC)
	uint8_t nwk_ext_fc = 0x0; // NWK Ext FC (appid = 0)
	nwk_ext_fc |= 0x80;       // Direction: from GPS
	nwk_ext_fc |= (f->sec_lvl & 0x3) << 3;
	buf[len++] = nwk_fc;
	buf[len++] = nwk_ext_fc;

	u32_to_mem(gpf_source_id(f), buf+len);
	len += 4;
	u32_to_mem(f->sec_frame_counter, buf+len);
	len += 4;

	if (f->sec_lvl == GP_SECURITY_LEVEL_FC_MIC_ENCRYPTED) {
		gp_nonce_t nonce;
		gp_compute_nonce(gpf_source_id(f), f->sec_frame_counter, false, &nonce);

		uint8_t plain_len = 1 + f->payload_len;
		uint8_t plain[plain_len];

		assert(plain_len <= 32);
		uint8_t cipher[32] = {0};
		uint8_t mic[4];

		plain[0] = f->cmd_id;
		memcpy(plain+1, f->payload, f->payload_len);

		int res = aes_ccm_ae(ctx.gpd_key.data, 16, nonce.data, 4,
		    plain, plain_len, buf + header_offset, 10, cipher, mic);
		if (res != 0) {
			LOG_ERR("gp: failed to encrypt outgoing raw frame");
			return false;
		}

		// Append CmdID + payload data + MIC
		memcpy(buf+len, cipher, plain_len);
		len += plain_len;
		memcpy(buf+len, mic, 4);
		len += 4;
	} else {
		LOG_FATAL("gp_send_raw_frame: unsupported security level 0x%02x", f->sec_lvl);
		return false;
	}

	buf[0] = len-1;
	buf[len++] = 0x0; // Priority (0 = High, 1 = Normal)
	buf[len++] = 0x1; // use CCA

	EmberStatus es;
	ezsp_send_frame(EZSP_SEND_RAW_MESSAGE_EXT, buf, len);
	if (!ezsp_read_reply_status(EZSP_SEND_RAW_MESSAGE_EXT, &es))
		return false;
	if (es != EMBER_SUCCESS) {
		LOG_ERR("gp: EZSP_SEND_RAW_MESSAGE_EXT failed: %s", ember_status_to_str(es));
		return false;
	}

	return true;
}

static uint8_t gpf_nwk_fc_byte(GpFrame *f)
{
	uint8_t fc = 0;
	fc |= 0x00;  /* Assume bit 1 to 0 = 0b00 (Frame type = Data) */
	fc |= 0x0c;  /* Assume bit 5 to 2 = 0b0011 (Protocol version = 0x03) */
	if (f->auto_commissioning)
		fc |= 0x40;  /* Bit 6 is set when autocommissionning is true */
	fc |= 0x80;      /* Assume bit 7 is set (NWK frame extension is enabled) */
	return fc;
}

static uint8_t gpf_ext_nwk_fc_byte(GpFrame *f, bool is_rx)
{
	uint8_t fc = 0;

	/* We only support app_id = 0 */
	assert(f->addr.app_id == GP_APP_SOURCE_ID);

	/* Bits 2 to 0 contain the application ID. */
	fc |= f->addr.app_id & 0x07;

	/* Bits 4 to 3 contain the security level */
	fc |= (f->sec_lvl & 0x03U) << 3;
	/*
	 * Bit 5, SecurityKey, indicates the type of key used for frame protection.
	 * It is set to 1 to indicate an individual key, or 0 for a shared key.
	 */
	if (f->key_type == GP_KEY_TYPE_GPD_OOB || f->key_type == GP_KEY_TYPE_GPD_DERIVED)
		fc |= 0x20;

	/* Bit 6 is set if RX after TX is true */
	if (GPF_RX_AFTER_TX(f))
		fc |= 0x40;

	/* Bit 7 is set if transmission is done to GPD, cleared if transmission is done from GPD */
	if (!is_rx)
		fc |= 0x80;

	return fc;
}

static bool gpf_decrypt(GpFrame *f)
{
	gp_nonce_t nonce;
	gp_compute_nonce(gpf_source_id(f), f->sec_frame_counter, true, &nonce);

	/*
	 * AddAuthData buffer.
	 *
	 * For GP_SECURITY_LEVEL_FC_MIC_ENCRYPTED (0x3):
	 *   AddAuthData = Header
	 *   Header = NWK FC + NWK EXT FC + SrcID + Frame Counter
	 *
	 * For GP_SECURITY_LEVEL_FC_MIC (0x2):
	 *   AddAuthData = Header + Payload
	 *   Header = NWK FC + NWK EXT FC + SrcID + Frame Counter
	 *   Payload = CmdID + Cmd Data
	 */
	uint8_t aad[128];
	size_t aad_len = 0;

	aad[0] = gpf_nwk_fc_byte(f);
	aad[1] = gpf_ext_nwk_fc_byte(f, true);
	u32_to_mem(gpf_source_id(f), aad+2);
	u32_to_mem(f->sec_frame_counter, aad+6);
	aad_len = 10;

	if (f->sec_lvl == GP_SECURITY_LEVEL_FC_MIC) {
		if (f->payload_len + 1 > (sizeof(aad) - aad_len)) {
			LOG_ERR("gpf_decrypt: payload too big (%d)", f->payload_len);
			return false;
		}
		aad[aad_len++] = f->cmd_id;
		memcpy(aad + aad_len, f->payload, f->payload_len);
		aad_len += f->payload_len;
	}
	if (aad_len > 30) {
		LOG_ERR("gp: FIXME: aes_ccm_ad cannot handle AddAuthData > 30");
		return false;
	}

	uint8_t plain[128];
	uint8_t cipher[1+f->payload_len];
	uint8_t cipher_len = 0;

	if (f->sec_lvl == GP_SECURITY_LEVEL_FC_MIC_ENCRYPTED) {
		cipher[0] = f->cmd_id;
		memcpy(cipher+1, f->payload, f->payload_len);
		cipher_len = 1 + f->payload_len;
	}

	uint8_t auth[4];
	u32_to_mem(f->mic, auth);

	int r = aes_ccm_ad(ctx.gpd_key.data, 16, nonce.data, 4, cipher, cipher_len,
	       aad, aad_len, auth, plain);
	if (r != 0) {
		LOG_WARN("gp: could not decrypt or validate GPF");
		return false;
	}

	if (f->sec_lvl == GP_SECURITY_LEVEL_FC_MIC_ENCRYPTED) {
		/* Overwrite encrypted payload with decrypted data. */
		f->cmd_id = plain[0];
		memcpy(f->payload, plain+1, f->payload_len);
	}

	LOG_DBG("gp: decrypted GPF from 0x%04x: cmdId: 0x%02x", gpf_source_id(f), f->cmd_id);
	return true;
}

static bool gp_process_secure_frame(GpFrame *f)
{
	/* Make sure we can handle the security type. */
	switch (f->sec_lvl) {
	case GP_SECURITY_LEVEL_FC_MIC:
	case GP_SECURITY_LEVEL_FC_MIC_ENCRYPTED:
		break;
	default:
		LOG_WARN("gp: encrypted GPF from 0x%04x: unsupported security level 0x%02x",
		    gpf_source_id(f), f->sec_lvl);
		return false;
	}

	if (!gpf_decrypt(f))
		return false;

	if (f->cmd_id == GPF_CMD_SUCCESS) {
		LOG_INFO("gp: GPD 0x%04x was successfully commissioned!", gpf_source_id(f));
		return true;
	}

	if (ctx.cb_fn(f))
		return true;

	LOG_WARN("gp: unsupported GPF cmd: 0x%02x", f->cmd_id);
	return false;
}

bool gp_process_raw_frame(const uint8_t *buf, uint8_t len)
{
	GpFrame gpf;
	if (!gp_parse_frame(buf, len, &gpf))
		return false;

	if (gpf.addr.app_id != GP_APP_SOURCE_ID) {
		LOG_WARN("gp: unsupported GPF from IEEE address, ignoring");
		return false;
	}

	if (gpf.sec_lvl == GP_SECURITY_LEVEL_NONE)
		return gp_process_insecure_frame(&gpf);

	return gp_process_secure_frame(&gpf);
}
