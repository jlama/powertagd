#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "zcl.h"
#include "log.h"
#include "util.h"


static const char *cluster_basic_attr_name(ZclAttrId id)
{
	switch (id) {
	case ZCL_BASIC_ZCL_VERSION:
		return "zcl_ver";
	case ZCL_BASIC_APP_VERSION:
		return "app_ver";
	case ZCL_BASIC_STACK_VERSION:
		return "stack_ver";
	case ZCL_BASIC_HW_VERSION:
		return "hw_ver";
	case ZCL_BASIC_MFR_NAME:
		return "mfr";
	case ZCL_BASIC_MODEL_ID:
		return "model";
	case ZCL_BASIC_DATE_CODE:
		return "date";
	case ZCL_BASIC_SW_BUILD:
		return "sw_build";

	// Schneider PowerTag
	case ZCL_BASIC_SE_POWERTAG_FW_VER:
		return "fw_ver";
	case ZCL_BASIC_SE_POWERTAG_HW_VER:
		return "hw_ver";
	case ZCL_BASIC_SE_POWERTAG_SERIAL:
		return "serial";
	case ZCL_BASIC_SE_POWERTAG_BRAND:
		return "brand";
	case ZCL_BASIC_SE_POWERTAG_MODEL:
		return "model";
	}

	return NULL;
}

static const char *cluster_metering_attr_name(ZclAttrId id)
{
	switch (id) {
	case ZCL_METERING_TOTAL_ENERGY_DELIVERED:
		return "total_energy_tx";
	case ZCL_METERING_TOTAL_ENERGY_RECEIVED:
		return "total_energy_rx";
	case ZCL_METERING_POWER_FACTOR:
		return "power_factor";

	// 0x03: Formatting
	case ZCL_METERING_UNIT_MEASURE:
		return "unit_of_measure";
	case ZCL_METERING_MULTIPLIER:
		return "multiplier";
	case ZCL_METERING_DIVISOR:
		return "divisor";

	// PowerTag specific
	case ZCL_METERING_SE_TOTAL_ENERGY_DELIVERED_PHASE_A:
		return "total_energy_p1_tx";
	case ZCL_METERING_SE_TOTAL_ENERGY_DELIVERED_PHASE_B:
		return "total_energy_p2_tx";
	case ZCL_METERING_SE_TOTAL_ENERGY_DELIVERED_PHASE_C:
		return "total_energy_p3_tx";

	case ZCL_METERING_SE_TOTAL_ENERGY_RECEIVED_PHASE_A:
		return "total_energy_p1_rx";
	case ZCL_METERING_SE_TOTAL_ENERGY_RECEIVED_PHASE_B:
		return "total_energy_p2_rx";
	case ZCL_METERING_SE_TOTAL_ENERGY_RECEIVED_PHASE_C:
		return "total_energy_p3_rx";

	case ZCL_METERING_SE_PARTIAL_ENERGY_DELIVERED:
		return "partial_energy_tx";
	case ZCL_METERING_SE_PARTIAL_ENERGY_DELIVERED_PHASE_A:
		return "partial_energy_p1_tx";
	case ZCL_METERING_SE_PARTIAL_ENERGY_DELIVERED_PHASE_B:
		return "partial_energy_p2_tx";
	case ZCL_METERING_SE_PARTIAL_ENERGY_DELIVERED_PHASE_C:
		return "partial_energy_p2_tx";

	case ZCL_METERING_SE_PARTIAL_ENERGY_RECEIVED:
		return "partial_energy_rx";
	case ZCL_METERING_SE_PARTIAL_ENERGY_RECEIVED_PHASE_A:
		return "partial_energy_p1_rx";
	case ZCL_METERING_SE_PARTIAL_ENERGY_RECEIVED_PHASE_B:
		return "partial_energy_p2_rx";
	case ZCL_METERING_SE_PARTIAL_ENERGY_RECEIVED_PHASE_C:
		return "partial_energy_p3_rx";
	}

	return NULL;
}

static const char *cluster_emr_attr_name(ZclAttrId id)
{
	switch (id) {
	case ZCL_EMR_MEASUREMENT_TYPE:
		return "measurement_type";

	// 0x03: AC (Non-phase specific) Measurements
	case ZCL_EMR_AC_FREQUENCY:
		return "freq";
	case ZCL_EMR_AC_FREQUENCY_MIN:
		return "freq_min";
	case ZCL_EMR_AC_FREQUENCY_MAX:
		return "freq_max";
	case ZCL_EMR_AC_NEUTRAL_CURRENT:
		return "current_neutral";
	case ZCL_EMR_AC_TOTAL_ACTIVE_POWER:
		return "total_power_active";
	case ZCL_EMR_AC_TOTAL_REACTIVE_POWER:
		return "total_power_reactive";
	case ZCL_EMR_AC_TOTAL_APPARENT_POWER:
		return "total_power_apparent";

	// 0x04: AC (Non-phase specific) Formatting
	case ZCL_EMR_FREQUENCY_MULTIPLIER:
		return "freq_multiplier";
	case ZCL_EMR_FREQUENCY_DIVISOR:
		return "freq_divisor";
	case ZCL_EMR_POWER_MULTIPLIER:
		return "power_multiplier";
	case ZCL_EMR_POWER_DIVISOR:
		return "power_divisor";

	// 0x05: AC (Single Phase) Measurements
	case ZCL_EMR_AC_P1_LINE_CURRENT:
		return "line_current";
	case ZCL_EMR_AC_P1_ACTIVE_CURRENT:
		return "current_p1_active";
	case ZCL_EMR_AC_P1_REACTIVE_CURRENT:
		return "current_p1_reactive";
	case ZCL_EMR_AC_P1_RMS_VOLTAGE:
		return "voltage_p1";
	case ZCL_EMR_AC_P1_RMS_VOLTAGE_MIN:
		return "voltage_p1_min";
	case ZCL_EMR_AC_P1_RMS_VOLTAGE_MAX:
		return "voltage_p1_max";
	case ZCL_EMR_AC_P1_RMS_CURRENT:
		return "current_p1";
	case ZCL_EMR_AC_P1_RMS_CURRENT_MIN:
		return "current_p1_min";
	case ZCL_EMR_AC_P1_RMS_CURRENT_MAX:
		return "current_p1_max";
	case ZCL_EMR_AC_P1_ACTIVE_POWER:
		return "power_p1_active";
	case ZCL_EMR_AC_P1_ACTIVE_POWER_MIN:
		return "power_p1_active_min";
	case ZCL_EMR_AC_P1_ACTIVE_POWER_MAX:
		return "power_p1_active_max";
	case ZCL_EMR_AC_P1_REACTIVE_POWER:
		return "power_p1_reactive";
	case ZCL_EMR_AC_P1_APPARENT_POWER:
		return "power_p1_apparent";
	case ZCL_EMR_AC_P1_POWER_FACTOR:
		return "power_factor_p1";

	// 0x06: AC Formatting
	case ZCL_EMR_AC_VOLTAGE_MULTIPLIER:
		return "voltage_multiplier";
	case ZCL_EMR_AC_VOLTAGE_DIVISOR:
		return "voltage_divisor";
	case ZCL_EMR_AC_CURRENT_MULTIPLIER:
		return "current_multiplier";
	case ZCL_EMR_AC_CURRENT_DIVISOR:
		return "current_divisor";
	case ZCL_EMR_AC_POWER_MULTIPLIER:
		return "ac_power_multiplier";
	case ZCL_EMR_AC_POWER_DIVISOR:
		return "ac_power_divisor";

	// 0x09: AC Phase B Measurements
	case ZCL_EMR_AC_P2_LINE_CURRENT:
		return "line_current_p2";
	case ZCL_EMR_AC_P2_ACTIVE_CURRENT:
		return "current_p2_active";
	case ZCL_EMR_AC_P2_REACTIVE_CURRENT:
		return "current_p2_reactive";
	case ZCL_EMR_AC_P2_RMS_VOLTAGE:
		return "voltage_p2";
	case ZCL_EMR_AC_P2_RMS_VOLTAGE_MIN:
		return "voltage_p2_min";
	case ZCL_EMR_AC_P2_RMS_VOLTAGE_MAX:
		return "voltage_p2_max";
	case ZCL_EMR_AC_P2_RMS_CURRENT:
		return "current_p2";
	case ZCL_EMR_AC_P2_RMS_CURRENT_MIN:
		return "current_p2_min";
	case ZCL_EMR_AC_P2_RMS_CURRENT_MAX:
		return "current_p2_max";
	case ZCL_EMR_AC_P2_ACTIVE_POWER:
		return "power_p2_active";
	case ZCL_EMR_AC_P2_ACTIVE_POWER_MIN:
		return "power_p2_active_min";
	case ZCL_EMR_AC_P2_ACTIVE_POWER_MAX:
		return "power_p2_active_max";
	case ZCL_EMR_AC_P2_REACTIVE_POWER:
		return "power_p2_reactive";
	case ZCL_EMR_AC_P2_APPARENT_POWER:
		return "power_p2_apparent";
	case ZCL_EMR_AC_P2_POWER_FACTOR:
		return "power_factor_p2";

	// 0x0A: AC Phase C Measurements
	case ZCL_EMR_AC_P3_LINE_CURRENT:
		return "line_current_p3";
	case ZCL_EMR_AC_P3_ACTIVE_CURRENT:
		return "current_p3_active";
	case ZCL_EMR_AC_P3_REACTIVE_CURRENT:
		return "current_p3_reactive";
	case ZCL_EMR_AC_P3_RMS_VOLTAGE:
		return "voltage_p3";
	case ZCL_EMR_AC_P3_RMS_VOLTAGE_MIN:
		return "voltage_p3_min";
	case ZCL_EMR_AC_P3_RMS_VOLTAGE_MAX:
		return "voltage_p3_max";
	case ZCL_EMR_AC_P3_RMS_CURRENT:
		return "current_p3";
	case ZCL_EMR_AC_P3_RMS_CURRENT_MIN:
		return "current_p3_min";
	case ZCL_EMR_AC_P3_RMS_CURRENT_MAX:
		return "current_p3_max";
	case ZCL_EMR_AC_P3_ACTIVE_POWER:
		return "power_p3_active";
	case ZCL_EMR_AC_P3_ACTIVE_POWER_MIN:
		return "power_p3_active_min";
	case ZCL_EMR_AC_P3_ACTIVE_POWER_MAX:
		return "power_p3_active_max";
	case ZCL_EMR_AC_P3_REACTIVE_POWER:
		return "power_p3_reactive";
	case ZCL_EMR_AC_P3_APPARENT_POWER:
		return "power_p3_apparent";
	case ZCL_EMR_AC_P3_POWER_FACTOR:
		return "power_factor_p3";

	// Schneider PowerTag
	case ZCL_EMR_AC_VOLTAGE_PHASE_AB:
		return "voltage_phase_ab";
	case ZCL_EMR_AC_VOLTAGE_PHASE_BC:
		return "voltage_phase_bc";
	case ZCL_EMR_AC_VOLTAGE_PHASE_CA:
		return "voltage_phase_ac";
	case ZCL_EMR_POWERTAG_ALARM:
		return "alarm";
	}

	return NULL;
}

const char *zcl_attr_name(ZclClusterId cluster, ZclAttrId id)
{
	switch (cluster) {
	case ZCL_CLUSTER_BASIC:
		return cluster_basic_attr_name(id);
	case ZCL_CLUSTER_METERING:
		return cluster_metering_attr_name(id);
	case ZCL_CLUSTER_ELECTRICAL_MEASUREMENTS:
		return cluster_emr_attr_name(id);
	default:
		LOG_WARN("zcl_attr_name: unknown cluster ID 0x%04x", cluster);
		return NULL;
	}
}

const char *zcl_attr_type_name(ZclAttrValueType type)
{
	switch (type) {
	case ZCL_ATTR_TYPE_NONE:
		return "none";

	/* General discrete data types */
	case ZCL_ATTR_TYPE_DATA_8:
		return "data8";
	case ZCL_ATTR_TYPE_DATA_16:
		return "data16";
	case ZCL_ATTR_TYPE_DATA_24:
		return "data24";
	case ZCL_ATTR_TYPE_DATA_32:
		return "data32";
	case ZCL_ATTR_TYPE_DATA_40:
		return "data40";
	case ZCL_ATTR_TYPE_DATA_48:
		return "data48";
	case ZCL_ATTR_TYPE_DATA_56:
		return "data56";
	case ZCL_ATTR_TYPE_DATA_64:
		return "data64";

	case ZCL_ATTR_TYPE_BOOL:
		return "bool";

	/* Discrete bitmap types */
	case ZCL_ATTR_TYPE_BITMAP_8:
		return "bitmap8";
	case ZCL_ATTR_TYPE_BITMAP_16:
		return "bitmap16";
	case ZCL_ATTR_TYPE_BITMAP_24:
		return "bitmap24";
	case ZCL_ATTR_TYPE_BITMAP_32:
		return "bitmap32";
	case ZCL_ATTR_TYPE_BITMAP_40:
		return "bitmap40";
	case ZCL_ATTR_TYPE_BITMAP_48:
		return "bitmap48";
	case ZCL_ATTR_TYPE_BITMAP_56:
		return "bitmap56";
	case ZCL_ATTR_TYPE_BITMAP_64:
		return "bitmap64";

	/* Unsigned integer analog types */
	case ZCL_ATTR_TYPE_U8:
		return "u8";
	case ZCL_ATTR_TYPE_U16:
		return "u16";
	case ZCL_ATTR_TYPE_U24:
		return "u24";
	case ZCL_ATTR_TYPE_U32:
		return "u32";
	case ZCL_ATTR_TYPE_U40:
		return "u40";
	case ZCL_ATTR_TYPE_U48:
		return "u48";
	case ZCL_ATTR_TYPE_U56:
		return "u56";
	case ZCL_ATTR_TYPE_U64:
		return "u64";

	/* Signed integer analog types */
	case ZCL_ATTR_TYPE_S8:
		return "i8";
	case ZCL_ATTR_TYPE_S16:
		return "i16";
	case ZCL_ATTR_TYPE_S24:
		return "i24";
	case ZCL_ATTR_TYPE_S32:
		return "i32";
	case ZCL_ATTR_TYPE_S40:
		return "i40";
	case ZCL_ATTR_TYPE_S48:
		return "i48";
	case ZCL_ATTR_TYPE_S56:
		return "i56";
	case ZCL_ATTR_TYPE_S64:
		return "i64";

	/* Enum types */
	case ZCL_ATTR_TYPE_ENUM_8:
		return "enum8";
	case ZCL_ATTR_TYPE_ENUM_16:
		return "enum16";

	/* Float types */
	case ZCL_ATTR_TYPE_FLOAT_16:
		return "float16";
	case ZCL_ATTR_TYPE_FLOAT_32:
		return "float32";
	case ZCL_ATTR_TYPE_FLOAT_64:
		return "double";

	/* String types */
	case ZCL_ATTR_TYPE_STR_BYTE:
		return "array_u8";
	case ZCL_ATTR_TYPE_STR_CHAR:
		return "string";
	case ZCL_ATTR_TYPE_STR_BYTE_16:
		return "array_u16";
	case ZCL_ATTR_TYPE_STR_CHAR_16:
		return "wide_string";

	/* Ordered sequence types */
	case ZCL_ATTR_TYPE_ARRAY:
		return "array";
	case ZCL_ATTR_TYPE_STRUCT:
		return "struct";

	/* Collection types */
	case ZCL_ATTR_TYPE_SET:
		return "set";
	case ZCL_ATTR_TYPE_BAG:
		return "bag";

	/* Time types */
	case ZCL_ATTR_TYPE_TIME_NOW:
		return "time";
	case ZCL_ATTR_TYPE_TIME_DATE:
		return "date";
	case ZCL_ATTR_TYPE_TIME_UTC:
		return "time_utc";

	/* Identifier types */
	case ZCL_ATTR_TYPE_CLUSTER_ID:
		return "cluster_id";
	case ZCL_ATTR_TYPE_ATTR_ID:
		return "attr_id";
	case ZCL_ATTR_TYPE_BACNET_OID:
		return "bacnet_oid";

	/* Miscellaneous types */
	case ZCL_ATTR_TYPE_IEEE_ADDR:
		return "ieee_addr";
	case ZCL_ATTR_TYPE_128BIT_KEY:
		return "key_128bit";

	case ZCL_ATTR_TYPE_UNKNOWN:
		return "unknown";
	default:
		return "invalid";
	}
}

static int zcl_parse_num_value(const uint8_t *buf, size_t len,
    uint8_t bytes, bool is_signed, ZclAttr *attr)
{
	assert(bytes >= 1 && bytes <= 8);

	if (len < bytes) {
		LOG_ERR("zcl_parse_num_value: buffer too small for %s attribute (%zu)",
		    zcl_attr_type_name(attr->type), len);
		return -1;
	}

	uint64_t u = 0;
	int64_t i = 0;
	switch (bytes) {
	case 1:
		u = buf[0];
		i = (u & 0x80) ? u - 0x100 : u;
		break;
	case 2:
		u = u16_from_mem(buf);
		i = (u & 0x8000) ? u - 0x10000 : u;
		break;
	case 3:
		u = u24_from_mem(buf);
		i = (u & 0x800000) ? u - 0x1000000 : u;
		break;
	case 4:
		u = u32_from_mem(buf);
		i = (u & 0x80000000) ? u - 0x100000000 : u;
		break;
	case 5:
		u = u40_from_mem(buf);
		i = (u & 0x8000000000) ? u - 0x10000000000 : u;
		break;
	case 6:
		u = u48_from_mem(buf);
		i = (u & 0x800000000000) ? u - 0x1000000000000 : u;
		break;
	case 7:
		u = u56_from_mem(buf);
		i = (u & 0x80000000000000) ? u - 0x100000000000000 : u;
		break;
	case 8:
		u = u64_from_mem(buf);
		i = (int64_t)u;
		break;
	}

	if (is_signed) {
		attr->type = ZCL_ATTR_TYPE_S64;
		attr->value.i64 = i;
	} else {
		attr->type = ZCL_ATTR_TYPE_U64;
		attr->value.u64 = u;
	}

	return bytes;
}

static int zcl_parse_str_value(const uint8_t *buf, size_t len, ZclAttr *attr)
{
	if (len < 1) {
		LOG_ERR("zcl_parse_str_value: buffer too small for %s attribute (%zu)",
		    zcl_attr_type_name(attr->type), len);
		return -1;
	}

	uint8_t slen = buf[0];
	if (slen == 0 || slen == 0xff) {
		attr->value.str = "";
		attr->value_len = 0;
		return 1;
	}

	buf++, len--;

	if (len < slen) {
		LOG_ERR("zcl_parse_str_value: buffer too small for %d bytes string (%zu)",
		    slen, len);
		return -1;
	}

	char *s = malloc(slen+1);
	if (s == NULL)
		LOG_FATAL("zcl_parse_str_value: malloc(%d) failed for attr 0x%04x", slen, attr->id);

	memcpy(s, buf, slen);
	s[slen] = 0;

	attr->value.str = s;
	attr->value_len = slen;
	return 1 + slen;
}

/* Return the size of the attribute parsed. */
int zcl_parse_attr(const uint8_t *buf, size_t len, ZclAttr *attr)
{
	if (len < 3) {
		LOG_ERR("zcl_parse_attr: buffer too small (%zu)", len);
		return -1;
	}

	uint16_t id = u16_from_mem(buf);
	uint8_t type = buf[2];
	buf += 3, len -= 3;

	attr->id = id;
	attr->orig_type = type;
	attr->type = type;

#define CHECK_LEN(x) \
	if (len < (x)) { \
		LOG_ERR("zcl_parse_attr: buffer too small for %s attribute (%zu)", \
		    zcl_attr_type_name(type), len); \
		return -1; \
	}

	switch (type) {
	/* No data, we are done */
	case ZCL_ATTR_TYPE_NONE:
		return 3;

	case ZCL_ATTR_TYPE_BOOL:
		CHECK_LEN(1);
		if (*buf != 0 && *buf != 1) {
			LOG_ERR("zcl_parse_attr: invalid value for bool type (0x%02x)", *buf);
			return -1;
		}
		attr->value.b = *buf;
		return 4;

	case ZCL_ATTR_TYPE_DATA_8:
	case ZCL_ATTR_TYPE_BITMAP_8:
	case ZCL_ATTR_TYPE_U8:
	case ZCL_ATTR_TYPE_ENUM_8:
		return 3 + zcl_parse_num_value(buf, len, 1, false, attr);

	case ZCL_ATTR_TYPE_DATA_16:
	case ZCL_ATTR_TYPE_BITMAP_16:
	case ZCL_ATTR_TYPE_U16:
	case ZCL_ATTR_TYPE_ENUM_16:
		return 3 + zcl_parse_num_value(buf, len, 2, false, attr);

	case ZCL_ATTR_TYPE_DATA_24:
	case ZCL_ATTR_TYPE_BITMAP_24:
	case ZCL_ATTR_TYPE_U24:
		return 3 + zcl_parse_num_value(buf, len, 3, false, attr);

	case ZCL_ATTR_TYPE_DATA_32:
	case ZCL_ATTR_TYPE_BITMAP_32:
	case ZCL_ATTR_TYPE_U32:
		return 3 + zcl_parse_num_value(buf, len, 4, false, attr);

	case ZCL_ATTR_TYPE_DATA_40:
	case ZCL_ATTR_TYPE_BITMAP_40:
	case ZCL_ATTR_TYPE_U40:
		return 3 + zcl_parse_num_value(buf, len, 5, false, attr);

	case ZCL_ATTR_TYPE_DATA_48:
	case ZCL_ATTR_TYPE_BITMAP_48:
	case ZCL_ATTR_TYPE_U48:
		return 3 + zcl_parse_num_value(buf, len, 6, false, attr);

	case ZCL_ATTR_TYPE_DATA_56:
	case ZCL_ATTR_TYPE_BITMAP_56:
	case ZCL_ATTR_TYPE_U56:
		return 3 + zcl_parse_num_value(buf, len, 7, false, attr);

	case ZCL_ATTR_TYPE_DATA_64:
	case ZCL_ATTR_TYPE_BITMAP_64:
	case ZCL_ATTR_TYPE_U64:
		return 3 + zcl_parse_num_value(buf, len, 8, false, attr);

	/* Signed integer analog types */
	case ZCL_ATTR_TYPE_S8:
		return 3 + zcl_parse_num_value(buf, len, 1, true, attr);
	case ZCL_ATTR_TYPE_S16:
		return 3 + zcl_parse_num_value(buf, len, 2, true, attr);
	case ZCL_ATTR_TYPE_S24:
		return 3 + zcl_parse_num_value(buf, len, 3, true, attr);
	case ZCL_ATTR_TYPE_S32:
		return 3 + zcl_parse_num_value(buf, len, 4, true, attr);
	case ZCL_ATTR_TYPE_S40:
		return 3 + zcl_parse_num_value(buf, len, 5, true, attr);
	case ZCL_ATTR_TYPE_S48:
		return 3 + zcl_parse_num_value(buf, len, 6, true, attr);
	case ZCL_ATTR_TYPE_S56:
		return 3 + zcl_parse_num_value(buf, len, 7, true, attr);
	case ZCL_ATTR_TYPE_S64:
		return 3 + zcl_parse_num_value(buf, len, 8, true, attr);


	/* String types */
	case ZCL_ATTR_TYPE_STR_BYTE:
	case ZCL_ATTR_TYPE_STR_CHAR:
		return 3 + zcl_parse_str_value(buf, len, attr);

	default:
		LOG_ERR("zcl_parse_attr: unsupported attribute type '%s'", zcl_attr_type_name(type));
		return -1;
	}

	// UNREACHED
	return -1;
}

void zcl_attr_free(ZclAttr *attr)
{
	if (attr->type == ZCL_ATTR_TYPE_STR_CHAR && attr->value_len > 0)
		free(attr->value.str);
}

ZclAttrList *zcl_attr_list_init(int cap)
{
	ZclAttrList *list = malloc(sizeof(*list) + (cap * sizeof(ZclAttr)));
	if (list == NULL)
		LOG_FATAL("zcl_attr_list_init: malloc failed: %s", strerror(errno));

	list->count = 0;
	list->capacity = cap;
	memset(list->attrs, 0, cap * sizeof(ZclAttr));
	return list;
}

ZclAttrList *zcl_parse_attr_list(const uint8_t *buf, size_t len)
{
	ZclAttrList *list = zcl_attr_list_init(8);

	while (len >= 3) {
		if (list->count >= list->capacity) {
			list = realloc(list, sizeof(*list) + (list->capacity * 2 * sizeof(ZclAttr)));
			if (list == NULL)
				LOG_FATAL("zcl_parse_attr_list: realloc failed: %s", strerror(errno));
			list->capacity *= 2;
		}

		int r = zcl_parse_attr(buf, len, &list->attrs[list->count]);
		if (r < 0)
			return NULL;

		list->count++;
		buf += r, len -= r;
	}
	return list;
}

void zcl_attr_list_free(ZclAttrList *list)
{
	for (int i = 0; i < list->count; i++)
		zcl_attr_free(&list->attrs[i]);
	free(list);
}

const char *zcl_attr_format_value(ZclAttr *attr)
{
	static char buf[64];

	switch (attr->type) {
	case ZCL_ATTR_TYPE_NONE:
		return "\"\"";

	case ZCL_ATTR_TYPE_BOOL:
		return (attr->value.b) ? "true" : "false";

	case ZCL_ATTR_TYPE_U64:
		snprintf(buf, sizeof(buf), "%llu", (unsigned long long)attr->value.u64);
		return buf;

	case ZCL_ATTR_TYPE_S64:
		snprintf(buf, sizeof(buf), "%lld", (long long)attr->value.i64);
		return buf;

	case ZCL_ATTR_TYPE_FLOAT_32:
		snprintf(buf, sizeof(buf), "%.2f", attr->value.flt);
		return buf;

	case ZCL_ATTR_TYPE_STR_CHAR:
		snprintf(buf, sizeof(buf), "\"%s\"", attr->value.str);
		return buf;
	}

	LOG_ERR("zcl_attr_format_value: unknown value type 0x%02X", attr->type);
	return "";
}
