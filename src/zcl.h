#ifndef ZCL_H
#define ZCL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ZCL cluster IDs
typedef uint16_t ZclClusterId;
enum {
	ZCL_CLUSTER_BASIC                   = 0x0000,
	ZCL_CLUSTER_DEVICE_TEMP             = 0x0002,
	ZCL_CLUSTER_IDENTIFY                = 0x0003,
	ZCL_CLUSTER_METERING                = 0x0702,
	ZCL_CLUSTER_ELECTRICAL_MEASUREMENTS = 0x0b04,
	ZCL_CLUSTER_DIAGNOSTICS             = 0x0b05,
};

// Basic cluster attributes
enum {
	ZCL_BASIC_ZCL_VERSION   = 0x0000, // uint8
	ZCL_BASIC_APP_VERSION   = 0x0001, // uint8
	ZCL_BASIC_STACK_VERSION = 0x0002, // uint8
	ZCL_BASIC_HW_VERSION    = 0x0003, // uint8
	ZCL_BASIC_MFR_NAME      = 0x0004, // string
	ZCL_BASIC_MODEL_ID      = 0x0005, // string
	ZCL_BASIC_DATE_CODE     = 0x0006, // string
	ZCL_BASIC_SW_BUILD      = 0x4000, // string

	// Schneider PowerTag
	ZCL_BASIC_SE_POWERTAG_FW_VER = 0xe001, // string
	ZCL_BASIC_SE_POWERTAG_HW_VER = 0xe002, // string
	ZCL_BASIC_SE_POWERTAG_SERIAL = 0xe004, // string
	ZCL_BASIC_SE_POWERTAG_BRAND  = 0xe008, // string
	ZCL_BASIC_SE_POWERTAG_MODEL  = 0xe009, // string
};

// Identify cluster attributes
enum {
	ZCL_IDENTIFY_TIME = 0x0000, // uint16, time in seconds
};

// Metering cluster attributes
enum {
	// 0x00: Reading Information Set
	ZCL_METERING_TOTAL_ENERGY_DELIVERED = 0x0000, // uint48
	ZCL_METERING_TOTAL_ENERGY_RECEIVED  = 0x0001, // uint48
	ZCL_METERING_POWER_FACTOR = 0x0006, // int8 (-100 to 100%)

	// 0x03: Formatting
	ZCL_METERING_UNIT_MEASURE = 0x0300, // enum8
	ZCL_METERING_MULTIPLIER   = 0x0301, // uint24
	ZCL_METERING_DIVISOR      = 0x0302, // uint24

	// Schneider PowerTag specific
	ZCL_METERING_SE_TOTAL_ENERGY_DELIVERED_PHASE_A = 0x410c, // uint48
	ZCL_METERING_SE_TOTAL_ENERGY_DELIVERED_PHASE_B = 0x420c, // uint48
	ZCL_METERING_SE_TOTAL_ENERGY_DELIVERED_PHASE_C = 0x430c, // uint48

	ZCL_METERING_SE_PARTIAL_ENERGY_DELIVERED         = 0x4000, // uint48
	ZCL_METERING_SE_PARTIAL_ENERGY_DELIVERED_PHASE_A = 0x410d, // uint48
	ZCL_METERING_SE_PARTIAL_ENERGY_DELIVERED_PHASE_B = 0x420d, // uint48
	ZCL_METERING_SE_PARTIAL_ENERGY_DELIVERED_PHASE_C = 0x430d, // uint48

	ZCL_METERING_SE_TOTAL_ENERGY_RECEIVED_PHASE_A = 0x410e, // uint48
	ZCL_METERING_SE_TOTAL_ENERGY_RECEIVED_PHASE_B = 0x420e, // uint48
	ZCL_METERING_SE_TOTAL_ENERGY_RECEIVED_PHASE_C = 0x430e, // uint48

	ZCL_METERING_SE_PARTIAL_ENERGY_RECEIVED         = 0x4013, // uint48
	ZCL_METERING_SE_PARTIAL_ENERGY_RECEIVED_PHASE_A = 0x410f, // uint48
	ZCL_METERING_SE_PARTIAL_ENERGY_RECEIVED_PHASE_B = 0x420f, // uint48
	ZCL_METERING_SE_PARTIAL_ENERGY_RECEIVED_PHASE_C = 0x430f, // uint48
};

// Electrical Measurement cluster attributes
enum {
	// 0x00: Basic Information
	ZCL_EMR_MEASUREMENT_TYPE = 0x0000, // map32

	// 0x01: DC Measurement
	// 0x02: DC Formatting

	// 0x03: AC (Non-phase specific) Measurements
	ZCL_EMR_AC_FREQUENCY               = 0x0300, // uint16, Hz
	ZCL_EMR_AC_FREQUENCY_MIN           = 0x0301, // uint16, Hz
	ZCL_EMR_AC_FREQUENCY_MAX           = 0x0302, // uint16, Hz
	ZCL_EMR_AC_NEUTRAL_CURRENT         = 0x0303, // uint16, A
	ZCL_EMR_AC_TOTAL_ACTIVE_POWER      = 0x0304, // int32, kW
	ZCL_EMR_AC_TOTAL_REACTIVE_POWER    = 0x0305, // int32, kVAr
	ZCL_EMR_AC_TOTAL_APPARENT_POWER    = 0x0306, // uint32, kVA

	// 0x04: AC (Non-phase specific) Formatting
	ZCL_EMR_FREQUENCY_MULTIPLIER    = 0x0400, // uint16
	ZCL_EMR_FREQUENCY_DIVISOR       = 0x0401, // uint16
	ZCL_EMR_POWER_MULTIPLIER        = 0x0402, // uint32
	ZCL_EMR_POWER_DIVISOR           = 0x0403, // uint32

	// 0x05: AC (Single Phase) Measurements
	ZCL_EMR_AC_P1_LINE_CURRENT         = 0x0501, // uint16, A
	ZCL_EMR_AC_P1_ACTIVE_CURRENT       = 0x0502, // int16, A
	ZCL_EMR_AC_P1_REACTIVE_CURRENT     = 0x0503, // int16, A
	ZCL_EMR_AC_P1_RMS_VOLTAGE          = 0x0505, // uint16, V
	ZCL_EMR_AC_P1_RMS_VOLTAGE_MIN      = 0x0506, // uint16, V
	ZCL_EMR_AC_P1_RMS_VOLTAGE_MAX      = 0x0507, // uint16, V
	ZCL_EMR_AC_P1_RMS_CURRENT          = 0x0508, // uint16, A
	ZCL_EMR_AC_P1_RMS_CURRENT_MIN      = 0x0509, // uint16, A
	ZCL_EMR_AC_P1_RMS_CURRENT_MAX      = 0x050a, // uint16, A
	ZCL_EMR_AC_P1_ACTIVE_POWER         = 0x050b, // int16, W
	ZCL_EMR_AC_P1_ACTIVE_POWER_MIN     = 0x050c, // int16, W
	ZCL_EMR_AC_P1_ACTIVE_POWER_MAX     = 0x050d, // int16, W
	ZCL_EMR_AC_P1_REACTIVE_POWER       = 0x050e, // int16, VAr
	ZCL_EMR_AC_P1_APPARENT_POWER       = 0x050f, // uint16, VA
	ZCL_EMR_AC_P1_POWER_FACTOR         = 0x0510, // int8, 0-100%

	// 0x06: AC Formatting
	ZCL_EMR_AC_VOLTAGE_MULTIPLIER   = 0x0600, // uint16
	ZCL_EMR_AC_VOLTAGE_DIVISOR      = 0x0601, // uint16
	ZCL_EMR_AC_CURRENT_MULTIPLIER   = 0x0602, // uint16
	ZCL_EMR_AC_CURRENT_DIVISOR      = 0x0603, // uint16
	ZCL_EMR_AC_POWER_MULTIPLIER     = 0x0604, // uint16
	ZCL_EMR_AC_POWER_DIVISOR        = 0x0605, // uint16

	// 0x09: AC Phase B Measurements
	ZCL_EMR_AC_P2_LINE_CURRENT      = 0x0901, // uint16, A
	ZCL_EMR_AC_P2_ACTIVE_CURRENT    = 0x0902, // int16, A
	ZCL_EMR_AC_P2_REACTIVE_CURRENT  = 0x0903, // int16, A
	ZCL_EMR_AC_P2_RMS_VOLTAGE       = 0x0905, // uint16, V
	ZCL_EMR_AC_P2_RMS_VOLTAGE_MIN   = 0x0906, // uint16, V
	ZCL_EMR_AC_P2_RMS_VOLTAGE_MAX   = 0x0907, // uint16, V
	ZCL_EMR_AC_P2_RMS_CURRENT       = 0x0908, // uint16, A
	ZCL_EMR_AC_P2_RMS_CURRENT_MIN   = 0x0909, // uint16, A
	ZCL_EMR_AC_P2_RMS_CURRENT_MAX   = 0x090a, // uint16, A
	ZCL_EMR_AC_P2_ACTIVE_POWER      = 0x090b, // int16, W
	ZCL_EMR_AC_P2_ACTIVE_POWER_MIN  = 0x090c, // int16, W
	ZCL_EMR_AC_P2_ACTIVE_POWER_MAX  = 0x090d, // int16, W
	ZCL_EMR_AC_P2_REACTIVE_POWER    = 0x090e, // int16, VAr
	ZCL_EMR_AC_P2_APPARENT_POWER    = 0x090f, // uint16, VA
	ZCL_EMR_AC_P2_POWER_FACTOR      = 0x0910, // int8, 0-100%

	// 0x0A: AC Phase C Measurements
	ZCL_EMR_AC_P3_LINE_CURRENT      = 0x0a01, // uint16, A
	ZCL_EMR_AC_P3_ACTIVE_CURRENT    = 0x0a02, // int16, A
	ZCL_EMR_AC_P3_REACTIVE_CURRENT  = 0x0a03, // int16, A
	ZCL_EMR_AC_P3_RMS_VOLTAGE       = 0x0a05, // uint16, V
	ZCL_EMR_AC_P3_RMS_VOLTAGE_MIN   = 0x0a06, // uint16, V
	ZCL_EMR_AC_P3_RMS_VOLTAGE_MAX   = 0x0a07, // uint16, V
	ZCL_EMR_AC_P3_RMS_CURRENT       = 0x0a08, // uint16, A
	ZCL_EMR_AC_P3_RMS_CURRENT_MIN   = 0x0a09, // uint16, A
	ZCL_EMR_AC_P3_RMS_CURRENT_MAX   = 0x0a0a, // uint16, A
	ZCL_EMR_AC_P3_ACTIVE_POWER      = 0x0a0b, // int16, W
	ZCL_EMR_AC_P3_ACTIVE_POWER_MIN  = 0x0a0c, // int16, W
	ZCL_EMR_AC_P3_ACTIVE_POWER_MAX  = 0x0a0d, // int16, W
	ZCL_EMR_AC_P3_REACTIVE_POWER    = 0x0a0e, // int16, VAr
	ZCL_EMR_AC_P3_APPARENT_POWER    = 0x0a0f, // uint16, VA
	ZCL_EMR_AC_P3_POWER_FACTOR      = 0x0a10, // int8, 0-100%

	// Schneider PowerTag
	ZCL_EMR_AC_VOLTAGE_PHASE_AB = 0x4b00,
	ZCL_EMR_AC_VOLTAGE_PHASE_BC = 0x4c00,
	ZCL_EMR_AC_VOLTAGE_PHASE_CA = 0x4d00,

	// TODO: figure out the bitmap values for overload and undervoltage.
	ZCL_EMR_POWERTAG_ALARM = 0x4800, // bitmap16 (0x2 = voltage loss)
};

// Diagnostics cluster attributes
enum {
	ZCL_DIAG_LAST_MESSAGE_LQI  = 0x011c, // int8
	ZCL_DIAG_LAST_MESSAGE_RSSI = 0x011d, // int8
};

// Attribute Types
typedef uint16_t ZclAttrValueType;
enum {
	ZCL_ATTR_TYPE_NONE = 0x00,

	/* General discrete data types */
	ZCL_ATTR_TYPE_DATA_8  = 0x08, // 1 byte
	ZCL_ATTR_TYPE_DATA_16 = 0x09,
	ZCL_ATTR_TYPE_DATA_24 = 0x0a,
	ZCL_ATTR_TYPE_DATA_32 = 0x0b,
	ZCL_ATTR_TYPE_DATA_40 = 0x0c,
	ZCL_ATTR_TYPE_DATA_48 = 0x0d,
	ZCL_ATTR_TYPE_DATA_56 = 0x0e,
	ZCL_ATTR_TYPE_DATA_64 = 0x0f,

	ZCL_ATTR_TYPE_BOOL = 0x10, // 1 byte, 0xff = invalid value

	/* Discrete bitmap types */
	ZCL_ATTR_TYPE_BITMAP_8  = 0x18,
	ZCL_ATTR_TYPE_BITMAP_16 = 0x19,
	ZCL_ATTR_TYPE_BITMAP_24 = 0x1a,
	ZCL_ATTR_TYPE_BITMAP_32 = 0x1b,
	ZCL_ATTR_TYPE_BITMAP_40 = 0x1c,
	ZCL_ATTR_TYPE_BITMAP_48 = 0x1d,
	ZCL_ATTR_TYPE_BITMAP_56 = 0x1e,
	ZCL_ATTR_TYPE_BITMAP_64 = 0x1f,

	/* Unsigned integer analog types */
	ZCL_ATTR_TYPE_U8  = 0x20,
	ZCL_ATTR_TYPE_U16 = 0x21,
	ZCL_ATTR_TYPE_U24 = 0x22,
	ZCL_ATTR_TYPE_U32 = 0x23,
	ZCL_ATTR_TYPE_U40 = 0x24,
	ZCL_ATTR_TYPE_U48 = 0x25,
	ZCL_ATTR_TYPE_U56 = 0x26,
	ZCL_ATTR_TYPE_U64 = 0x27,

	/* Signed integer analog types */
	ZCL_ATTR_TYPE_S8  = 0x28,
	ZCL_ATTR_TYPE_S16 = 0x29,
	ZCL_ATTR_TYPE_S24 = 0x2a,
	ZCL_ATTR_TYPE_S32 = 0x2b,
	ZCL_ATTR_TYPE_S40 = 0x2c,
	ZCL_ATTR_TYPE_S48 = 0x2d,
	ZCL_ATTR_TYPE_S56 = 0x2e,
	ZCL_ATTR_TYPE_S64 = 0x2f,

	/* Enum types */
	ZCL_ATTR_TYPE_ENUM_8  = 0x30,
	ZCL_ATTR_TYPE_ENUM_16 = 0x31,

	/* Float types */
	ZCL_ATTR_TYPE_FLOAT_16 = 0x38,
	ZCL_ATTR_TYPE_FLOAT_32 = 0x39,
	ZCL_ATTR_TYPE_FLOAT_64 = 0x3a,

	/* String types */
	ZCL_ATTR_TYPE_STR_BYTE    = 0x41,
	ZCL_ATTR_TYPE_STR_CHAR    = 0x42,
	ZCL_ATTR_TYPE_STR_BYTE_16 = 0x43,
	ZCL_ATTR_TYPE_STR_CHAR_16 = 0x44,

	/* Ordered sequence types */
	ZCL_ATTR_TYPE_ARRAY  = 0x48,
	ZCL_ATTR_TYPE_STRUCT = 0x4c,

	/* Collection types */
	ZCL_ATTR_TYPE_SET = 0x50,
	ZCL_ATTR_TYPE_BAG = 0x51,

	/* Time types */
	ZCL_ATTR_TYPE_TIME_NOW  = 0xe0, // Time Of Day, 4 bytes
	ZCL_ATTR_TYPE_TIME_DATE = 0xe1, // 4 bytes
	ZCL_ATTR_TYPE_TIME_UTC  = 0xe2, // 4 bytes

	/* Identifier types */
	ZCL_ATTR_TYPE_CLUSTER_ID = 0xe8,
	ZCL_ATTR_TYPE_ATTR_ID    = 0xe9,
	ZCL_ATTR_TYPE_BACNET_OID = 0xea,

	/* Miscellaneous types */
	ZCL_ATTR_TYPE_IEEE_ADDR  = 0xf0, // 8 bytes
	ZCL_ATTR_TYPE_128BIT_KEY = 0xf1, // 16 bytes
	//ZCL_ATTR_TYPE_OPAQUE

	ZCL_ATTR_TYPE_UNKNOWN = 0xff,
};

typedef uint16_t ZclAttrId;

typedef struct {
	ZclAttrId id;
	ZclAttrValueType orig_type;
	ZclAttrValueType type;
	union {
		bool b;
		int64_t i64;
		uint64_t u64;
		float flt;
		char *str;
	} value;
	uint32_t value_len;
} ZclAttr;

typedef struct {
	int count;
	int capacity;
	ZclAttr attrs[0];
} ZclAttrList;

const char *zcl_attr_name(ZclClusterId cluster, ZclAttrId id);
const char *zcl_attr_type_name(ZclAttrValueType type);

int zcl_parse_attr(const uint8_t *buf, size_t len, ZclAttr *attr);
ZclAttrList *zcl_parse_attr_list(const uint8_t *buf, size_t len);

void zcl_attr_free(ZclAttr *attr);
void zcl_attr_list_free(ZclAttrList *list);

const char *zcl_attr_format_value(ZclAttr *attr);

#endif
