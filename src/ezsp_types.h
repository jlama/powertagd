/*
 * ezsp_types.h
 */

#ifndef EZSP_TYPES_H
#define EZSP_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t EzspStatus;
enum {
	EZSP_SUCCESS = 0x00,

	EZSP_ASH_IN_PROGRESS      = 0x20, // Operation not yet complete
	EZSP_HOST_FATAL_ERROR     = 0x21, // Fatal error detected by Host
	EZSP_ASH_NCP_FATAL_ERROR  = 0x22, // Fatal error detected by NCP
	EZSP_DATA_FRAME_TOO_LONG  = 0x23, // Tried to send DATA frame too long
	EZSP_DATA_FRAME_TOO_SHORT = 0x24, // Tried to send DATA frame too short
	EZSP_NO_TX_SPACE          = 0x25, // No space for sent data frame
	EZSP_NO_RX_SPACE          = 0x26, // No space for received data frame
	EZSP_NO_RX_DATA           = 0x27, // No receive data available

	EZSP_NOT_CONNECTED        = 0x28, // Not in connected state
	EZSP_ERR_VERSION_NOT_SET  = 0x30, // NCP received a cmd before EZSP version had been set
	EZSP_ERR_INVALID_FRAME_ID = 0x31, // NCP received a cmd with unknown frame ID
	EZSP_ERR_WRONG_DIRECTION  = 0x32, // The direction flag in the frame control field was incorrect
	EZSP_ERR_TRUNCATED        = 0x33, // Truncated flag in frame control field was set
	// Overflow flag in the frame control field was set, and one or more
	// callbacks were lost due to lack of memory.
	EZSP_ERR_OVERFLOW         = 0x34,
	EZSP_ERR_OUT_OF_MEMORY    = 0x35,
	EZSP_ERR_INVALID_VALUE    = 0x36,
	EZSP_ERR_INVALID_ID       = 0x37, // Configuration ID was not recognized
	EZSP_ERR_INVALID_CALL     = 0x38, // Configuration value can no longer be modified
	EZSP_ERR_NO_RESPONSE      = 0x39, // NCP failed to respond to a command
	EZSP_ERR_COMMAND_TOO_LONG = 0x40, // Command length exceeded max EZSP frame length
	EZSP_ERR_QUEUE_FULL       = 0x41, // UART RX queue was full causing a callback to be dropped
	EZSP_ERR_COMMAND_FILTERED = 0x42, // Command has been filtered out by NCP

	EZSP_ERR_SECURITY_KEY_ALREADY_SET        = 0x43,
	EZSP_ERR_SECURITY_TYPE_INVALID           = 0x44,
	EZSP_ERR_SECURITY_PARAMETERS_INVALID     = 0x45,
	EZSP_ERR_SECURITY_PARAMETERS_ALREADY_SET = 0x46,
	EZSP_ERR_SECURITY_KEY_NOT_SET            = 0x47,
	EZSP_ERR_SECURITY_PARAMETERS_NOT_SET     = 0x48,
	// Received frame with unsupported control byte
	EZSP_ERR_UNSUPPORTED_CONTROL             = 0x49,
	// Received frame is unsecure, when security is established
	EZSP_ERR_UNSECURE_FRAME                  = 0x4A,
};

typedef uint16_t EzspCmdId;
enum {
	/* Configuration frames */
	EZSP_VERSION                                  = 0x0000,
	EZSP_GET_CONFIG_VALUE                         = 0x0052,
	EZSP_SET_CONFIG_VALUE                         = 0x0053,
	EZSP_ADD_ENDPOINT                             = 0x0002,
	EZSP_SET_POLICY                               = 0x0055,
	EZSP_GET_POLICY                               = 0x0056,
	EZSP_SEND_PANID_UPDATE                        = 0x0057,
	EZSP_GET_VALUE                                = 0x00AA,
	EZSP_GET_EXTENDED_VALUE                       = 0x0003,
	EZSP_SET_VALUE                                = 0x00AB,

	/* Utilities frames */
	EZSP_NOP                                      = 0x0005,
	EZSP_ECHO                                     = 0x0081,
	EZSP_INVALID_COMMAND                          = 0x0058,
	EZSP_CALLBACK                                 = 0x0006,
	EZSP_NO_CALLBACKS                             = 0x0007,
	EZSP_SET_TOKEN                                = 0x0009,
	EZSP_GET_TOKEN                                = 0x000A,
	EZSP_GET_MFG_TOKEN                            = 0x000B,
	EZSP_SET_MFG_TOKEN                            = 0x000C,
	EZSP_STACK_TOKEN_CHANGED_HANDLER              = 0x000D,
	EZSP_GET_RANDOM_NUMBER                        = 0x0049,
	EZSP_SET_TIMER                                = 0x000E,
	EZSP_GET_TIMER                                = 0x004E,
	EZSP_TIMER_HANDLER                            = 0x000F,
	EZSP_DEBUG_WRITE                              = 0x0012,
	EZSP_READ_AND_CLEAR_COUNTERS                  = 0x0065,
	EZSP_READ_COUNTERS                            = 0x00F1,
	EZSP_COUNTER_ROLLOVER_HANDLER                 = 0x00F2,
	EZSP_DELAY_TEST                               = 0x009D,
	EZSP_GET_LIBRARY_STATUS                       = 0x0001,
	EZSP_GET_XNCP_INFO                            = 0x0013,
	EZSP_CUSTOM_FRAME                             = 0x0047,
	EZSP_CUSTOM_FRAME_HANDLER                     = 0x0054,
	EZSP_GET_EUI64                                = 0x0026,
	EZSP_GET_NODE_ID                              = 0x0027,
	EZSP_GET_PHY_INTERFACE_COUNT                  = 0x00FC,
	EZSP_GET_TRUE_RANDOM_ENTROPY_SOURCE           = 0x004F,

	/* Networking frames */
	EZSP_SET_MANUFACTURER_CODE                    = 0x0015,
	EZSP_SET_POWER_DESCRIPTOR                     = 0x0016,
	EZSP_NETWORK_INIT                             = 0x0017,
	EZSP_NETWORK_STATE                            = 0x0018,
	EZSP_STACK_STATUS_HANDLER                     = 0x0019,
	EZSP_START_SCAN                               = 0x001A,
	EZSP_ENERGY_SCAN_RESULT_HANDLER               = 0x0048,
	EZSP_NETWORK_FOUND_HANDLER                    = 0x001B,
	EZSP_SCAN_COMPLETE_HANDLER                    = 0x001C,
	EZSP_UNUSED_PANID_FOUND_HANDLER               = 0x00D2,
	EZSP_FIND_UNUSED_PANID                        = 0x00D3,
	EZSP_STOP_SCAN                                = 0x001D,
	EZSP_FORM_NETWORK                             = 0x001E,
	EZSP_JOIN_NETWORK                             = 0x001F,
	EZSP_LEAVE_NETWORK                            = 0x0020,
	EZSP_FIND_AND_REJOIN_NETWORK                  = 0x0021,
	EZSP_PERMIT_JOINING                           = 0x0022,
	EZSP_CHILD_JOIN_HANDLER                       = 0x0023,
	EZSP_ENERGY_SCAN_REQUEST                      = 0x009C,
	EZSP_GET_NETWORK_PARAMETERS                   = 0x0028,
	EZSP_GET_RADIO_PARAMETERS                     = 0x00FD,
	EZSP_GET_PARENT_CHILD_PARAMETERS              = 0x0029,
	EZSP_GET_CHILD_DATA                           = 0x004A,
	EZSP_SET_CHILD_DATA                           = 0x00AC,
	EZSP_GET_SOURCE_ROUTE_TABLE_TOTAL_SIZE        = 0x00C3,
	EZSP_GET_SOURCE_ROUTE_TABLE_FILLED_SIZE       = 0x00C2,
	EZSP_GET_SOURCE_ROUTE_TABLE_ENTRY             = 0x00C1,
	EZSP_GET_NEIGHBOR                             = 0x0079,
	EZSP_GET_NEIGHBOR_FRAME_COUNTER               = 0x003E,
	EZSP_SET_NEIGHBOR_FRAME_COUNTER               = 0x00AD,
	EZSP_SET_ROUTING_SHORTCUT_THRESHOLD           = 0x00D0,
	EZSP_GET_ROUTING_SHORTCUT_THRESHOLD           = 0x00D1,
	EZSP_NEIGHBOR_COUNT                           = 0x007A,
	EZSP_GET_ROUTE_TABLE_ENTRY                    = 0x007B,
	EZSP_SET_RADIO_POWER                          = 0x0099,
	EZSP_SET_RADIO_CHANNEL                        = 0x009A,
	EZSP_GET_RADIO_CHANNEL                        = 0x00FF,
	EZSP_SET_RADIO_IEEE802154_CCA_MODE            = 0x0095,
	EZSP_SET_CONCENTRATOR                         = 0x0010,
	EZSP_SET_BROKEN_ROUTE_ERROR_CODE              = 0x0011,
	EZSP_MULTI_PHY_START                          = 0x00F8,
	EZSP_MULTI_PHY_STOP                           = 0x00F9,
	EZSP_MULTI_PHY_SET_RADIO_POWER                = 0x00FA,
	EZSP_SEND_LINK_POWER_DELTA_REQUEST            = 0x00F7,
	EZSP_MULTI_PHY_SET_RADIO_CHANNEL              = 0x00FB,
	EZSP_GET_DUTY_CYCLE_STATE                     = 0x0035,
	EZSP_SET_DUTY_CYCLE_LIMITS_IN_STACK           = 0x0040,
	EZSP_GET_DUTY_CYCLE_LIMITS                    = 0x004B,
	EZSP_GET_CURRENT_DUTY_CYCLE                   = 0x004C,
	EZSP_DUTY_CYCLE_HANDLER                       = 0x004D,
	EZSP_SEND_RAW_MESSAGE                         = 0x0096,
	EZSP_SEND_RAW_MESSAGE_EXT                     = 0x0051,
	EZSP_RAW_TRANSMIT_COMPLETE_HANDLER            = 0x0098,

	/* Green Power frames */
	EZSP_GP_PROXY_TABLE_PROCESS_GP_PAIRING        = 0x00C9,
	EZSP_GP_SEND                                  = 0x00C6,
	EZSP_GP_SENT_HANDLER                          = 0x00C7,
	EZSP_GP_INCOMING_MESSAGE_HANDLER              = 0x00C5,
	EZSP_GP_PROXY_TABLE_GET_ENTRY                 = 0x00C8,
	EZSP_GP_PROXY_TABLE_LOOKUP                    = 0x00C0,
	EZSP_GP_SINK_TABLE_GET_ENTRY                  = 0x00DD,
	EZSP_GP_SINK_TABLE_LOOKUP                     = 0x00DE,
	EZSP_GP_SINK_TABLE_SET_ENTRY                  = 0x00DF,
	EZSP_GP_SINK_TABLE_REMOVE_ENTRY               = 0x00E0,
	EZSP_GP_SINK_TABLE_FIND_OR_ALLOCATE_ENTRY     = 0x00E1,
	EZSP_GP_SINK_TABLE_CLEAR_ALL                  = 0x00E2,
	EZSP_GP_SINK_TABLE_INIT                       = 0x0070,

	/* Security frames */
	EZSP_SET_INITIAL_SECURITY_STATE               = 0x0068,
	EZSP_GET_CURRENT_SECURITY_STATE               = 0x0069,
	EZSP_GET_KEY                                  = 0x006a,
	EZSP_CLEAR_KEY_TABLE                          = 0x00B1,
	EZSP_CLEAR_TRANSIENT_LINK_KEYS                = 0x006B,
};

typedef uint8_t EzspConfigId;
enum {
	/**
	 * The number of packet buffers available to the stack. When set to the
	 * special value 0xFF, the NCP will allocate all remaining configuration RAM
	 * towards packet buffers, such that the resulting count will be the largest
	 * whole number of packet buffers that can fit into the available memory.
	 */
	EZSP_CONFIG_PACKET_BUFFER_COUNT = 0x01,

	/**
	 * The maximum number of router neighbors the stack can keep track of.
	 * A neighbor is a node within radio range.
	 */
	EZSP_CONFIG_NEIGHBOR_TABLE_SIZE = 0x02,

	/**
	 * The maximum number of APS retried messages the
	 * stack can be transmitting at any time.
	 */
	EZSP_CONFIG_APS_UNICAST_MESSAGE_COUNT = 0x03,

	/**
	 * The maximum number of non-volatile bindings supported by the stack.
	 */
	EZSP_CONFIG_BINDING_TABLE_SIZE = 0x04,

	/**
	 * The maximum number of EUI64 to network address associations that the
	 * stack can maintain for the application.
	 * (Note, the total number of such address associations maintained by the
	 * NCP is the sum of the value of this setting and the value of
	 * ::EZSP_CONFIG_TRUST_CENTER_ADDRESS_CACHE_SIZE).
	 */
	EZSP_CONFIG_ADDRESS_TABLE_SIZE = 0x05,

	/**
	 * The maximum number of multicast groups that the device may be a member of.
	 */
	EZSP_CONFIG_MULTICAST_TABLE_SIZE = 0x06,

	/**
	 * The maximum number of destinations to which a node can route messages.
	 * This includes both messages originating at this node and those relayed
	 * for others.
	 */
	EZSP_CONFIG_ROUTE_TABLE_SIZE = 0x07,

	/**
	 * The number of simultaneous route discoveries that a node will support.
	 */
	EZSP_CONFIG_DISCOVERY_TABLE_SIZE = 0x08,


	/**
	 * Specifies the stack profile.
	 */
	EZSP_CONFIG_STACK_PROFILE = 0x0C,

	/**
	 * The security level used for security at the MAC and network layers.
	 * The supported values are 0 (no security) and 5 (payload is encrypted and
	 * a four-byte MIC is used for authentication).
	 */
	EZSP_CONFIG_SECURITY_LEVEL = 0x0D,

	/**
	 * The maximum number of hops for a message.
	 */
	EZSP_CONFIG_MAX_HOPS = 0x10,

	/**
	 * The maximum number of end device children that a router will support.
	 */
	EZSP_CONFIG_MAX_END_DEVICE_CHILDREN = 0x11,

	/**
	 * The maximum amount of time that the MAC will hold a message for
	 * indirect transmission to a child.
	 */
	EZSP_CONFIG_INDIRECT_TRANSMISSION_TIMEOUT = 0x12,

	/**
	 * The maximum amount of time that an end device child can wait between
	 * polls. If no poll is heard within this timeout, then the parent removes
	 * the end device from its tables.
	 */
	EZSP_CONFIG_END_DEVICE_POLL_TIMEOUT = 0x13,

	/**
	 * The maximum amount of time that a mobile node can
	 * wait between polls. If no poll is heard within this timeout,
	 * then the parent removes the mobile node from its
	 * tables.
	 */
	EZSP_CONFIG_MOBILE_NODE_POLL_TIMEOUT = 0x14,

	/**
	 * The number of child table entries reserved for use only
	 * by mobile nodes.
	 */
	EZSP_CONFIG_RESERVED_MOBILE_CHILD_ENTRIES = 0x15,


	/**
	 * Enables boost power mode and/or the alternate transmitter output.
	 */
	EZSP_CONFIG_TX_POWER_MODE = 0x17,

	/**
	 * 0: Allow this node to relay messages. 1: Prevent this
	 * node from relaying messages.
	 */
	EZSP_CONFIG_DISABLE_RELAY = 0x18,

	/**
	 * The maximum number of EUI64 to network address associations that the Trust Center can
	 * maintain. These address cache entries are reserved for and reused by the Trust Center when
	 * processing device join/rejoin authentications. This cache size limits the number of
	 * overlapping joins the Trust Center can process within a narrow time window (e.g. two
	 * seconds), and thus should be set to the maximum number of near simultaneous joins the Trust
	 * Center is expected to accommodate. (Note, the total number of such address associations
	 * maintained by the NCP is the sum of the value of this setting and the value of
	 * ::EZSP_CONFIG_ADDRESS_TABLE_SIZE.)
	 */
	EZSP_CONFIG_TRUST_CENTER_ADDRESS_CACHE_SIZE = 0x19,

	/**
	 * The size of the source route table.
	 */
	EZSP_CONFIG_SOURCE_ROUTE_TABLE_SIZE = 0x1A,

	/**
	 * The number of blocks of a fragmented message that
	 * can be sent in a single window.
	 */
	EZSP_CONFIG_FRAGMENT_WINDOW_SIZE = 0x1C,

	/**
	 * The time the stack will wait (in milliseconds) between
	 * sending blocks of a fragmented message.
	 */
	EZSP_CONFIG_FRAGMENT_DELAY_MS = 0x1D,


	/**
	 * The size of the Key Table used for storing individual link keys
	 * (if the device is a Trust Center) or Application Link Keys (if the
	 * device is a normal node).
	 */
	EZSP_CONFIG_KEY_TABLE_SIZE = 0x1E,

	/**
	 * The APS ACK timeout value. The stack waits this amount of time between
	 * resends of APS retried messages.
	 */
	EZSP_CONFIG_APS_ACK_TIMEOUT = 0x1F,

	/**
	 * The duration of a beacon jitter, in the units used by the
	 * 15.4 scan parameter (((1 << duration) + 1) * 15ms),
	 * when responding to a beacon request.
	 */
	EZSP_CONFIG_BEACON_JITTER_DURATION = 0x20,

	/**
	 * The time the coordinator will wait (in seconds) for a
	 * second end device bind request to arrive.
	 */
	EZSP_CONFIG_END_DEVICE_BIND_TIMEOUT = 0x21,

	/**
	 * The number of PAN id conflict reports that must be
	 * received by the network manager within one minute to
	 * trigger a PAN id change.
	 */
	EZSP_CONFIG_PAN_ID_CONFLICT_REPORT_THRESHOLD = 0x22,

	/**
	 * The timeout value in minutes for how long the Trust
	 * Center or a normal node waits for the ZigBee Request
	 * Key to complete. On the Trust Center this controls
	 * whether or not the device buffers the request, waiting for
	 * a matching pair of ZigBee Request Key. If the value is
	 * non-zero, the Trust Center buffers and waits for that
	 * amount of time. If the value is zero, the Trust Center
	 * does not buffer the request and immediately responds
	 * to the request. Zero is the most compliant behavior.
	 */
	EZSP_CONFIG_REQUEST_KEY_TIMEOUT = 0x24,

	/**
	 * This value indicates the size of the runtime modifiable
	 * certificate table. Normally certificates are stored in MFG
	 * tokens but this table can be used to field upgrade
	 * devices with new Smart Energy certificates. This value
	 * cannot be set, it can only be queried.
	 */
	EZSP_CONFIG_CERTIFICATE_TABLE_SIZE = 0x29,

	/**
	 * This is a bitmask that controls which incoming ZDO request messages are passed to the
	 * application. The bits are defined in the EmberZdoConfigurationFlags enumeration. To see
	 * if the application is required to send a ZDO response in reply to an incoming message, the
	 * application must check the APS options bitfield within the incomingMessageHandler
	 * callback to see if the EMBER_APS_OPTION_ZDO_RESPONSE_REQUIRED flag is set.
	 */
	EZSP_CONFIG_APPLICATION_ZDO_FLAGS = 0x2A,

	/**
	 * The maximum number of broadcasts during a single
	 * broadcast timeout period.
	 */
	EZSP_CONFIG_BROADCAST_TABLE_SIZE = 0x2B,

	/**
	 * The size of the MAC filter list table.
	 */
	EZSP_CONFIG_MAC_FILTER_TABLE_SIZE = 0x2C,

	/**
	 * The number of supported networks.
	 */
	EZSP_CONFIG_SUPPORTED_NETWORKS = 0x2D,

	/**
	 * Whether multicasts are sent to the RxOnWhenIdle=true
	 * address (0xFFFD) or the sleepy broadcast address
	 * (0xFFFF). The RxOnWhenIdle=true address is the
	 * ZigBee compliant destination for multicasts.
	 */
	EZSP_CONFIG_SEND_MULTICASTS_TO_SLEEPY_ADDRESS = 0x2E,

	/**
	 * ZLL group address initial configuration.
	 */
	EZSP_CONFIG_ZLL_GROUP_ADDRESSES = 0x2F,

	/**
	 * ZLL rssi threshold initial configuration.
	 */
	EZSP_CONFIG_ZLL_RSSI_THRESHOLD = 0x30,

	/**
	 * Toggles the mtorr flow control in the stack.
	 */
	EZSP_CONFIG_MTORR_FLOW_CONTROL = 0x33,

	/**
	 * Setting the retry queue size.
	 */
	EZSP_CONFIG_RETRY_QUEUE_SIZE = 0x34,

	/**
	 * Setting the new broadcast entry threshold.
	 */
	EZSP_CONFIG_NEW_BROADCAST_ENTRY_THRESHOLD = 0x35,

	/**
	 * The number of passive acknowledgements to record from neighbors before
	 * we stop re-transmitting broadcasts.
	 */
	EZSP_CONFIG_BROADCAST_MIN_ACKS_NEEDED = 0x37,

	/**
	 * The length of time, in seconds, that a trust center will
	 * allow a Trust Center (insecure) rejoin for a device that is
	 * using the well-known link key. This timeout takes effect
	 * once rejoins using the well-known key has been
	 * allowed. This command updates the
	 * emAllowTcRejoinsUsingWellKnownKeyTimeoutSec
	 * value.
	 */
	EZSP_CONFIG_TC_REJOINS_USING_WELL_KNOWN_KEY_TIMEOUT_S = 0x38,

	/* Green Power proxy table size. This value is read-only and cannot be set at runtime. */
	EZSP_CONFIG_GP_PROXY_TABLE_SIZE = 0x41,
	/* Green Power sink table size. This value is read-only and cannot be set at runtime. */
	EZSP_CONFIG_GP_SINK_TABLE_SIZE  = 0x42,
};

typedef uint8_t EzspPolicyId;
enum {
	// Controls trust center behavior.
	EZSP_TRUST_CENTER_POLICY = 0x00,
	// Controls how external binding modification requests are handled.
	EZSP_BINDING_MODIFICATION_POLICY = 0x01,
	// Controls whether the Host supplies unicast replies.
	EZSP_UNICAST_REPLIES_POLICY = 0x02,
	// Controls whether pollHandler callbacks are generated.
	EZSP_POLL_HANDLER_POLICY = 0x03,
	// Controls whether the message contents are included in the messageSentHandler callback.
	EZSP_MESSAGE_CONTENTS_IN_CALLBACK_POLICY = 0x04,
	// Controls whether the Trust Center will respond to Trust Center link key requests.
	EZSP_TC_KEY_REQUEST_POLICY = 0x05,
	// Controls whether the Trust Center will respond to application link key requests.
	EZSP_APP_KEY_REQUEST_POLICY = 0x06,
	/*
	 * Controls whether ZigBee packets that appear invalid are automatically
	 * dropped by the stack. A counter will be incremented when this occurs.
	 */
	EZSP_PACKET_VALIDATE_LIBRARY_POLICY = 0x07,
	// Controls whether the stack will process ZLL messages.
	EZSP_ZLL_POLICY = 0x08,
	/*
	 * Controls whether Trust Center (insecure) rejoins for devices using
	 * the well-known link key are accepted. If rejoining using the well-known
	 * key is allowed, it is disabled again after
	 * emAllowTcRejoinsUsingWellKnownKeyTimeoutSec seconds.
	 */
	EZSP_TC_REJOINS_USING_WELL_KNOWN_KEY_POLICY = 0x09,
};

/*
 * EzspPolicyFlags is a policy decision bitmask that controls the
 * Trust Center decision strategies.
 * The bitmask is modified and extracted from a ezsp_policy_value_t for
 * supporting bitmask operations.
 */
typedef uint16_t EzspPolicyFlags;
enum {
	EZSP_DECISION_DEFAULT_CONFIG             = 0x0000,
	EZSP_DECISION_ALLOW_JOINS                = 0x0001,
	EZSP_DECISION_ALLOW_UNSECURED_REJOINS    = 0x0002,
	EZSP_DECISION_SEND_KEY_IN_CLEAR          = 0x0004,
	EZSP_DECISION_IGNORE_UNSECURED_REJOINS   = 0x0008,
	EZSP_DECISION_JOINS_USE_INSTALL_CODE_KEY = 0x0010,
	EZSP_DECISION_DEFER_JOINS                = 0x0020,
};

/*
 * ezsp_policy_value_t identifies a policy decision.
 */
typedef uint8_t EzspPolicyValue;
enum {
	/**
	 * Send the network key encrypted with the joining or rejoining device's trust center link key.
	 * The trust center and any joining or rejoining device are assumed to share a link key, either
	 * preconfigured or obtained under a previous policy. This is the default value for the
	 * EZSP_TRUST_CENTER_POLICY.
	 */
	EZSP_ALLOW_PRECONFIGURED_KEY_JOINS = EZSP_DECISION_ALLOW_JOINS | EZSP_DECISION_ALLOW_UNSECURED_REJOINS,

	// Delay sending the network key to a new joining device.
	//EZSP_DEFER_JOINS_REJOINS_HAVE_LINK_KEY = 0x07,

	/**
	 * EZSP_BINDING_MODIFICATION_POLICY default decision. Do not allow the local binding table
	 * to be changed by remote nodes.
	 */
	EZSP_DISALLOW_BINDING_MODIFICATION = 0x10,
	/**
	 * EZSP_BINDING_MODIFICATION_POLICY decision. Allow remote nodes to change the local
	 * binding table.
	 */
	EZSP_ALLOW_BINDING_MODIFICATION = 0x11,
	/**
	 * EZSP_BINDING_MODIFICATION_POLICY decision. Allows remote nodes to set local binding
	 * entries only if the entries correspond to endpoints defined on the device, and for output
	 * clusters bound to those endpoints.
	 */
	EZSP_CHECK_BINDING_MODIFICATIONS_ARE_VALID_ENDPOINT_CLUSTERS = 0x12,

	/**
	 * EZSP_UNICAST_REPLIES_POLICY default decision. The NCP will automatically send an empty
	 * reply (containing no payload) for every unicast received.
	 */
	EZSP_HOST_WILL_NOT_SUPPLY_REPLY = 0x20,
	/**
	 * EZSP_UNICAST_REPLIES_POLICY decision. The NCP will only send a reply if it receives a
	 * sendReply command from the Host.
	 */
	EZSP_HOST_WILL_SUPPLY_REPLY = 0x21,

	/**
	 * EZSP_POLL_HANDLER_POLICY default decision. Do not inform the Host when a child polls.
	 */
	EZSP_POLL_HANDLER_IGNORE = 0x30,
	/**
	 * EZSP_POLL_HANDLER_POLICY decision. Generate a pollHandler callback when a child polls.
	 */
	EZSP_POLL_HANDLER_CALLBACK = 0x31,

	/**
	 * EZSP_MESSAGE_CONTENTS_IN_CALLBACK_POLICY default decision. Include only the message
	 * tag in the messageSentHandler callback.
	 */
	EZSP_MESSAGE_TAG_ONLY_IN_CALLBACK = 0x40,
	/**
	 * EZSP_MESSAGE_CONTENTS_IN_CALLBACK_POLICY decision. Include both the message tag and
	 * the message contents in the messageSentHandler callback.
	 */
	EZSP_MESSAGE_TAG_AND_CONTENTS_IN_CALLBACK = 0x41,

	/**
	 * EZSP_TC_KEY_REQUEST_POLICY decision. When the Trust Center receives a request for a Trust
	 * Center link key, it will be ignored.
	 */
	EZSP_DENY_TC_KEY_REQUESTS = 0x50,
	/**
	 * EZSP_TC_KEY_REQUEST_POLICY decision. When the Trust Center receives a request for a Trust
	 * Center link key, it will reply to it with the corresponding key.
	 */
	EZSP_ALLOW_TC_KEY_REQUESTS = 0x51,
	/**
	 * EZSP_TC_KEY_REQUEST_POLICY decision. When the Trust Center receives a request for a Trust
	 * Center link key, it will generate a key to send to the joiner.
	 */
	EZSP_GENERATE_NEW_TC_LINK_KEY = 0x52,

	/**
	 * EZSP_APP_KEY_REQUEST_POLICY decision. When the Trust Center receives a request for an
	 * application link key, it will be ignored.
	 */
	EZSP_DENY_APP_KEY_REQUESTS = 0x60,
	/**
	 * EZSP_APP_KEY_REQUEST_POLICY decision. When the Trust Center receives a request for an
	 * application link key, it will randomly generate a key and send it to both partners.
	 */
	EZSP_ALLOW_APP_KEY_REQUESTS = 0x61,

	/**
	 * Indicates that packet validate library checks are enabled on the NCP.
	 */
	EZSP_PACKET_VALIDATE_LIBRARY_CHECKS_ENABLED = 0x62,
	/**
	 * Indicates that packet validate library checks are NOT enabled on the NCP.
	 */
	EZSP_PACKET_VALIDATE_LIBRARY_CHECKS_DISABLED = 0x63
};

typedef uint8_t EzspValueId;
enum {
	EZSP_VALUE_UART_SYNCH_CALLBACKS = 0x04,
};

// EZSP network scan types.
enum {
	EZSP_ENERGY_SCAN = 0x00, // Scan each channel for its RSSI value
	EZSP_ACTIVE_SCAN = 0x01, // Scan each channel for available networks
};

/*
 * Ember stack status codes.
 */
typedef uint8_t EmberStatus;
enum {
	EMBER_SUCCESS                                = 0x00,
	EMBER_ERR_FATAL                              = 0x01,
	EMBER_BAD_ARGUMENT                           = 0x02,
	EMBER_NOT_FOUND                              = 0x03,

	EMBER_EEPROM_MFG_STACK_VERSION_MISMATCH      = 0x04,
	EMBER_INCOMPATIBLE_STATIC_MEMORY_DEFINITIONS = 0x05,
	EMBER_EEPROM_MFG_VERSION_MISMATCH            = 0x06,
	EMBER_EEPROM_STACK_VERSION_MISMATCH          = 0x07,

	EMBER_NO_BUFFERS                             = 0x18,
	EMBER_PACKET_HANDOFF_DROP_PACKET             = 0x19,

	EMBER_SERIAL_INVALID_BAUD_RATE               = 0x20,
	EMBER_SERIAL_INVALID_PORT                    = 0x21,
	EMBER_SERIAL_TX_OVERFLOW                     = 0x22,
	EMBER_SERIAL_RX_OVERFLOW                     = 0x23,
	EMBER_SERIAL_RX_FRAME_ERROR                  = 0x24,
	EMBER_SERIAL_RX_PARITY_ERROR                 = 0x25,
	EMBER_SERIAL_RX_EMPTY                        = 0x26,
	EMBER_SERIAL_RX_OVERRUN_ERROR                = 0x27,

	EMBER_MAC_TRANSMIT_QUEUE_FULL                = 0x39,
	EMBER_MAC_UNKNOWN_HEADER_TYPE                = 0x3A,
	EMBER_MAC_ACK_HEADER_TYPE                    = 0x3B,
	EMBER_MAC_SCANNING                           = 0x3D,
	EMBER_MAC_NO_DATA                            = 0x31,
	EMBER_MAC_JOINED_NETWORK                     = 0x32,
	EMBER_MAC_BAD_SCAN_DURATION                  = 0x33,
	EMBER_MAC_INCORRECT_SCAN_TYPE                = 0x34,
	EMBER_MAC_INVALID_CHANNEL_MASK               = 0x35,
	EMBER_MAC_COMMAND_TRANSMIT_FAILURE           = 0x36,
	EMBER_MAC_NO_ACK_RECEIVED                    = 0x40,
	EMBER_MAC_RADIO_NETWORK_SWITCH_FAILED        = 0x41,
	EMBER_MAC_INDIRECT_TIMEOUT                   = 0x42,

	EMBER_SIM_EEPROM_ERASE_PAGE_GREEN            = 0x43,
	EMBER_SIM_EEPROM_ERASE_PAGE_RED              = 0x44,
	EMBER_SIM_EEPROM_FULL                        = 0x45,
	EMBER_SIM_EEPROM_INIT_1_FAILED               = 0x48,
	EMBER_SIM_EEPROM_INIT_2_FAILED               = 0x49,
	EMBER_SIM_EEPROM_INIT_3_FAILED               = 0x4A,
	EMBER_SIM_EEPROM_REPAIRING                   = 0x4D,

	EMBER_ERR_FLASH_WRITE_INHIBITED              = 0x46,
	EMBER_ERR_FLASH_VERIFY_FAILED                = 0x47,
	EMBER_ERR_FLASH_PROG_FAIL                    = 0x4B,
	EMBER_ERR_FLASH_ERASE_FAIL                   = 0x4C,

	EMBER_ERR_BOOTLOADER_TRAP_TABLE_BAD          = 0x58,
	EMBER_ERR_BOOTLOADER_TRAP_UNKNOWN            = 0x59,
	EMBER_ERR_BOOTLOADER_NO_IMAGE                = 0x5A,

	EMBER_DELIVERY_FAILED                        = 0x66,
	EMBER_BINDING_INDEX_OUT_OF_RANGE             = 0x69,
	EMBER_ADDRESS_TABLE_INDEX_OUT_OF_RANGE       = 0x6A,
	EMBER_INVALID_BINDING_INDEX                  = 0x6C,
	EMBER_INVALID_CALL                           = 0x70,
	EMBER_COST_NOT_KNOWN                         = 0x71,
	EMBER_MAX_MESSAGE_LIMIT_REACHED              = 0x72,
	EMBER_MESSAGE_TOO_LONG                       = 0x74,
	EMBER_BINDING_IS_ACTIVE                      = 0x75,
	EMBER_ADDRESS_TABLE_ENTRY_IS_ACTIVE          = 0x76,
	EMBER_TRANSMISSION_SUSPENDED                 = 0x77,

	EMBER_MATCH                                  = 0x78,
	EMBER_DROP_FRAME                             = 0x79,
	EMBER_PASS_UNPROCESSED                       = 0x7A,
	EMBER_TX_THEN_DROP                           = 0x7B,
	EMBER_NO_SECURITY                            = 0x7C,
	EMBER_COUNTER_FAILURE                        = 0x7D,
	EMBER_AUTH_FAILURE                           = 0x7E,
	EMBER_UNPROCESSED                            = 0x7F,

	EMBER_ADC_CONVERSION_DONE                    = 0x80,
	EMBER_ADC_CONVERSION_BUSY                    = 0x81,
	EMBER_ADC_CONVERSION_DEFERRED                = 0x82,
	EMBER_ADC_NO_CONVERSION_PENDING              = 0x84,
	EMBER_SLEEP_INTERRUPTED                      = 0x85,

	EMBER_PHY_TX_SCHED_FAIL                      = 0x87,
	EMBER_PHY_TX_UNDERFLOW                       = 0x88,
	EMBER_PHY_TX_INCOMPLETE                      = 0x89,
	EMBER_PHY_INVALID_CHANNEL                    = 0x8A,
	EMBER_PHY_INVALID_POWER                      = 0x8B,
	EMBER_PHY_TX_BUSY                            = 0x8C,
	EMBER_PHY_TX_CCA_FAIL                        = 0x8D,
	EMBER_PHY_TX_BLOCKED                         = 0x8E,
	EMBER_PHY_ACK_RECEIVED                       = 0x8F,

	EMBER_NETWORK_UP                             = 0x90,
	EMBER_NETWORK_DOWN                           = 0x91,
	EMBER_JOIN_FAILED                            = 0x94,
	EMBER_MOVE_FAILED                            = 0x96,
	EMBER_CANNOT_JOIN_AS_ROUTER                  = 0x98,
	EMBER_NODE_ID_CHANGED                        = 0x99,
	EMBER_PAN_ID_CHANGED                         = 0x9A,
	EMBER_CHANNEL_CHANGED                        = 0x9B,
	EMBER_NETWORK_OPENED                         = 0x9C,
	EMBER_NETWORK_CLOSED                         = 0x9D,
	EMBER_NO_BEACONS                             = 0xAB,
	EMBER_RECEIVED_KEY_IN_THE_CLEAR              = 0xAC,
	EMBER_NO_NETWORK_KEY_RECEIVED                = 0xAD,
	EMBER_NO_LINK_KEY_RECEIVED                   = 0xAE,
	EMBER_PRECONFIGURED_KEY_REQUIRED             = 0xAF,

	EMBER_KEY_INVALID                            = 0xB2,
	EMBER_INVALID_SECURITY_LEVEL                 = 0x95,
	EMBER_IEEE_ADDRESS_DISCOVERY_IN_PROGRESS     = 0xBE,
	EMBER_APS_ENCRYPTION_ERROR                   = 0xA6,
	EMBER_SECURITY_STATE_NOT_SET                 = 0xA8,
	EMBER_KEY_TABLE_INVALID_ADDRESS              = 0xB3,
	EMBER_SECURITY_CONFIGURATION_INVALID         = 0xB7,
	EMBER_TOO_SOON_FOR_SWITCH_KEY                = 0xB8,
	EMBER_SIGNATURE_VERIFY_FAILURE               = 0xB9,
	EMBER_KEY_NOT_AUTHORIZED                     = 0xBB,
	EMBER_SECURITY_DATA_INVALID                  = 0xBD,

	EMBER_NOT_JOINED                             = 0x93,
	EMBER_NETWORK_BUSY                           = 0xA1,
	EMBER_INVALID_ENDPOINT                       = 0xA3,
	EMBER_BINDING_HAS_CHANGED                    = 0xA4,
	EMBER_INSUFFICIENT_RANDOM_DATA               = 0xA5,
	EMBER_SOURCE_ROUTE_FAILURE                   = 0xA9,
	EMBER_MANY_TO_ONE_ROUTE_FAILURE              = 0xAA,

	EMBER_STACK_AND_HARDWARE_MISMATCH            = 0xB0,
	EMBER_INDEX_OUT_OF_RANGE                     = 0xB1,
	EMBER_TABLE_FULL                             = 0xB4,
	EMBER_TABLE_ENTRY_ERASED                     = 0xB6,
	EMBER_LIBRARY_NOT_PRESENT                    = 0xB5,
	EMBER_OPERATION_IN_PROGRESS                  = 0xBA,
	EMBER_TRUST_CENTER_EUI_HAS_CHANGED           = 0xBC,

	EMBER_NVM3_TOKEN_NO_VALID_PAGES              = 0xC0,
	EMBER_NVM3_ERR_OPENED_WITH_OTHER_PARAMETERS  = 0xC1,
	EMBER_NVM3_ERR_ALIGNMENT_INVALID             = 0xC2,
	EMBER_NVM3_ERR_SIZE_TOO_SMALL                = 0xC3,
	EMBER_NVM3_ERR_PAGE_SIZE_NOT_SUPPORTED       = 0xC4,
	EMBER_NVM3_ERR_TOKEN_INIT                    = 0xC5,
	EMBER_NVM3_ERR_UPGRADE                       = 0xC6,
	EMBER_NVM3_ERR_UNKNOWN                       = 0xC7,

	EMBER_APPLICATION_ERROR_0                    = 0xF0,
	EMBER_APPLICATION_ERROR_1                    = 0xF1,
	EMBER_APPLICATION_ERROR_2                    = 0xF2,
	EMBER_APPLICATION_ERROR_3                    = 0xF3,
	EMBER_APPLICATION_ERROR_4                    = 0xF4,
	EMBER_APPLICATION_ERROR_5                    = 0xF5,
	EMBER_APPLICATION_ERROR_6                    = 0xF6,
	EMBER_APPLICATION_ERROR_7                    = 0xF7,
	EMBER_APPLICATION_ERROR_8                    = 0xF8,
	EMBER_APPLICATION_ERROR_9                    = 0xF9,
	EMBER_APPLICATION_ERROR_10                   = 0xFA,
	EMBER_APPLICATION_ERROR_11                   = 0xFB,
	EMBER_APPLICATION_ERROR_12                   = 0xFC,
	EMBER_APPLICATION_ERROR_13                   = 0xFD,
	EMBER_APPLICATION_ERROR_14                   = 0xFE,
	EMBER_APPLICATION_ERROR_15                   = 0xFF,
};

// 128-bit encryption key.
#define EMBER_KEY_LEN 16
typedef struct __attribute__((packed)) {
	uint8_t data[EMBER_KEY_LEN];
} EmberKey;

// EUI 64-bit ID (an IEEE address).
typedef uint64_t EmberEUI64;

// 16-bit ZigBee network address.
typedef uint16_t EmberNodeId;

typedef uint8_t EmberNwkStatus;
enum {
	EMBER_NO_NETWORK               = 0x00,
	EMBER_JOINING_NETWORK          = 0x01,
	EMBER_JOINED_NETWORK           = 0x02,
	EMBER_JOINED_NETWORK_NO_PARENT = 0x03,
	EMBER_LEAVING_NETWORK          = 0x04,
};

typedef uint8_t EmberNodeType;
enum {
	EMBER_NODE_UNKNOWN_DEVICE    = 0x00,
	EMBER_NODE_COORDINATOR       = 0x01,
	EMBER_NODE_ROUTER            = 0x02,
	EMBER_NODE_END_DEVICE        = 0x03,
	EMBER_NODE_SLEEPY_END_DEVICE = 0x04,
};

typedef struct __attribute__((packed)) {
		uint8_t extended_pan_id[8];
		uint16_t pan_id;
		uint8_t radio_tx_power;
		uint8_t radio_channel;
		uint8_t join_method;
		uint16_t nwk_manager_id;
		uint8_t nwk_update_id;
		uint32_t channels;
} EmberNwkConfig;

// EmberInitialSecurityBitmask
typedef uint16_t EmberInitialSecurityFlags;
enum {
	EMBER_STANDARD_SECURITY_MODE            = 0x00,
	EMBER_DISTRIBUTED_TRUST_CENTER_MODE     = 0x02,
	// All nodes will share the same TC link key.
	EMBER_TRUST_CENTER_GLOBAL_LINK_KEY      = 0x04,
	// Enable devices that perform MAC association with a pre-configured
	// network key to join the network. Only set on the TC.
	EMBER_PRECONFIGURED_NETWORK_KEY_MODE    = 0x08,
	EMBER_HAVE_TRUST_CENTER_EUI64           = 0x40,
	EMBER_TRUST_CENTER_USES_HASHED_LINK_KEY = 0x84,
	EMBER_HAVE_PRECONFIGURED_KEY            = 0x100,
	EMBER_HAVE_NETWORK_KEY                  = 0x200,
	EMBER_GET_LINK_KEY_WHEN_JOINING         = 0x400,
	EMBER_REQUIRE_ENCRYPTED_KEY             = 0x800,
	EMBER_NO_FRAME_COUNTER_RESET            = 0x1000,
	EMBER_GET_PRECONFIGURED_KEY_FROM_INSTALL_CODE = 0x2000,
};

typedef struct __attribute__((packed)) {
	EmberInitialSecurityFlags flags; // See above.

	// Only valid if EMBER_HAVE_PRECONFIGURED_KEY is set in flags.
	uint8_t pc_key[EMBER_KEY_LEN];  // Pre-configured key
	// Only valid if EMBER_HAVE_NETWORK_KEY is set in flags.
	uint8_t nwk_key[EMBER_KEY_LEN]; // Network key
	/*
	 * The sequence number associated with the network key.
	 * Only valid if EMBER_HAVE_NETWORK_KEY is set in flags.
	 */
	uint8_t nwk_key_seq_num;
	// Only valid if EMBER_HAVE_TRUST_CENTER_EUI64 is set in flags.
	EmberEUI64 tc_eui;
} EmberInitialSecurityState;

// Only for EZSP v9
typedef uint32_t sl_status_t;
enum {
	SL_STATUS_OK                   = 0x0000,  // No error.
	SL_STATUS_FAIL                 = 0x0001,  // Generic error.
	// State Errors
	SL_STATUS_INVALID_STATE        = 0x0002, // Generic invalid state error.
	SL_STATUS_NOT_READY            = 0x0003, // Module is not ready for requested operation.
	SL_STATUS_BUSY                 = 0x0004, // Module is busy and cannot carry out requested operation.
	SL_STATUS_IN_PROGRESS          = 0x0005, // Operation is in progress and not yet complete (pass or fail).
	SL_STATUS_ABORT                = 0x0006, // Operation aborted.
	SL_STATUS_TIMEOUT              = 0x0007, // Operation timed out.
	SL_STATUS_PERMISSION           = 0x0008, // Operation not allowed per permissions.
	SL_STATUS_WOULD_BLOCK          = 0x0009, // Non-blocking operation would block.
	SL_STATUS_IDLE                 = 0x000A, // Operation/module is Idle, cannot carry requested operation.
	SL_STATUS_IS_WAITING           = 0x000B, // Operation cannot be done while construct is waiting.
	SL_STATUS_NONE_WAITING         = 0x000C, // No task/construct waiting/pending for that action/event.
	SL_STATUS_SUSPENDED            = 0x000D, // Operation cannot be done while construct is suspended.
	SL_STATUS_NOT_AVAILABLE        = 0x000E, // Feature not available due to software configuration.
	SL_STATUS_NOT_SUPPORTED        = 0x000F, // Feature not supported.
	SL_STATUS_INITIALIZATION       = 0x0010, // Initialization failed.
	SL_STATUS_NOT_INITIALIZED      = 0x0011, // Module has not been initialized.
	SL_STATUS_ALREADY_INITIALIZED  = 0x0012, // Module has already been initialized.
	SL_STATUS_DELETED              = 0x0013, // Object/construct has been deleted.
	SL_STATUS_ISR                  = 0x0014, // Illegal call from ISR.
	SL_STATUS_NETWORK_UP           = 0x0015, // Illegal call because network is up.
	SL_STATUS_NETWORK_DOWN         = 0x0016, // Illegal call because network is down.
	SL_STATUS_NOT_JOINED           = 0x0017, // Failure due to not being joined in a network.
	SL_STATUS_NO_BEACONS           = 0x0018, // Invalid operation as there are no beacons.
};

const char *ezsp_status_to_str(EzspStatus status);
const char *ezsp_cmd_id_to_str(EzspCmdId id);
const char *ezsp_config_id_to_str(EzspConfigId id);
const char *ezsp_policy_id_to_str(EzspPolicyId id);

const char *ember_status_to_str(EmberStatus status);
const char *ember_node_type_to_str(EmberNodeType node);

/*
 * Check whether a key is all zeros.
 */
static inline bool ember_key_is_null(EmberKey *key)
{
	static EmberKey zero_key = {0};
	return (memcmp(key->data, zero_key.data, sizeof(zero_key.data)) == 0);
}

#endif // EZSP_TYPES_H
