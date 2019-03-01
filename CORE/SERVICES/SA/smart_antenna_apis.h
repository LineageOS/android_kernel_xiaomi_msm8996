/*
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
 *
 * Previously licensed under the ISC license by Qualcomm Atheros, Inc.
 *
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * DOC: contains smart antenna APIs.
 */

#ifndef __SMART_ANT_API_H__
#define __SMART_ANT_API_H__

#ifndef BIT
#define BIT(n)                                   (1 << (n))
#endif

#define SMART_ANTENNA_MAX_RATE_SERIES 4
#define SMART_ANT_MAX_SA_CHAINS 4

#define SMART_ANT_STATUS_SUCCESS 0
#define SMART_ANT_STATUS_FAILURE -1


#define MAX_CCK_OFDM_RATES 12 /* Maximum CCK, OFDM rates supported */

/* Maximum MCS rates supported; 4 rates in each dword */
#define MAX_MCS_RATES 128
#define MAX_RATE_COUNTERS 2

#define RATE_INDEX_CCK_OFDM       0
#define RATE_INDEX_MCS            1

/* Maximum supported chain number */
#define SA_MAX_CHAIN_NUM     2

/**
 * enum radio_id - ID for different wlan card.
 */
enum radio_id {
	wifi0 = 0,
	wifi1,
};

/**
 * struct sa_config - Smart Antenna config info
 * @channel_num: SAP home channel number
 */
struct sa_config {
	uint8_t channel_num;
};

/**
 * struct sa_rate_cap - Rate capability for a connected peer
 * @ratecode_legacy: Rate code array for CCK OFDM
 * @mcs: mcs index for HT/VHT mode
 * @ratecount: Max Rate count for each mode
 */
struct sa_rate_cap {
	uint8_t ratecode_legacy[MAX_CCK_OFDM_RATES];
	uint8_t mcs[MAX_MCS_RATES];
	uint8_t ratecount[MAX_RATE_COUNTERS];
};

/**
 * struct sa_node_info - Detailed info about the connected peer
 * @mac_addr: MAC address of the connected peer
 * @channel_num: operating channel number
 * @node_caps: Capability for the connected node
 * @rate_cap: supported rates
 */
struct sa_node_info {
	uint8_t mac_addr[6];
	uint8_t channel_num;
	uint8_t nss;

#define SMART_ANT_BW_5MHZ                        BIT(0)
#define SMART_ANT_BW_10MHZ                       BIT(1)
#define SMART_ANT_BW_20MHZ                       BIT(2)
#define SMART_ANT_BW_40MHZ                       BIT(3)
#define SMART_ANT_BW_80MHZ                       BIT(4)
#define SMART_ANT_NODE_HT                        BIT(8)
#define SMART_ANT_NODE_VHT                       BIT(9)
	uint32_t node_caps;
	struct sa_rate_cap rate_cap;
};

/**
 * struct sa_comb_stats - combined stats for one frm
 * @retry_num: retry numbers
 * @ack_rssi: per chain RSSI of each ACK
 */
struct sa_comb_stats {
	uint8_t  retry_num;
	uint8_t  ack_rssi[SA_MAX_CHAIN_NUM];
	uint32_t time_stamp;
};


#define SA_RATE_TYPE_SHIFT                   15
#define SA_RATE_MASK                         0x7fff
#define SA_RATE_TYPE(rate) \
	((rate) & bit(SA_RATE_TYPE_SHIFT)) >> SA_RATE_TYPE_SHIFT

/**
 * struct sa_tx_stats_feedback - feedback for TX stats
 * @magic: magic number for deferent antenna settings
 * @tid: TID.
 * @pkt_nums: msdu number corresponding this TX feed back
 * @tx_rate:  msb is flag for legacy rate or mcs index
 *   if msb=0, legacy rate is reported, units of 500 kb/s
 *   if msb=1, MCS index is reported.
 * @msdu: stats for each msdu.
 */
struct sa_tx_stats_feedback {
	uint32_t magic;
	uint8_t  tid;
	uint16_t pkt_num;
	uint16_t tx_rate;
	struct sa_comb_stats msdu[0];
};

/**
 * struct  sa_rx_stats_feedback - feedback for RX stats
 * @magic: magic number for deferent antenna settings
 * @tid: TID
 * @rx_rate:  msb is flag for legacy rate or mcs index
 *   if msb=0, legacy rate is reported, units of 500 kb/s
 *   if msb=1, MCS index is reported.
 * @pkt_num: received packets nmber
 * @rx_rssi: percchain rssi
 * @timestamp: timestap
 */
struct  sa_rx_stats_feedback {
	uint32_t magic;
	uint8_t  tid;
	uint16_t rx_rate;
	uint16_t pkt_num;
	uint8_t rx_rssi[SA_MAX_CHAIN_NUM];
	uint32_t timestamp;
};

/**
 * struct sa_int_stats_feedback - feedback for interference stats
 * @magic: magic number for deferent antenna settings
 * @rx_time: time receiving frms, both on/out BSS. Unit in percentage.
 * @rx_bad_time: time for RX bad. Unit in percentage.
 * @tx_time: time sending frms, both success/failure. Unit in percentage.
 * @tx_bad_time: timer for TX bad. Unit in percentage.
 * @idle_time: time idlei Unit in percentage.
 * @on_bss_time: time on BSSi Unit in percentage.
 * @out_bss_time: time out BSSi Unit in percentage.
 * @phyerr_count: phy error count
 */
struct sa_int_stats_feedback {
	uint32_t magic;
	uint32_t rx_time;
	uint32_t rx_bad_time;
	uint32_t tx_time;
	uint32_t tx_bad_time;
	uint32_t idle_time;
	uint32_t on_bss_time;
	uint32_t out_bss_time;
	uint32_t phyerr_count;
	uint32_t timestamp;
};

/**
 * struct sa_params - config parameters from Smart Antenna module
 * @interval: report period for interference statistics. uinit in ms.
 *
 */
struct sa_params {
	uint32_t interval;
};

/**
 * struct smartantenna_ops - Callback from Smart Antenna module
 * @sa_init: Callback used by the WLAN driver to notify the initialization of
 *   a radio device or when the smart antenna configuration parameters
 *   are changed
 * @sa_deinit: Callback used by the WLAN driver to de-initialization
 *   the Smart Antenna Module.
 * @sa_node_connect: Callback to inform the Smart Antenna driver about
 *   the connection of a new node.
 * @sa_node_disconnect: Callback to inform the Smart Antenna driver about
 *   the disconnection of a connected node.
 * @sa_update_txfeedback: WLAN driver notifies to the Smart antenna driver
 *   every completion of a transmitted data packet (aggregated or individual)
 *   and passes the transmit feedback information of a specific link. The Smart
 *   antenna driver uses this information to estimate the channel quality.
 * @sa_update_rxfeedback: WLAN driver notifies to the Smart antenna driver
 *   the successful reception of a data WLAN packet (aggregated or individual)
 *   and passes the reception parameters through the structure sa_rx_feedback.
 * @sa_update_intfeedback: WLAN driver notifies to the Smart antenna
 *   driver the interference statistics  Feedback interval will be set according
 *   config paramters from Smart Antenna module.
 * @sa_get_config_parameters: Wlan driver gets config parameter from Smart
 *   Antenna module.
 */
struct smartantenna_ops {
	int (* sa_init)(struct sa_config * sa_config, int new_init);
	int (* sa_deinit)(enum radio_id radio_id);
	int (* sa_node_connect)(void **ccp, struct sa_node_info *node_info);
	int (* sa_node_disconnect)(void *ccp);
	int (* sa_update_txfeedback)(void *ccp,
				     struct sa_tx_stats_feedback *tx_stats,
				     uint8_t *status);
	int (* sa_update_rxfeedback)(void *ccp,
				     struct sa_rx_stats_feedback *rx_stats,
				     uint8_t *status);
	int (* sa_update_intfeedback)(void *ccp,
				      struct sa_int_stats_feedback *int_stats,
				      uint8_t *status);
	int (* sa_get_config_parameters)(struct sa_params *params);
};

/**
 * register_smart_ant_ops() - 3rd party module call this function to register
 *   the callbacks to WLAN driver.
 * @sa_ops: 3rd party module callbacks
 *
 * return: 0 for success.
 */
extern int register_smart_ant_ops(struct smartantenna_ops *sa_ops);

/**
 * deregister_smart_ant_ops() - 3rd party module call this function to
 *   deregister the callbacks to WLAN driver.
 * @interface_name: wlan interface name
 *
 * return: 0 for success.
 */
extern int deregister_smart_ant_ops(char *interface_name);

/**
 * set_smart_ant_control() - 3rd party module call this fuction to
 *   change antenna settings.
 * @magic: magic number for each settings. Used to disguish stats
 *   between different settings.
 *
 * return: 0 for success.
 */
extern int set_smart_ant_control(uint32_t magic);
#endif
