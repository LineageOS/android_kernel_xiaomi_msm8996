/*
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
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
 * DOC: contains smart antenna interfaces for internal modules.
 */

#ifndef __IF_SMART_ANTENNA_H__
#define __IF_SMART_ANTENNA_H__

#include "smart_antenna_apis.h"

struct smart_ant;
struct sa_ops {
	int (* sa_init)(struct smart_ant *sa, bool new_init);
	int (* sa_deinit)(struct smart_ant *sa);
	void (* sa_node_connect)(struct smart_ant *sa,
				 struct sa_node_info *node);
	void (* sa_node_disconnect)(struct smart_ant *sa, uint8_t *mac_addr);
	int (* sa_update_txfeedback)(struct smart_ant *sa, uint8_t *mac_addr,
				     struct sa_tx_stats_feedback *tx_feedback);
	int (* sa_update_rxfeedback)(struct smart_ant *sa, uint8_t *mac_addr,
				     struct sa_rx_stats_feedback *rx_feedback);
	int (* sa_update_intfeedback)(struct smart_ant *sa, uint8_t *mac_addr,
				   struct sa_int_stats_feedback *int_feedback);
	int (* sa_get_config)(struct smart_ant *sa);
};

#ifdef WLAN_SMART_ANTENNA_FEATURE

extern struct sa_ops *sa_get_ops(void);
extern struct smart_ant * sa_get_handle(void);

/**
 * smart_antenna_init() - initialize smart antenna related feature
 *  @new_init: flag for a new STA.
 *    0: No; Other: new STA.
 *
 * return: 0 for success.
 */
static __inline__
int smart_antenna_init(bool new_init)
{
	struct smart_ant *sa;
	struct sa_ops *sa_ops;

	sa = sa_get_handle();

	if (sa == NULL) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna handle.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	sa_ops = sa_get_ops();

	if (!sa_ops || !sa_ops->sa_init) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna ops.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	return sa_ops->sa_init(sa, new_init);
}

/**
 * smart_antenna_deinit() - deinitialize the module.
 *  @notify: whether to indicate the SMART ANTENNA kernel module.
 *    0: No; 1: Indicate.
 *
 * return: 0 for success.
 */
static __inline__
int smart_antenna_deinit(int notify)
{
	struct smart_ant *sa;
	struct sa_ops *sa_ops;

	sa = sa_get_handle();

	if (sa == NULL) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna handle.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	sa_ops = sa_get_ops();
	if (!sa_ops || !sa_ops->sa_deinit) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna ops.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}
	return sa_ops->sa_deinit(sa);
}

/**
 * smart_antenna_node_connected() - indicate a node connection envent
 *  to SMART Antenna module.
 * @node: node info.
 *
 */
static __inline__
void smart_antenna_node_connected(struct sa_node_info *node)
{
	struct smart_ant *sa;
	struct sa_ops *sa_ops;

	sa = sa_get_handle();

	if (sa == NULL) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna handle.", __func__);
		return;
	}

	sa_ops = sa_get_ops();
	if (!sa_ops || !sa_ops->sa_node_connect) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna ops.", __func__);
		return;
	}
	sa_ops->sa_node_connect(sa, node);
}

/**
 * smart_antenna_node_disconnected() - indicate a node disconnection envent
 *  to SMART Antenna module.
 * @mac_addr: node MAC address.
 *
 */
static __inline__
void smart_antenna_node_disconnected(tSirMacAddr mac_addr)
{
	struct smart_ant *sa;
	struct sa_ops *sa_ops;

	sa = sa_get_handle();

	if (sa == NULL) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna handle.", __func__);
		return;
	}

	sa_ops = sa_get_ops();
	if (!sa_ops || !sa_ops->sa_node_disconnect) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna ops.", __func__);
		return;
	}
	sa_ops->sa_node_disconnect(sa, mac_addr);
}

/**
 * smart_antenna_update_tx_stats() - update TX stats for a peer to
 *  Smart Antenna module.
 * @mac_addr: MAC address for the peer.
 * @Tx_feedback: TX stats.
 *
 */
static __inline__
void smart_antenna_update_tx_stats(tSirMacAddr mac_addr,
				   struct sa_tx_stats_feedback *tx_feedback)
{
	struct smart_ant *sa;
	struct sa_ops *sa_ops;

	sa = sa_get_handle();

	if (sa == NULL) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna handle.", __func__);
		return;
	}

	sa_ops = sa_get_ops();
	if (!sa_ops || !sa_ops->sa_update_txfeedback) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna ops.", __func__);
		return;
	}
	sa_ops->sa_update_txfeedback(sa, mac_addr, tx_feedback);
}

/**
 * smart_antenna_update_rx_stats() - update RX stats for a peer to
 *  Smart Antenna module.
 * @mac_addr: MAC address for the peer.
 * @rx_feedback: RX stats.
 *
 */
static __inline__
void smart_antenna_update_rx_stats(tSirMacAddr mac_addr,
				   struct sa_rx_stats_feedback *rx_feedback)
{
	struct smart_ant *sa;
	struct sa_ops *sa_ops;

	sa = sa_get_handle();

	if (sa == NULL) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna handle.", __func__);
		return;
	}

	sa_ops = sa_get_ops();
	if (!sa_ops || !sa_ops->sa_update_rxfeedback) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna ops.", __func__);
		return;
	}
	sa_ops->sa_update_rxfeedback(sa, mac_addr, rx_feedback);
}

/**
 * smart_antenna_update_int_stats() - undate interference stats for a peer to
 *  smart antenna module.
 * @mac_addr: MAC address for the peer.
 * @int_feedback: interference stats.
 *
 */
static __inline__
void smart_antenna_update_int_stats(tSirMacAddr mac_addr,
				    struct sa_int_stats_feedback *int_feedback)
{
	struct smart_ant *sa;
	struct sa_ops *sa_ops;

	sa = sa_get_handle();

	if (sa == NULL) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna handle.", __func__);
		return;
	}

	sa_ops = sa_get_ops();
	if (!sa_ops || !sa_ops->sa_update_intfeedback) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Failed to get smart antenna ops.", __func__);
		return;
	}
	sa_ops->sa_update_intfeedback(sa, mac_addr, int_feedback);
}

void smart_antenna_attach(void);
void smart_antenna_deattach(void);
#else
/**
 * smart_antenna_init() - initialize smart antenna related feature
 *  @new_init: flag for a new initialization.
 *    0: No; Other: new initialization.
 *
 * return: 0 for success.
 */
static __inline__
int smart_antenna_init(int new_init)
{
	return 0;
}

/**
 * smart_antenna_deinit() - deinitialize the module.
 *  @notify: whether to indicate the SMART ANTENNA kernel module.
 *    0: No; 1: Indicate.
 *
 * return: 0 for success.
 */
static __inline__
int smart_antenna_deinit(int notify)
{
	return 0;
}

/**
 * smart_antenna_node_connected() - indicate a node connection envent
 *  to SMART Antenna module.
 * @node: node info.
 *
 */
static __inline__
void smart_antenna_node_connected(struct sa_node_info *node)
{
}

/**
 * smart_antenna_node_disconnected() - indicate a node disconnection envent
 *  to SMART Antenna module.
 * @mac_addr: node MAC address.
 *
 */
static __inline__
void smart_antenna_node_disconnected(tSirMacAddr mac_addr)
{
}

/**
 * smart_antenna_update_tx_stats() - update TX stats for a peer to
 *  Smart Antenna module.
 * @mac_addr: MAC address for the peer.
 * @Tx_feedback: TX stats.
 *
 */
static __inline__
void smart_antenna_update_tx_stats(tSirMacAddr mac_addr,
				   struct sa_tx_stats_feedback *tx_feedback)
{
}

/**
 * smart_antenna_update_rx_stats() - update RX stats for a peer to
 *  Smart Antenna module.
 * @mac_addr: MAC address for the peer.
 * @rx_feedback: RX stats.
 *
 */
static __inline__
void smart_antenna_update_rx_stats(tSirMacAddr mac_addr,
				   struct sa_rx_stats_feedback *rx_feedback)
{
}

/**
 * smart_antenna_update_int_stats() - undate interference stats for a peer to
 *  smart antenna module.
 * @mac_addr: MAC address for the peer.
 * @int_feedback: interference stats.
 *
 */
static __inline__
void smart_antenna_update_int_stats(tSirMacAddr mac_addr,
				    struct sa_int_stats_feedback *int_feedback)
{
}

static __inline__ void smart_antenna_attach(void)
{
}

static __inline void smart_antenna_deattach(void)
{
}
#endif
#endif
