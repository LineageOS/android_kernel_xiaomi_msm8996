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
 * DOC: contains smart antenna core functions.
 */
#include "smart_ant.h"
#include "if_smart_antenna.h"

struct smart_ant g_smart_ant_handle;

/**
 * __smart_ant_init() - Smart antenna module Initialization.
 * @sa: smart antenna handle
 * @new_init: flag for the STA started.
 *
 */
static int __smart_ant_init(struct smart_ant *sa, bool new_init)
{
	int ret = 0;
	struct smartantenna_ops *sa_ops;
	struct sa_config sa_init_config = {0, };

	if (sa == NULL) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna handle is NULL.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	if (new_init)
		sa->smart_ant_state |= SMART_ANT_STATE_AP_STARTED;

	if (!(sa->smart_ant_state & SMART_ANT_STATE_CB_REGISTERED)) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna state(%d) is not right.",
			   __func__, sa->smart_ant_state);
		return SMART_ANT_STATUS_FAILURE;
	}

	sa_ops = sa->sa_callbacks;
	if (sa_ops == NULL || sa_ops->sa_init == NULL) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart Antenna functions are not registered !!! \n",
			   __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	if (sa->smart_ant_state & SMART_ANT_STATE_AP_STARTED) {
		sa_init_config.channel_num = sa->curchan;
		ret = sa_ops->sa_init(&sa_init_config, true);
		if (ret < 0) {
			SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
				   "%s: Failed to initialize Smart Antenna \n",
				   __func__);
			return SMART_ANT_STATUS_FAILURE;
		}

		adf_os_atomic_inc(&sa->sa_init);
		sa->smart_ant_enabled = true;
		sa->smart_ant_state |= SMART_ANT_STATE_INIT_DONE;
		SA_DPRINTK(sa, SMART_ANTENNA_DEBUG,
			   "%s: SMART ANTENNA initialized.", __func__);
	}

	return SMART_ANT_STATUS_SUCCESS;
}

/**
 * __smart_ant_deinit() - Smart antenna module Deinitialization.
 * @sa: smart antenna handle
 *
 */
static int __smart_ant_deinit(struct smart_ant *sa)
{
	struct smartantenna_ops *sa_ops;

	if (sa == NULL) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna handle is NULL.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}
	sa->smart_ant_state &= ~SMART_ANT_STATE_AP_STARTED;
	sa_ops = sa->sa_callbacks;

	if (!(sa->smart_ant_state & SMART_ANT_STATE_INIT_DONE)) {
		SA_DPRINTK(sa, SMART_ANTENNA_DEBUG,
			   "%s: Smart Antenna deinit is already done !\n",
			   __func__);
		return 0;
	}

	adf_os_atomic_dec(&sa->sa_init);
	if (sa_ops && sa_ops->sa_deinit)
		sa_ops->sa_deinit(SMART_ANT_DEFAULT_ID);
	sa->smart_ant_enabled = false;
	sa->smart_ant_state &= ~SMART_ANT_STATE_INIT_DONE;
	SA_DPRINTK(sa, SMART_ANTENNA_INFO,
		   "%s: Smart Antenna deinit is done !\n", __func__);
	return SMART_ANT_STATUS_SUCCESS;
}

/**
 * sa_get_node() - Get one node from the node list and increase the ref count
 * @sa: smart antenna handle
 * @mac_addr: Node mac address
 * @inc: true, increase the ref count; flase, not to increase the ref count
 *
 * Return: Node pointer once it is found in the list, otherwise NULL
 */
static struct sa_node * sa_get_node(struct smart_ant *sa,
				    uint8_t *mac_addr,
				    bool inc)
{
	struct sa_node *node, *tmp_node;

	if (!sa || !mac_addr)
		return NULL;

	adf_os_spin_lock(&sa->sa_lock);
	TAILQ_FOREACH_SAFE(node, &sa->node_list, sa_elm, tmp_node) {
		adf_os_spin_unlock(&sa->sa_lock);
		if (vos_mem_compare(node->node_info.mac_addr, mac_addr, 6)) {
			SA_DPRINTK(sa, SMART_ANTENNA_DEBUG,
				   "%s: Node found "MAC_ADDRESS_STR,
				   __func__, MAC_ADDR_ARRAY(mac_addr));
			if (inc == true)
				adf_os_atomic_inc(&node->ref_count);
			return node;
		}
		adf_os_spin_lock(&sa->sa_lock);
	}
	adf_os_spin_unlock(&sa->sa_lock);
	return NULL;
}

/**
 * sa_put_node() - Decrease the node refcount and release the node once the
 *   count is less than 0.
 * @sa: smart antenna handle
 * @node: node to be released
 *
 */
static void sa_put_node(struct smart_ant *sa, struct sa_node *node)
{
	if (!sa || !node)
		return;

	if (adf_os_atomic_dec_and_test(&node->ref_count)) {
		SA_DPRINTK(sa, SMART_ANTENNA_DEBUG,
			   "%s: Node "MAC_ADDRESS_STR" is released",
			   __func__, MAC_ADDR_ARRAY(node->node_info.mac_addr));
		adf_os_spin_lock(&sa->sa_lock);
		TAILQ_REMOVE(&sa->node_list, node, sa_elm);
		adf_os_spin_unlock(&sa->sa_lock);
		vos_mem_free(node);
	}
}

/**
 * __smart_ant_node_connect() - handler for new node connected
 * @sa: smart antenna handle
 * @node_info: information for the connected node
 *
 */
static void __smart_ant_node_connect(struct smart_ant *sa,
				     struct sa_node_info *node_info)
{
	void *node_ccp;
	struct smartantenna_ops *sa_ops;
	struct sa_node *new_node, *old_node, *tmp_node;

	if (sa == NULL) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna handle is NULL.", __func__);
		return;
	}

	if (!SMART_ANT_STATE_OK(sa->smart_ant_state)) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna state(%d) is not right.",
			   __func__, sa->smart_ant_state);
		return;
	}
	sa_ops = sa->sa_callbacks;

	new_node = vos_mem_malloc(sizeof(new_node));
	if (!new_node) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Failed to alloc buffer for node info.",
			   __func__);
		goto error;
	}
	vos_mem_zero(new_node, sizeof(new_node));

	SA_DPRINTK(sa, SMART_ANTENNA_INFO,
		   "%s: Node(%pk) MAC address is "MAC_ADDRESS_STR" current channel is %d, stream number is %d, ode capability is 0x%x, supports %d lagecy rate %d HT rate",
		   __func__, new_node,
		   MAC_ADDR_ARRAY(node_info->mac_addr), node_info->channel_num,
		   node_info->nss, node_info->node_caps,
		   node_info->rate_cap.ratecount[0],
		   node_info->rate_cap.ratecount[1]);

	adf_os_atomic_init(&new_node->ref_count);
	vos_mem_copy(new_node->node_info.mac_addr, node_info->mac_addr, 6);
	new_node->node_info.channel_num = node_info->channel_num;
	new_node->node_info.nss = node_info->nss;
	new_node->node_info.rate_cap.ratecount[RATE_INDEX_CCK_OFDM] =
			node_info->rate_cap.ratecount[RATE_INDEX_CCK_OFDM];
	vos_mem_copy(new_node->node_info.rate_cap.ratecode_legacy,
		     node_info->rate_cap.ratecode_legacy,
		     node_info->rate_cap.ratecount[RATE_INDEX_CCK_OFDM]);
	new_node->node_info.rate_cap.ratecount[RATE_INDEX_MCS] =
			node_info->rate_cap.ratecount[RATE_INDEX_MCS];
	vos_mem_copy(new_node->node_info.rate_cap.mcs,
		     node_info->rate_cap.mcs,
		     node_info->rate_cap.ratecount[RATE_INDEX_MCS]);

	if (sa_ops && sa_ops->sa_node_connect)
		sa_ops->sa_node_connect(&node_ccp, &new_node->node_info);
	new_node->node_ccp = node_ccp;

	/* insert the SA node to list */
	adf_os_spin_lock(&sa->sa_lock);
	TAILQ_FOREACH_SAFE(old_node, &sa->node_list, sa_elm, tmp_node) {
		adf_os_spin_unlock(&sa->sa_lock);
		if (vos_mem_compare(old_node->node_info.mac_addr,
					node_info->mac_addr, 6)) {
			SA_DPRINTK(sa, SMART_ANTENNA_DEBUG,
				   "%s: Node already exists in the connected list.",
				   __func__);
			old_node->node_ccp = node_ccp;
			goto error;
		}
		adf_os_spin_lock(&sa->sa_lock);
	}
	adf_os_atomic_set(&new_node->ref_count, 1);
	TAILQ_INSERT_TAIL(&sa->node_list, new_node, sa_elm);
	adf_os_spin_unlock(&sa->sa_lock);

	return;
error:
	if (new_node)
		vos_mem_free(new_node);
}

/**
 * __smart_ant_node_disconnect() - Called when a node disconnected from the BSS.
 * @sa: smart antenna handle
 * @mac_addr: MAC address of the node.
 *
 */
static void __smart_ant_node_disconnect(struct smart_ant *sa, uint8_t *mac_addr)
{
	struct sa_node *node;
	struct smartantenna_ops *sa_ops;

	if (sa == NULL) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna handle is NULL.", __func__);
		return;
	}

	if (!SMART_ANT_STATE_OK(sa->smart_ant_state)) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna state(%d) is not right.",
			   __func__, sa->smart_ant_state);
		return;
	}
	sa_ops = sa->sa_callbacks;

	SA_DPRINTK(sa, SMART_ANTENNA_INFO,
		   "%s: Node "MAC_ADDRESS_STR" disconnected.",
		   __func__, MAC_ADDR_ARRAY(mac_addr));

	/*  Do not increase node ref count, so it will be deleate */
	node = sa_get_node(sa, mac_addr, false);
	if (node) {
		SA_DPRINTK(sa, SMART_ANTENNA_DEBUG,
		   "%s: Node(%pk) found in the connected list. "MAC_ADDRESS_STR,
		   __func__, node, MAC_ADDR_ARRAY(node->node_info.mac_addr));
		sa_put_node(sa, node);
	} else {
		SA_DPRINTK(sa, SMART_ANTENNA_ERROR,
			   "%s: Node not in list.", __func__);
	}
}

/**
 * __smart_ant_update_txfeedback() - TX stats feedback when TX completed.
 * @sa: smart antenna handle
 * @mac_addr: MAC address of the node
 * @tx_feedback: TX stats
 *
 * Return: 0 for success
 */
static int __smart_ant_update_txfeedback(struct smart_ant *sa,
				uint8_t *mac_addr,
				struct sa_tx_stats_feedback *tx_feedback)
{
	uint8_t status;
	struct sa_node *node;
	struct smartantenna_ops *sa_ops;

	if (sa == NULL) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna handle is NULL.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	if (!SMART_ANT_STATE_OK(sa->smart_ant_state)) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna state(%d) is not right.",
			   __func__, sa->smart_ant_state);
		return SMART_ANT_STATUS_FAILURE;
	}
	sa_ops = sa->sa_callbacks;

	SA_DPRINTK(sa, SMART_ANTENNA_INFO,
		   "%s: Feedback from "MAC_ADDRESS_STR,
		   __func__, MAC_ADDR_ARRAY(mac_addr));

	/* Find the node context */
	node = sa_get_node(sa, mac_addr, true);
	if (node) {
		if (sa_ops && sa_ops->sa_update_txfeedback)
			sa_ops->sa_update_txfeedback(node->node_ccp,
						     tx_feedback,
						     &status);
		sa_put_node(sa, node);
		return SMART_ANT_STATUS_SUCCESS;
	} else {
		SA_DPRINTK(sa, SMART_ANTENNA_ERROR,
			   "%s: Node not found in the connected list.",
			   __func__);
		return SMART_ANT_STATUS_FAILURE;
	}
}

/**
 * __smart_ant_update_rxfeedback() - RX stats feedback
 * @sa: smart antenna handle
 * @mac_addr: MAC address of the node
 * @rx_feedback: TX stats
 *
 * Return: 0 for success
 */
static int
__smart_ant_update_rxfeedback(struct smart_ant *sa,
			      uint8_t *mac_addr,
			      struct sa_rx_stats_feedback *rx_feedback)
{
	uint8_t status;
	struct sa_node *node;
	struct smartantenna_ops *sa_ops;

	if (sa == NULL) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna handle is NULL.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	if (!mac_addr) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Mac ADDRESS is NULL.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	if (!SMART_ANT_STATE_OK(sa->smart_ant_state)) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna state(%d) is not right.",
			   __func__, sa->smart_ant_state);
		return SMART_ANT_STATUS_FAILURE;
	}
	sa_ops = sa->sa_callbacks;

	SA_DPRINTK(sa, SMART_ANTENNA_DEBUG,
		   "%s: Rx feedback from Peer "MAC_ADDRESS_STR,
		   __func__, MAC_ADDR_ARRAY(mac_addr));

	/* Find the node context */
	node = sa_get_node(sa, mac_addr, true);

	if (node) {
		if (sa_ops && sa_ops->sa_update_rxfeedback)
			sa_ops->sa_update_rxfeedback(node->node_ccp,
						     rx_feedback,
						     &status);
		sa_put_node(sa, node);
		return SMART_ANT_STATUS_SUCCESS;
	} else {
		SA_DPRINTK(sa, SMART_ANTENNA_ERROR,
			   "%s: Node not found in the connected list.",
			   __func__);
		return SMART_ANT_STATUS_FAILURE;
	}
}

/**
 * __smart_ant_update_intfeedback() - Interference stats feedback
 * @sa: smart antenna handle
 * @mac_addr: MAC address of the node
 * @int_feedback: interference stats
 *
 * Return: 0 for success
 */
static int
__smart_ant_update_intfeedback(struct smart_ant *sa,
			       uint8_t *mac_addr,
			       struct sa_int_stats_feedback *int_feedback)
{
	uint8_t status;
	struct sa_node *node;
	struct smartantenna_ops *sa_ops;

	if (sa == NULL) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna handle is NULL.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	if (!SMART_ANT_STATE_OK(sa->smart_ant_state)) {
		SA_DPRINTK(sa, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna state(%d) is not right.",
			   __func__, sa->smart_ant_state);
		return SMART_ANT_STATUS_FAILURE;
	}
	sa_ops = sa->sa_callbacks;

	/* Find the node context */
	node = sa_get_node(sa, mac_addr, true);
	if (node) {
		if (sa_ops && sa_ops->sa_update_intfeedback)
			sa_ops->sa_update_intfeedback(node->node_ccp,
						      int_feedback,
						      &status);
		sa_put_node(sa, node);
		return SMART_ANT_STATUS_SUCCESS;
	} else {
		SA_DPRINTK(sa, SMART_ANTENNA_ERROR,
		   "%s: Node not found in the connected list.",
		   __func__);
		   return SMART_ANT_STATUS_FAILURE;
	}
}

/**
 * __smart_ant_get_config() - Get smart antenna config
 * @sa: smart antenna handle
 *
 * return: 0 for success.
 */
static int __smart_ant_get_config(struct smart_ant *sa)
{
	return SMART_ANT_STATUS_SUCCESS;
}

/**
 * sa_get_handle() - Get smart antenna handle
 *
 * Return: Smart Antenna handle.
 */
struct smart_ant *sa_get_handle(void)
{
	if (g_smart_ant_handle.smart_ant_state & SMART_ANT_STATE_ATTACHED) {
		return &g_smart_ant_handle;
	} else {
		SA_DPRINTK((struct smart_ant *)NULL, SMART_ANTENNA_DEBUG,
			   "%s: Smart Antenna Module is attached.", __func__);
		return NULL;
	}
}

/**
 * sa_get_ops() - Get smart antenna core operations
 *
 * Return: Smart Antenna core operations.
 */
struct sa_ops *sa_get_ops(void)
{
	return &g_smart_ant_handle.sap_ops;
}

/**
 * smart_antenna_attach() - Attach smart antenna module
 *
 */
void smart_antenna_attach(void)
{
	SA_DPRINTK((struct smart_ant *)NULL, SMART_ANTENNA_DEBUG,
		   "%s: Smart Antenna Module is attached.", __func__);
	vos_mem_zero(&g_smart_ant_handle, sizeof(struct smart_ant));
	g_smart_ant_handle.sa_debug_mask = SMART_ANTENNA_DEFAULT_LEVEL;
	g_smart_ant_handle.smart_ant_enabled = false;
	g_smart_ant_handle.smart_ant_state |= SMART_ANT_STATE_ATTACHED;
	g_smart_ant_handle.curchan = SMART_ANT_UNSUPPORTED_CHANNEL;
	g_smart_ant_handle.sap_ops.sa_init = __smart_ant_init;
	g_smart_ant_handle.sap_ops.sa_deinit = __smart_ant_deinit;
	g_smart_ant_handle.sap_ops.sa_node_connect = __smart_ant_node_connect;
	g_smart_ant_handle.sap_ops.sa_node_disconnect =
					__smart_ant_node_disconnect;
	g_smart_ant_handle.sap_ops.sa_update_txfeedback =
					__smart_ant_update_txfeedback;
	g_smart_ant_handle.sap_ops.sa_update_rxfeedback =
					__smart_ant_update_rxfeedback;
	g_smart_ant_handle.sap_ops.sa_update_intfeedback =
					__smart_ant_update_intfeedback;
	g_smart_ant_handle.sap_ops.sa_get_config =
					__smart_ant_get_config;
	TAILQ_INIT(&g_smart_ant_handle.node_list);
	adf_os_spinlock_init(&g_smart_ant_handle.sa_lock);
}

/**
 * smart_antenna_deattach() - Deattach smart antenna module
 *
 */
void smart_antenna_deattach(void)
{
	SA_DPRINTK((struct smart_ant *)NULL, SMART_ANTENNA_DEBUG,
		   "%s: Smart Antenna Module is deattached.", __func__);
	g_smart_ant_handle.smart_ant_state &= ~SMART_ANT_STATE_ATTACHED;
	adf_os_spinlock_destroy(&g_smart_ant_handle.sa_lock);
}
