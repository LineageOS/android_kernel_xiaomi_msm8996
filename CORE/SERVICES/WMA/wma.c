/*
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
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
 * This file was originally distributed by Qualcomm Atheros, Inc.
 * under proprietary terms before Copyright ownership was assigned
 * to the Linux Foundation.
 */

/**========================================================================

  \file     wma.c
  \brief    Implementation of WMA

  ========================================================================*/
/**=========================================================================
  EDIT HISTORY FOR FILE


  This section contains comments describing changes made to the module.
  Notice that changes are listed in reverse chronological order.

  $Header:$   $DateTime: $ $Author: $


  when              who           what, where, why
  --------          ---           -----------------------------------------
  12/03/2013        Ganesh        Implementation of WMA APIs.
                    Kondabattini
  27/03/2013        Ganesh        Rx Management Support added
                    Babu
  ==========================================================================*/

/* ################ Header files ################ */
#include "wma.h"
#include "wma_api.h"
#include "vos_api.h"
#include "wmi_unified_api.h"
#include "wlan_qct_sys.h"
#include "wniApi.h"
#include "aniGlobal.h"
#include "wmi_unified.h"
#include "wniCfgAp.h"
#include "wlan_hal_cfg.h"
#include "cfgApi.h"
#include "ol_txrx_ctrl_api.h"
#if defined(CONFIG_HL_SUPPORT)
#include "wlan_tgt_def_config_hl.h"
#else
#include "wlan_tgt_def_config.h"
#endif

#include "adf_nbuf.h"
#include "adf_os_types.h"
#include "ol_txrx_api.h"
#include "vos_memory.h"
#include "ol_txrx_types.h"
#include "ol_txrx_peer_find.h"

#include "wlan_qct_wda.h"
#include "wlan_qct_wda_msg.h"
#include "limApi.h"

#include "wdi_out.h"
#include "wdi_in.h"

#include "vos_utils.h"
#include "tl_shim.h"
#if defined(QCA_WIFI_FTM) && !defined(QCA_WIFI_ISOC)
#include "testmode.h"
#endif


#if !defined(REMOVE_PKT_LOG) && !defined(QCA_WIFI_ISOC)
#include "pktlog_ac.h"
#endif

#include "dbglog_host.h"
/* FIXME: Inclusion of .c looks odd but this is how it is in internal codebase */
#include "wmi_version_whitelist.c"

/* ################### defines ################### */
#define WMA_2_4_GHZ_MAX_FREQ  3000

#define WMA_DEFAULT_SCAN_PRIORITY            1
#define WMA_DEFAULT_SCAN_REQUESTER_ID        1
/* default value */
#define DEFAULT_INFRA_STA_KEEP_ALIVE_PERIOD  20
#define DEFAULT_MAX_IDLETIME 20
/*There is no standard way of caluclating minimum inactive
 *timer and max unresposive timer from max inactive timer
 *the below expression are taken from qca_main code
 */

/*REFEFERENCE_TIME refers to the time that we need to wait for ack
 *after sending an keepalive frame.
 */
#define REFERENCE_TIME  5
/*The minimum amount of time AP begins to consider STA inactive*/
#define MIN_IDLE_INACTIVE_TIME_SECS(val)   ((val - REFERENCE_TIME)/2)
/* Once a STA exceeds the maximum unresponsive time, the AP will send a
 * WMI_STA_KICKOUT event to the host so the STA can be deleted.
 */
#define MAX_UNRESPONSIVE_TIME_SECS(val)   (val + REFERENCE_TIME)

#define AGC_DUMP  1
#define CHAN_DUMP 2
#define WD_DUMP   3

static void wma_send_msg(tp_wma_handle wma_handle, u_int16_t msg_type,
			 void *body_ptr, u_int32_t body_val);

static tANI_U32 gFwWlanFeatCaps;

#if defined(QCA_WIFI_FTM) && !defined(QCA_WIFI_ISOC)
void wma_utf_attach(tp_wma_handle wma_handle);
void wma_utf_detach(tp_wma_handle wma_handle);
static VOS_STATUS
wma_process_ftm_command(tp_wma_handle wma_handle,
			struct ar6k_testmode_cmd_data *msg_buffer);
#endif
static void *wma_find_vdev_by_addr(tp_wma_handle wma, u_int8_t *addr,
				   u_int8_t *vdev_id)
{
	u_int8_t i;

	for (i = 0; i < wma->max_bssid; i++) {
		if (vos_is_macaddr_equal(
			(v_MACADDR_t *) wma->interfaces[i].addr,
			(v_MACADDR_t *) addr) == VOS_TRUE) {
			*vdev_id = i;
			return wma->interfaces[i].handle;
		}
	}
	return NULL;
}

/*
 * 802.11n D2.0 defined values for "Minimum MPDU Start Spacing":
 *   0 for no restriction
 *   1 for 1/4 us - Our lower layer calculations limit our precision to 1 msec
 *   2 for 1/2 us - Our lower layer calculations limit our precision to 1 msec
 *   3 for 1 us
 *   4 for 2 us
 *   5 for 4 us
 *   6 for 8 us
 *   7 for 16 us
 */
static const u_int8_t wma_mpdu_spacing[] = {0, 1, 1, 1, 2, 4, 8, 16};

static inline uint8_t wma_parse_mpdudensity(u_int8_t mpdudensity)
{
	if (mpdudensity < sizeof(wma_mpdu_spacing))
		return wma_mpdu_spacing[mpdudensity];
	else
		return 0;
}

/* Function   : wma_find_vdev_by_id
 * Descriptin : Returns vdev handle for given vdev id.
 * Args       : @wma - wma handle, @vdev_id - vdev ID
 * Returns    : Returns vdev handle if given vdev id is valid.
 *              Otherwise returns NULL.
 */
static inline void *wma_find_vdev_by_id(tp_wma_handle wma, u_int8_t vdev_id)
{
	if (vdev_id > wma->max_bssid)
		return NULL;

	return wma->interfaces[vdev_id].handle;
}

/* Function    : wma_get_vdev_count
 * Discription : Returns number of active vdev.
 * Args        : @wma - wma handle
 * Returns     : Returns valid vdev count.
 */
static inline u_int8_t wma_get_vdev_count(tp_wma_handle wma)
{
	u_int8_t vdev_count = 0, i;

	for (i = 0; i < wma->max_bssid; i++) {
		if (wma->interfaces[i].handle)
			vdev_count++;
	}
	return vdev_count;
}

/* Function   : wma_is_vdev_in_ap_mode
 * Descriptin : Helper function to know whether given vdev id
 *              is in AP mode or not.
 * Args       : @wma - wma handle, @ vdev_id - vdev ID.
 * Returns    : True -  if given vdev id is in AP mode.
 *              False - if given vdev id is not in AP mode.
 */
static bool wma_is_vdev_in_ap_mode(tp_wma_handle wma, u_int8_t vdev_id)
{
	struct wma_txrx_node *intf = wma->interfaces;

	if (vdev_id > wma->max_bssid) {
		WMA_LOGP("%s: Invalid vdev_id %hu", __func__, vdev_id);
		VOS_ASSERT(0);
		return false;
	}

	if ((intf[vdev_id].type == WMI_VDEV_TYPE_AP) &&
		((intf[vdev_id].sub_type == WMI_UNIFIED_VDEV_SUBTYPE_P2P_GO) ||
		 (intf[vdev_id].sub_type == 0)))
		return true;

	return false;
}

/*
 * Function     : wma_find_bssid_by_vdev_id
 * Description  : Get the BSS ID corresponding to the vdev ID
 * Args         : @wma - wma handle, @vdev_id - vdev ID
 * Returns      : Returns pointer to bssid on success,
 *                otherwise returns NULL.
 */
static inline u_int8_t *wma_find_bssid_by_vdev_id(tp_wma_handle wma,
						  u_int8_t vdev_id)
{
	if (vdev_id >= wma->max_bssid)
		return NULL;

	return wma->interfaces[vdev_id].bssid;
}

/*
 * Function	: wma_find_vdev_by_bssid
 * Description	: Get the VDEV ID corresponding from BSS ID
 * Args		: @wma - wma handle, @vdev_id - vdev ID
 * Returns	: Returns pointer to bssid on success,
 *                otherwise returns NULL.
 */
static void *wma_find_vdev_by_bssid(tp_wma_handle wma, u_int8_t *bssid,
				    u_int8_t *vdev_id)
{
	int i;

	for (i = 0; i < wma->max_bssid; i++) {
		if (vos_is_macaddr_equal(
			(v_MACADDR_t *)wma->interfaces[i].bssid,
			(v_MACADDR_t *)bssid) == VOS_TRUE) {
			*vdev_id = i;
			return wma->interfaces[i].handle;
		}
	}

	return NULL;
}

#ifdef BIG_ENDIAN_HOST

/* ############# function definitions ############ */

/* function   : wma_swap_bytes
 * Descriptin :
 * Args       :
 * Retruns    :
 */
v_VOID_t wma_swap_bytes(v_VOID_t *pv, v_SIZE_t n)
{
	v_SINT_t no_words;
	v_SINT_t i;
	v_U32_t *word_ptr;

	no_words =   n/sizeof(v_U32_t);
	word_ptr = (v_U32_t *)pv;
	for (i=0; i<no_words; i++) {
		*(word_ptr + i) = __cpu_to_le32(*(word_ptr + i));
	}
}
#define SWAPME(x, len) wma_swap_bytes(&x, len);
#endif

static struct wma_target_req *wma_find_vdev_req(tp_wma_handle wma,
						u_int8_t vdev_id,
						u_int8_t type)
{
	struct wma_target_req *req_msg = NULL, *tmp;
	bool found = false;

	adf_os_spin_lock_bh(&wma->vdev_respq_lock);
	list_for_each_entry_safe(req_msg, tmp,
				 &wma->vdev_resp_queue, node) {
		if (req_msg->vdev_id != vdev_id)
			continue;
		if (req_msg->type != type)
			continue;

		found = true;
		list_del(&req_msg->node);
		break;
	}
	adf_os_spin_unlock_bh(&wma->vdev_respq_lock);
	if (!found) {
		WMA_LOGD("%s: target request not found for vdev_id %d type %d\n",
			 __func__, vdev_id, type);
		return NULL;
	}
	WMA_LOGD("%s: target request found for vdev id: %d type %d msg %d\n",
		 __func__, vdev_id, type, req_msg->msg_type);
	return req_msg;
}

static void wma_vdev_start_rsp(tp_wma_handle wma,
			tpAddBssParams add_bss,
			wmi_vdev_start_response_event_fixed_param *resp_event)
{
#ifndef QCA_WIFI_ISOC
	struct beacon_info *bcn;
#endif
	if (resp_event->status) {
		add_bss->status = VOS_STATUS_E_FAILURE;
		goto send_fail_resp;
	}
#ifndef QCA_WIFI_ISOC
	if (add_bss->operMode == BSS_OPERATIONAL_MODE_AP) {
	wma->interfaces[resp_event->vdev_id].beacon =
				vos_mem_malloc(sizeof(struct beacon_info));

	bcn = wma->interfaces[resp_event->vdev_id].beacon;
	if (!bcn) {
		WMA_LOGE("%s: Failed alloc memory for beacon struct\n");
		add_bss->status = VOS_STATUS_E_FAILURE;
		goto send_fail_resp;
	}
	bcn->buf = adf_nbuf_alloc(NULL, WMA_BCN_BUF_MAX_SIZE, 0,
				  sizeof(u_int32_t), 0);
	if (!bcn->buf) {
		WMA_LOGE("%s: No memory allocated for beacon buffer\n",
			  __func__);
		vos_mem_free(bcn);
		add_bss->status = VOS_STATUS_E_FAILURE;
		goto send_fail_resp;
	}
	bcn->len = 0;
	bcn->dtim_count = 0;
	bcn->dma_mapped = 0;
	bcn->seq_no = MIN_SW_SEQ;
	adf_os_spinlock_init(&bcn->lock);

	WMA_LOGD("%s: Allocated beacon struct %p, template memory %p\n",
		__func__, bcn, bcn->buf);
	}
#endif
	add_bss->status = VOS_STATUS_SUCCESS;
	add_bss->bssIdx = resp_event->vdev_id;
send_fail_resp:
	WMA_LOGD("%s: Sending add bss rsp to umac(vdev %d status %d)\n",
		 __func__, resp_event->vdev_id, add_bss->status);
	wma_send_msg(wma, WDA_ADD_BSS_RSP, (void *)add_bss, 0);
}

static int wma_vdev_start_resp_handler(void *handle, u_int8_t *cmd_param_info,
				       u_int32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	struct wma_target_req *req_msg;
	WMI_VDEV_START_RESP_EVENTID_param_tlvs *param_buf;
	wmi_vdev_start_response_event_fixed_param *resp_event;

	param_buf = (WMI_VDEV_START_RESP_EVENTID_param_tlvs *) cmd_param_info;
	if (!param_buf) {
		WMA_LOGE("Invalid start response event buffer");
		return -EINVAL;
	}

	resp_event = param_buf->fixed_param;
	req_msg = wma_find_vdev_req(wma, resp_event->vdev_id,
				    WMA_TARGET_REQ_TYPE_VDEV_START);
	if (!req_msg) {
		WMA_LOGP("%s: Failed to lookup request message for vdev %d\n",
			 __func__, resp_event->vdev_id);
		return -EINVAL;
	}
	vos_timer_stop(&req_msg->event_timeout);
	if (req_msg->msg_type == WDA_CHNL_SWITCH_REQ) {
		tpSwitchChannelParams params =
			(tpSwitchChannelParams) req_msg->user_data;
		WMA_LOGD("%s: Send channel switch resp vdev %d status %d\n",
			 __func__, resp_event->vdev_id, resp_event->status);
		params->status = resp_event->status;
		wma_send_msg(wma, WDA_SWITCH_CHANNEL_RSP, (void *)params, 0);
	} else if (req_msg->msg_type == WDA_ADD_BSS_REQ) {
		tpAddBssParams bssParams = (tpAddBssParams) req_msg->user_data;
		wma_vdev_start_rsp(wma, bssParams, resp_event);
	}
	vos_timer_destroy(&req_msg->event_timeout);
	vos_mem_free(req_msg);

	return 0;
}

/* function   : wma_unified_debug_print_event_handler
 * Descriptin :
 * Args       :
 * Returns    :
 */
static int wma_unified_debug_print_event_handler(void *handle, u_int8_t *datap,
						 u_int32_t len)
{
	WMI_DEBUG_PRINT_EVENTID_param_tlvs *param_buf;
	u_int8_t *data;
	u_int32_t datalen;

	param_buf = (WMI_DEBUG_PRINT_EVENTID_param_tlvs *)datap;
	if (!param_buf) {
		WMA_LOGE("Get NULL point message from FW");
		return -ENOMEM;
	}
	data = param_buf->data;
	datalen = param_buf->num_data;

#ifdef BIG_ENDIAN_HOST
    {
	    char dbgbuf[500] = {0};
	    memcpy(dbgbuf, data, datalen);
	    SWAPME(dbgbuf, datalen);
	    WMA_LOGD("FIRMWARE:%s", dbgbuf);
	    return 0;
    }
#else
	WMA_LOGD("FIRMWARE:%s", data);
    return 0;
#endif
}

static int
wmi_unified_vdev_set_param_send(wmi_unified_t wmi_handle, u_int32_t if_id,
				u_int32_t param_id, u_int32_t param_value)
{
	int ret;
	wmi_vdev_set_param_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	u_int16_t len = sizeof(*cmd);

	buf = wmi_buf_alloc(wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s:wmi_buf_alloc failed", __func__);
		return -ENOMEM;
	}
	cmd = (wmi_vdev_set_param_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_vdev_set_param_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_vdev_set_param_cmd_fixed_param));
	cmd->vdev_id = if_id;
	cmd->param_id = param_id;
	cmd->param_value = param_value;
	WMA_LOGD("Setting vdev %d param = %x, value = %u",
				if_id, param_id, param_value);
	ret = wmi_unified_cmd_send(wmi_handle, buf, len,
					WMI_VDEV_SET_PARAM_CMDID);
	if (ret < 0) {
		WMA_LOGE("Failed to send set param command ret = %d", ret);
		wmi_buf_free(buf);
	}
	return ret;
}

static v_VOID_t wma_set_default_tgt_config(tp_wma_handle wma_handle)
{
	wmi_resource_config tgt_cfg = {
		0, /* Filling zero for TLV Tag and Length fields */
		CFG_TGT_NUM_VDEV,
		CFG_TGT_NUM_PEERS + CFG_TGT_NUM_VDEV, /* reserve an additional peer for each VDEV */
		CFG_TGT_NUM_OFFLOAD_PEERS,
		CFG_TGT_NUM_OFFLOAD_REORDER_BUFFS,
		CFG_TGT_NUM_PEER_KEYS,
		CFG_TGT_NUM_TIDS,
		CFG_TGT_AST_SKID_LIMIT,
		CFG_TGT_DEFAULT_TX_CHAIN_MASK,
		CFG_TGT_DEFAULT_RX_CHAIN_MASK,
		{ CFG_TGT_RX_TIMEOUT_LO_PRI, CFG_TGT_RX_TIMEOUT_LO_PRI, CFG_TGT_RX_TIMEOUT_LO_PRI, CFG_TGT_RX_TIMEOUT_HI_PRI },
		CFG_TGT_RX_DECAP_MODE,
		CFG_TGT_DEFAULT_SCAN_MAX_REQS,
		CFG_TGT_DEFAULT_BMISS_OFFLOAD_MAX_VDEV,
		CFG_TGT_DEFAULT_ROAM_OFFLOAD_MAX_VDEV,
		CFG_TGT_DEFAULT_ROAM_OFFLOAD_MAX_PROFILES,
		CFG_TGT_DEFAULT_NUM_MCAST_GROUPS,
		CFG_TGT_DEFAULT_NUM_MCAST_TABLE_ELEMS,
		CFG_TGT_DEFAULT_MCAST2UCAST_MODE,
		CFG_TGT_DEFAULT_TX_DBG_LOG_SIZE,
		CFG_TGT_WDS_ENTRIES,
		CFG_TGT_DEFAULT_DMA_BURST_SIZE,
		CFG_TGT_DEFAULT_MAC_AGGR_DELIM,
		CFG_TGT_DEFAULT_RX_SKIP_DEFRAG_TIMEOUT_DUP_DETECTION_CHECK,
		CFG_TGT_DEFAULT_VOW_CONFIG,
		CFG_TGT_DEFAULT_GTK_OFFLOAD_MAX_VDEV,
		CFG_TGT_NUM_MSDU_DESC,
		CFG_TGT_MAX_FRAG_TABLE_ENTRIES,
	};

	WMITLV_SET_HDR(&tgt_cfg.tlv_header,WMITLV_TAG_STRUC_wmi_resource_config,
		       WMITLV_GET_STRUCT_TLVLEN(wmi_resource_config));
	/* reduce the peer/vdev if CFG_TGT_NUM_MSDU_DESC exceeds 1000 */
#ifdef PERE_IP_HDR_ALIGNMENT_WAR
	if (scn->host_80211_enable) {
		/*
		 * To make the IP header begins at dword aligned address,
		 * we make the decapsulation mode as Native Wifi.
		 */
		tgt_cfg.rx_decap_mode = CFG_TGT_RX_DECAP_MODE_NWIFI;
	}
#endif
	wma_handle->wlan_resource_config = tgt_cfg;
}

static int32_t wmi_unified_peer_delete_send(wmi_unified_t wmi,
					u_int8_t peer_addr[IEEE80211_ADDR_LEN],
					u_int8_t vdev_id)
{
	wmi_peer_delete_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len = sizeof(*cmd);

	buf = wmi_buf_alloc(wmi, len);
	if (!buf) {
		WMA_LOGP("%s: wmi_buf_alloc failed\n", __func__);
		return -ENOMEM;
	}
	cmd = (wmi_peer_delete_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_peer_delete_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_peer_delete_cmd_fixed_param));
	WMI_CHAR_ARRAY_TO_MAC_ADDR(peer_addr, &cmd->peer_macaddr);
	cmd->vdev_id = vdev_id;

	if (wmi_unified_cmd_send(wmi, buf, len, WMI_PEER_DELETE_CMDID)) {
		WMA_LOGP("Failed to send peer delete command\n");
		adf_nbuf_free(buf);
		return -EIO;
	}
	WMA_LOGD("%s: peer_addr %pM vdev_id %d\n", __func__, peer_addr, vdev_id);
	return 0;
}

static int32_t wmi_unified_peer_flush_tids_send(wmi_unified_t wmi,
					    u_int8_t peer_addr
							[IEEE80211_ADDR_LEN],
					    u_int32_t peer_tid_bitmap,
					    u_int8_t vdev_id)
{
	wmi_peer_flush_tids_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len = sizeof(*cmd);

	buf = wmi_buf_alloc(wmi, len);
	if (!buf) {
		WMA_LOGP("%s: wmi_buf_alloc failed\n", __func__);
		return -ENOMEM;
	}
	cmd = (wmi_peer_flush_tids_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_peer_flush_tids_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_peer_flush_tids_cmd_fixed_param));
	WMI_CHAR_ARRAY_TO_MAC_ADDR(peer_addr, &cmd->peer_macaddr);
	cmd->peer_tid_bitmap = peer_tid_bitmap;
	cmd->vdev_id = vdev_id;

	if (wmi_unified_cmd_send(wmi, buf, len, WMI_PEER_FLUSH_TIDS_CMDID)) {
		WMA_LOGP("Failed to send flush tid command\n");
		adf_nbuf_free(buf);
		return -EIO;
	}
	WMA_LOGD("%s: peer_addr %pM vdev_id %d\n", __func__, peer_addr, vdev_id);
	return 0;
}

static void wma_remove_peer(tp_wma_handle wma, u_int8_t *bssid,
			    u_int8_t vdev_id, ol_txrx_peer_handle peer)
{
#define PEER_ALL_TID_BITMASK 0xffffffff
	u_int32_t peer_tid_bitmap = PEER_ALL_TID_BITMASK;

	if (peer)
		ol_txrx_peer_detach(peer);

	wma->peer_count--;
	WMA_LOGD("%s: bssid %pM vdevid %d peer_count %d\n", __func__,
		 bssid, vdev_id, wma->peer_count);
	/* Flush all TIDs except MGMT TID for this peer in Target */
	peer_tid_bitmap &= ~(0x1 << WMI_MGMT_TID);
	wmi_unified_peer_flush_tids_send(wma->wmi_handle, bssid,
					 peer_tid_bitmap, vdev_id);

	wmi_unified_peer_delete_send(wma->wmi_handle, bssid, vdev_id);
#undef PEER_ALL_TID_BITMASK
}

static int wma_peer_sta_kickout_event_handler(void *handle, u8 *event, u32 len)
{
	tp_wma_handle wma = (tp_wma_handle)handle;
	WMI_PEER_STA_KICKOUT_EVENTID_param_tlvs *param_buf = NULL;
	wmi_peer_sta_kickout_event_fixed_param *kickout_event = NULL;
	u_int8_t vdev_id, peer_id, macaddr[IEEE80211_ADDR_LEN];
	ol_txrx_peer_handle peer;
	ol_txrx_pdev_handle pdev;
	tpDeleteStaContext del_sta_ctx;

	WMA_LOGD("%s: Enter", __func__);
	param_buf = (WMI_PEER_STA_KICKOUT_EVENTID_param_tlvs *) event;
	kickout_event = param_buf->fixed_param;
	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);
	WMI_MAC_ADDR_TO_CHAR_ARRAY(&kickout_event->peer_macaddr, macaddr);
	peer = ol_txrx_find_peer_by_addr(pdev, macaddr, &peer_id);
	if (!peer) {
		WMA_LOGE("PEER [%pM] not found", macaddr);
		return -EINVAL;
	}

	if (tl_shim_get_vdevid(peer, &vdev_id) != VOS_STATUS_SUCCESS) {
		WMA_LOGE("Not able to find BSSID for peer [%pM]", macaddr);
		return -EINVAL;
	}

	del_sta_ctx =
		(tpDeleteStaContext)vos_mem_malloc(sizeof(tDeleteStaContext));
	if (!del_sta_ctx) {
		WMA_LOGE("VOS MEM Alloc Failed for tDeleteStaContext");
		return -EINVAL;
	}

	WMA_LOGD("%s:\nPEER:[%pM]\n BSSID:[%pM]\nINTERFACE:%d\npeer_ID:%d\n",
		 __func__, macaddr, wma->interfaces[vdev_id].addr, vdev_id,
		 peer_id);
	del_sta_ctx->staId = peer_id;
	vos_mem_copy(del_sta_ctx->addr2, macaddr, IEEE80211_ADDR_LEN);
	vos_mem_copy(del_sta_ctx->bssId, wma->interfaces[vdev_id].addr,
		     IEEE80211_ADDR_LEN);
	del_sta_ctx->reasonCode = HAL_DEL_STA_REASON_CODE_KEEP_ALIVE;
	wma_send_msg(wma, SIR_LIM_DELETE_STA_CONTEXT_IND, (void *)del_sta_ctx,
		     0);
	WMA_LOGD("%s: Exit", __func__);
	return 0;
}

static int wma_vdev_stop_resp_handler(void *handle, u_int8_t *cmd_param_info,
				      u32 len)
{
	tp_wma_handle wma = (tp_wma_handle)handle;
	struct wma_target_req *req_msg;
	WMI_VDEV_STOPPED_EVENTID_param_tlvs *param_buf;
	wmi_vdev_stopped_event_fixed_param *resp_event;
	ol_txrx_peer_handle peer;
	ol_txrx_pdev_handle pdev;
	u_int8_t peer_id;

	param_buf = (WMI_VDEV_STOPPED_EVENTID_param_tlvs *) cmd_param_info;
	if (!param_buf) {
		WMA_LOGE("Invalid event buffer");
		return -EINVAL;
	}

	resp_event = param_buf->fixed_param;
	req_msg = wma_find_vdev_req(wma, resp_event->vdev_id,
				    WMA_TARGET_REQ_TYPE_VDEV_STOP);
	if (!req_msg) {
		WMA_LOGP("%s: Failed to lookup vdev request for vdev id %d\n",
			 __func__, resp_event->vdev_id);
		return -EINVAL;
	}
	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);

	vos_timer_stop(&req_msg->event_timeout);
	if (req_msg->msg_type == WDA_DELETE_BSS_REQ) {
		tpDeleteBssParams params =
			(tpDeleteBssParams)req_msg->user_data;
#ifndef QCA_WIFI_ISOC
		struct beacon_info *bcn;
#endif
		peer = ol_txrx_find_peer_by_addr(pdev, params->bssid, &peer_id);
		if (!peer)
			WMA_LOGD("%s Failed to find peer %pM\n",
					__func__, params->bssid);
		wma_remove_peer(wma, params->bssid, resp_event->vdev_id, peer);
#ifndef QCA_WIFI_ISOC
		bcn = wma->interfaces[resp_event->vdev_id].beacon;

		if (bcn) {
			WMA_LOGD("%s: Freeing beacon struct %p, "
				 "template memory %p\n", __func__,
				 bcn, bcn->buf);
			if (bcn->dma_mapped)
				adf_nbuf_unmap_single(pdev->osdev, bcn->buf,
						      ADF_OS_DMA_TO_DEVICE);
			adf_nbuf_free(bcn->buf);
			vos_mem_free(bcn);
			wma->interfaces[resp_event->vdev_id].beacon = NULL;
		}
#endif
		params->status = VOS_STATUS_SUCCESS;
		wma_send_msg(wma, WDA_DELETE_BSS_RSP, (void *)params, 0);
	}
	vos_timer_destroy(&req_msg->event_timeout);
	vos_mem_free(req_msg);
	return 0;
}

#ifndef QCA_WIFI_ISOC
u_int8_t *wma_add_p2p_ie(u_int8_t *frm)
{
	u_int8_t wfa_oui[3] = WMA_P2P_WFA_OUI;
	struct p2p_ie *p2p_ie=(struct p2p_ie *) frm;

	p2p_ie->p2p_id = WMA_P2P_IE_ID;
	p2p_ie->p2p_oui[0] = wfa_oui[0];
	p2p_ie->p2p_oui[1] = wfa_oui[1];
	p2p_ie->p2p_oui[2] = wfa_oui[2];
	p2p_ie->p2p_oui_type = WMA_P2P_WFA_VER;
	p2p_ie->p2p_len = 4;
	return (frm + sizeof(struct p2p_ie));
}

static void wma_update_beacon_noa_ie(
		struct beacon_info *bcn,
		u_int16_t new_noa_sub_ie_len)
{
	struct p2p_ie *p2p_ie;
	u_int8_t *buf;

	/* if there is nothing to add, just return */
	if (new_noa_sub_ie_len == 0) {
		if (bcn->noa_sub_ie_len && bcn->noa_ie) {
			WMA_LOGD("%s: NoA is present in previous beacon, "
				"but not present in swba event, "
				"So Reset the NoA",
				__func__);
			/* TODO: Assuming p2p noa ie is last ie in the beacon */
			vos_mem_zero(bcn->noa_ie, (bcn->noa_sub_ie_len +
						sizeof(struct p2p_ie)) );
			bcn->len -= (bcn->noa_sub_ie_len +
					sizeof(struct p2p_ie));
			bcn->noa_ie = NULL;
			bcn->noa_sub_ie_len = 0;
		}
		WMA_LOGD("%s: No need to update NoA", __func__);
		return;
	}

	if (bcn->noa_sub_ie_len && bcn->noa_ie) {
		/* NoA present in previous beacon, update it */
		WMA_LOGD("%s: NoA present in previous beacon, "
			"update the NoA IE, bcn->len %u"
			"bcn->noa_sub_ie_len %u",
			__func__, bcn->len, bcn->noa_sub_ie_len);
		bcn->len -= (bcn->noa_sub_ie_len + sizeof(struct p2p_ie)) ;
		vos_mem_zero(bcn->noa_ie,
				(bcn->noa_sub_ie_len + sizeof(struct p2p_ie)));
	} else { /* NoA is not present in previous beacon */
		WMA_LOGD("%s: NoA not present in previous beacon, add it. "
			"bcn->len %u", __func__, bcn->len);
		buf = adf_nbuf_data(bcn->buf);
		bcn->noa_ie = buf + bcn->len;
	}

	bcn->noa_sub_ie_len = new_noa_sub_ie_len;
	wma_add_p2p_ie(bcn->noa_ie);
	p2p_ie = (struct p2p_ie *) bcn->noa_ie;
	p2p_ie->p2p_len += new_noa_sub_ie_len;
	vos_mem_copy((bcn->noa_ie + sizeof(struct p2p_ie)), bcn->noa_sub_ie,
			new_noa_sub_ie_len);

	bcn->len += (new_noa_sub_ie_len + sizeof(struct p2p_ie));
	WMA_LOGI("%s: Updated beacon length with NoA Ie is %u",
		__func__, bcn->len);
}

static void wma_p2p_create_sub_ie_noa(
		u_int8_t *buf,
		struct p2p_sub_element_noa *noa,
		u_int16_t *new_noa_sub_ie_len)
{
	u_int8_t tmp_octet = 0;
	int i;
	u_int8_t *buf_start = buf;

	*buf++ = WMA_P2P_SUB_ELEMENT_NOA;     /* sub-element id */
	ASSERT(noa->num_descriptors <= WMA_MAX_NOA_DESCRIPTORS);

	/*
	 * Length = (2 octets for Index and CTWin/Opp PS) and
	 * (13 octets for each NOA Descriptors)
	 */
	P2PIE_PUT_LE16(buf, WMA_NOA_IE_SIZE(noa->num_descriptors));
	buf += 2;

	*buf++ = noa->index;        /* Instance Index */

	tmp_octet = noa->ctwindow & WMA_P2P_NOA_IE_CTWIN_MASK;
	if (noa->oppPS) {
		tmp_octet |= WMA_P2P_NOA_IE_OPP_PS_SET;
	}
	*buf++ = tmp_octet;         /* Opp Ps and CTWin capabilities */

	for (i = 0; i < noa->num_descriptors; i++) {
		ASSERT(noa->noa_descriptors[i].type_count != 0);

		*buf++ = noa->noa_descriptors[i].type_count;

		P2PIE_PUT_LE32(buf, noa->noa_descriptors[i].duration);
		buf += 4;
		P2PIE_PUT_LE32(buf, noa->noa_descriptors[i].interval);
		buf += 4;
		P2PIE_PUT_LE32(buf, noa->noa_descriptors[i].start_time);
		buf += 4;
	}
	*new_noa_sub_ie_len = (buf - buf_start);
}

static void wma_update_noa(struct beacon_info *beacon,
		struct p2p_sub_element_noa *noa_ie)
{
	u_int16_t new_noa_sub_ie_len;

	/* Call this function by holding the spinlock on beacon->lock */

	if (noa_ie) {
		if ((noa_ie->ctwindow == 0) && (noa_ie->oppPS == 0) &&
				(noa_ie->num_descriptors == 0)) {
			/* NoA is not present */
			WMA_LOGD("%s: NoA is not present", __func__);
			new_noa_sub_ie_len = 0;
		}
		else {
			/* Create the binary blob containing NOA sub-IE */
			WMA_LOGD("%s: Create NOA sub ie", __func__);
			wma_p2p_create_sub_ie_noa(&beacon->noa_sub_ie[0],
					noa_ie, &new_noa_sub_ie_len);
		}
	}
	else {
		WMA_LOGD("%s: No need to add NOA", __func__);
		new_noa_sub_ie_len = 0;  /* no NOA IE sub-attributes */
	}

	wma_update_beacon_noa_ie(beacon, new_noa_sub_ie_len);
}

static void wma_update_probe_resp_noa(tp_wma_handle wma_handle,
					struct p2p_sub_element_noa *noa_ie)
{
	tSirP2PNoaAttr *noa_attr = (tSirP2PNoaAttr *) adf_os_mem_alloc(
						NULL, sizeof(tSirP2PNoaAttr));
	WMA_LOGD("Received update NoA event");
	if (!noa_attr) {
		WMA_LOGE("Failed to allocate memory for tSirP2PNoaAttr");
		return;
	}

	adf_os_mem_set(noa_attr, 0, sizeof(tSirP2PNoaAttr));

	noa_attr->index = noa_ie->index;
	noa_attr->oppPsFlag = noa_ie->oppPS;
	noa_attr->ctWin = noa_ie->ctwindow;
	if (!noa_ie->num_descriptors) {
		WMA_LOGD("Zero NoA descriptors");
	}
	else {
		WMA_LOGD("%d NoA descriptors", noa_ie->num_descriptors);
		noa_attr->uNoa1IntervalCnt =
			noa_ie->noa_descriptors[0].type_count;
		noa_attr->uNoa1Duration =
			noa_ie->noa_descriptors[0].duration;
		noa_attr->uNoa1Interval =
			noa_ie->noa_descriptors[0].interval;
		noa_attr->uNoa1StartTime =
			noa_ie->noa_descriptors[0].start_time;
		if (noa_ie->num_descriptors > 1) {
			noa_attr->uNoa2IntervalCnt =
				noa_ie->noa_descriptors[1].type_count;
			noa_attr->uNoa2Duration =
				noa_ie->noa_descriptors[1].duration;
			noa_attr->uNoa2Interval =
				noa_ie->noa_descriptors[1].interval;
			noa_attr->uNoa2StartTime =
				noa_ie->noa_descriptors[1].start_time;
		}
	}
	WMA_LOGI("Sending SIR_HAL_P2P_NOA_ATTR_IND to LIM");
	wma_send_msg(wma_handle, SIR_HAL_P2P_NOA_ATTR_IND, (void *)noa_attr ,
			0);
}

static void wma_send_bcn_buf_ll(tp_wma_handle wma,
				ol_txrx_pdev_handle pdev,
				u_int8_t vdev_id,
				WMI_HOST_SWBA_EVENTID_param_tlvs *param_buf)
{
	wmi_bcn_send_from_host_cmd_fixed_param *cmd;
	struct ieee80211_frame *wh;
	struct beacon_info *bcn;
	wmi_tim_info *tim_info = param_buf->tim_info;
	u_int8_t *bcn_payload;
	wmi_buf_t wmi_buf;
	a_status_t ret;
	struct beacon_tim_ie *tim_ie;
	wmi_p2p_noa_info *p2p_noa_info = param_buf->p2p_noa_info;
	struct p2p_sub_element_noa noa_ie;
	u_int8_t i;
	int status;

	bcn = wma->interfaces[vdev_id].beacon;
	if (!bcn->buf) {
		WMA_LOGE("%s: Invalid beacon buffer\n", __func__);
		return;
	}

	wmi_buf = wmi_buf_alloc(wma->wmi_handle, sizeof(*cmd));
	if (!wmi_buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed\n", __func__);
		return;
	}

	adf_os_spin_lock_bh(&bcn->lock);

	bcn_payload = adf_nbuf_data(bcn->buf);

	tim_ie = (struct beacon_tim_ie *)(&bcn_payload[bcn->tim_ie_offset]);

	if(tim_info->tim_changed) {
		if(tim_info->tim_num_ps_pending)
			vos_mem_copy(&tim_ie->tim_bitmap, tim_info->tim_bitmap,
				WMA_TIM_SUPPORTED_PVB_LENGTH);
		else
			vos_mem_zero(&tim_ie->tim_bitmap,
				WMA_TIM_SUPPORTED_PVB_LENGTH);
		/*
		 * Currently we support fixed number of
		 * peers as limited by HAL_NUM_STA.
		 * tim offset is always 0
		 */
		tim_ie->tim_bitctl = 0;
	}

	/* Update DTIM Count */
	if (tim_ie->dtim_count == 0)
		tim_ie->dtim_count = tim_ie->dtim_period - 1;
	else
		tim_ie->dtim_count--;

	/*
	 * DTIM count needs to be backedup so that
	 * when umac updates the beacon template
	 * current dtim count can be updated properly
	 */
	bcn->dtim_count = tim_ie->dtim_count;

	/* update state for buffered multicast frames on DTIM */
	if (tim_info->tim_mcast && (tim_ie->dtim_count == 0 ||
		tim_ie->dtim_period == 1))
		tim_ie->tim_bitctl |= 1;
	else
		tim_ie->tim_bitctl &= ~1;

	/* To avoid sw generated frame sequence the same as H/W generated frame,
	 * the value lower than min_sw_seq is reserved for HW generated frame */
	if ((bcn->seq_no & IEEE80211_SEQ_MASK) < MIN_SW_SEQ)
		bcn->seq_no = MIN_SW_SEQ;

	wh = (struct ieee80211_frame *) bcn_payload;
	*(u_int16_t *)&wh->i_seq[0] = htole16(bcn->seq_no
					      << IEEE80211_SEQ_SEQ_SHIFT);
	bcn->seq_no++;

	if (WMI_UNIFIED_NOA_ATTR_IS_MODIFIED(p2p_noa_info)) {
		vos_mem_zero(&noa_ie, sizeof(noa_ie));

		noa_ie.index = WMI_UNIFIED_NOA_ATTR_INDEX_GET(p2p_noa_info);
		noa_ie.oppPS = WMI_UNIFIED_NOA_ATTR_OPP_PS_GET(p2p_noa_info);
		noa_ie.ctwindow = WMI_UNIFIED_NOA_ATTR_CTWIN_GET(p2p_noa_info);
		noa_ie.num_descriptors = WMI_UNIFIED_NOA_ATTR_NUM_DESC_GET(
				p2p_noa_info);
		WMA_LOGI("%s: index %lu, oppPs %lu, ctwindow %lu, "
			"num_descriptors = %lu", __func__, noa_ie.index,
			noa_ie.oppPS, noa_ie.ctwindow, noa_ie.num_descriptors);
		for(i = 0; i < noa_ie.num_descriptors; i++) {
			noa_ie.noa_descriptors[i].type_count =
				p2p_noa_info->noa_descriptors[i].type_count;
			noa_ie.noa_descriptors[i].duration =
				p2p_noa_info->noa_descriptors[i].duration;
			noa_ie.noa_descriptors[i].interval =
				p2p_noa_info->noa_descriptors[i].interval;
			noa_ie.noa_descriptors[i].start_time =
				p2p_noa_info->noa_descriptors[i].start_time;
			WMA_LOGI("%s: NoA descriptor[%d] type_count %lu, "
				"duration %lu, interval %lu, start_time = %lu",
				__func__, i,
				noa_ie.noa_descriptors[i].type_count,
				noa_ie.noa_descriptors[i].duration,
				noa_ie.noa_descriptors[i].interval,
				noa_ie.noa_descriptors[i].start_time);
		}
		wma_update_noa(bcn, &noa_ie);

		/* Send a msg to LIM to update the NoA IE in probe response
		 * frames transmitted by the host */
		wma_update_probe_resp_noa(wma, &noa_ie);
	}

	if (bcn->dma_mapped) {
		adf_nbuf_unmap_single(pdev->osdev, bcn->buf,
				      ADF_OS_DMA_TO_DEVICE);
		bcn->dma_mapped = 0;
	}
	ret = adf_nbuf_map_single(pdev->osdev, bcn->buf,
				  ADF_OS_DMA_TO_DEVICE);
	if (ret != A_STATUS_OK) {
		adf_nbuf_free(wmi_buf);
		WMA_LOGE("%s: failed map beacon buf to DMA region\n",
				__func__);
		adf_os_spin_unlock_bh(&bcn->lock);
		return;
	}

	bcn->dma_mapped = 1;
	cmd = (wmi_bcn_send_from_host_cmd_fixed_param *) wmi_buf_data(wmi_buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_bcn_send_from_host_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_bcn_send_from_host_cmd_fixed_param));
	cmd->vdev_id = vdev_id;
	cmd->data_len = bcn->len;
	cmd->frame_ctrl = *((A_UINT16 *)wh->i_fc);
	cmd->frag_ptr = adf_nbuf_get_frag_paddr_lo(bcn->buf, 0);

	/* Notify Firmware of DTM and mcast/bcast traffic */
	if (tim_ie->dtim_count == 0) {
		cmd->dtim_flag |= WMI_BCN_SEND_DTIM_ZERO;
		 /* deliver mcast/bcast traffic in next DTIM beacon */
		if (tim_ie->tim_bitctl & 0x01)
			cmd->dtim_flag |= WMI_BCN_SEND_DTIM_BITCTL_SET;
	}

	status = wmi_unified_cmd_send(wma->wmi_handle, wmi_buf, sizeof(*cmd),
			     WMI_PDEV_SEND_BCN_CMDID);

	if (status != EOK) {
		WMA_LOGE("Failed to send WMI_PDEV_SEND_BCN_CMDID command");
		wmi_buf_free(wmi_buf);
	}
	adf_os_spin_unlock_bh(&bcn->lock);
}

static int wma_beacon_swba_handler(void *handle, u_int8_t *event, u_int32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	WMI_HOST_SWBA_EVENTID_param_tlvs *param_buf;
	wmi_host_swba_event_fixed_param *swba_event;
	u_int32_t vdev_map;
	ol_txrx_pdev_handle pdev;
	u_int8_t vdev_id = 0;

	param_buf = (WMI_HOST_SWBA_EVENTID_param_tlvs *) event;
	if (!param_buf) {
		WMA_LOGE("Invalid swba event buffer");
		return -EINVAL;
	}
	swba_event = param_buf->fixed_param;
	vdev_map = swba_event->vdev_map;

	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);

	for ( ; vdev_map; vdev_id++, vdev_map >>= 1) {
		if (!(vdev_map & 0x1))
			continue;
		if (!wdi_out_cfg_is_high_latency(pdev->ctrl_pdev))
			wma_send_bcn_buf_ll(wma, pdev, vdev_id, param_buf);
		break;
	}
	return 0;
}
#endif

#ifdef WLAN_FEATURE_GTK_OFFLOAD
static int wma_gtk_offload_status_event(void *handle, u_int8_t *event,
					u_int32_t len)
{
	tp_wma_handle wma = (tp_wma_handle)handle;
	WMI_GTK_OFFLOAD_STATUS_EVENT_fixed_param *status;
	WMI_GTK_OFFLOAD_STATUS_EVENTID_param_tlvs *param_buf;
	tpSirGtkOffloadGetInfoRspParams resp;
	vos_msg_t vos_msg;
	u_int8_t *bssid;

	WMA_LOGD("%s Enter", __func__);

	param_buf = (WMI_GTK_OFFLOAD_STATUS_EVENTID_param_tlvs *)event;
	if (!param_buf) {
		WMA_LOGE("param_buf is NULL");
		return -EINVAL;
	}

	status = (WMI_GTK_OFFLOAD_STATUS_EVENT_fixed_param *)param_buf->fixed_param;

	if (len < sizeof(WMI_GTK_OFFLOAD_STATUS_EVENT_fixed_param)) {
		WMA_LOGE("Invalid length for GTK status");
		return -EINVAL;
	}
	bssid = wma_find_bssid_by_vdev_id(wma, status->vdev_id);
	if (!bssid) {
		WMA_LOGE("invalid bssid for vdev id %d", status->vdev_id);
		return -ENOENT;
	}

	resp = vos_mem_malloc(sizeof(*resp));
	if (!resp) {
		WMA_LOGE("%s: Failed to alloc response", __func__);
		return -ENOMEM;
	}
	vos_mem_zero(resp, sizeof(*resp));
	resp->mesgType = eWNI_PMC_GTK_OFFLOAD_GETINFO_RSP;
	resp->mesgLen = sizeof(*resp);
	resp->ulStatus = VOS_STATUS_SUCCESS;
	resp->ulTotalRekeyCount = status->refresh_cnt;
	/* TODO: Is the total rekey count and GTK rekey count same? */
	resp->ulGTKRekeyCount = status->refresh_cnt;

	vos_mem_copy(&resp->ullKeyReplayCounter,  &status->replay_counter,
		     GTK_REPLAY_COUNTER_BYTES);

	vos_mem_copy(resp->bssId, bssid, ETH_ALEN);

#ifdef IGTK_OFFLOAD
	/* TODO: Is the refresh count same for GTK and IGTK? */
	resp->ulIGTKRekeyCount = status->refresh_cnt;
#endif

	vos_msg.type = eWNI_PMC_GTK_OFFLOAD_GETINFO_RSP;
	vos_msg.bodyptr = (void *)resp;
	vos_msg.bodyval = 0;

	if (vos_mq_post_message(VOS_MQ_ID_SME, (vos_msg_t*)&vos_msg)
			!= VOS_STATUS_SUCCESS) {
		WMA_LOGE("Failed to post GTK response to SME");
		vos_mem_free(resp);
		return -EINVAL;
	}

	WMA_LOGD("GTK: got target status with replaycouter %x. vdev %d. " \
		 "Refresh GTK %d times exchanges since last set operation.",
		 status->replay_counter, status->vdev_id, status->refresh_cnt);

	WMA_LOGD("%s Exit", __func__);

	return 0;
}
#endif

#ifdef FEATURE_OEM_DATA_SUPPORT
static int wma_oem_data_rsp_event_callback(void *handle, u_int8_t *datap,
						 u_int32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	WMI_OEM_DATA_RSP_EVENTID_param_tlvs *param_buf;
	u_int8_t *data;
	u_int32_t datalen;
	tStartOemDataRsp *pStartOemDataRsp;

	param_buf = (WMI_OEM_DATA_RSP_EVENTID_param_tlvs *)datap;
	if (!param_buf) {
		WMA_LOGE("%s: Received NULL buf ptr from FW", __func__);
		return -ENOMEM;
	}

	data = param_buf->data;
	datalen = param_buf->num_data;

	if (!data) {
		WMA_LOGE("%s: Received NULL data from FW", __func__);
		return -EINVAL;
	}

	if (datalen > OEM_DATA_RSP_SIZE) {
		WMA_LOGE("%s: Received data len (%d) exceeds max value (%d)",
		         __func__, datalen, OEM_DATA_RSP_SIZE);
		return -EINVAL;
	}

	pStartOemDataRsp = vos_mem_malloc(sizeof(tStartOemDataRsp));

	vos_mem_zero(pStartOemDataRsp, sizeof(tStartOemDataRsp));
	vos_mem_copy(&pStartOemDataRsp->oemDataRsp[0], data, datalen);

	wma_send_msg(wma, WDA_START_OEM_DATA_RSP, (void *)pStartOemDataRsp, 0);
	vos_mem_free(data);
	return 0;
}

static int wma_oem_data_error_report_event_callback(void *handle,
	u_int8_t *datap, u_int32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	WMI_OEM_DATA_ERROR_REPORT_EVENTID_param_tlvs *param_buf;
	u_int8_t *data;
	u_int32_t datalen;
	tStartOemDataRsp *pStartOemDataRsp;

	param_buf = (WMI_OEM_DATA_ERROR_REPORT_EVENTID_param_tlvs *)datap;
	if (!param_buf) {
		WMA_LOGE("%s: Received NULL buf ptr from FW", __func__);
		return -ENOMEM;
	}

	data = param_buf->data;
	datalen = param_buf->num_data;

	if (!data) {
		WMA_LOGE("%s: Received NULL data from FW", __func__);
		return -EINVAL;
	}

	if (datalen > OEM_DATA_RSP_SIZE) {
		WMA_LOGE("%s: Received data len (%d) exceeds max value (%d)",
		         __func__, datalen, OEM_DATA_RSP_SIZE);
		return -EINVAL;
	}

	pStartOemDataRsp = vos_mem_malloc(sizeof(tStartOemDataRsp));

	vos_mem_zero(pStartOemDataRsp, sizeof(tStartOemDataRsp));
	vos_mem_copy(&pStartOemDataRsp->oemDataRsp[0], data, datalen);

	wma_send_msg(wma, WDA_START_OEM_DATA_RSP, (void *)data, 0);
	vos_mem_free(data);
	return 0;
}
#endif /* FEATURE_OEM_DATA_SUPPORT */

/*
 * Allocate and init wmi adaptation layer.
 */
VOS_STATUS WDA_open(v_VOID_t *vos_context, v_VOID_t *os_ctx,
		    wda_tgt_cfg_cb tgt_cfg_cb,
		    tMacOpenParameters *mac_params)
{
	tp_wma_handle wma_handle;
	HTC_HANDLE htc_handle;
	adf_os_device_t adf_dev;
	v_VOID_t *wmi_handle;
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;

	WMA_LOGD("%s: Enter", __func__);

	adf_dev = vos_get_context(VOS_MODULE_ID_ADF, vos_context);
	htc_handle = vos_get_context(VOS_MODULE_ID_HTC, vos_context);

	if (!htc_handle) {
		WMA_LOGP("\n Invalid HTC handle");
		return VOS_STATUS_E_INVAL;
	}

	/* Alloc memory for WMA Context */
	vos_status = vos_alloc_context(vos_context, VOS_MODULE_ID_WDA,
				       (v_VOID_t **) &wma_handle,
				       sizeof (t_wma_handle));

	if (vos_status != VOS_STATUS_SUCCESS) {
		WMA_LOGP("Memory allocation failed for wma_handle");
		return VOS_STATUS_E_NOMEM;
	}

	vos_mem_zero(wma_handle, sizeof (t_wma_handle));

	/* attach the wmi */
	wmi_handle = wmi_unified_attach(wma_handle);
	if (!wmi_handle) {
		WMA_LOGP("failed to attach WMI");
		vos_status = VOS_STATUS_E_NOMEM;
		goto err_wmi_attach;
	}

	WMA_LOGA("WMA --> wmi_unified_attach - success");

	/* initialize default target config */
	wma_set_default_tgt_config(wma_handle);

	/* Allocate cfg handle */
	((pVosContextType) vos_context)->cfg_ctx =
		ol_pdev_cfg_attach(((pVosContextType) vos_context)->adf_ctx);
	if (!(((pVosContextType) vos_context)->cfg_ctx)) {
		WMA_LOGP("failed to init cfg handle");
		goto err_wmi_attach;
	}

	/* Save the WMI & HTC handle */
	wma_handle->wmi_handle = wmi_handle;
	wma_handle->htc_handle = htc_handle;
	wma_handle->vos_context = vos_context;
        wma_handle->adf_dev = adf_dev;

#if defined(QCA_WIFI_FTM) && !defined(QCA_WIFI_ISOC)
	if (vos_get_conparam() == VOS_FTM_MODE)
		wma_utf_attach(wma_handle);
#endif

        /*TODO: Recheck below parameters */
	mac_params->maxStation = WMA_MAX_SUPPORTED_STAS;
        mac_params->maxBssId = WMA_MAX_SUPPORTED_BSS;
	mac_params->frameTransRequired = 0;

	wma_handle->max_station = mac_params->maxStation;
	wma_handle->max_bssid = mac_params->maxBssId;
	wma_handle->frame_xln_reqd = mac_params->frameTransRequired;
	wma_handle->driver_type = mac_params->driverType;
	wma_handle->interfaces = vos_mem_malloc(sizeof(struct wma_txrx_node) *
						wma_handle->max_bssid);
	if (!wma_handle->interfaces) {
		WMA_LOGP("failed to allocate interface table");
		goto err_wmi_attach;
	}
	vos_mem_zero(wma_handle->interfaces, sizeof(struct wma_txrx_node) *
					wma_handle->max_bssid);
	/* Register the debug print event handler */
	wmi_unified_register_event_handler(wma_handle->wmi_handle,
					   WMI_DEBUG_PRINT_EVENTID,
					   wma_unified_debug_print_event_handler);

	wma_handle->tgt_cfg_update_cb = tgt_cfg_cb;

#ifdef QCA_WIFI_ISOC
	vos_status = vos_event_init(&wma_handle->cfg_nv_tx_complete);
	if (vos_status != VOS_STATUS_SUCCESS) {
		WMA_LOGP("cfg_nv_tx_complete initialization failed");
		goto err_event_init;
	}

	vos_status = vos_event_init(&(wma_handle->cfg_nv_rx_complete));
	if (VOS_STATUS_SUCCESS != vos_status) {
		WMA_LOGP("cfg_nv_tx_complete initialization failed");
		return VOS_STATUS_E_FAILURE;
	}
#endif
        vos_status = vos_event_init(&wma_handle->wma_ready_event);
	if (vos_status != VOS_STATUS_SUCCESS) {
		WMA_LOGP("wma_ready_event initialization failed");
		goto err_event_init;
	}
        vos_status = vos_event_init(&wma_handle->target_suspend);
	if (vos_status != VOS_STATUS_SUCCESS) {
		WMA_LOGP("target suspend event initialization failed");
		goto err_event_init;
	}

	/* Init Tx Frame Complete event */
	vos_status = vos_event_init(&wma_handle->tx_frm_download_comp_event);
	if (!VOS_IS_STATUS_SUCCESS(vos_status)) {
		WMA_LOGP("failed to init tx_frm_download_comp_event");
		goto err_event_init;
	}
	INIT_LIST_HEAD(&wma_handle->vdev_resp_queue);
	adf_os_spinlock_init(&wma_handle->vdev_respq_lock);

	/* Register vdev start response event handler */
	wmi_unified_register_event_handler(wma_handle->wmi_handle,
					   WMI_VDEV_START_RESP_EVENTID,
					   wma_vdev_start_resp_handler);

	/* Register vdev stop response event handler */
	wmi_unified_register_event_handler(wma_handle->wmi_handle,
					   WMI_VDEV_STOPPED_EVENTID,
					   wma_vdev_stop_resp_handler);

	/* register for STA kickout function */
	wmi_unified_register_event_handler(wma_handle->wmi_handle,
					   WMI_PEER_STA_KICKOUT_EVENTID,
					   wma_peer_sta_kickout_event_handler);

#ifdef FEATURE_OEM_DATA_SUPPORT
		wmi_unified_register_event_handler(wma_handle->wmi_handle,
						   WMI_OEM_DATA_RSP_EVENTID,
						   wma_oem_data_rsp_event_callback);

		wmi_unified_register_event_handler(wma_handle->wmi_handle,
						   WMI_OEM_DATA_ERROR_REPORT_EVENTID,
						   wma_oem_data_error_report_event_callback);
#endif

	/* Firmware debug log */
	vos_status = dbglog_init(wma_handle->wmi_handle);
	if (vos_status != VOS_STATUS_SUCCESS) {
		WMA_LOGP("Firmware Dbglog initialization failed");
		goto err_event_init;
	}
	WMA_LOGD("%s: Exit", __func__);

	return VOS_STATUS_SUCCESS;

err_event_init:
	wmi_unified_unregister_event_handler(wma_handle->wmi_handle,
					     WMI_DEBUG_PRINT_EVENTID);
err_wmi_attach:
	vos_mem_free(wma_handle->interfaces);
	vos_free_context(wma_handle->vos_context, VOS_MODULE_ID_WDA,
			 wma_handle);

	WMA_LOGD("%s: Exit", __func__);

	return vos_status;
}

/* function   : wma_pre_start
 * Descriptin :
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_pre_start(v_VOID_t *vos_ctx)
{
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
	A_STATUS status = A_OK;
	tp_wma_handle wma_handle;
	vos_msg_t wma_msg = {0} ;

	WMA_LOGD("%s: Enter", __func__);

	wma_handle = vos_get_context(VOS_MODULE_ID_WDA, vos_ctx);

	/* Validate the wma_handle */
	if (NULL == wma_handle) {
		WMA_LOGP("invalid argument");
		vos_status = VOS_STATUS_E_INVAL;
		goto end;
	}
	/* Open endpoint for ctrl path - WMI <--> HTC */
	status = wmi_unified_connect_htc_service(
			wma_handle->wmi_handle,
			wma_handle->htc_handle);
	if (A_OK != status) {
		WMA_LOGP("wmi_unified_connect_htc_service");
		vos_status = VOS_STATUS_E_FAULT;
		goto end;
	}

	WMA_LOGA("WMA --> wmi_unified_connect_htc_service - success");

#ifdef QCA_WIFI_ISOC
	/* Open endpoint for cfg and nv download path - WMA <--> HTC */
	status = wma_htc_cfg_nv_connect_service(wma_handle);
	if (A_OK != status) {
		WMA_LOGP("\n htc_connect_service failed");
		vos_status = VOS_STATUS_E_FAULT;
		goto end;
	}
#endif
	/* Trigger the CFG DOWNLOAD */
	wma_msg.type = WNI_CFG_DNLD_REQ ;
	wma_msg.bodyptr = NULL;
	wma_msg.bodyval = 0;

	vos_status = vos_mq_post_message( VOS_MQ_ID_WDA, &wma_msg );
	if (VOS_STATUS_SUCCESS !=vos_status) {
		WMA_LOGP("Failed to post WNI_CFG_DNLD_REQ msg");
		VOS_ASSERT(0);
		vos_status = VOS_STATUS_E_FAILURE;
	}
end:
	WMA_LOGD("%s: Exit", __func__);
	return vos_status;
}

/* function   : wma_send_msg
 * Descriptin :
 * Args       :
 * Returns    :
 */
static void wma_send_msg(tp_wma_handle wma_handle, u_int16_t msg_type,
		void *body_ptr, u_int32_t body_val)
{
	tSirMsgQ msg = {0} ;
	tANI_U32 status = VOS_STATUS_SUCCESS ;
	tpAniSirGlobal pMac = (tpAniSirGlobal )vos_get_context(VOS_MODULE_ID_PE,
			wma_handle->vos_context);
	msg.type        = msg_type;
	msg.bodyval     = body_val;
	msg.bodyptr     = body_ptr;
	status = limPostMsgApi(pMac, &msg);
	if (VOS_STATUS_SUCCESS != status) {
		if(NULL != body_ptr)
			vos_mem_free(body_ptr);
		VOS_ASSERT(0) ;
	}
	return ;
}

/* function   : wma_get_txrx_vdev_type
 * Descriptin :
 * Args       :
 * Returns    :
 */
enum wlan_op_mode wma_get_txrx_vdev_type(u_int32_t type)
{
	enum wlan_op_mode vdev_type = wlan_op_mode_unknown;
	switch (type) {
		case WMI_VDEV_TYPE_AP:
			vdev_type = wlan_op_mode_ap;
			break;
		case WMI_VDEV_TYPE_STA:
			vdev_type = wlan_op_mode_sta;
			break;
		case WMI_VDEV_TYPE_IBSS:
		case WMI_VDEV_TYPE_MONITOR:
		default:
			WMA_LOGE("Invalid vdev type %u", type);
			vdev_type = wlan_op_mode_unknown;
	}

	return vdev_type;
}

/* function   : wma_unified_vdev_create_send
 * Descriptin :
 * Args       :
 * Returns    :
 */
int wma_unified_vdev_create_send(wmi_unified_t wmi_handle, u_int8_t if_id,
				 u_int32_t type, u_int32_t subtype,
				 u_int8_t macaddr[IEEE80211_ADDR_LEN])
{
	wmi_vdev_create_cmd_fixed_param* cmd;
	wmi_buf_t buf;
	int len = sizeof(*cmd);
	int ret;

	buf = wmi_buf_alloc(wmi_handle, len);
	if (!buf) {
		WMA_LOGP("%s:wmi_buf_alloc failed\n", __FUNCTION__);
		return ENOMEM;
	}
	cmd = (wmi_vdev_create_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_vdev_create_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_vdev_create_cmd_fixed_param));
	cmd->vdev_id = if_id;
	cmd->vdev_type = type;
	cmd->vdev_subtype = subtype;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(macaddr, &cmd->vdev_macaddr);
	WMA_LOGA("%s: ID = %d VAP Addr = %02x:%02x:%02x:%02x:%02x:%02x:\n",
		 __func__, if_id,
		 macaddr[0], macaddr[1], macaddr[2],
		 macaddr[3], macaddr[4], macaddr[5]);
	ret = wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_CREATE_CMDID);
	if (ret != EOK) {
		WMA_LOGE("Failed to send WMI_VDEV_CREATE_CMDID");
		wmi_buf_free(buf);
	}
	return ret;
}

/* function   : wma_unified_vdev_delete_send
 * Descriptin :
 * Args       :
 * Returns    :
 */
static int wma_unified_vdev_delete_send(wmi_unified_t wmi_handle, u_int8_t if_id)
{
	wmi_vdev_delete_cmd_fixed_param* cmd;
	wmi_buf_t buf;
	int ret;

	buf = wmi_buf_alloc(wmi_handle, sizeof(*cmd));
	if (!buf) {
		WMA_LOGP("%s:wmi_buf_alloc failed\n", __FUNCTION__);
		return ENOMEM;
	}

	cmd = (wmi_vdev_delete_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_vdev_delete_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_vdev_delete_cmd_fixed_param));
	cmd->vdev_id = if_id;
	ret = wmi_unified_cmd_send(wmi_handle, buf, sizeof(wmi_vdev_delete_cmd_fixed_param),
			WMI_VDEV_DELETE_CMDID);
	if (ret != EOK) {
		WMA_LOGE("Failed to send WMI_VDEV_DELETE_CMDID");
		wmi_buf_free(buf);
	}
	return ret;
}

/* function   : wma_vdev_detach
 * Descriptin :
 * Args       :
 * Returns    :
 */
static VOS_STATUS wma_vdev_detach(tp_wma_handle wma_handle,
				tpDelStaSelfParams pdel_sta_self_req_param)
{
	VOS_STATUS status = VOS_STATUS_SUCCESS;
	void *txrx_hdl;
	ol_txrx_peer_handle peer;
	ol_txrx_pdev_handle pdev;
	u_int8_t peer_id;
	u_int8_t vdev_id = pdel_sta_self_req_param->sessionId;

	if ((wma_handle->interfaces[vdev_id].type == WMI_VDEV_TYPE_AP) &&
			((wma_handle->interfaces[vdev_id].sub_type ==
			  WMI_UNIFIED_VDEV_SUBTYPE_P2P_DEVICE))) {

		WMA_LOGA("P2P Device: removing self peer %pM",
				pdel_sta_self_req_param->selfMacAddr);

		pdev = vos_get_context(VOS_MODULE_ID_TXRX,
				wma_handle->vos_context);

		peer = ol_txrx_find_peer_by_addr(pdev,
				pdel_sta_self_req_param->selfMacAddr,
				&peer_id);
		if (!peer) {
			WMA_LOGE("%s Failed to find peer %pM\n", __func__,
					pdel_sta_self_req_param->selfMacAddr);
		}
		wma_remove_peer(wma_handle,
				pdel_sta_self_req_param->selfMacAddr,
				pdel_sta_self_req_param->sessionId,
				peer);
	}

	/* remove the interface from ath_dev */
	if (wma_unified_vdev_delete_send(wma_handle->wmi_handle,
			pdel_sta_self_req_param->sessionId)) {
		WMA_LOGP("Unable to remove an interface for ath_dev.\n");
		status = VOS_STATUS_E_FAILURE;
	}

	txrx_hdl = wma_handle->interfaces[pdel_sta_self_req_param->sessionId].handle;
	if(!txrx_hdl)
		status = VOS_STATUS_E_FAILURE;
	else
		ol_txrx_vdev_detach(txrx_hdl, NULL, NULL);
	vos_mem_zero(&wma_handle->interfaces[pdel_sta_self_req_param->sessionId],
		     sizeof(wma_handle->interfaces[pdel_sta_self_req_param->sessionId]));

	WMA_LOGA("vdev_id:%hu vdev_hdl:%p\n", pdel_sta_self_req_param->sessionId,
			txrx_hdl);

	wma_send_msg(wma_handle, WDA_DEL_STA_SELF_RSP, (void *)pdel_sta_self_req_param, 0);
	return status;
}

static int wmi_unified_peer_create_send(wmi_unified_t wmi,
					const u_int8_t *peer_addr,
					u_int32_t vdev_id)
{
	wmi_peer_create_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len = sizeof(*cmd);

	buf = wmi_buf_alloc(wmi, len);
	if (!buf) {
		WMA_LOGP("%s: wmi_buf_alloc failed\n", __func__);
		return -ENOMEM;
	}
	cmd = (wmi_peer_create_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_peer_create_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_peer_create_cmd_fixed_param));
	WMI_CHAR_ARRAY_TO_MAC_ADDR(peer_addr, &cmd->peer_macaddr);
	cmd->vdev_id = vdev_id;

	if (wmi_unified_cmd_send(wmi, buf, len, WMI_PEER_CREATE_CMDID)) {
		WMA_LOGP("failed to send WMI_PEER_CREATE_CMDID\n");
		adf_nbuf_free(buf);
		return -EIO;
	}
	WMA_LOGD("%s: peer_addr %pM vdev_id %d\n", __func__, peer_addr, vdev_id);
	return 0;
}

static VOS_STATUS wma_create_peer(tp_wma_handle wma, ol_txrx_pdev_handle pdev,
				  ol_txrx_vdev_handle vdev, u8 *peer_addr,
				  u_int8_t vdev_id)
{
	ol_txrx_peer_handle peer;

	WMA_LOGD("%s: peer_addr %pM vdev_id %d\n", __func__, peer_addr, vdev_id);
	if (++wma->peer_count > wma->wlan_resource_config.num_peers) {
		WMA_LOGP("%s, the peer count exceeds the limit %d\n",
			 __func__, wma->peer_count - 1);
		goto err;
	}
	peer = ol_txrx_peer_attach(pdev, vdev, peer_addr);
	if (!peer)
		goto err;

	if (wmi_unified_peer_create_send(wma->wmi_handle, peer_addr,
					 vdev_id) < 0) {
		WMA_LOGP("%s : Unable to create peer in Target\n", __func__);
		ol_txrx_peer_detach(peer);
		goto err;
	}
	return VOS_STATUS_SUCCESS;
err:
	wma->peer_count--;
	return VOS_STATUS_E_FAILURE;
}

static void wma_set_sta_keep_alive(tp_wma_handle wma, u_int8_t vdev_id,
				   v_U32_t method, v_U32_t timeperiod,
				   u_int8_t *hostv4addr, u_int8_t *destv4addr,
				   u_int8_t *destmac)
{
	wmi_buf_t buf;
	WMI_STA_KEEPALIVE_CMD_fixed_param *cmd;
	WMI_STA_KEEPALVE_ARP_RESPONSE *arp_rsp;
	u_int8_t *buf_ptr;
	int len;

	WMA_LOGD("%s: Enter", __func__);
	len = sizeof(*cmd) + sizeof(*arp_rsp);
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		 WMA_LOGE("wmi_buf_alloc failed");
		 return;
	}

	cmd = (WMI_STA_KEEPALIVE_CMD_fixed_param *) wmi_buf_data(buf);
	buf_ptr = (u_int8_t *)cmd;
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_WMI_STA_KEEPALIVE_CMD_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       WMI_STA_KEEPALIVE_CMD_fixed_param));
	cmd->interval = timeperiod;
	cmd->enable = (timeperiod)? 1:0;
	cmd->vdev_id = vdev_id;
	WMA_LOGD("Keep Alive: vdev_id:%d interval:%u method:%d", vdev_id,
		 timeperiod, method);
	arp_rsp = (WMI_STA_KEEPALVE_ARP_RESPONSE *)(buf_ptr + sizeof(*cmd));
	WMITLV_SET_HDR(&arp_rsp->tlv_header,
		       WMITLV_TAG_STRUC_WMI_STA_KEEPALVE_ARP_RESPONSE,
		       WMITLV_GET_STRUCT_TLVLEN(WMI_STA_KEEPALVE_ARP_RESPONSE));

	if (method == SIR_KEEP_ALIVE_UNSOLICIT_ARP_RSP) {
		cmd->method = WMI_STA_KEEPALIVE_METHOD_UNSOLICITED_ARP_RESPONSE;
		vos_mem_copy(&arp_rsp->sender_prot_addr, hostv4addr,
				SIR_IPV4_ADDR_LEN);
		vos_mem_copy(&arp_rsp->target_prot_addr, destv4addr,
				SIR_IPV4_ADDR_LEN);
		WMI_CHAR_ARRAY_TO_MAC_ADDR(destmac,&arp_rsp->dest_mac_addr);
	} else {
		cmd->method = WMI_STA_KEEPALIVE_METHOD_NULL_FRAME;
	}

	if (wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				 WMI_STA_KEEPALIVE_CMDID)) {
		WMA_LOGE("Failed to set KeepAlive");
		adf_nbuf_free(buf);
	}

	WMA_LOGD("%s: Exit", __func__);
	return;
}

static inline tANI_U32 wma_get_maxidle_time(struct sAniSirGlobal *mac,
						tANI_U32 sub_type)
{
	tANI_U16 cfg_id;
	tANI_U32 max_idletime;

	switch (sub_type) {
	case WMI_UNIFIED_VDEV_SUBTYPE_P2P_GO:
		cfg_id = WNI_CFG_GO_KEEP_ALIVE_TIMEOUT;
		break;
	default:
		/*For softAp the subtype value will be zero*/
		cfg_id = WNI_CFG_AP_KEEP_ALIVE_TIMEOUT;
	}

	if(wlan_cfgGetInt(mac, cfg_id, &max_idletime) != eSIR_SUCCESS) {
		WMA_LOGE("Failed to get value for cfg id:%d", cfg_id);
		max_idletime = DEFAULT_MAX_IDLETIME;
	}

	return max_idletime;
}

static void wma_set_sap_keepalive(tp_wma_handle wma, u_int8_t vdev_id)
{
	tANI_U32 cfg_data_val, min_inactive_time, max_unresponsive_time;
	struct sAniSirGlobal *mac =
		(struct sAniSirGlobal*)vos_get_context(VOS_MODULE_ID_PE,
						      wma->vos_context);

	cfg_data_val = wma_get_maxidle_time(mac,
					    wma->interfaces[vdev_id].sub_type);
	if (!cfg_data_val) /*0 -> Disabled*/
	    return;

	min_inactive_time = MIN_IDLE_INACTIVE_TIME_SECS(cfg_data_val);
	max_unresponsive_time =
			     MAX_UNRESPONSIVE_TIME_SECS(cfg_data_val);

	if (wmi_unified_vdev_set_param_send(wma->wmi_handle,
					    vdev_id,
	       WMI_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS,
		       (min_inactive_time < 0)? 0 : min_inactive_time))
		WMA_LOGE("Failed to Set AP MIN IDLE INACTIVE TIME");

	if (wmi_unified_vdev_set_param_send(wma->wmi_handle,
					    vdev_id,
	       WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS,
					    cfg_data_val))
		WMA_LOGE("Failed to Set AP MAX IDLE INACTIVE TIME");

	if (wmi_unified_vdev_set_param_send(wma->wmi_handle,
					    vdev_id,
		WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS,
					    max_unresponsive_time))
		WMA_LOGE("Failed to Set MAX UNRESPONSIVE TIME");

	WMA_LOGD("%s:vdev_id:%d min_inactive_time:%d max_inactive_time:%d"
		 " max_unresponsive_time:%d", __func__, vdev_id,
		 (min_inactive_time > 0)? min_inactive_time : 0, cfg_data_val,
		 max_unresponsive_time);
}

/* function   : wma_vdev_attach
 * Descriptin :
 * Args       :
 * Returns    :
 */
static ol_txrx_vdev_handle wma_vdev_attach(tp_wma_handle wma_handle,
					   tpAddStaSelfParams self_sta_req)
{
	ol_txrx_vdev_handle txrx_vdev_handle = NULL;
	ol_txrx_pdev_handle txrx_pdev = vos_get_context(VOS_MODULE_ID_TXRX,
			wma_handle->vos_context);
	enum wlan_op_mode txrx_vdev_type;
	VOS_STATUS status = VOS_STATUS_SUCCESS;
	struct sAniSirGlobal *mac =
		(struct sAniSirGlobal*)vos_get_context(VOS_MODULE_ID_PE,
						      wma_handle->vos_context);
	tANI_U32 cfg_val;
	int ret;

	/* Create a vdev in target */
	if (wma_unified_vdev_create_send(wma_handle->wmi_handle,
						self_sta_req->sessionId,
						self_sta_req->type,
						self_sta_req->subType,
						self_sta_req->selfMacAddr))
	{
		WMA_LOGP("Unable to add an interface for ath_dev.\n");
		status = VOS_STATUS_E_RESOURCES;
		goto end;
	}

	txrx_vdev_type = wma_get_txrx_vdev_type(self_sta_req->type);

	if (wlan_op_mode_unknown == txrx_vdev_type) {
		WMA_LOGE("Failed to get txrx vdev type");
		wma_unified_vdev_delete_send(wma_handle->wmi_handle,
						self_sta_req->sessionId);
		goto end;
	}

	txrx_vdev_handle = ol_txrx_vdev_attach(txrx_pdev,
						self_sta_req->selfMacAddr,
						self_sta_req->sessionId,
						txrx_vdev_type);

	WMA_LOGA("vdev_id %hu, txrx_vdev_handle = %p", self_sta_req->sessionId,
			txrx_vdev_handle);

	if (NULL == txrx_vdev_handle) {
		WMA_LOGP("ol_txrx_vdev_attach failed");
		status = VOS_STATUS_E_FAILURE;
		wma_unified_vdev_delete_send(wma_handle->wmi_handle,
						self_sta_req->sessionId);
		goto end;
	}
	wma_handle->interfaces[self_sta_req->sessionId].handle = txrx_vdev_handle;
	vos_mem_copy(wma_handle->interfaces[self_sta_req->sessionId].addr,
		     self_sta_req->selfMacAddr,
		     sizeof(wma_handle->interfaces[self_sta_req->sessionId].addr));
	switch (self_sta_req->type) {
	case WMI_VDEV_TYPE_STA:
		if(wlan_cfgGetInt(mac, WNI_CFG_INFRA_STA_KEEP_ALIVE_PERIOD,
				  &cfg_val ) != eSIR_SUCCESS) {
			WMA_LOGE("Failed to get value for "
				 "WNI_CFG_INFRA_STA_KEEP_ALIVE_PERIOD");
			cfg_val = DEFAULT_INFRA_STA_KEEP_ALIVE_PERIOD;
		}

		wma_set_sta_keep_alive(wma_handle,
				       self_sta_req->sessionId,
				       SIR_KEEP_ALIVE_NULL_PKT,
				       cfg_val,
				       NULL,
				       NULL,
				       NULL);
		break;
	}

	wma_handle->interfaces[self_sta_req->sessionId].type =
		self_sta_req->type;
	wma_handle->interfaces[self_sta_req->sessionId].sub_type =
		self_sta_req->subType;

	if ((self_sta_req->type == WMI_VDEV_TYPE_AP) &&
			(self_sta_req->subType ==
			 WMI_UNIFIED_VDEV_SUBTYPE_P2P_DEVICE)) {
		WMA_LOGA("P2P Device: creating self peer %pM, vdev_id %hu",
				self_sta_req->selfMacAddr,
				self_sta_req->sessionId);
		status = wma_create_peer(wma_handle, txrx_pdev,
				txrx_vdev_handle, self_sta_req->selfMacAddr,
				self_sta_req->sessionId);
		if (status != VOS_STATUS_SUCCESS) {
			WMA_LOGE("%s: Failed to create peer\n", __func__);
			status = VOS_STATUS_E_FAILURE;
			wma_unified_vdev_delete_send(wma_handle->wmi_handle,
					self_sta_req->sessionId);
		}
	}

	if (wlan_cfgGetInt(mac, WNI_CFG_RTS_THRESHOLD,
			&cfg_val) == eSIR_SUCCESS) {
		ret = wmi_unified_vdev_set_param_send(wma_handle->wmi_handle,
						      self_sta_req->sessionId,
						      WMI_VDEV_PARAM_RTS_THRESHOLD,
						      cfg_val);
		if (ret)
			WMA_LOGE("Failed to set WMI_VDEV_PARAM_RTS_THRESHOLD");
	} else {
		WMA_LOGE("Failed to get value for WNI_CFG_RTS_THRESHOLD, leaving unchanged");
	}

	if (wlan_cfgGetInt(mac, WNI_CFG_FRAGMENTATION_THRESHOLD,
                        &cfg_val) == eSIR_SUCCESS) {
		ret = wmi_unified_vdev_set_param_send(wma_handle->wmi_handle,
						      self_sta_req->sessionId,
						      WMI_VDEV_PARAM_FRAGMENTATION_THRESHOLD,
						      cfg_val);
		if (ret)
			WMA_LOGE("Failed to set WMI_VDEV_PARAM_FRAGMENTATION_THRESHOLD");
	} else {
		WMA_LOGE("Failed to get value for WNI_CFG_FRAGMENTATION_THRESHOLD, leaving unchanged");
	}
	if (self_sta_req->type == WMI_VDEV_TYPE_STA) {
        /* Enable roaming offload
		 * return value is not significant because some firmware versions may have
		 * roam offload always enabled. It will stay enabled even if this command fails.
		 */
	ret = wmi_unified_vdev_set_param_send(wma_handle->wmi_handle, self_sta_req->sessionId,
						  WMI_VDEV_PARAM_ROAM_FW_OFFLOAD, 1);
	}

end:
	self_sta_req->status = status;
	wma_send_msg(wma_handle, WDA_ADD_STA_SELF_RSP, (void *)self_sta_req, 0);
	return txrx_vdev_handle;
}

static VOS_STATUS wma_wni_cfg_dnld(tp_wma_handle wma_handle)
{
	VOS_STATUS vos_status = VOS_STATUS_E_FAILURE;
	v_VOID_t *file_img = NULL;
	v_SIZE_t file_img_sz = 0;
	v_VOID_t *cfg_bin = NULL;
	v_SIZE_t cfg_bin_sz = 0;
	v_BOOL_t status = VOS_FALSE;
	v_VOID_t *mac = vos_get_context(VOS_MODULE_ID_PE,
			wma_handle->vos_context);

	WMA_LOGD("%s: Enter", __func__);

	if (NULL == mac) {
		WMA_LOGP("Invalid context");
		VOS_ASSERT(0);
		return VOS_STATUS_E_FAILURE;
	}

	/* get the number of bytes in the CFG Binary... */
	vos_status = vos_get_binary_blob(VOS_BINARY_ID_CONFIG, NULL,
			&file_img_sz);
	if (VOS_STATUS_E_NOMEM != vos_status) {
		WMA_LOGP("Error in obtaining the binary size");
		goto fail;
	}

	/* malloc a buffer to read in the Configuration binary file. */
	file_img = vos_mem_malloc(file_img_sz);
	if (NULL == file_img) {
		WMA_LOGP("Unable to allocate memory for the CFG binary"
				"[size= %d bytes]", file_img_sz);
		vos_status = VOS_STATUS_E_NOMEM;
		goto fail;
	}

	/* Get the entire CFG file image. */
	vos_status = vos_get_binary_blob(VOS_BINARY_ID_CONFIG, file_img,
			&file_img_sz);
	if (VOS_STATUS_SUCCESS != vos_status) {
		WMA_LOGP("Error: Cannot retrieve CFG file image from vOSS."
				"[size= %d bytes]", file_img_sz);
		goto fail;
	}

	/*
	 * Validate the binary image.  This function will return a pointer
	 * and length where the CFG binary is located within the binary image file.
	 */
	status = sys_validateStaConfig( file_img, file_img_sz,
			&cfg_bin, &cfg_bin_sz );
	if ( VOS_FALSE == status )
	{
		WMA_LOGP("Error: Cannot find STA CFG in binary image file.");
		vos_status = VOS_STATUS_E_FAILURE;
		goto fail;
	}
	/*
	 * TODO: call the config download function
	 * for now calling the existing cfg download API
	 */
	processCfgDownloadReq(mac, cfg_bin_sz, cfg_bin);
	if (file_img != NULL) {
		vos_mem_free(file_img);
	}

	WMA_LOGD("%s: Exit", __func__);
	return vos_status;

fail:
	if(cfg_bin != NULL)
		vos_mem_free( file_img );

	WMA_LOGD("%s: Exit", __func__);
	return vos_status;
}

/* function   : wma_set_scan_info
 * Descriptin : function to save current ongoing scan info
 * Args       : wma handle, scan id, scan requestor id, vdev id
 * Returns    : None
 */
static inline void wma_set_scan_info(tp_wma_handle wma_handle,
					u_int32_t scan_id,
					u_int32_t requestor,
					u_int32_t vdev_id,
					tSirP2pScanType p2p_scan_type)
{
	wma_handle->interfaces[vdev_id].scan_info.scan_id = scan_id;
	wma_handle->interfaces[vdev_id].scan_info.scan_requestor_id =
								requestor;
	wma_handle->interfaces[vdev_id].scan_info.p2p_scan_type = p2p_scan_type;
}

/* function   : wma_reset_scan_info
 * Descriptin : function to reset the current ongoing scan info
 * Args       : wma handle, vdev_id
 * Returns    : None
 */
static inline void wma_reset_scan_info(tp_wma_handle wma_handle,
				       u_int8_t vdev_id)
{
	vos_mem_zero((void *) &(wma_handle->interfaces[vdev_id].scan_info),
			sizeof(struct scan_param));
}

/* function   : wma_get_buf_start_scan_cmd
 * Descriptin :
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_get_buf_start_scan_cmd(tp_wma_handle wma_handle,
					tSirScanOffloadReq *scan_req,
					wmi_buf_t *buf,
					int *buf_len)
{
	wmi_start_scan_cmd_fixed_param *cmd;
	wmi_chan_list *chan_list = NULL;
	wmi_mac_addr *bssid;
	wmi_ssid *ssid = NULL;
	u_int32_t *tmp_ptr, ie_len_with_pad;
	VOS_STATUS vos_status = VOS_STATUS_E_FAILURE;
	u_int8_t *buf_ptr;
	int i;
	int len = sizeof(*cmd);

	len += WMI_TLV_HDR_SIZE; /* Length TLV placeholder for array of uint32 */
	/* calculate the length of buffer required */
	if (scan_req->channelList.numChannels)
		len += scan_req->channelList.numChannels * sizeof(u_int32_t);

	len += WMI_TLV_HDR_SIZE; /* Length TLV placeholder for array of wmi_ssid structures */
	if (scan_req->numSsid)
		len += scan_req->numSsid * sizeof(wmi_ssid);

	len += WMI_TLV_HDR_SIZE; /* Length TLV placeholder for array of wmi_mac_addr structures */
	len += sizeof(wmi_mac_addr);

	len += WMI_TLV_HDR_SIZE; /* Length TLV placeholder for array of bytes */
	if (scan_req->uIEFieldLen)
		len += roundup(scan_req->uIEFieldLen, sizeof(u_int32_t));

	/* Allocate the memory */
	*buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (!*buf) {
		WMA_LOGP("failed to allocate memory for start scan cmd");
		vos_status = VOS_STATUS_E_FAILURE;
		goto error;
	}

	buf_ptr = (u_int8_t *) wmi_buf_data(*buf);
	cmd = (wmi_start_scan_cmd_fixed_param *) buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_start_scan_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_start_scan_cmd_fixed_param));

	cmd->vdev_id = scan_req->sessionId;
	/*TODO: Populate actual values */
	cmd->scan_id = WMA_HOST_SCAN_REQID_PREFIX | ++wma_handle->scan_id;
	cmd->scan_priority = WMA_DEFAULT_SCAN_PRIORITY;
	cmd->scan_req_id = WMA_HOST_SCAN_REQUESTOR_ID_PREFIX |
			   WMA_DEFAULT_SCAN_REQUESTER_ID;

	/* Set the scan events which the driver is intereseted to receive */
	/* TODO: handle all the other flags also */
	cmd->notify_scan_events = WMI_SCAN_EVENT_STARTED |
				WMI_SCAN_EVENT_START_FAILED |
				WMI_SCAN_EVENT_FOREIGN_CHANNEL |
				WMI_SCAN_EVENT_COMPLETED;

	cmd->dwell_time_active = scan_req->maxChannelTime;
	cmd->dwell_time_passive = scan_req->maxChannelTime;

	cmd->max_scan_time = WMA_HW_DEF_SCAN_MAX_DURATION;
	cmd->scan_ctrl_flags |= WMI_SCAN_ADD_OFDM_RATES;

	if (!scan_req->p2pScanType) {
		WMA_LOGD("Normal Scan request");
		cmd->scan_ctrl_flags |= WMI_SCAN_ADD_CCK_RATES;
		cmd->scan_ctrl_flags |= WMI_SCAN_ADD_BCAST_PROBE_REQ;
		if (scan_req->scanType == eSIR_PASSIVE_SCAN)
			cmd->scan_ctrl_flags |= WMI_SCAN_FLAG_PASSIVE;
		cmd->scan_ctrl_flags |= WMI_SCAN_FILTER_PROBE_REQ;
		cmd->repeat_probe_time = scan_req->maxChannelTime/3;
	}
	else {
		WMA_LOGD("P2P Scan");
		switch (scan_req->p2pScanType) {
		case P2P_SCAN_TYPE_LISTEN:
			WMA_LOGD("P2P_SCAN_TYPE_LISTEN");
			cmd->scan_ctrl_flags |= WMI_SCAN_FLAG_PASSIVE;
			cmd->notify_scan_events |=
				WMI_SCAN_EVENT_FOREIGN_CHANNEL;
			cmd->repeat_probe_time = 0;
			break;
		case P2P_SCAN_TYPE_SEARCH:
			WMA_LOGD("P2P_SCAN_TYPE_SEARCH");
			cmd->scan_ctrl_flags |= WMI_SCAN_FILTER_PROBE_REQ;
			cmd->repeat_probe_time = scan_req->maxChannelTime/3;
			break;
		default:
			WMA_LOGE("Invalid scan type");
			goto error;
		}
	}

	buf_ptr += sizeof(*cmd);
	tmp_ptr = (u_int32_t *) (buf_ptr + WMI_TLV_HDR_SIZE);

	if (scan_req->channelList.numChannels) {
		chan_list = (wmi_chan_list *) tmp_ptr;
		cmd->num_chan = scan_req->channelList.numChannels;
		for (i = 0; i < scan_req->channelList.numChannels; ++i) {
			tmp_ptr[i] = vos_chan_to_freq(
					scan_req->channelList.channelNumber[i]);
		}
	}
	WMITLV_SET_HDR(buf_ptr,
		       WMITLV_TAG_ARRAY_UINT32,
		       (cmd->num_chan * sizeof(u_int32_t)));
	buf_ptr += WMI_TLV_HDR_SIZE + (cmd->num_chan * sizeof(u_int32_t));

	cmd->num_ssids = scan_req->numSsid;
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_FIXED_STRUC,
		       (cmd->num_ssids * sizeof(wmi_ssid)));
	if (scan_req->numSsid) {
		ssid = (wmi_ssid *) (buf_ptr + WMI_TLV_HDR_SIZE);
		for (i = 0; i < scan_req->numSsid; ++i) {
			ssid->ssid_len = scan_req->ssId[i].length;
			vos_mem_copy(ssid->ssid, scan_req->ssId[i].ssId,
					scan_req->ssId[i].length);
			ssid++;
		}
	}
	buf_ptr +=  WMI_TLV_HDR_SIZE + (cmd->num_ssids * sizeof(wmi_ssid));

	cmd->num_bssid = 1;
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_FIXED_STRUC,
		       (cmd->num_bssid * sizeof(wmi_mac_addr)));
	bssid = (wmi_mac_addr *) (buf_ptr + WMI_TLV_HDR_SIZE);
	WMI_CHAR_ARRAY_TO_MAC_ADDR(scan_req->bssId, bssid);
	buf_ptr += WMI_TLV_HDR_SIZE + (cmd->num_bssid * sizeof(wmi_mac_addr));

	cmd->ie_len = scan_req->uIEFieldLen;
	ie_len_with_pad = roundup(scan_req->uIEFieldLen, sizeof(u_int32_t));
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_BYTE, ie_len_with_pad);
	if (scan_req->uIEFieldLen) {
		vos_mem_copy(buf_ptr + WMI_TLV_HDR_SIZE,
			     (u_int8_t *)scan_req +
			     (scan_req->uIEFieldOffset),
			     scan_req->uIEFieldLen);
	}
	buf_ptr += WMI_TLV_HDR_SIZE + ie_len_with_pad;

	*buf_len = len;
	vos_status = VOS_STATUS_SUCCESS;
error:
	vos_mem_free(scan_req);
	return vos_status;
}

/* function   : wma_get_buf_stop_scan_cmd
 * Descriptin : function to fill the args for wmi_stop_scan_cmd
 * Args       : wma handle, wmi command buffer, buffer length, vdev_id
 * Returns    : failure or success
 */
VOS_STATUS wma_get_buf_stop_scan_cmd(tp_wma_handle wma_handle,
					wmi_buf_t *buf,
					int *buf_len,
					tAbortScanParams *abort_scan_req)
{
	wmi_stop_scan_cmd_fixed_param *cmd;
	VOS_STATUS vos_status;
	int len = sizeof(*cmd);

	/* Allocate the memory */
	*buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (!*buf) {
		WMA_LOGP("failed to allocate memory for stop scan cmd");
		vos_status = VOS_STATUS_E_FAILURE;
		goto error;
	}

	cmd = (wmi_stop_scan_cmd_fixed_param *) wmi_buf_data(*buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_stop_scan_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(wmi_stop_scan_cmd_fixed_param));
	cmd->vdev_id = abort_scan_req->SessionId;
	cmd->requestor =
	      wma_handle->interfaces[cmd->vdev_id].scan_info.scan_requestor_id;
	cmd->scan_id = wma_handle->interfaces[cmd->vdev_id].scan_info.scan_id;
	/* stop the scan with the corresponding scan_id */
	cmd->req_type = WMI_SCAN_STOP_ONE;

	*buf_len = len;
	vos_status = VOS_STATUS_SUCCESS;
error:
	vos_mem_free(abort_scan_req);
	return vos_status;

}

/* function   : wma_start_scan
 * Descriptin :
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_start_scan(tp_wma_handle wma_handle,
			tSirScanOffloadReq *scan_req)
{
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
	wmi_buf_t buf;
	wmi_start_scan_cmd_fixed_param *cmd;
	int status = 0;
	int len;
	tSirScanOffloadEvent *scan_event;

	/* Sanity check to find whether vdev id active or not */
	if (!wma_handle->interfaces[scan_req->sessionId].handle) {
		WMA_LOGA("vdev id [%d] is not active", scan_req->sessionId);
		goto error1;
	}

	/* Fill individual elements of wmi_start_scan_req and
	 * TLV for channel list, bssid, ssid etc ... */
	vos_status = wma_get_buf_start_scan_cmd(wma_handle, scan_req,
			&buf, &len);
	if (vos_status != VOS_STATUS_SUCCESS) {
		WMA_LOGE("Failed to get buffer for start scan cmd");
		goto error1;
	}

	/* Save current scan info */
	cmd = (wmi_start_scan_cmd_fixed_param *) wmi_buf_data(buf);

	wma_set_scan_info(wma_handle, cmd->scan_id,
			cmd->scan_req_id, cmd->vdev_id,
			scan_req->p2pScanType);

	status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
			len, WMI_START_SCAN_CMDID);
	/* Call the wmi api to request the scan */
	if (status != EOK) {
		WMA_LOGE("wmi_unified_cmd_send returned Error %d",
			status);
		vos_status = VOS_STATUS_E_FAILURE;
		goto error;
	}

	WMA_LOGI("WMA --> WMI_START_SCAN_CMDID");
	return VOS_STATUS_SUCCESS;
error:
	wma_reset_scan_info(wma_handle, cmd->vdev_id);
	if (buf)
		adf_nbuf_free(buf);
error1:
	scan_event = (tSirScanOffloadEvent *) vos_mem_malloc
		(sizeof(tSirScanOffloadEvent));
	if (!scan_event) {
		WMA_LOGP("Failed to allocate memory for scan rsp");
		return VOS_STATUS_E_NOMEM;
	}
	scan_event->event = WMI_SCAN_EVENT_COMPLETED;
	scan_event->reasonCode = eSIR_SME_SCAN_FAILED;
	wma_send_msg(wma_handle, WDA_RX_SCAN_EVENT, (void *) scan_event, 0) ;

	return vos_status;
}

/* function   : wma_stop_scan
 * Descriptin : function to send the stop scan command
 * Args       : wma_handle
 * Returns    : failure or success
 */
VOS_STATUS wma_stop_scan(tp_wma_handle wma_handle,
			 tAbortScanParams *abort_scan_req)
{
	VOS_STATUS vos_status;
	wmi_buf_t buf;
	int status = 0;
	int len;

	vos_status = wma_get_buf_stop_scan_cmd(wma_handle, &buf, &len,
					       abort_scan_req);
	if (vos_status != VOS_STATUS_SUCCESS) {
		WMA_LOGE("Failed to get buffer for stop scan cmd");
		goto error1;
	}

	status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
			len, WMI_STOP_SCAN_CMDID);
	/* Call the wmi api to request the scan */
	if (status != EOK) {
		WMA_LOGE("wmi_unified_cmd_send WMI_STOP_SCAN_CMDID returned Error %d",
			status);
		vos_status = VOS_STATUS_E_FAILURE;
		goto error;
	}

	WMA_LOGI("WMA --> WMI_STOP_SCAN_CMDID");

	return VOS_STATUS_SUCCESS;
error:
	if (buf)
		adf_nbuf_free(buf);
error1:
	return vos_status;
}

/* function   : wma_update_channel_list
 * Descriptin : Function is used to update the support channel list
 * Args       : wma_handle, list of supported channels and power
 * Returns    : SUCCESS or FAILURE
 */
VOS_STATUS wma_update_channel_list(WMA_HANDLE handle,
				tSirUpdateChanList *chan_list)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	wmi_buf_t buf;
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
	wmi_scan_chan_list_cmd_fixed_param *cmd;
	int status, i;
	u_int8_t *buf_ptr;
	wmi_channel *chan_info;
	u_int16_t len = sizeof(*cmd) + WMI_TLV_HDR_SIZE;

	len += sizeof(wmi_channel) * chan_list->numChan;
	buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("Failed to allocate memory");
		vos_status = VOS_STATUS_E_NOMEM;
		goto end;
	}

	buf_ptr = (u_int8_t *) wmi_buf_data(buf);
	cmd = (wmi_scan_chan_list_cmd_fixed_param *) buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_scan_chan_list_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_scan_chan_list_cmd_fixed_param));

	WMA_LOGD("no of channels = %d, len = %d", chan_list->numChan, len);

	cmd->num_scan_chans = chan_list->numChan;
	WMITLV_SET_HDR((buf_ptr + sizeof(wmi_scan_chan_list_cmd_fixed_param)),
		       WMITLV_TAG_ARRAY_STRUC,
		       sizeof(wmi_channel) * chan_list->numChan);
	chan_info = (wmi_channel *) (buf_ptr + sizeof(*cmd) + WMI_TLV_HDR_SIZE);

	for (i = 0; i < chan_list->numChan; ++i) {
		WMITLV_SET_HDR(&chan_info->tlv_header,
			       WMITLV_TAG_STRUC_wmi_channel,
			       WMITLV_GET_STRUCT_TLVLEN(wmi_channel));
		chan_info->mhz =
			vos_chan_to_freq(chan_list->chanParam[i].chanId);
		chan_info->band_center_freq1 = chan_info->mhz;
		chan_info->band_center_freq2 = 0;

		WMA_LOGD("chan[%d] = %u", i, chan_info->mhz);

		if (chan_info->mhz < WMA_2_4_GHZ_MAX_FREQ) {
			WMI_SET_CHANNEL_MODE(chan_info, MODE_11G);
		} else {
			WMI_SET_CHANNEL_MODE(chan_info, MODE_11A);
		}

		WMI_SET_CHANNEL_MAX_POWER(chan_info,
					  chan_list->chanParam[i].pwr);

		WMI_SET_CHANNEL_REG_POWER(chan_info,
					  chan_list->chanParam[i].pwr);
		/*TODO: Set WMI_SET_CHANNEL_MIN_POWER */
		/*TODO: Set WMI_SET_CHANNEL_ANTENNA_MAX */
		/*TODO: WMI_SET_CHANNEL_REG_CLASSID*/
		chan_info++;
	}

	status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
			WMI_SCAN_CHAN_LIST_CMDID);

	if (status != EOK) {
		vos_status = VOS_STATUS_E_FAILURE;
		WMA_LOGE("Failed to send WMI_SCAN_CHAN_LIST_CMDID");
		wmi_buf_free(buf);
	}
end:
	return vos_status;
}

/* function   : wma_roam_scan_offload_mode
 * Descriptin : send WMI_ROAM_SCAN_MODE TLV to firmware. It has a piggyback
 *            : of WMI_ROAM_SCAN_MODE.
 * Args       : scan_cmd_fp contains the scan parameters.
 *            : mode controls rssi based and periodic scans by roam engine.
 * Returns    :
 */
VOS_STATUS wma_roam_scan_offload_mode(tp_wma_handle wma_handle, u_int8_t sessionId,
        wmi_start_scan_cmd_fixed_param *scan_cmd_fp, u_int32_t mode)
{
    VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
    wmi_buf_t buf = NULL;
    int status = 0;
    int len;
    wmi_roam_scan_mode_fixed_param *roam_scan_mode_fp;
    u_int8_t *buf_ptr;

    /* Need to create a buf with roam_scan command at front and piggyback with scan command */
    len = sizeof(wmi_roam_scan_mode_fixed_param) + sizeof(wmi_start_scan_cmd_fixed_param);
    buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
    if (!buf) {
        WMA_LOGD("%s : wmi_buf_alloc failed\n", __func__);
        return VOS_STATUS_E_NOMEM;
    }

    buf_ptr = (u_int8_t *) wmi_buf_data(buf);
    roam_scan_mode_fp = (wmi_roam_scan_mode_fixed_param *) buf_ptr;
    WMITLV_SET_HDR(&roam_scan_mode_fp->tlv_header,
               WMITLV_TAG_STRUC_wmi_roam_scan_mode_fixed_param,
               WMITLV_GET_STRUCT_TLVLEN(wmi_roam_scan_mode_fixed_param));

    roam_scan_mode_fp->roam_scan_mode = mode;
    roam_scan_mode_fp->vdev_id = sessionId;
    /* Fill in scan parameters suitable for roaming scan */
    buf_ptr += sizeof(wmi_roam_scan_mode_fixed_param);
    vos_mem_copy(buf_ptr, scan_cmd_fp, sizeof(wmi_start_scan_cmd_fixed_param));
    /* Ensure there is no additional IEs */
    scan_cmd_fp->ie_len = 0;
    WMITLV_SET_HDR(buf_ptr,
               WMITLV_TAG_STRUC_wmi_start_scan_cmd_fixed_param,
               WMITLV_GET_STRUCT_TLVLEN(wmi_start_scan_cmd_fixed_param));
    status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
            len, WMI_ROAM_SCAN_MODE);
    if (status != EOK) {
        WMA_LOGE("wmi_unified_cmd_send WMI_ROAM_SCAN_MODE returned Error %d",
            status);
        vos_status = VOS_STATUS_E_FAILURE;
        goto error;
    }

    WMA_LOGI("%s: WMA --> WMI_ROAM_SCAN_MODE", __func__);
    return VOS_STATUS_SUCCESS;
error:
    wmi_buf_free(buf);

    return vos_status;
}

/* function   : wma_roam_scan_offload_rssi_threshold
 * Descriptin : Send WMI_ROAM_SCAN_RSSI_THRESHOLD TLV to firmware
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_roam_scan_offload_rssi_thresh(tp_wma_handle wma_handle, u_int8_t sessionId,
            A_UINT32 rssi_thresh, A_UINT32 rssi_thresh_diff)
{
    VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
    wmi_buf_t buf = NULL;
    int status = 0;
    int len;
    u_int8_t *buf_ptr;
    wmi_roam_scan_rssi_threshold_fixed_param *rssi_threshold_fp;

    /* Send rssi threshold */
    len = sizeof(wmi_roam_scan_rssi_threshold_fixed_param);
    buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
    if (!buf) {
        WMA_LOGE("%s : wmi_buf_alloc failed\n", __func__);
        return VOS_STATUS_E_NOMEM;
    }

    buf_ptr = (u_int8_t *) wmi_buf_data(buf);
    rssi_threshold_fp = (wmi_roam_scan_rssi_threshold_fixed_param *) buf_ptr;
    WMITLV_SET_HDR(&rssi_threshold_fp->tlv_header,
               WMITLV_TAG_STRUC_wmi_roam_scan_rssi_threshold_fixed_param,
               WMITLV_GET_STRUCT_TLVLEN(
                   wmi_roam_scan_rssi_threshold_fixed_param));
    /* fill in threshold values */
    rssi_threshold_fp->vdev_id = sessionId;
    rssi_threshold_fp->roam_scan_rssi_thresh = rssi_thresh;
    rssi_threshold_fp->roam_rssi_thresh_diff = rssi_thresh_diff;

    status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
            len, WMI_ROAM_SCAN_RSSI_THRESHOLD);
    if (status != EOK) {
        WMA_LOGE("wmi_unified_cmd_send WMI_ROAM_SCAN_RSSI_THRESHOLD returned Error %d",
            status);
        vos_status = VOS_STATUS_E_FAILURE;
        goto error;
    }

    WMA_LOGI("%s: WMA --> WMI_ROAM_SCAN_RSSI_THRESHOLD roam_scan_rssi_thresh=%d, roam_rssi_thresh_diff=%d",
                    __func__, rssi_thresh, rssi_thresh_diff);
    return VOS_STATUS_SUCCESS;
error:
    wmi_buf_free(buf);

    return vos_status;
}

/* function   : wma_roam_scan_offload_scan_period
 * Descriptin : Send WMI_ROAM_SCAN_PERIOD TLV to firmware
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_roam_scan_offload_scan_period(tp_wma_handle wma_handle, u_int8_t sessionId,
            A_UINT32 scan_period, A_UINT32 scan_age)
{
    VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
    wmi_buf_t buf = NULL;
    int status = 0;
    int len;
    u_int8_t *buf_ptr;
    wmi_roam_scan_period_fixed_param *scan_period_fp;

    /* Send scan period values */
    len = sizeof(wmi_roam_scan_period_fixed_param);
    buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
    if (!buf) {
        WMA_LOGE("%s : wmi_buf_alloc failed\n", __func__);
        return VOS_STATUS_E_NOMEM;
    }

    buf_ptr = (u_int8_t *) wmi_buf_data(buf);
    scan_period_fp = (wmi_roam_scan_period_fixed_param *) buf_ptr;
    WMITLV_SET_HDR(&scan_period_fp->tlv_header,
               WMITLV_TAG_STRUC_wmi_roam_scan_period_fixed_param,
               WMITLV_GET_STRUCT_TLVLEN(
                   wmi_roam_scan_period_fixed_param));
    /* fill in scan period values */
    scan_period_fp->vdev_id = sessionId;
    scan_period_fp->roam_scan_period = scan_period; /* 20 seconds */
    scan_period_fp->roam_scan_age = scan_age;

    status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
            len, WMI_ROAM_SCAN_PERIOD);
    if (status != EOK) {
        WMA_LOGE("wmi_unified_cmd_send WMI_ROAM_SCAN_PERIOD returned Error %d",
            status);
        vos_status = VOS_STATUS_E_FAILURE;
        goto error;
    }

    WMA_LOGI("%s: WMA --> WMI_ROAM_SCAN_PERIOD roam_scan_period=%d, roam_scan_age=%d",
                    __func__, scan_period, scan_age);
    return VOS_STATUS_SUCCESS;
error:
    wmi_buf_free(buf);

    return vos_status;
}
/* function   : wma_roam_scan_offload_rssi_change
 * Descriptin : Send WMI_ROAM_SCAN_RSSI_CHANGE_THRESHOLD TLV to firmware
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_roam_scan_offload_rssi_change(tp_wma_handle wma_handle, u_int8_t sessionId,
            A_UINT32 rssi_change_thresh, A_UINT32 bcn_rssi_weight)
{
    VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
    wmi_buf_t buf = NULL;
    int status = 0;
    int len;
    u_int8_t *buf_ptr;
    wmi_roam_scan_rssi_change_threshold_fixed_param *rssi_change_fp;

    /* Send rssi change parameters */
    len = sizeof(wmi_roam_scan_rssi_change_threshold_fixed_param);
    buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
    if (!buf) {
        WMA_LOGE("%s : wmi_buf_alloc failed\n", __func__);
        return VOS_STATUS_E_NOMEM;
    }

    buf_ptr = (u_int8_t *) wmi_buf_data(buf);
    rssi_change_fp = (wmi_roam_scan_rssi_change_threshold_fixed_param *) buf_ptr;
    WMITLV_SET_HDR(&rssi_change_fp->tlv_header,
               WMITLV_TAG_STRUC_wmi_roam_scan_rssi_change_threshold_fixed_param,
               WMITLV_GET_STRUCT_TLVLEN(
                   wmi_roam_scan_rssi_change_threshold_fixed_param));
    /* fill in rssi change threshold (hysteresis) values */
    rssi_change_fp->vdev_id = sessionId;
    rssi_change_fp->roam_scan_rssi_change_thresh = rssi_change_thresh;
    rssi_change_fp->bcn_rssi_weight = bcn_rssi_weight;

    status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
            len, WMI_ROAM_SCAN_RSSI_CHANGE_THRESHOLD);
    if (status != EOK) {
        WMA_LOGE("wmi_unified_cmd_send WMI_ROAM_SCAN_RSSI_CHANGE_THRESHOLD returned Error %d",
            status);
        vos_status = VOS_STATUS_E_FAILURE;
        goto error;
    }

    WMA_LOGI("%s: WMA --> WMI_ROAM_SCAN_RSSI_CHANGE_THERSHOLD roam_scan_rssi_change_thresh=%d, bcn_rssi_weight=%d",
                    __func__, rssi_change_thresh, bcn_rssi_weight);
    return VOS_STATUS_SUCCESS;
error:
    wmi_buf_free(buf);

    return vos_status;
}

/* function   : wma_roam_scan_offload_chan_list
 * Descriptin : Send WMI_ROAM_CHAN_LIST TLV to firmware
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_roam_scan_offload_chan_list(tp_wma_handle wma_handle, u_int8_t sessionId,
            u_int8_t chan_count, u_int8_t *chan_list)
{
    VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
    wmi_buf_t buf = NULL;
    int status = 0;
    int len, list_tlv_len;
    int i;
    u_int8_t *buf_ptr;
    wmi_roam_chan_list_fixed_param *chan_list_fp;
    A_UINT32    *roam_chan_list_array;

    if (chan_count == 0)
    {
        WMA_LOGD("%s : invalid number of channels %d\n", __func__, chan_count);
        return VOS_STATUS_E_INVAL;
    }
    /* Channel list is a table of 2 TLV's */
    list_tlv_len = WMI_TLV_HDR_SIZE + chan_count * sizeof(A_UINT32);
    len = sizeof(wmi_roam_chan_list_fixed_param) + list_tlv_len;
    buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
    if (!buf) {
        WMA_LOGE("%s : wmi_buf_alloc failed\n", __func__);
        return VOS_STATUS_E_NOMEM;
    }

    buf_ptr = (u_int8_t *) wmi_buf_data(buf);
    chan_list_fp = (wmi_roam_chan_list_fixed_param *) buf_ptr;
    WMITLV_SET_HDR(&chan_list_fp->tlv_header,
               WMITLV_TAG_STRUC_wmi_roam_chan_list_fixed_param,
               WMITLV_GET_STRUCT_TLVLEN(wmi_roam_chan_list_fixed_param));
    chan_list_fp->vdev_id = sessionId;
    chan_list_fp->num_chan = chan_count;
    chan_list_fp->chan_list_type = WMI_ROAM_SCAN_CHAN_LIST_TYPE_STATIC;

    buf_ptr += sizeof(wmi_roam_chan_list_fixed_param);
    WMITLV_SET_HDR(buf_ptr,    WMITLV_TAG_ARRAY_UINT32,
               (chan_list_fp->num_chan * sizeof(u_int32_t)));
    roam_chan_list_array = (A_UINT32 *)(buf_ptr + WMI_TLV_HDR_SIZE);
    WMA_LOGI("%s: %d channels = ", __func__, chan_list_fp->num_chan);
    for (i = 0; i < chan_list_fp->num_chan; i++) {
        roam_chan_list_array[i] = vos_chan_to_freq(chan_list[i]);
        WMA_LOGI("%d,",roam_chan_list_array[i]);
    }
    WMA_LOGI("\n");

    status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
            len, WMI_ROAM_CHAN_LIST);
    if (status != EOK) {
        WMA_LOGE("wmi_unified_cmd_send WMI_ROAM_CHAN_LIST returned Error %d",
            status);
        vos_status = VOS_STATUS_E_FAILURE;
        goto error;
    }

    WMA_LOGI("%s: WMA --> WMI_ROAM_SCAN_CHAN_LIST", __func__);
    return VOS_STATUS_SUCCESS;
error:
    wmi_buf_free(buf);

    return vos_status;
}

/* function   : eCsrAuthType_to_rsn_authmode
 * Descriptin : Map CSR's authentication type into RSN auth mode used by firmware
 * Args       :
 * Returns    :
 */


A_UINT32 eCsrAuthType_to_rsn_authmode (eCsrAuthType authtype) {
    switch(authtype) {
        case    eCSR_AUTH_TYPE_OPEN_SYSTEM:
            return (IEEE80211_AUTH_OPEN);
        case    eCSR_AUTH_TYPE_WPA:
        case    eCSR_AUTH_TYPE_WPA_PSK:
            return(IEEE80211_AUTH_WPA);
        case    eCSR_AUTH_TYPE_RSN:
        case    eCSR_AUTH_TYPE_RSN_PSK:
#if defined WLAN_FEATURE_VOWIFI_11R
        case    eCSR_AUTH_TYPE_FT_RSN:
        case    eCSR_AUTH_TYPE_FT_RSN_PSK:
            return(IEEE80211_AUTH_RSNA);
#endif
#ifdef FEATURE_WLAN_WAPI
        case    eCSR_AUTH_TYPE_WAPI_WAI_CERTIFICATE:
        case    eCSR_AUTH_TYPE_WAPI_WAI_PSK:
            return(IEEE80211_AUTH_WAPI);
#endif
#ifdef FEATURE_WLAN_CCX
        case    eCSR_AUTH_TYPE_CCKM_WPA:
        case    eCSR_AUTH_TYPE_CCKM_RSN:
            return(IEEE80211_AUTH_CCKM);
#endif
        default:
            return(WMI_AUTH_NONE);
    }
}

/* function   : eCsrEncryptionType_to_rsn_cipherset
 * Descriptin : Map CSR's encryption type into RSN cipher types used by firmware
 * Args       :
 * Returns    :
 */

A_UINT32 eCsrEncryptionType_to_rsn_cipherset (eCsrEncryptionType encr) {

    switch (encr) {
        case    eCSR_ENCRYPT_TYPE_WEP40_STATICKEY:
        case    eCSR_ENCRYPT_TYPE_WEP104_STATICKEY:
        case    eCSR_ENCRYPT_TYPE_WEP40:
        case    eCSR_ENCRYPT_TYPE_WEP104:
            return (IEEE80211_CIPHER_WEP);
        case    eCSR_ENCRYPT_TYPE_TKIP:
            return (IEEE80211_CIPHER_TKIP);
        case    eCSR_ENCRYPT_TYPE_AES:
            return (IEEE80211_CIPHER_AES_CCM);
#ifdef FEATURE_WLAN_WAPI
        case    eCSR_ENCRYPT_TYPE_WPI:
            return (IEEE80211_CIPHER_WAPI);
#endif /* FEATURE_WLAN_WAPI */
        case    eCSR_ENCRYPT_TYPE_ANY:
        case    eCSR_ENCRYPT_TYPE_NONE:
        default:
            return (IEEE80211_CIPHER_NONE);
    }
}

/* function   : wma_roam_scan_fill_ap_profile
 * Descriptin : Fill ap_profile structure from configured parameters
 * Args       :
 * Returns    :
 */
v_VOID_t wma_roam_scan_fill_ap_profile(tp_wma_handle wma_handle, tpAniSirGlobal pMac,
tANI_U8 sessionId, wmi_ap_profile *ap_profile_p)
{
    ap_profile_p->ssid.ssid_len = pMac->roam.roamSession[sessionId].connectedProfile.SSID.length;
    vos_mem_copy(ap_profile_p->ssid.ssid,
                 pMac->roam.roamSession[sessionId].connectedProfile.SSID.ssId,
                 ap_profile_p->ssid.ssid_len);
    ap_profile_p->rsn_authmode =
            eCsrAuthType_to_rsn_authmode(pMac->roam.roamSession[sessionId].connectedProfile.AuthType);
    ap_profile_p->rsn_ucastcipherset =
            eCsrEncryptionType_to_rsn_cipherset(pMac->roam.roamSession[sessionId].connectedProfile.EncryptionType);
    ap_profile_p->rsn_mcastcipherset =
            eCsrEncryptionType_to_rsn_cipherset(pMac->roam.roamSession[sessionId].connectedProfile.mcEncryptionType);
    ap_profile_p->rsn_mcastmgmtcipherset = ap_profile_p->rsn_mcastcipherset;
    // DPD @@ ap_profile_p->rssi_threshold = pMac->roam.configParam.vccRssiThreshold;
    ap_profile_p->rssi_threshold = 5;
}

/* function   : wma_roam_scan_scan_params
 * Descriptin : Fill scan_params structure from configured parameters
 * Args       : roam_req pointer = NULL if this routine is called before connect
 *            : It will be non-NULL if called after assoc.
 * Returns    :
 */
v_VOID_t wma_roam_scan_fill_scan_params(tp_wma_handle wma_handle, tpAniSirGlobal pMac,
        tSirRoamOffloadScanReq *roam_req, wmi_start_scan_cmd_fixed_param *scan_params)
{
    /* Pronto values
     * scan_params.dwell_time_active = tSirRoamOffloadScanReq->NeighborScanChannelMaxTime;
     * scan_params.dwell_time_passive = tSirRoamOffloadScanReq->NeighborScanChannelMaxTime;
     * scan_params.min_rest_time = tSirRoamOffloadScanReq->NeighborScanTimerPeriod;
     * scan_params.max_rest_time = tSirRoamOffloadScanReq->NeighborScanTimerPeriod;
     * scan_params.repeat_probe_time = 50;
     * scan_params.probe_spacing_time = 0;
     * scan_params.probe_delay = 0;
     * scan_params.max_scan_time = 50000;
     * scan_params.idle_time = 200;
     */

    /*
     * Currently it uses default parameters similar to Windows platform.
     * They will be tuned after experiments and matching with CSR parameters
     * used for Pronto.
     */
    scan_params->dwell_time_active = 500;
    scan_params->dwell_time_passive = 500;
    scan_params->min_rest_time = 50;
    scan_params->max_rest_time = 500;
    scan_params->repeat_probe_time = 50;
    scan_params->probe_spacing_time = 0;
    scan_params->probe_delay = 0;
    scan_params->max_scan_time = 50000;
    scan_params->idle_time = 200;
}
/* function   : wma_roam_scan_offload_ap_profile
 * Descriptin : Send WMI_ROAM_AP_PROFILE TLV to firmware
 * Args       : AP profile parameters are passed in as the structure used in TLV
 * Returns    :
 */
VOS_STATUS wma_roam_scan_offload_ap_profile(tp_wma_handle wma_handle, u_int8_t sessionId,
        wmi_ap_profile *ap_profile_p)
{
    VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
    wmi_buf_t buf = NULL;
    int status = 0;
    int len;
    u_int8_t *buf_ptr;
    wmi_roam_ap_profile_fixed_param *roam_ap_profile_fp;

    len = sizeof(wmi_roam_ap_profile_fixed_param) +
          sizeof(wmi_ap_profile);

    buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
    if (!buf) {
        WMA_LOGE("%s : wmi_buf_alloc failed\n", __func__);
        return VOS_STATUS_E_NOMEM;
    }

    buf_ptr = (u_int8_t *) wmi_buf_data(buf);
    roam_ap_profile_fp = (wmi_roam_ap_profile_fixed_param *) buf_ptr;
    WMITLV_SET_HDR(&roam_ap_profile_fp->tlv_header,
               WMITLV_TAG_STRUC_wmi_roam_ap_profile_fixed_param,
               WMITLV_GET_STRUCT_TLVLEN(
                   wmi_roam_ap_profile_fixed_param));
    /* fill in threshold values */
    roam_ap_profile_fp->vdev_id = sessionId;
    roam_ap_profile_fp->id = 0;
    buf_ptr += sizeof(wmi_roam_ap_profile_fixed_param);

    vos_mem_copy(buf_ptr, ap_profile_p, sizeof(wmi_ap_profile));
    WMITLV_SET_HDR(buf_ptr,
               WMITLV_TAG_STRUC_wmi_ap_profile,
               WMITLV_GET_STRUCT_TLVLEN(
                   wmi_ap_profile));
    status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
            len, WMI_ROAM_AP_PROFILE);
    if (status != EOK) {
        WMA_LOGE("wmi_unified_cmd_send WMI_ROAM_AP_PROFILE returned Error %d",
            status);
        vos_status = VOS_STATUS_E_FAILURE;
        goto error;
    }

    WMA_LOGI("WMA --> WMI_ROAM_AP_PROFILE and other parameters");
    return VOS_STATUS_SUCCESS;
error:
    wmi_buf_free(buf);

    return vos_status;
}

/* function   : wma_roam_scan_offload_init_connect
 * Descriptin : Rome firmware requires that roam scan engine is configured prior to
 *            : sending VDEV_UP command to firmware. This routine configures it
 *            : to default values with only periodic scan mode. Rssi triggerred scan
 *            : is not enabled, preventing unnecessary off-channel scans while EAPOL
 *            : handshake is completed.
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_roam_scan_offload_init_connect(tp_wma_handle wma_handle, u_int8_t sessionId)
{
    VOS_STATUS vos_status;
    tpAniSirGlobal pMac = (tpAniSirGlobal)vos_get_context(VOS_MODULE_ID_PE,
                wma_handle->vos_context);
    wmi_start_scan_cmd_fixed_param scan_params;
    wmi_ap_profile ap_profile;

    if (!pMac) {
        return VOS_STATUS_SUCCESS;
    }
    if (pMac->roam.roamSession[sessionId].connectedProfile.SSID.length == 0) {
        /* No need to configure roam scan for null SSID. */
        return VOS_STATUS_SUCCESS;
    }
    /* first program the parameters to conservative values so that roaming scan won't be
     * triggered before association completes
     */
    /* rssi_thresh = 10 is low enough */
    vos_status = wma_roam_scan_offload_rssi_thresh(wma_handle, sessionId, 10, 30);
    vos_status = wma_roam_scan_offload_scan_period(wma_handle, sessionId,
                                                   100000, 500000);
    vos_status = wma_roam_scan_offload_rssi_change(wma_handle, sessionId,
                                                   15, 14);
    wma_roam_scan_fill_ap_profile(wma_handle, pMac, sessionId, &ap_profile);

    vos_status = wma_roam_scan_offload_ap_profile(wma_handle, sessionId, &ap_profile);

    wma_roam_scan_fill_scan_params(wma_handle, pMac, NULL, &scan_params);
    vos_status = wma_roam_scan_offload_mode(wma_handle, sessionId, &scan_params,
            WMI_ROAM_SCAN_MODE_PERIODIC);
    return vos_status;
}


/* function   : wma_process_roam_scan_req
 * Descriptin : Main routine to handle ROAM commands coming from CSR module.
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_process_roam_scan_req(tp_wma_handle wma_handle,
            tSirRoamOffloadScanReq *roam_req)
{
    VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
    wmi_start_scan_cmd_fixed_param scan_params;
    wmi_ap_profile ap_profile;
    tpAniSirGlobal pMac = (tpAniSirGlobal)vos_get_context(VOS_MODULE_ID_PE,
                wma_handle->vos_context);
    A_UINT32    mode;

    vos_trace_setValue(VOS_MODULE_ID_WDA, VOS_TRACE_LEVEL_DEBUG, 1);
    WMA_LOGI("%s: command 0x%x\n", __func__, roam_req->Command);
    switch (roam_req->Command) {
        case ROAM_SCAN_OFFLOAD_START:
        case ROAM_SCAN_OFFLOAD_STOP:
            /* first program the parameters */
            /*
             * Scan/Roam threshold parameters are translated from fields of tSirRoamOffloadScanReq
             * to WMITLV values sent to Rome firmware.
             * roam_scan_rssi_thresh = tSirRoamOffloadScanReq->LookupThreshold
             * roam_rssi_thresh_diff = 50 - roam_scan_rssi_thresh (so that opportunistic low
             *                         priority scan will trigger at rssi < 50 db)
             * roam_scan_period = tSirRoamOffloadScanReq->neighborResultsRefreshPeriod,
             *                         default is 20000 (20 seconds)
             * roam_scan_age = 3 * roam_scan_period
             * roam_scan_rssi_change_thresh = 7 (trigger another roam scan only if rssi changes
             *                                more than this value).
             * bcn_rssi_weight = 14 (default used for hw generated beacon rssi interrupt)
             */

            /*
             * Current values for roaming parameters are hardcoded for initial testing.
             * They will be changed to values coming from tSirRoamOffloadScanReq after testing
             * and tuning.
             */
            if(wma_roam_scan_offload_rssi_thresh(wma_handle, roam_req->sessionId, 30, 30)
                                             != VOS_STATUS_SUCCESS) {
                break;
            }
            if (wma_roam_scan_offload_scan_period(wma_handle, roam_req->sessionId,
                                                  100000, 500000) != VOS_STATUS_SUCCESS) {
                break;
            }
            if (wma_roam_scan_offload_rssi_change(wma_handle, roam_req->sessionId,
                                                  15, 14) != VOS_STATUS_SUCCESS) {
                break;
            }
            wma_roam_scan_fill_ap_profile(wma_handle, pMac, roam_req->sessionId, &ap_profile);

            if (wma_roam_scan_offload_ap_profile(wma_handle, roam_req->sessionId,
                                              &ap_profile) != VOS_STATUS_SUCCESS) {
                break;
            }
            if (wma_roam_scan_offload_chan_list(wma_handle, roam_req->sessionId,
                                roam_req->ValidChannelCount,
                                &roam_req->ValidChannelList[0]) != VOS_STATUS_SUCCESS) {
                break;
            }


            wma_roam_scan_fill_scan_params(wma_handle, pMac, roam_req, &scan_params);
            if (roam_req->Command == ROAM_SCAN_OFFLOAD_START) {
                mode = (WMI_ROAM_SCAN_MODE_PERIODIC | WMI_ROAM_SCAN_MODE_RSSI_CHANGE);
            } else {
                mode = WMI_ROAM_SCAN_MODE_NONE; /* STOP */
            }
            vos_status = wma_roam_scan_offload_mode(wma_handle, roam_req->sessionId, &scan_params,
                            mode);
            break;

        case ROAM_SCAN_OFFLOAD_RESTART:
            /* Not needed. Rome offload engine does not stop after any scan */
            break;

        case ROAM_SCAN_OFFLOAD_UPDATE_CFG:
            /*
             * Runtime (after association) changes to rssi thresholds and other parameters.
             */
            if (wma_roam_scan_offload_rssi_thresh(wma_handle, roam_req->sessionId, 30, 30)
                                             != VOS_STATUS_SUCCESS) {
                break;
            }
            if (wma_roam_scan_offload_scan_period(wma_handle, roam_req->sessionId,
                                               20000, 120000) != VOS_STATUS_SUCCESS) {
                break;
            }
            wma_roam_scan_offload_rssi_change(wma_handle, roam_req->sessionId, 15, 14);
            break;

        default:
            break;
    }
    vos_mem_free(roam_req);
    return vos_status;
}

static WLAN_PHY_MODE wma_chan_to_mode(u8 chan, ePhyChanBondState chan_offset,
                                      u8 vht_capable)
{
	WLAN_PHY_MODE phymode = MODE_UNKNOWN;

	/* 2.4 GHz band */
	if ((chan >= WMA_11G_CHANNEL_BEGIN) && (chan <= WMA_11G_CHANNEL_END)) {
		switch (chan_offset) {
		case PHY_SINGLE_CHANNEL_CENTERED:
			phymode = vht_capable ? MODE_11AC_VHT20 :MODE_11NG_HT20;
			break;
		case PHY_DOUBLE_CHANNEL_LOW_PRIMARY:
		case PHY_DOUBLE_CHANNEL_HIGH_PRIMARY:
			phymode = vht_capable ? MODE_11AC_VHT40 :MODE_11NG_HT40;
			break;
                case PHY_QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_CENTERED:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_LOW:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_CENTERED:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_CENTERED_40MHZ_CENTERED:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_LOW:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_HIGH:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_HIGH:
                        phymode = MODE_11AC_VHT80;
                        break;

		default:
			break;
		}
	}

	/* 5 GHz band */
	if ((chan >= WMA_11A_CHANNEL_BEGIN) && (chan <= WMA_11A_CHANNEL_END)) {
		switch (chan_offset) {
		case PHY_SINGLE_CHANNEL_CENTERED:
			phymode = vht_capable ? MODE_11AC_VHT20 :MODE_11NA_HT20;
			break;
		case PHY_DOUBLE_CHANNEL_LOW_PRIMARY:
		case PHY_DOUBLE_CHANNEL_HIGH_PRIMARY:
			phymode = vht_capable ? MODE_11AC_VHT40 :MODE_11NA_HT40;
			break;
                case PHY_QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_CENTERED:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_CENTERED_40MHZ_CENTERED:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_CENTERED:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_LOW:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_LOW:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_HIGH:
                case PHY_QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_HIGH:
                        phymode = MODE_11AC_VHT80;
                        break;

		default:
			break;
		}
	}
	WMA_LOGD("%s: phymode %d channel %d offset %d vht_capable %d\n", __func__,
		 phymode, chan, chan_offset, vht_capable);

	return phymode;
}

tANI_U8 wma_getCenterChannel(tANI_U8 chan, tANI_U8 chan_offset)
{
        tANI_U8 band_center_chan = 0;

        if ((chan_offset == PHY_QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_CENTERED) ||
            (chan_offset == PHY_QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_LOW))
               band_center_chan = chan + 2;
        else if (chan_offset == PHY_QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_LOW)
               band_center_chan = chan + 6;
        else if ((chan_offset == PHY_QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_HIGH) ||
              (chan_offset == PHY_QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_CENTERED))
               band_center_chan = chan - 2;
        else if (chan_offset == PHY_QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_HIGH)
               band_center_chan = chan - 6;

        return band_center_chan;
}

static VOS_STATUS wma_vdev_start(tp_wma_handle wma,
				 struct wma_vdev_start_req *req)
{
	wmi_vdev_start_request_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	wmi_channel *chan;
	int32_t len;
	WLAN_PHY_MODE chanmode;
	u_int8_t *buf_ptr;

	len = sizeof(*cmd) + sizeof(wmi_channel) +
	       WMI_TLV_HDR_SIZE;
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s : wmi_buf_alloc failed\n", __func__);
		return VOS_STATUS_E_NOMEM;
	}
	buf_ptr = (u_int8_t *) wmi_buf_data(buf);
	cmd = (wmi_vdev_start_request_cmd_fixed_param *) buf_ptr;
	chan = (wmi_channel *) (buf_ptr + sizeof(*cmd));
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_vdev_start_request_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_vdev_start_request_cmd_fixed_param));
	WMITLV_SET_HDR(&chan->tlv_header,
		       WMITLV_TAG_STRUC_wmi_channel,
		       WMITLV_GET_STRUCT_TLVLEN(wmi_channel));
	cmd->vdev_id = req->vdev_id;

	/* Fill channel info */
	chan->mhz = vos_chan_to_freq(req->chan);
	chanmode = wma_chan_to_mode(req->chan, req->chan_offset,
                                    req->vht_capable);
	WMI_SET_CHANNEL_MODE(chan, chanmode);
	chan->band_center_freq1 = chan->mhz;

	if (chanmode == MODE_11AC_VHT80)
            chan->band_center_freq1 = vos_chan_to_freq(wma_getCenterChannel
                                             (req->chan, req->chan_offset));

	if ((chanmode == MODE_11NA_HT40) || (chanmode == MODE_11NG_HT40) ||
            (chanmode == MODE_11AC_VHT40)) {
		if (req->chan_offset == PHY_DOUBLE_CHANNEL_LOW_PRIMARY)
			chan->band_center_freq1 += 10;
		else
			chan->band_center_freq1 -= 10;
	}
	chan->band_center_freq2 = 0;
	/*
	 * If the channel has DFS set, flip on radar reporting.
	 *
	 * It may be that this should only be done for IBSS/hostap operation
	 * as this flag may be interpreted (at some point in the future)
	 * by the firmware as "oh, and please do radar DETECTION."
	 *
	 * If that is ever the case we would insert the decision whether to
	 * enable the firmware flag here.
	 */
	if (req->is_dfs) {
		WMI_SET_CHANNEL_FLAG(chan, WMI_CHAN_FLAG_DFS);
		cmd->disable_hw_ack = (req->oper_mode) ? 0 : 1;
	}

	cmd->beacon_interval = req->beacon_intval;
	cmd->dtim_period = req->dtim_period;
	/* FIXME: Find out min, max and regulatory power levels */
	WMI_SET_CHANNEL_MIN_POWER(chan, req->max_txpow);

	/* TODO: Handle regulatory class, max antenna */

	/* Copy the SSID */
	if (req->ssid.length) {
		if (req->ssid.length < sizeof(cmd->ssid.ssid))
			cmd->ssid.ssid_len = req->ssid.length;
		else
			cmd->ssid.ssid_len = sizeof(cmd->ssid.ssid);
		vos_mem_copy(cmd->ssid.ssid, req->ssid.ssId,
			     cmd->ssid.ssid_len);
	}

	if (req->hidden_ssid)
		cmd->flags |= WMI_UNIFIED_VDEV_START_HIDDEN_SSID;

	if (req->pmf_enabled)
		cmd->flags |= WMI_UNIFIED_VDEV_START_PMF_ENABLED;

	cmd->num_noa_descriptors = 0;
	buf_ptr = (u_int8_t *)(((u_int32_t) cmd) + sizeof(*cmd) +
				sizeof(wmi_channel));
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_STRUC,
		       cmd->num_noa_descriptors *
		       sizeof(wmi_p2p_noa_descriptor));
	WMA_LOGD("%s: vdev_id %d freq %d channel %d chanmode %d is_dfs %d\
		 beacon interval %d dtim %d center_chan %d \n", __func__, req->vdev_id,
		 chan->mhz, req->chan, chanmode, req->is_dfs,
		 req->beacon_intval, cmd->dtim_period, chan->band_center_freq1);

	if (wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				 WMI_VDEV_START_REQUEST_CMDID) < 0) {
		WMA_LOGP("Failed to send vdev start command\n");
		adf_nbuf_free(buf);
		return VOS_STATUS_E_FAILURE;
	}

	return VOS_STATUS_SUCCESS;
}

void wma_vdev_resp_timer(void *data)
{
	tp_wma_handle wma;
	struct wma_target_req *tgt_req = (struct wma_target_req *)data;
	void *vos_context = vos_get_global_context(VOS_MODULE_ID_WDA, NULL);
	ol_txrx_peer_handle peer;
	ol_txrx_pdev_handle pdev;
	u_int8_t peer_id;

	wma = (tp_wma_handle) vos_get_context(VOS_MODULE_ID_WDA, vos_context);
	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);

	WMA_LOGD("%s: request %d is timed out\n", __func__, tgt_req->msg_type);
	wma_find_vdev_req(wma, tgt_req->vdev_id, tgt_req->type);
	if (tgt_req->msg_type == WDA_CHNL_SWITCH_REQ) {
		tpSwitchChannelParams params =
			(tpSwitchChannelParams)tgt_req->user_data;
		params->status = VOS_STATUS_E_TIMEOUT;
		wma_send_msg(wma, WDA_SWITCH_CHANNEL_RSP, (void *)params, 0);
	} else if (tgt_req->msg_type == WDA_DELETE_BSS_REQ) {
		tpDeleteBssParams params =
			(tpDeleteBssParams)tgt_req->user_data;
		peer = ol_txrx_find_peer_by_addr(pdev, params->bssid, &peer_id);
		wma_remove_peer(wma, params->bssid, tgt_req->vdev_id, peer);
		params->status = VOS_STATUS_E_TIMEOUT;
		wma_send_msg(wma, WDA_DELETE_BSS_RSP, (void *)params, 0);
	}
	vos_timer_destroy(&tgt_req->event_timeout);
	vos_mem_free(tgt_req);
}

static struct wma_target_req *wma_fill_vdev_req(tp_wma_handle wma, u_int8_t vdev_id,
						u_int32_t msg_type, u_int8_t type,
						void *params)
{
	struct wma_target_req *req;

	req = vos_mem_malloc(sizeof(*req));
	if (!req) {
		WMA_LOGP("Failed to allocate memory for msg %d vdev %d\n",
			 msg_type, vdev_id);
		return NULL;
	}

	WMA_LOGD("%s: vdev_id %d msg %d\n", __func__, vdev_id, msg_type);
	req->vdev_id = vdev_id;
	req->msg_type = msg_type;
	req->type = type;
	req->user_data = params;
	vos_timer_init(&req->event_timeout, VOS_TIMER_TYPE_SW,
		       wma_vdev_resp_timer, req);
	vos_timer_start(&req->event_timeout, 1000);
	adf_os_spin_lock_bh(&wma->vdev_respq_lock);
	list_add_tail(&req->node, &wma->vdev_resp_queue);
	adf_os_spin_unlock_bh(&wma->vdev_respq_lock);
	return req;
}

static void wma_remove_vdev_req(tp_wma_handle wma, u_int8_t vdev_id,
				u_int8_t type)
{
	struct wma_target_req *req_msg;

	req_msg = wma_find_vdev_req(wma, vdev_id, type);
	if (!req_msg)
		return;

	vos_timer_stop(&req_msg->event_timeout);
	vos_timer_destroy(&req_msg->event_timeout);
	vos_mem_free(req_msg);
}

static void wma_set_channel(tp_wma_handle wma, tpSwitchChannelParams params)
{
	struct wma_vdev_start_req req;
	struct wma_target_req *msg;
	VOS_STATUS status;

	vos_mem_zero(&req, sizeof(req));
	if (!wma_find_vdev_by_addr(wma, params->selfStaMacAddr, &req.vdev_id)) {
		WMA_LOGP("%s: Failed to find vdev id for %pM\n",
			 __func__, params->selfStaMacAddr);
		status = VOS_STATUS_E_FAILURE;
		goto send_resp;
	}
	msg = wma_fill_vdev_req(wma, req.vdev_id, WDA_CHNL_SWITCH_REQ,
				WMA_TARGET_REQ_TYPE_VDEV_START, params);
	if (!msg) {
		WMA_LOGP("Failed to fill channel switch request for vdev %d\n",
			 req.vdev_id);
		status = VOS_STATUS_E_NOMEM;
		goto send_resp;
	}
	req.chan = params->channelNumber;
	req.chan_offset = params->secondaryChannelOffset;
#ifdef WLAN_FEATURE_VOWIFI
	req.max_txpow = params->maxTxPower;
#else
	req.max_txpow = params->localPowerConstraint;
#endif
	req.beacon_intval = 100;
	req.dtim_period = 1;
	status = wma_vdev_start(wma, &req);
	if (status != VOS_STATUS_SUCCESS) {
		wma_remove_vdev_req(wma, req.vdev_id, WMA_TARGET_REQ_TYPE_VDEV_START);
		WMA_LOGP("vdev start failed status = %d\n", status);
		goto send_resp;
	}

	return;
send_resp:
	WMA_LOGD("%s: channel %d offset %d txpower %d status %d\n", __func__,
		 params->channelNumber, params->secondaryChannelOffset,
#ifdef WLAN_FEATURE_VOWIFI
		 params->maxTxPower,
#else
		 params->localPowerConstraint,
#endif
		 status);
	params->status = status;
	wma_send_msg(wma, WDA_SWITCH_CHANNEL_RSP, (void *)params, 0);
}

static WLAN_PHY_MODE wma_peer_phymode(tSirNwType nw_type, u_int8_t is_ht,
				      u_int8_t is_cw40, u_int8_t is_vht, u_int8_t is_cw_vht)
{
	WLAN_PHY_MODE phymode = MODE_UNKNOWN;

	switch (nw_type) {
		case eSIR_11B_NW_TYPE:
			phymode = MODE_11B;
			break;
		case eSIR_11G_NW_TYPE:
                        if (is_vht) {
                               if (is_cw_vht)
                                       phymode = MODE_11AC_VHT80;
                               else
                                       phymode = (is_cw40) ?
                                               MODE_11AC_VHT40 :
                                               MODE_11AC_VHT20;
                        }
                        else if (is_ht)
				phymode = (is_cw40) ?
					MODE_11NG_HT40 : MODE_11NG_HT20;
			else
				phymode = MODE_11G;
			break;
		case eSIR_11A_NW_TYPE:
                        if (is_vht) {
                                if (is_cw_vht)
                                        phymode = MODE_11AC_VHT80;
                                else
                                        phymode = (is_cw40) ?
                                                MODE_11AC_VHT40 :
                                                MODE_11AC_VHT20;
                        }
                        else if (is_ht)
				phymode = (is_cw40) ?
					MODE_11NA_HT40 : MODE_11NA_HT20;
			else
				phymode = MODE_11A;
			break;
		default:
			WMA_LOGP("Invalid nw type %d\n", nw_type);
			break;
	}
	WMA_LOGD("%s: nw_type %d is_ht %d is_cw40 %d is_vht %d is_cw_vht %d\
                 phymode %d\n", __func__, nw_type, is_ht, is_cw40,
                 is_vht, is_cw_vht, phymode);

	return phymode;
}

static int32_t wmi_unified_send_txbf(tp_wma_handle wma,
					   tpAddStaParams params)
{
    wmi_vdev_txbf_en txbf_en;

    /* This is set when Other partner is Bformer
	and we are capable bformee(enabled both in ini and fw) */
	txbf_en.sutxbfee = params->vhtTxBFCapable;
	txbf_en.mutxbfee = params->vhtTxMUBformeeCapable;
	txbf_en.sutxbfer = 0;
	txbf_en.mutxbfer = 0;

	/* When MU TxBfee is set, SU TxBfee must be set by default */
	if (txbf_en.mutxbfee)
			txbf_en.sutxbfee = txbf_en.mutxbfee;

	WMA_LOGD("txbf_en.sutxbfee %d txbf_en.mutxbfee %d\n",
			txbf_en.sutxbfee, txbf_en.mutxbfee);

	return(wmi_unified_vdev_set_param_send(wma->wmi_handle,
			params->smesessionId, WMI_VDEV_PARAM_TXBF,
			*((A_UINT8 *)&txbf_en)));
}

static int32_t wmi_unified_send_peer_assoc(tp_wma_handle wma,
					   tSirNwType nw_type,
					   tpAddStaParams params)
{
	ol_txrx_pdev_handle pdev;
	wmi_peer_assoc_complete_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len;
	int32_t ret, max_rates, i;
	u_int8_t rx_stbc, tx_stbc;
	u_int8_t *rate_pos, *buf_ptr;
	wmi_rate_set peer_legacy_rates, peer_ht_rates;
        wmi_vht_rate_set *mcs;
	u_int32_t num_peer_legacy_rates;
	u_int32_t num_peer_ht_rates;

	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);

	vos_mem_zero(&peer_legacy_rates, sizeof(wmi_rate_set));
	vos_mem_zero(&peer_ht_rates, sizeof(wmi_rate_set));

	/* Legacy Rateset */
	rate_pos = (u_int8_t *) peer_legacy_rates.rates;
	for (i = 0; i < SIR_NUM_11B_RATES; i++) {
		if (!params->supportedRates.llbRates[i])
			continue;
		rate_pos[peer_legacy_rates.num_rates++] =
			params->supportedRates.llbRates[i];
	}
	for (i = 0; i < SIR_NUM_11A_RATES; i++) {
		if (!params->supportedRates.llaRates[i])
			continue;
		rate_pos[peer_legacy_rates.num_rates++] =
			params->supportedRates.llaRates[i];
	}

	/* Set the Legacy Rates to Word Aligned */
	num_peer_legacy_rates = roundup(peer_legacy_rates.num_rates,
					sizeof(u_int32_t));

	/* HT Rateset */
	max_rates = sizeof(peer_ht_rates.rates) /
		    sizeof(peer_ht_rates.rates[0]);
	rate_pos = (u_int8_t *) peer_ht_rates.rates;
	for (i = 0; i < MAX_SUPPORTED_RATES; i++) {
		if (params->supportedRates.supportedMCSSet[i / 8] &
					(1 << (i % 8))) {
			rate_pos[peer_ht_rates.num_rates++] = i;
		}
		if (peer_ht_rates.num_rates == max_rates)
		       break;
	}

	if (params->htCapable && !peer_ht_rates.num_rates) {
		u_int8_t temp_ni_rates[8] = {0x0, 0x1, 0x2, 0x3,
					     0x4, 0x5, 0x6, 0x7};
		/*
		 * Workaround for EV 116382: The peer is marked HT but with
		 * supported rx mcs set is set to 0. 11n spec mandates MCS0-7
		 * for a HT STA. So forcing the supported rx mcs rate to
		 * MCS 0-7. This workaround will be removed once we get
		 * clarification from WFA regarding this STA behavior.
		 */

		/* TODO: Do we really need this? */
		WMA_LOGW("Peer is marked as HT capable but supported mcs rate is 0");
		peer_ht_rates.num_rates = sizeof(temp_ni_rates);
		vos_mem_copy((u_int8_t *) peer_ht_rates.rates, temp_ni_rates,
			     peer_ht_rates.num_rates);
	}

	/* Set the Peer HT Rates to Word Aligned */
	num_peer_ht_rates = roundup(peer_ht_rates.num_rates,
					sizeof(u_int32_t));

	len = sizeof(*cmd) +
		WMI_TLV_HDR_SIZE + /* Place holder for peer legacy rate array */
		(num_peer_legacy_rates * sizeof(u_int8_t)) + /* peer legacy rate array size */
		WMI_TLV_HDR_SIZE + /* Place holder for peer Ht rate array */
		(num_peer_ht_rates * sizeof(u_int8_t)) + /* peer HT rate array size */
		sizeof(wmi_vht_rate_set);

	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed\n", __func__);
		return -ENOMEM;
	}

	buf_ptr = (u_int8_t *) wmi_buf_data(buf);
	cmd = (wmi_peer_assoc_complete_cmd_fixed_param *) buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_peer_assoc_complete_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_peer_assoc_complete_cmd_fixed_param));
	if (wma_is_vdev_in_ap_mode(wma, params->smesessionId))
		WMI_CHAR_ARRAY_TO_MAC_ADDR(params->staMac, &cmd->peer_macaddr);
	else
		WMI_CHAR_ARRAY_TO_MAC_ADDR(params->bssId, &cmd->peer_macaddr);
	cmd->vdev_id = params->smesessionId;
	cmd->peer_new_assoc = 1;
	cmd->peer_associd = params->assocId;

	/*
	 * The target only needs a subset of the flags maintained in the host.
	 * Just populate those flags and send it down
	 */
	cmd->peer_flags = 0;

	if (params->wmmEnabled)
		cmd->peer_flags |= WMI_PEER_QOS;

	if (params->uAPSD) {
		cmd->peer_flags |= WMI_PEER_APSD;
		WMA_LOGD("Set WMI_PEER_APSD: uapsd Mask %d", params->uAPSD);
	}

	if (params->htCapable) {
		cmd->peer_flags |= WMI_PEER_HT;
		cmd->peer_rate_caps |= WMI_RC_HT_FLAG;
	}

	if (params->txChannelWidthSet) {
		cmd->peer_flags |= WMI_PEER_40MHZ;
		cmd->peer_rate_caps |= WMI_RC_CW40_FLAG;
		if (params->fShortGI40Mhz)
			cmd->peer_rate_caps |= WMI_RC_SGI_FLAG;
	} else if (params->fShortGI20Mhz)
		cmd->peer_rate_caps |= WMI_RC_SGI_FLAG;

#ifdef WLAN_FEATURE_11AC
	if (params->vhtCapable) {
		cmd->peer_flags |= (WMI_PEER_HT | WMI_PEER_VHT);
		cmd->peer_rate_caps |= WMI_RC_HT_FLAG;
	}

	if (params->vhtTxChannelWidthSet)
		cmd->peer_flags |= WMI_PEER_80MHZ;

	cmd->peer_vht_caps = params->vht_caps;
#endif
	rx_stbc = (params->ht_caps & IEEE80211_HTCAP_C_RXSTBC) >>
			IEEE80211_HTCAP_C_RXSTBC_S;
	if (rx_stbc) {
		cmd->peer_flags |= WMI_PEER_STBC;
		cmd->peer_rate_caps |= (rx_stbc << WMI_RC_RX_STBC_FLAG_S);
	}

        tx_stbc = (params->ht_caps & IEEE80211_HTCAP_C_TXSTBC) >>
                        IEEE80211_HTCAP_C_TXSTBC_S;
        if (tx_stbc) {
                cmd->peer_flags |= WMI_PEER_STBC;
                cmd->peer_rate_caps |= (tx_stbc << WMI_RC_TX_STBC_FLAG_S);
        }

	if (params->htLdpcCapable || params->vhtLdpcCapable)
		cmd->peer_flags |= WMI_PEER_LDPC;

	switch (params->mimoPS) {
		case eSIR_HT_MIMO_PS_STATIC:
			cmd->peer_flags |= WMI_PEER_STATIC_MIMOPS;
			break;
		case eSIR_HT_MIMO_PS_DYNAMIC:
			cmd->peer_flags |= WMI_PEER_DYN_MIMOPS;
			break;
		case eSIR_HT_MIMO_PS_NO_LIMIT:
			cmd->peer_flags |= WMI_PEER_SPATIAL_MUX;
			break;
		default:
			break;
	}
	cmd->peer_flags |= WMI_PEER_AUTH;
	if (params->wpa_rsn
#ifdef FEATURE_WLAN_WAPI
	    || params->encryptType == eSIR_ED_WPI
#endif
	   )
		cmd->peer_flags |= WMI_PEER_NEED_PTK_4_WAY;
	if (params->wpa_rsn >> 1)
		cmd->peer_flags |= WMI_PEER_NEED_GTK_2_WAY;

#ifdef QCA_WIFI_ISOC
	/*
	if (RSN_AUTH_IS_OPEN(&ni->ni_rsn)) {
		ol_txrx_peer_state_update(pdev, params->bssId, ol_txrx_peer_state_auth);
	}
	else {
		ol_txrx_peer_state_update(pdev, params->bssId, ol_txrx_peer_state_conn);
	}
	*/
#else
	ol_txrx_peer_state_update(pdev, params->bssId, ol_txrx_peer_state_auth);
#endif

	cmd->peer_caps = params->capab_info;
	cmd->peer_listen_intval = params->listenInterval;
	cmd->peer_ht_caps = params->ht_caps;
	cmd->peer_max_mpdu = (1 << (IEEE80211_HTCAP_MAXRXAMPDU_FACTOR +
				    params->maxAmpduSize)) - 1;
	cmd->peer_mpdu_density = wma_parse_mpdudensity(params->maxAmpduDensity);

	if (params->supportedRates.supportedMCSSet[1] &&
	    params->supportedRates.supportedMCSSet[2])
		cmd->peer_rate_caps |= WMI_RC_TS_FLAG;
	else if (params->supportedRates.supportedMCSSet[1])
		cmd->peer_rate_caps |= WMI_RC_DS_FLAG;

	/* Update peer legacy rate information */
	buf_ptr += sizeof(*cmd);
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_BYTE,
		       num_peer_legacy_rates);
	buf_ptr += WMI_TLV_HDR_SIZE;
	cmd->num_peer_legacy_rates = peer_legacy_rates.num_rates;
	vos_mem_copy(buf_ptr, peer_legacy_rates.rates,
		     peer_legacy_rates.num_rates);

	/* Update peer HT rate information */
	buf_ptr += num_peer_legacy_rates;
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_BYTE,
		       num_peer_ht_rates);
	buf_ptr += WMI_TLV_HDR_SIZE;
	cmd->num_peer_ht_rates = peer_ht_rates.num_rates;
	vos_mem_copy(buf_ptr, peer_ht_rates.rates,
		     peer_ht_rates.num_rates);

	/* VHT Rates */
	buf_ptr += num_peer_ht_rates;
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_STRUC_wmi_vht_rate_set,
		       WMITLV_GET_STRUCT_TLVLEN(wmi_vht_rate_set));

	cmd->peer_nss = MAX((peer_ht_rates.num_rates + 7) / 8, 1);

	WMA_LOGD("peer_nss %d peer_ht_rates.num_rates %d \n", cmd->peer_nss,
                  peer_ht_rates.num_rates);

        mcs = (wmi_vht_rate_set *)buf_ptr;
        if ( params->vhtCapable) {
#define VHT2x2MCSMASK 0xc
                mcs->rx_max_rate = params->supportedRates.vhtRxHighestDataRate;
                mcs->rx_mcs_set  = params->supportedRates.vhtRxMCSMap;
                mcs->tx_max_rate = params->supportedRates.vhtTxHighestDataRate;
                mcs->tx_mcs_set  = params->supportedRates.vhtTxMCSMap;

                cmd->peer_nss = ((mcs->rx_mcs_set & VHT2x2MCSMASK)
                                    == VHT2x2MCSMASK) ? 1 : 2;
	}

	cmd->peer_phymode = wma_peer_phymode(nw_type, params->htCapable,
                                             params->txChannelWidthSet,
                                             params->vhtCapable,
                                             params->vhtTxChannelWidthSet);

        WMA_LOGD("%s: vdev_id %d associd %d peer_flags %x rate_caps %x\
                 peer_caps %x listen_intval %d ht_caps %x max_mpdu %d\
                 nss %d phymode %d peer_mpdu_density %d\n", __func__,
                 cmd->vdev_id, cmd->peer_associd, cmd->peer_flags,
                 cmd->peer_rate_caps, cmd->peer_caps,
                 cmd->peer_listen_intval, cmd->peer_ht_caps,
                 cmd->peer_max_mpdu, cmd->peer_nss, cmd->peer_phymode,
                 cmd->peer_mpdu_density);

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_PEER_ASSOC_CMDID);
	if (ret != EOK) {
		WMA_LOGP("Failed to send peer assoc command ret = %d\n", ret);
		adf_nbuf_free(buf);
	}
	return ret;
}

static int
wmi_unified_pdev_set_param(wmi_unified_t wmi_handle, WMI_PDEV_PARAM param_id,
				u_int32_t param_value)
{
	int ret;
	wmi_pdev_set_param_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	u_int16_t len = sizeof(*cmd);

	buf = wmi_buf_alloc(wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s:wmi_buf_alloc failed", __func__);
		return -ENOMEM;
	}
	cmd = (wmi_pdev_set_param_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_pdev_set_param_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_pdev_set_param_cmd_fixed_param));
	cmd->reserved0 = 0;
	cmd->param_id = param_id;
	cmd->param_value = param_value;
	WMA_LOGD("Setting pdev param = %x, value = %u",
			param_id, param_value);
	ret = wmi_unified_cmd_send(wmi_handle, buf, len,
					WMI_PDEV_SET_PARAM_CMDID);
	if (ret != EOK) {
		WMA_LOGE("Failed to send set param command ret = %d", ret);
		wmi_buf_free(buf);
	}
	return ret;
}

static int32_t wma_txrx_fw_stats_reset(tp_wma_handle wma_handle,
					uint8_t vdev_id, u_int32_t value)
{
	struct ol_txrx_stats_req req;
	ol_txrx_vdev_handle vdev;

	vdev = wma_find_vdev_by_id(wma_handle, vdev_id);
	if (!vdev) {
		WMA_LOGE("%s:Invalid vdev handle", __func__);
		return -EINVAL;
	}
	vos_mem_zero(&req, sizeof(req));
	req.stats_type_reset_mask = value;
	ol_txrx_fw_stats_get(vdev, &req);

	return 0;
}

static int32_t wma_set_txrx_fw_stats_level(tp_wma_handle wma_handle,
					   uint8_t vdev_id, u_int32_t value)
{
	struct ol_txrx_stats_req req;
	ol_txrx_vdev_handle vdev;

	vdev = wma_find_vdev_by_id(wma_handle, vdev_id);
	if (!vdev) {
		WMA_LOGE("%s:Invalid vdev handle", __func__);
		return -EINVAL;
	}
	vos_mem_zero(&req, sizeof(req));
	req.print.verbose = 1;
	if (value <= WMA_FW_TX_PPDU_STATS)
		req.stats_type_upload_mask = 1 << (value - 1);
	else if (value == WMA_FW_TX_CONCISE_STATS) {
		/*
		 * Stats request 5 is the same as stats request 4,
		 * but with only a concise printout.
		 */
		req.print.concise = 1;
		req.stats_type_upload_mask = 1 << (WMA_FW_TX_PPDU_STATS - 1);
	} else if (value == WMA_FW_TX_RC_STATS)
		req.stats_type_upload_mask = 1 << (WMA_FW_TX_CONCISE_STATS - 1);

	ol_txrx_fw_stats_get(vdev, &req);

	return 0;
}

static int32_t wma_set_priv_cfg(tp_wma_handle wma_handle,
				wda_cli_set_cmd_t *privcmd)
{
	int32_t ret = 0;

	switch (privcmd->param_id) {
	case WMA_VDEV_TXRX_FWSTATS_ENABLE_CMDID:
		ret = wma_set_txrx_fw_stats_level(wma_handle,
						  privcmd->param_vdev_id,
						  privcmd->param_value);
		break;
	case WMA_VDEV_TXRX_FWSTATS_RESET_CMDID:
		ret = wma_txrx_fw_stats_reset(wma_handle,
						privcmd->param_vdev_id,
						privcmd->param_value);
		break;
	default:
		WMA_LOGE("Invalid wma config command id:%d",
			 privcmd->param_id);
		ret = -EINVAL;
	}
	return ret;
}

static void wma_process_cli_set_cmd(tp_wma_handle wma,
					wda_cli_set_cmd_t *privcmd)
{
	int ret = 0, vid = privcmd->param_vdev_id;
	struct wma_txrx_node *intr = wma->interfaces;
	tpAniSirGlobal pMac = (tpAniSirGlobal )vos_get_context(VOS_MODULE_ID_PE,
				wma->vos_context);

	WMA_LOGD("wmihandle %p", wma->wmi_handle);

	if (privcmd->param_id >= WMI_CMDID_MAX) {
		/*
		 * This configuration setting is not done using any wmi
		 * command, call appropriate handler.
		 */
		if (wma_set_priv_cfg(wma, privcmd))
			WMA_LOGE("Failed to set wma priv congiuration");
		return;
	}

	switch (privcmd->param_vp_dev) {
	case VDEV_CMD:
		WMA_LOGD("vdev id %d pid %d pval %d", privcmd->param_vdev_id,
				privcmd->param_id, privcmd->param_value);
		ret = wmi_unified_vdev_set_param_send(wma->wmi_handle,
						privcmd->param_vdev_id,
						privcmd->param_id,
						privcmd->param_value);
		if (ret) {
			WMA_LOGE("wmi_unified_vdev_set_param_send"
					" failed ret %d", ret);
			return;
		}
		break;
	case PDEV_CMD:
		WMA_LOGD("pdev pid %d pval %d", privcmd->param_id,
				privcmd->param_value);
		ret = wmi_unified_pdev_set_param(wma->wmi_handle,
						privcmd->param_id,
						privcmd->param_value);
		if (ret) {
			WMA_LOGE("wmi_unified_vdev_set_param_send"
					" failed ret %d", ret);
			return;
		}
		break;
	case GEN_CMD:
		WMA_LOGD("gen pid %d pval %d", privcmd->param_id,
				privcmd->param_value);
		switch (privcmd->param_id) {
		case GEN_VDEV_PARAM_AMPDU:
			ret = ol_txrx_aggr_cfg(
					wma_handle->interfaces[privcmd->param_vdev_id].handle,
					privcmd->param_value, 0);
			if (ret)
				WMA_LOGE("ol_txrx_aggr_cfg set ampdu"
						" failed ret %d", ret);
			intr[vid].config.ampdu = privcmd->param_value;
			break;
		case GEN_VDEV_PARAM_AMSDU:
			ret = ol_txrx_aggr_cfg(
					wma_handle->interfaces[privcmd->param_vdev_id].handle,
					0, privcmd->param_value);
			if (ret)
				WMA_LOGE("ol_txrx_aggr_cfg set amsdu"
						" failed ret %d", ret);
			intr[vid].config.amsdu = privcmd->param_value;
			break;
		case GEN_PARAM_DUMP_AGC_START:
			HTCDump(wma->htc_handle, AGC_DUMP, true);
			break;
		case GEN_PARAM_DUMP_AGC:
			HTCDump(wma->htc_handle, AGC_DUMP, false);
			break;
		case GEN_PARAM_DUMP_CHANINFO_START:
			HTCDump(wma->htc_handle, CHAN_DUMP, true);
			break;
		case GEN_PARAM_DUMP_CHANINFO:
			HTCDump(wma->htc_handle, CHAN_DUMP, false);
			break;
		case GEN_PARAM_DUMP_WATCHDOG:
			HTCDump(wma->htc_handle, WD_DUMP, false);
			break;
		default:
			WMA_LOGE("Invalid param id 0x%x", privcmd->param_id);
			break;
		}
		break;
	case DBG_CMD:
		WMA_LOGD("dbg pid %d pval %d", privcmd->param_id,
				privcmd->param_value);
		switch (privcmd->param_id) {
		case WMI_DBGLOG_LOG_LEVEL:
                        ret = dbglog_set_log_lvl(wma->wmi_handle, privcmd->param_value);
			if (ret)
				WMA_LOGE("dbglog_set_log_lvl"
						" failed ret %d", ret);
			break;
		case WMI_DBGLOG_VAP_ENABLE:
                        ret = dbglog_vap_log_enable(wma->wmi_handle, privcmd->param_value, TRUE);
			if (ret)
				WMA_LOGE("dbglog_vap_log_enable"
						" failed ret %d", ret);
			break;
		case WMI_DBGLOG_VAP_DISABLE:
                        ret = dbglog_vap_log_enable(wma->wmi_handle, privcmd->param_value, FALSE);
			if (ret)
				WMA_LOGE("dbglog_vap_log_enable"
						" failed ret %d", ret);
			break;
		case WMI_DBGLOG_MODULE_ENABLE:
                        ret = dbglog_module_log_enable(wma->wmi_handle, privcmd->param_value, TRUE);
			if (ret)
				WMA_LOGE("dbglog_module_log_enable"
						" failed ret %d", ret);
			break;
		case WMI_DBGLOG_MODULE_DISABLE:
                        ret = dbglog_module_log_enable(wma->wmi_handle, privcmd->param_value, FALSE);
			if (ret)
				WMA_LOGE("dbglog_module_log_enable"
						" failed ret %d", ret);
			break;
	        case WMI_DBGLOG_MOD_LOG_LEVEL:
                        ret = dbglog_set_mod_log_lvl(wma->wmi_handle, privcmd->param_value);
			if (ret)
				WMA_LOGE("dbglog_module_log_enable"
						" failed ret %d", ret);
			break;
		case WMI_DBGLOG_TYPE:
                        ret = dbglog_parser_type_init(wma->wmi_handle, privcmd->param_value);
			if (ret)
				WMA_LOGE("dbglog_parser_type_init"
						" failed ret %d", ret);
			break;
		case WMI_DBGLOG_REPORT_ENABLE:
                        ret = dbglog_report_enable(wma->wmi_handle, privcmd->param_value);
			if (ret)
				WMA_LOGE("dbglog_report_enable"
						" failed ret %d", ret);
			break;
		default:
			WMA_LOGE("Invalid param id 0x%x", privcmd->param_id);
			break;
		}
		break;
	default:
		WMA_LOGE("Invalid vpdev command id");
	}
	if (1 == privcmd->param_vp_dev) {
		switch (privcmd->param_id) {
		case WMI_VDEV_PARAM_NSS:
			intr[vid].config.nss = privcmd->param_value;
			break;
		case WMI_VDEV_PARAM_LDPC:
			intr[vid].config.ldpc = privcmd->param_value;
			break;
		case WMI_VDEV_PARAM_TX_STBC:
			intr[vid].config.tx_stbc = privcmd->param_value;
			break;
		case WMI_VDEV_PARAM_RX_STBC:
			intr[vid].config.rx_stbc = privcmd->param_value;
			break;
		case WMI_VDEV_PARAM_SGI:
			intr[vid].config.shortgi = privcmd->param_value;
			break;
		case WMI_VDEV_PARAM_ENABLE_RTSCTS:
			intr[vid].config.rtscts_en = privcmd->param_value;
			break;
		case WMI_VDEV_PARAM_CHWIDTH:
			intr[vid].config.chwidth = privcmd->param_value;
			break;
		case WMI_VDEV_PARAM_FIXED_RATE:
			intr[vid].config.tx_rate = privcmd->param_value;
			break;
		default:
			WMA_LOGE("Invalid wda_cli_set vdev command/Not"
				" yet implemented 0x%x", privcmd->param_id);
		     break;
		}
	} else if (2 == privcmd->param_vp_dev) {
		switch (privcmd->param_id) {
		case WMI_PDEV_PARAM_ANI_ENABLE:
			wma->pdevconfig.ani_enable = privcmd->param_value;
			break;
		case WMI_PDEV_PARAM_ANI_POLL_PERIOD:
			wma->pdevconfig.ani_poll_len = privcmd->param_value;
			break;
		case WMI_PDEV_PARAM_ANI_LISTEN_PERIOD:
			wma->pdevconfig.ani_listen_len = privcmd->param_value;
			break;
		case WMI_PDEV_PARAM_ANI_OFDM_LEVEL:
			wma->pdevconfig.ani_ofdm_level = privcmd->param_value;
			break;
		case WMI_PDEV_PARAM_ANI_CCK_LEVEL:
			wma->pdevconfig.ani_cck_level = privcmd->param_value;
			break;
		case WMI_PDEV_PARAM_DYNAMIC_BW:
			wma->pdevconfig.cwmenable = privcmd->param_value;
			break;
		case WMI_PDEV_PARAM_TX_CHAIN_MASK:
			wma->pdevconfig.txchainmask = privcmd->param_value;
			break;
		case WMI_PDEV_PARAM_RX_CHAIN_MASK:
			wma->pdevconfig.rxchainmask = privcmd->param_value;
			break;
		case WMI_PDEV_PARAM_TXPOWER_LIMIT2G:
			wma->pdevconfig.txpow2g = privcmd->param_value;
			if ((pMac->roam.configParam.bandCapability ==
				eCSR_BAND_ALL) ||
				(pMac->roam.configParam.bandCapability ==
				eCSR_BAND_24)) {
				if (cfgSetInt(pMac,
					WNI_CFG_CURRENT_TX_POWER_LEVEL,
					privcmd->param_value) != eSIR_SUCCESS) {
					WMA_LOGE("could not set"
					" WNI_CFG_CURRENT_TX_POWER_LEVEL");
				}
			}
			else
				WMA_LOGE("Current band is not 2G");
			break;
		case WMI_PDEV_PARAM_TXPOWER_LIMIT5G:
			wma->pdevconfig.txpow5g = privcmd->param_value;
			if ((pMac->roam.configParam.bandCapability ==
				eCSR_BAND_ALL) ||
				(pMac->roam.configParam.bandCapability ==
				eCSR_BAND_5G)) {
				if (cfgSetInt(pMac,
					WNI_CFG_CURRENT_TX_POWER_LEVEL,
					privcmd->param_value) != eSIR_SUCCESS) {
					WMA_LOGE("could not set"
					" WNI_CFG_CURRENT_TX_POWER_LEVEL");
				}
			}
			else
				WMA_LOGE("Current band is not 5G");
			break;
		default:
			WMA_LOGE("Invalid wda_cli_set pdev command/Not"
				" yet implemented 0x%x", privcmd->param_id);
			break;
		}
	}
}

int wma_cli_get_command(void *wmapvosContext, int vdev_id,
			int param_id, int vpdev)
{
	int ret = 0;
	tp_wma_handle wma;
	struct wma_txrx_node *intr = NULL;

	wma = (tp_wma_handle) vos_get_context(VOS_MODULE_ID_WDA,
						wmapvosContext);
	intr = wma->interfaces;

	if (VDEV_CMD == vpdev) {
		switch (param_id) {
		case WMI_VDEV_PARAM_NSS:
			ret = intr[vdev_id].config.nss;
			break;
		case WMI_VDEV_PARAM_LDPC:
			ret = intr[vdev_id].config.ldpc;
			break;
		case WMI_VDEV_PARAM_TX_STBC:
			ret = intr[vdev_id].config.tx_stbc;
			break;
		case WMI_VDEV_PARAM_RX_STBC:
			ret = intr[vdev_id].config.rx_stbc;
			break;
		case WMI_VDEV_PARAM_SGI:
			ret = intr[vdev_id].config.shortgi;
			break;
		case WMI_VDEV_PARAM_ENABLE_RTSCTS:
			ret = intr[vdev_id].config.rtscts_en;
			break;
		case WMI_VDEV_PARAM_CHWIDTH:
			ret = intr[vdev_id].config.chwidth;
			break;
		case WMI_VDEV_PARAM_FIXED_RATE:
			ret = intr[vdev_id].config.tx_rate;
			break;
		default:
			WMA_LOGE("Invalid cli_get vdev command/Not"
					" yet implemented 0x%x", param_id);
			return -EINVAL;
		}
	} else if (PDEV_CMD == vpdev) {
		switch (param_id) {
		case WMI_PDEV_PARAM_ANI_ENABLE:
			ret = wma->pdevconfig.ani_enable;
			break;
		case WMI_PDEV_PARAM_ANI_POLL_PERIOD:
			ret = wma->pdevconfig.ani_poll_len;
			break;
		case WMI_PDEV_PARAM_ANI_LISTEN_PERIOD:
			ret = wma->pdevconfig.ani_listen_len;
			break;
		case WMI_PDEV_PARAM_ANI_OFDM_LEVEL:
			ret = wma->pdevconfig.ani_ofdm_level;
			break;
		case WMI_PDEV_PARAM_ANI_CCK_LEVEL:
			ret = wma->pdevconfig.ani_cck_level;
			break;
		case WMI_PDEV_PARAM_DYNAMIC_BW:
			ret = wma->pdevconfig.cwmenable;
			break;
		case WMI_PDEV_PARAM_TX_CHAIN_MASK:
			ret = wma->pdevconfig.txchainmask;
			break;
		case WMI_PDEV_PARAM_RX_CHAIN_MASK:
			ret = wma->pdevconfig.rxchainmask;
			break;
		case WMI_PDEV_PARAM_TXPOWER_LIMIT2G:
			ret = wma->pdevconfig.txpow2g;
			break;
		case WMI_PDEV_PARAM_TXPOWER_LIMIT5G:
			ret = wma->pdevconfig.txpow5g;
			break;
		default:
			WMA_LOGE("Invalid cli_get pdev command/Not"
					" yet implemented 0x%x", param_id);
			return -EINVAL;
		}
	} else if (GEN_CMD == vpdev) {
		switch (param_id) {
		case GEN_VDEV_PARAM_AMPDU:
			ret = intr[vdev_id].config.ampdu;
			break;
		case GEN_VDEV_PARAM_AMSDU:
			ret = intr[vdev_id].config.amsdu;
			break;
		default:
			WMA_LOGE("Invalid generic vdev command/Not"
					" yet implemented 0x%x", param_id);
			return -EINVAL;
		}
	}
	return ret;
}

static int32_t wmi_unified_set_sta_ps_param(wmi_unified_t wmi_handle,
		u_int32_t vdev_id, u_int32_t param, u_int32_t value)
{
	wmi_sta_powersave_param_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len = sizeof(*cmd);

	WMA_LOGD("Set Sta Ps param vdevId %d Param %d val %d",
		      vdev_id, param, value);

	buf = wmi_buf_alloc(wmi_handle, len);
	if (!buf) {
		WMA_LOGP("Set Sta Ps param Mem Alloc Failed");
		return -ENOMEM;
	}

	cmd = (wmi_sta_powersave_param_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_sta_powersave_param_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_sta_powersave_param_cmd_fixed_param));
	cmd->vdev_id = vdev_id;
	cmd->param = param;
	cmd->value = value;

	if (wmi_unified_cmd_send(wmi_handle, buf, len,
			WMI_STA_POWERSAVE_PARAM_CMDID)) {
		WMA_LOGE("Set Sta Ps param Failed vdevId %d Param %d val %d",
			vdev_id, param, value);
		adf_nbuf_free(buf);
		return -EIO;
	}
	return 0;
}

static void
wma_update_protection_mode(tp_wma_handle wma, u_int8_t vdev_id,
			   u_int8_t llbcoexist)
{
	int ret;
	enum ieee80211_protmode prot_mode;

	prot_mode = llbcoexist ? IEEE80211_PROT_CTSONLY : IEEE80211_PROT_NONE;

	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
					      WMI_VDEV_PARAM_PROTECTION_MODE,
					      prot_mode);

	if (ret)
		WMA_LOGE("Failed to send wmi protection mode cmd");
	else
		WMA_LOGD("Updated protection mode %d to target", prot_mode);
}

/*
 * Function	: wma_process_update_beacon_params
 * Description	: update the beacon parameters to target
 * Args		: wma handle, beacon parameters
 * Returns	: None
 */
static void
wma_process_update_beacon_params(tp_wma_handle wma,
				 tUpdateBeaconParams *bcn_params)
{
	if (!bcn_params) {
		WMA_LOGE("bcn_params NULL");
		return;
	}

	if (bcn_params->smeSessionId >= wma->max_bssid) {
		WMA_LOGE("Invalid vdev id %d", bcn_params->smeSessionId);
		return;
	}

	if (bcn_params->paramChangeBitmap & PARAM_llBCOEXIST_CHANGED)
		wma_update_protection_mode(wma, bcn_params->smeSessionId,
					   bcn_params->llbCoexist);
}

/*
 * Function    : wma_update_cfg_params
 * Description : update the cfg parameters to target
 * Args        : wma handle, cfg parameter
 * Returns     : None
 */
static void
wma_update_cfg_params(tp_wma_handle wma, tSirMsgQ *cfgParam)
{
	u_int8_t vdev_id;
	u_int32_t param_id;
	tANI_U32 cfg_val;
	int ret;
	/* get mac to acess CFG data base */
	struct sAniSirGlobal *pmac;

	switch(cfgParam->bodyval) {
	case WNI_CFG_RTS_THRESHOLD:
		param_id = WMI_VDEV_PARAM_RTS_THRESHOLD;
		break;
	case WNI_CFG_FRAGMENTATION_THRESHOLD:
		param_id = WMI_VDEV_PARAM_FRAGMENTATION_THRESHOLD;
		break;
	default:
		WMA_LOGD("Unhandled cfg parameter %d", cfgParam->bodyval);
		return;
	}

	pmac = (struct sAniSirGlobal*)vos_get_context(VOS_MODULE_ID_PE,
					wma->vos_context);

	if (wlan_cfgGetInt(pmac, (tANI_U16) cfgParam->bodyval,
			   &cfg_val) != eSIR_SUCCESS)
	{
		WMA_LOGE("Failed to get value for CFG PARAMS %d. returning without updating",
			 cfgParam->bodyval);
		return;
	}

	for (vdev_id = 0; vdev_id < wma->max_bssid; vdev_id++) {
		if (wma->interfaces[vdev_id].handle != 0) {
			ret = wmi_unified_vdev_set_param_send(wma->wmi_handle,
				vdev_id, param_id, cfg_val);
			if (ret)
				WMA_LOGE("Update cfg params failed for vdevId %d", vdev_id);
		}
	}
}

/* BSS set params functions */
static void
wma_vdev_set_bss_params(tp_wma_handle wma, int vdev_id,
		tSirMacBeaconInterval beaconInterval, tANI_U8 dtimPeriod,
		tANI_U8 shortSlotTimeSupported, tANI_U8 llbCoexist)
{
	int ret;
	uint32_t slot_time;

	/* Beacon Interval setting */
	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
					      WMI_VDEV_PARAM_BEACON_INTERVAL,
					      beaconInterval);

	if (ret)
		WMA_LOGE("failed to set WMI_VDEV_PARAM_BEACON_INTERVAL\n");

	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
					      WMI_VDEV_PARAM_DTIM_PERIOD,
					      dtimPeriod);
	if (ret)
		WMA_LOGE("failed to set WMI_VDEV_PARAM_DTIM_PERIOD\n");

	/* Slot time */
	if (shortSlotTimeSupported)
		slot_time = WMI_VDEV_SLOT_TIME_SHORT;
	else
		slot_time = WMI_VDEV_SLOT_TIME_LONG;

	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
					      WMI_VDEV_PARAM_SLOT_TIME,
					      slot_time);
	if (ret)
		WMA_LOGE("failed to set WMI_VDEV_PARAM_SLOT_TIME\n");

	/* Initialize protection mode in case of coexistence */
	wma_update_protection_mode(wma, vdev_id, llbCoexist);
}

static void wma_add_bss_ap_mode(tp_wma_handle wma, tpAddBssParams add_bss)
{
	ol_txrx_pdev_handle pdev;
	ol_txrx_vdev_handle vdev;
	struct wma_vdev_start_req req;
	ol_txrx_peer_handle peer;
	struct wma_target_req *msg;
	u_int8_t vdev_id, peer_id;
	VOS_STATUS status;

	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);
	vdev = wma_find_vdev_by_addr(wma, add_bss->bssId, &vdev_id);
	if (!vdev) {
		WMA_LOGE("%s: Failed to get vdev handle\n", __func__);
		goto send_fail_resp;
	}

	status = wma_create_peer(wma, pdev, vdev, add_bss->bssId, vdev_id);
	if (status != VOS_STATUS_SUCCESS) {
		WMA_LOGE("%s: Failed to create peer\n", __func__);
		goto send_fail_resp;
	}

	peer = ol_txrx_find_peer_by_addr(pdev, add_bss->bssId, &peer_id);
	if (!peer) {
		WMA_LOGE("%s Failed to find peer %pM\n", __func__,
			 add_bss->bssId);
		goto send_fail_resp;
	}
	msg = wma_fill_vdev_req(wma, vdev_id, WDA_ADD_BSS_REQ,
				WMA_TARGET_REQ_TYPE_VDEV_START, add_bss);
	if (!msg) {
		WMA_LOGP("%s Failed to allocate vdev request vdev_id %d\n",
			 __func__, vdev_id);
		goto peer_cleanup;
	}

	add_bss->staContext.staIdx = ol_txrx_local_peer_id(peer);

	vos_mem_zero(&req, sizeof(req));
	req.vdev_id = vdev_id;
	req.chan = add_bss->currentOperChannel;
	req.chan_offset = add_bss->currentExtChannel;
        req.vht_capable = add_bss->vhtCapable;
#if defined WLAN_FEATURE_VOWIF
	req.max_txpow = add_bss->maxTxPower;
#else
	req.max_txpow = 0;
#endif
	req.beacon_intval = add_bss->beaconInterval;
	req.dtim_period = add_bss->dtimPeriod;
	req.hidden_ssid = add_bss->bHiddenSSIDEn;
	req.is_dfs = add_bss->bSpectrumMgtEnabled;
	req.oper_mode = BSS_OPERATIONAL_MODE_AP;
	req.ssid.length = add_bss->ssId.length;
	if (req.ssid.length > 0)
		vos_mem_copy(req.ssid.ssId, add_bss->ssId.ssId,
			     add_bss->ssId.length);

	status = wma_vdev_start(wma, &req);
	if (status != VOS_STATUS_SUCCESS) {
		wma_remove_vdev_req(wma, vdev_id,
				    WMA_TARGET_REQ_TYPE_VDEV_START);
		goto peer_cleanup;
	}

	/* Initialize protection mode to no protection */
	if (wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
					    WMI_VDEV_PARAM_PROTECTION_MODE,
					    IEEE80211_PROT_NONE)) {
		WMA_LOGE("Failed to initialize protection mode");
	}

	return;

peer_cleanup:
	wma_remove_peer(wma, add_bss->bssId, vdev_id, peer);
send_fail_resp:
	add_bss->status = VOS_STATUS_E_FAILURE;
	wma_send_msg(wma, WDA_ADD_BSS_RSP, (void *)add_bss, 0);
}

static void wma_add_bss_sta_mode(tp_wma_handle wma, tpAddBssParams add_bss)
{
	ol_txrx_pdev_handle pdev;
	struct wma_vdev_start_req req;
	struct wma_target_req *msg;
	u_int8_t vdev_id, peer_id;
	ol_txrx_peer_handle peer;
	VOS_STATUS status;
	struct wma_txrx_node *iface;

	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);
	vdev_id = add_bss->staContext.smesessionId;
	iface = &wma->interfaces[vdev_id];
	if (add_bss->operMode) {
		if (add_bss->reassocReq) {
			// Called in preassoc state. BSSID peer is already added by set_linkstate
			peer = ol_txrx_find_peer_by_addr(pdev, add_bss->bssId, &peer_id);
			if (!peer) {
				WMA_LOGE("%s Failed to find peer %pM\n", __func__,
					 add_bss->bssId);
				goto send_fail_resp;
			}
			msg = wma_fill_vdev_req(wma, vdev_id, WDA_ADD_BSS_REQ,
						WMA_TARGET_REQ_TYPE_VDEV_START, add_bss);
			if (!msg) {
				WMA_LOGP("%s Failed to allocate vdev request vdev_id %d\n",
					 __func__, vdev_id);
				goto peer_cleanup;
			}

			add_bss->staContext.staIdx = ol_txrx_local_peer_id(peer);

			vos_mem_zero(&req, sizeof(req));
			req.vdev_id = vdev_id;
			req.chan = add_bss->currentOperChannel;
			req.chan_offset = add_bss->currentExtChannel;
#if defined WLAN_FEATURE_VOWIF
			req.max_txpow = add_bss->maxTxPower;
#else
			req.max_txpow = 0;
#endif
			req.beacon_intval = add_bss->beaconInterval;
			req.dtim_period = add_bss->dtimPeriod;
			req.hidden_ssid = add_bss->bHiddenSSIDEn;
			req.is_dfs = add_bss->bSpectrumMgtEnabled;
			req.ssid.length = add_bss->ssId.length;
			req.oper_mode = BSS_OPERATIONAL_MODE_STA;
			if (req.ssid.length > 0)
				vos_mem_copy(req.ssid.ssId, add_bss->ssId.ssId,
						 add_bss->ssId.length);

			status = wma_vdev_start(wma, &req);
			if (status != VOS_STATUS_SUCCESS) {
				wma_remove_vdev_req(wma, vdev_id,
							WMA_TARGET_REQ_TYPE_VDEV_START);
				goto peer_cleanup;
			}
			// Save parameters later needed by WDA_ADD_STA_REQ
			iface->beaconInterval = add_bss->beaconInterval;
			iface->dtimPeriod = add_bss->dtimPeriod;
			iface->llbCoexist = add_bss->llbCoexist;
			iface->shortSlotTimeSupported = add_bss->shortSlotTimeSupported;
			// ADD_BSS_RESP will be deferred to completion of VDEV_START

		    return;
		}
		if (!add_bss->updateBss) {
			goto send_bss_resp;

		}
		/* Update peer state */
		if (add_bss->staContext.encryptType == eSIR_ED_NONE) {
			WMA_LOGD("%s: Update peer(%pM) state into auth\n",
				 __func__, add_bss->bssId);
			ol_txrx_peer_state_update(pdev, add_bss->bssId,
						  ol_txrx_peer_state_auth);
		} else {
			WMA_LOGD("%s: Update peer(%pM) state into conn\n",
				 __func__, add_bss->bssId);
			ol_txrx_peer_state_update(pdev, add_bss->bssId,
						  ol_txrx_peer_state_conn);
		}

		wmi_unified_send_txbf(wma, &add_bss->staContext);

		wmi_unified_send_peer_assoc(wma, add_bss->nwType,
					    &add_bss->staContext);
		if (add_bss->staContext.encryptType == eSIR_ED_NONE) {
			WMA_LOGD("%s: send peer authorize wmi cmd for %pM\n",
				 __func__, add_bss->bssId);
			wma_set_peer_param(wma, add_bss->bssId,
					   WMI_PEER_AUTHORIZE, 1,
					   add_bss->staContext.smesessionId);
			wma_vdev_set_bss_params(wma, add_bss->staContext.smesessionId,
					add_bss->beaconInterval, add_bss->dtimPeriod,
					add_bss->shortSlotTimeSupported, add_bss->llbCoexist);
		}
		/*
		 * Store the bssid in interface table, bssid will
		 * be used during group key setting sta mode.
		 */
		vos_mem_copy(iface->bssid, add_bss->bssId, ETH_ALEN);

	}
send_bss_resp:
		ol_txrx_find_peer_by_addr(pdev, add_bss->bssId,
					  &add_bss->staContext.staIdx);
		add_bss->status = (add_bss->staContext.staIdx < 0) ?
				VOS_STATUS_E_FAILURE : VOS_STATUS_SUCCESS;
		add_bss->bssIdx = add_bss->staContext.smesessionId;
		vos_mem_copy(add_bss->staContext.staMac, add_bss->bssId,
				 sizeof(add_bss->staContext.staMac));
	WMA_LOGD("%s: opermode %d update_bss %d nw_type %d bssid %pM"
			 " staIdx %d status %d\n", __func__, add_bss->operMode,
			 add_bss->updateBss, add_bss->nwType, add_bss->bssId,
			 add_bss->staContext.staIdx, add_bss->status);
		wma_send_msg(wma, WDA_ADD_BSS_RSP, (void *)add_bss, 0);
		return;

peer_cleanup:
		wma_remove_peer(wma, add_bss->bssId, vdev_id, peer);
send_fail_resp:
		add_bss->status = VOS_STATUS_E_FAILURE;
		wma_send_msg(wma, WDA_ADD_BSS_RSP, (void *)add_bss, 0);
}

static void wma_add_bss(tp_wma_handle wma, tpAddBssParams params)
{
	if ((params->halPersona == VOS_STA_SAP_MODE) ||
			(params->halPersona == VOS_P2P_GO_MODE))
		wma_add_bss_ap_mode(wma, params);
	else
		wma_add_bss_sta_mode(wma, params);
}

static int wmi_unified_vdev_up_send(wmi_unified_t wmi,
				    u_int8_t vdev_id, u_int16_t aid,
				    u_int8_t bssid[IEEE80211_ADDR_LEN])
{
	wmi_vdev_up_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len = sizeof(*cmd);

	printk("%s: VDEV_UP\n", __func__);
	WMA_LOGD("%s: vdev_id %d aid %d bssid %pM\n", __func__,
		 vdev_id, aid, bssid);
	buf = wmi_buf_alloc(wmi, len);
	if (!buf) {
		WMA_LOGP("%s:wmi_buf_alloc failed\n", __func__);
		return -ENOMEM;
	}
	cmd = (wmi_vdev_up_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_vdev_up_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(wmi_vdev_up_cmd_fixed_param));
	cmd->vdev_id = vdev_id;
	cmd->vdev_assoc_id = aid;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(bssid, &cmd->vdev_bssid);
	if (wmi_unified_cmd_send(wmi, buf, len, WMI_VDEV_UP_CMDID)) {
		WMA_LOGP("Failed to send vdev up command\n");
		adf_nbuf_free(buf);
		return -EIO;
	}
	return 0;
}

static int32_t wmi_unified_set_ap_ps_param(void *wma_ctx, u_int32_t vdev_id,
			u_int8_t *peer_addr, u_int32_t param, u_int32_t value)
{
	tp_wma_handle wma_handle = (tp_wma_handle) wma_ctx;
	wmi_ap_ps_peer_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t err;

	buf = wmi_buf_alloc(wma_handle->wmi_handle, sizeof(*cmd));
	if (!buf) {
		WMA_LOGE("Failed to allocate buffer to send set_ap_ps_param cmd");
		return -ENOMEM;
	}
	cmd = (wmi_ap_ps_peer_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_ap_ps_peer_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_ap_ps_peer_cmd_fixed_param));
	cmd->vdev_id = vdev_id;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(peer_addr, &cmd->peer_macaddr);
	cmd->param = param;
	cmd->value = value;
	err = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
				   sizeof(*cmd), WMI_AP_PS_PEER_PARAM_CMDID);
	if (err) {
		WMA_LOGE("Failed to send set_ap_ps_param cmd");
		adf_os_mem_free(buf);
		return -EIO;
	}
	return 0;
}

static int32_t wma_set_ap_peer_uapsd(tp_wma_handle wma, u_int32_t vdev_id,
		u_int8_t *peer_addr, u_int8_t uapsd_value, u_int8_t max_sp)
{
	u_int32_t uapsd = 0;
	u_int32_t max_sp_len = 0;
	int32_t ret = 0;

	if (uapsd_value & UAPSD_VO_ENABLED) {
		uapsd |= WMI_AP_PS_UAPSD_AC3_DELIVERY_EN |
			WMI_AP_PS_UAPSD_AC3_TRIGGER_EN;
	}

	if (uapsd_value & UAPSD_VI_ENABLED) {
		uapsd |= WMI_AP_PS_UAPSD_AC2_DELIVERY_EN |
			WMI_AP_PS_UAPSD_AC2_TRIGGER_EN;
	}

	if (uapsd_value & UAPSD_BK_ENABLED) {
		uapsd |= WMI_AP_PS_UAPSD_AC1_DELIVERY_EN |
			WMI_AP_PS_UAPSD_AC1_TRIGGER_EN;
	}

	if (uapsd_value & UAPSD_BE_ENABLED) {
		uapsd |= WMI_AP_PS_UAPSD_AC0_DELIVERY_EN |
			WMI_AP_PS_UAPSD_AC0_TRIGGER_EN;
	}

	switch (max_sp) {
	case UAPSD_MAX_SP_LEN_2:
		max_sp_len = WMI_AP_PS_PEER_PARAM_MAX_SP_2;
		break;
	case UAPSD_MAX_SP_LEN_4:
		max_sp_len = WMI_AP_PS_PEER_PARAM_MAX_SP_4;
		break;
	case UAPSD_MAX_SP_LEN_6:
		max_sp_len = WMI_AP_PS_PEER_PARAM_MAX_SP_6;
		break;
	default:
		max_sp_len = WMI_AP_PS_PEER_PARAM_MAX_SP_UNLIMITED;
		break;
	}

	WMA_LOGD("Set WMI_AP_PS_PEER_PARAM_UAPSD 0x%x for %pM",
		uapsd, peer_addr);

	ret = wmi_unified_set_ap_ps_param(wma, vdev_id,
					peer_addr,
					WMI_AP_PS_PEER_PARAM_UAPSD,
					uapsd);
	if (ret) {
		WMA_LOGE("Failed to set WMI_AP_PS_PEER_PARAM_UAPSD for %pM",
			peer_addr);
		return ret;
	}

	WMA_LOGD("Set WMI_AP_PS_PEER_PARAM_MAX_SP 0x%x for %pM",
		max_sp_len, peer_addr);

	ret = wmi_unified_set_ap_ps_param(wma, vdev_id,
					peer_addr,
					WMI_AP_PS_PEER_PARAM_MAX_SP,
					max_sp_len);
	if (ret) {
		WMA_LOGE("Failed to set WMI_AP_PS_PEER_PARAM_MAX_SP for %pM",
			 peer_addr);
		return ret;
	}
	return 0;
}

static void wma_add_sta_req_ap_mode(tp_wma_handle wma, tpAddStaParams add_sta)
{
	enum ol_txrx_peer_state state = ol_txrx_peer_state_conn;
	ol_txrx_pdev_handle pdev;
	ol_txrx_vdev_handle vdev;
	ol_txrx_peer_handle peer;
	u_int8_t peer_id;
	VOS_STATUS status;
	int32_t ret;

	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);

	/* UMAC sends WDA_ADD_STA_REQ msg twice to WMA when the station
	 * associates. First WDA_ADD_STA_REQ will have staType as
	 * STA_ENTRY_PEER and second posting will have STA_ENTRY_SELF.
	 * Peer creation is done in first WDA_ADD_STA_REQ and second
	 * WDA_ADD_STA_REQ which has STA_ENTRY_SELF is ignored and
	 * send fake response with success to UMAC. Otherwise UMAC
	 * will get blocked.
	 */
	if (add_sta->staType != STA_ENTRY_PEER) {
		add_sta->status = VOS_STATUS_SUCCESS;
		goto send_rsp;
	}

	vdev = wma_find_vdev_by_id(wma, add_sta->smesessionId);
	if (!vdev) {
		WMA_LOGE("%s: Failed to find vdev\n", __func__);
		add_sta->status = VOS_STATUS_E_FAILURE;
		goto send_rsp;
	}

	status = wma_create_peer(wma, pdev, vdev, add_sta->staMac,
				 add_sta->smesessionId);
	if (status != VOS_STATUS_SUCCESS) {
		WMA_LOGE("%s: Failed to create peer for %pM\n",
			 __func__, add_sta->staMac);
		add_sta->status = status;
		goto send_rsp;
	}

	peer = ol_txrx_find_peer_by_addr(pdev, add_sta->staMac,
					 &peer_id);
	if (!peer) {
		WMA_LOGE("%s: Failed to find peer handle using peer mac %pM\n",
			 __func__, add_sta->staMac);
		add_sta->status = VOS_STATUS_E_FAILURE;
		wma_remove_peer(wma, add_sta->staMac, add_sta->smesessionId, peer);
		goto send_rsp;
	}

	wmi_unified_send_txbf(wma, add_sta);

	ret = wmi_unified_send_peer_assoc(wma, add_sta->nwType, add_sta);
	if (ret) {
		add_sta->status = VOS_STATUS_E_FAILURE;
		wma_remove_peer(wma, add_sta->staMac, add_sta->smesessionId, peer);
		goto send_rsp;
	}
	if (add_sta->encryptType == eSIR_ED_NONE) {
		ret = wma_set_peer_param(wma, add_sta->staMac,
					 WMI_PEER_AUTHORIZE, 1,
					 add_sta->smesessionId);
		if (ret) {
			add_sta->status = VOS_STATUS_E_FAILURE;
			wma_remove_peer(wma, add_sta->staMac,
					add_sta->smesessionId, peer);
			goto send_rsp;
		}
		state = ol_txrx_peer_state_auth;
	}

	if (add_sta->uAPSD) {
		ret = wma_set_ap_peer_uapsd(wma, add_sta->smesessionId,
					add_sta->staMac,
					add_sta->uAPSD,
					add_sta->maxSPLen);
		if (ret) {
			WMA_LOGE("Failed to set peer uapsd param for %pM",
				 add_sta->staMac);
			add_sta->status = VOS_STATUS_E_FAILURE;
			wma_remove_peer(wma, add_sta->staMac,
					add_sta->smesessionId, peer);
			goto send_rsp;
		}
	}

	WMA_LOGD("%s: Moving peer %pM to state %d\n",
		 __func__, add_sta->staMac, state);
	ol_txrx_peer_state_update(pdev, add_sta->staMac, state);

	add_sta->staIdx = ol_txrx_local_peer_id(peer);
	add_sta->status = VOS_STATUS_SUCCESS;
send_rsp:
	WMA_LOGD("%s: Sending add sta rsp to umac (mac:%pM, status:%d)\n",
		__func__, add_sta->staMac, add_sta->status);
	wma_send_msg(wma, WDA_ADD_STA_RSP, (void *)add_sta, 0);
}

static void wma_add_sta_req_sta_mode(tp_wma_handle wma, tpAddStaParams params)
{
	ol_txrx_pdev_handle pdev;
	VOS_STATUS status = VOS_STATUS_SUCCESS;
	ol_txrx_peer_handle peer;
	struct wma_txrx_node *iface;

	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);
	iface = &wma->interfaces[params->smesessionId];
	if (params->staType != STA_ENTRY_SELF) {
		WMA_LOGP("%s: unsupported station type %d\n",
			 __func__, params->staType);
		goto out;
	}
	peer = ol_txrx_find_peer_by_addr(pdev, params->bssId, &params->staIdx);
	if (peer != NULL && peer->state == ol_txrx_peer_state_disc) {
		/*
		 * This is the case for reassociation.
		 * peer state update and peer_assoc is required since it
		 * was not done by WDA_ADD_BSS_REQ.
		 */

		/* Update peer state */
		if (params->encryptType == eSIR_ED_NONE) {
			WMA_LOGD("%s: Update peer(%pM) state into auth\n",
				 __func__, params->bssId);
			ol_txrx_peer_state_update(pdev, params->bssId,
						  ol_txrx_peer_state_auth);
		} else {
			WMA_LOGD("%s: Update peer(%pM) state into conn\n",
				 __func__, params->bssId);
			ol_txrx_peer_state_update(pdev, params->bssId,
						  ol_txrx_peer_state_conn);
		}

		if (params->encryptType == eSIR_ED_NONE) {
			WMA_LOGD("%s: send peer authorize wmi cmd for %pM\n",
				 __func__, params->bssId);
			wma_set_peer_param(wma, params->bssId,
					   WMI_PEER_AUTHORIZE, 1,
					   params->smesessionId);
		}
		wmi_unified_send_txbf(wma, params);
		wmi_unified_send_peer_assoc(wma, params->nwType,
					params);
	}
	wma_vdev_set_bss_params(wma, params->smesessionId, iface->beaconInterval,
			iface->dtimPeriod, iface->shortSlotTimeSupported, iface->llbCoexist);

	wma_roam_scan_offload_init_connect(wma, params->smesessionId);
	if (wmi_unified_vdev_up_send(wma->wmi_handle, params->smesessionId,
				     params->assocId, params->bssId) < 0) {
		WMA_LOGP("Failed to send vdev up cmd: vdev %d bssid %pM\n",
			 params->smesessionId, params->bssId);
		status = VOS_STATUS_E_FAILURE;
	}

out:
	params->status = status;
	WMA_LOGD("%s: statype %d vdev_id %d aid %d bssid %pM staIdx %d status %d\n",
		 __func__, params->staType, params->smesessionId, params->assocId,
		 params->bssId, params->staIdx, status);
	wma_send_msg(wma, WDA_ADD_STA_RSP, (void *)params, 0);
}

static void wma_add_sta(tp_wma_handle wma, tpAddStaParams add_sta)
{
	tANI_U8 oper_mode = BSS_OPERATIONAL_MODE_STA;

	if (wma_is_vdev_in_ap_mode(wma, add_sta->smesessionId))
		oper_mode = BSS_OPERATIONAL_MODE_AP;

	switch (oper_mode) {
	case BSS_OPERATIONAL_MODE_STA:
		wma_add_sta_req_sta_mode(wma, add_sta);
		break;

	case BSS_OPERATIONAL_MODE_AP:
		wma_add_sta_req_ap_mode(wma, add_sta);
		break;
	}
}

/*
 * This function reads WEP keys from cfg and fills
 * up key_info.
 */
static void wma_read_cfg_wepkey(tp_wma_handle wma_handle,
				tSirKeys *key_info, v_U32_t *def_key_idx,
				u_int8_t *num_keys)
{
	tSirRetStatus status;
	v_U32_t val = SIR_MAC_KEY_LENGTH;
	u_int8_t i, j;

	WMA_LOGD("Reading WEP keys from cfg");
	/* NOTE:def_key_idx is initialized to 0 by the caller */
	status = wlan_cfgGetInt(wma_handle->mac_context,
				WNI_CFG_WEP_DEFAULT_KEYID, def_key_idx);
	if (status != eSIR_SUCCESS)
		WMA_LOGE("Unable to read default id, defaulting to 0");

	for (i = 0, j = 0; i < SIR_MAC_MAX_NUM_OF_DEFAULT_KEYS; i++) {
		status = wlan_cfgGetStr(wma_handle->mac_context,
				(u_int16_t) WNI_CFG_WEP_DEFAULT_KEY_1 + i,
				key_info[j].key, &val);
		if (status != eSIR_SUCCESS) {
			WMA_LOGE("WEP key is not configured at :%d", i);
		} else {
			key_info[j].keyId = i;
			key_info[j].keyLength = (u_int16_t) val;
			j++;
		}
	}
	*num_keys = j;
}

/*
 * This function setsup wmi buffer from information
 * passed in key_params.
 */
static wmi_buf_t wma_setup_install_key_cmd(tp_wma_handle wma_handle,
				struct wma_set_key_params *key_params,
				u_int32_t *len)
{
	wmi_vdev_install_key_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	u_int8_t *buf_ptr;
	u_int8_t *key_data;

	if ((key_params->key_type == eSIR_ED_NONE &&
	    key_params->key_len) || (key_params->key_type != eSIR_ED_NONE &&
	    !key_params->key_len)) {
		WMA_LOGE("%s:Invalid set key request", __func__);
		return NULL;
	}

	*len = sizeof(*cmd) + roundup(key_params->key_len, sizeof(u_int32_t)) +
		WMI_TLV_HDR_SIZE;

	buf = wmi_buf_alloc(wma_handle->wmi_handle, *len);
	if (!buf) {
		WMA_LOGE("Failed to allocate buffer to send set key cmd");
		return NULL;
	}

	buf_ptr = (u_int8_t *) wmi_buf_data(buf);
	cmd = (wmi_vdev_install_key_cmd_fixed_param *) buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_vdev_install_key_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_vdev_install_key_cmd_fixed_param));
	cmd->vdev_id = key_params->vdev_id;
	cmd->key_ix = key_params->key_idx;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(key_params->peer_mac,
				   &cmd->peer_macaddr);
	if (key_params->unicast)
		cmd->key_flags |= PAIRWISE_USAGE;
	else
		cmd->key_flags |= GROUP_USAGE;

	switch (key_params->key_type) {
	case eSIR_ED_NONE:
		cmd->key_cipher = WMI_CIPHER_NONE;
		break;
	case eSIR_ED_WEP40:
	case eSIR_ED_WEP104:
		cmd->key_cipher = WMI_CIPHER_WEP;
		if (key_params->unicast &&
		    cmd->key_ix == key_params->def_key_idx)
			cmd->key_flags |= TX_USAGE;
		break;
	case eSIR_ED_TKIP:
		cmd->key_txmic_len = WMA_TXMIC_LEN;
		cmd->key_rxmic_len = WMA_RXMIC_LEN;
		cmd->key_cipher = WMI_CIPHER_TKIP;
		break;
#ifdef FEATURE_WLAN_WAPI
#define WPI_IV_LEN 16
	case eSIR_ED_WPI:
	{
		/*initialize receive and transmit IV with default values*/
		unsigned char tx_iv[16] = {0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,
					   0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,
					   0x36,0x5c};
		unsigned char rx_iv[16] = {0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,
					   0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,
					   0x5c,0x36};
		cmd->key_txmic_len = WMA_TXMIC_LEN;
		cmd->key_rxmic_len = WMA_RXMIC_LEN;
		vos_mem_copy(&cmd->wpi_key_rsc_counter, &rx_iv, WPI_IV_LEN);
		vos_mem_copy(&cmd->wpi_key_tsc_counter, &tx_iv, WPI_IV_LEN);
		cmd->key_cipher = WMI_CIPHER_WAPI;
		break;
	}
#endif
	case eSIR_ED_CCMP:
		cmd->key_cipher = WMI_CIPHER_AES_CCM;
		break;
	default:
		/* TODO: MFP ? */
		WMA_LOGE("%s:Invalid encryption type:%d", __func__, key_params->key_type);
		adf_nbuf_free(buf);
		return NULL;
	}

	buf_ptr += sizeof(wmi_vdev_install_key_cmd_fixed_param);
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_BYTE,
		       roundup(key_params->key_len, sizeof(u_int32_t)));
	key_data = (A_UINT8*)(buf_ptr + WMI_TLV_HDR_SIZE);
#ifdef BIG_ENDIAN_HOST
	{
		/* for big endian host, copy engine byte_swap is enabled
		 * But the key data content is in network byte order
		 * Need to byte swap the key data content - so when copy engine
		 * does byte_swap - target gets key_data content in the correct
		 * order.
		 */
		int8_t i;
		u_int32_t *destp, *srcp;

		destp = (u_int32_t *) key_data;
		srcp =  (u_int32_t *) key_params->key_data;
		for(i = 0;
		    i < roundup(key_params->key_len, sizeof(u_int32_t)) / 4;
		    i++) {
			*destp = le32_to_cpu(*srcp);
			destp++;
			srcp++;
		}
	}
#else
	vos_mem_copy((void *) key_data,
		     (const void *) key_params->key_data,
		     key_params->key_len);
#endif
	cmd->key_len = key_params->key_len;

	WMA_LOGD("Key setup : vdev_id %d key_idx %d key_type %d key_len %d"
		 " unicast %d peer_mac %pM def_key_idx %d", key_params->vdev_id,
		 key_params->key_idx, key_params->key_type, key_params->key_len,
		 key_params->unicast, key_params->peer_mac,
		 key_params->def_key_idx);

	return buf;
}

static void wma_set_bsskey(tp_wma_handle wma_handle, tpSetBssKeyParams key_info)
{
	struct wma_set_key_params key_params;
	wmi_buf_t buf;
	int32_t status;
	u_int32_t len = 0, i;
	v_U32_t def_key_idx = 0;
	ol_txrx_vdev_handle txrx_vdev;

	WMA_LOGD("BSS key setup");
	txrx_vdev = wma_find_vdev_by_id(wma_handle, key_info->smesessionId);
	if (!txrx_vdev) {
		WMA_LOGE("%s:Invalid vdev handle", __func__);
		key_info->status = eHAL_STATUS_FAILURE;
		goto out;
	}

	adf_os_mem_set(&key_params, 0, sizeof(key_params));
	key_params.vdev_id = key_info->smesessionId;
	key_params.key_type = key_info->encType;
	key_params.singl_tid_rc = key_info->singleTidRc;
	key_params.unicast = FALSE;
	if (txrx_vdev->opmode == wlan_op_mode_sta) {
		vos_mem_copy(key_params.peer_mac,
			wma_handle->interfaces[key_info->smesessionId].bssid,
			ETH_ALEN);
	} else {
		/* vdev mac address will be passed for AP/IBSS mode */
		vos_mem_copy(key_params.peer_mac, txrx_vdev->mac_addr.raw,
			     ETH_ALEN);
	}

	if (key_info->numKeys == 0 &&
	    (key_info->encType == eSIR_ED_WEP40 ||
	     key_info->encType == eSIR_ED_WEP104)) {
		wma_read_cfg_wepkey(wma_handle, key_info->key,
				    &def_key_idx, &key_info->numKeys);
	}

	for (i = 0; i < key_info->numKeys; i++) {
		if (key_params.key_type != eSIR_ED_NONE &&
		    !key_info->key[i].keyLength)
			continue;
		key_params.key_idx = key_info->key[i].keyId;
		key_params.key_len = key_info->key[i].keyLength;
		if (key_info->encType == eSIR_ED_TKIP) {
			vos_mem_copy(key_params.key_data,
				     key_info->key[i].key, 16);
			vos_mem_copy(&key_params.key_data[16],
				     &key_info->key[i].key[24], 8);
			vos_mem_copy(&key_params.key_data[24],
				     &key_info->key[i].key[16], 8);
		} else
			vos_mem_copy((v_VOID_t *) key_params.key_data,
				     (const v_VOID_t *) key_info->key[i].key,
				     key_info->key[i].keyLength);

		buf = wma_setup_install_key_cmd(wma_handle, &key_params, &len);
		if (!buf) {
			WMA_LOGE("%s:Failed to setup install key buf", __func__);
			key_info->status = eHAL_STATUS_FAILED_ALLOC;
			goto out;
		}

		status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
					      WMI_VDEV_INSTALL_KEY_CMDID);
		if (status) {
			adf_nbuf_free(buf);
			WMA_LOGE("%s:Failed to send install key command", __func__);
			key_info->status = eHAL_STATUS_FAILURE;
			goto out;
		}
	}

	/* TODO: Should we wait till we get HTT_T2H_MSG_TYPE_SEC_IND? */
	key_info->status = eHAL_STATUS_SUCCESS;

out:
	wma_send_msg(wma_handle, WDA_SET_BSSKEY_RSP, (void *)key_info, 0);
}

static void wma_set_stakey(tp_wma_handle wma_handle, tpSetStaKeyParams key_info)
{
	wmi_buf_t buf;
	int32_t status, i;
	u_int32_t len = 0;
	ol_txrx_pdev_handle txrx_pdev;
	ol_txrx_vdev_handle txrx_vdev;
	struct ol_txrx_peer_t *peer;
	u_int8_t num_keys = 0, peer_id;
	struct wma_set_key_params key_params;
	v_U32_t def_key_idx = 0;

	WMA_LOGD("STA key setup");

	/* Get the txRx Pdev handle */
	txrx_pdev = vos_get_context(VOS_MODULE_ID_TXRX,
				    wma_handle->vos_context);
	if (!txrx_pdev) {
		WMA_LOGE("%s:Invalid txrx pdev handle", __func__);
		key_info->status = eHAL_STATUS_FAILURE;
		goto out;
	}

	peer = ol_txrx_find_peer_by_addr(txrx_pdev, key_info->peerMacAddr,
					 &peer_id);
	if (!peer) {
		WMA_LOGE("%s:Invalid peer for key setting", __func__);
		key_info->status = eHAL_STATUS_FAILURE;
		goto out;
	}

	txrx_vdev = wma_find_vdev_by_id(wma_handle, key_info->smesessionId);
	if(!txrx_vdev) {
		WMA_LOGE("%s:TxRx Vdev Handle is NULL", __func__);
		key_info->status = eHAL_STATUS_FAILURE;
		goto out;
	}

	if (key_info->defWEPIdx == WMA_INVALID_KEY_IDX &&
	    (key_info->encType == eSIR_ED_WEP40 ||
	     key_info->encType == eSIR_ED_WEP104) &&
	     txrx_vdev->opmode != wlan_op_mode_ap) {
		wma_read_cfg_wepkey(wma_handle, key_info->key,
				    &def_key_idx, &num_keys);
		key_info->defWEPIdx = def_key_idx;
	} else {
		num_keys = SIR_MAC_MAX_NUM_OF_DEFAULT_KEYS;
		if (key_info->encType != eSIR_ED_NONE) {
			for (i = 0; i < num_keys; i++) {
				if (key_info->key[i].keyDirection ==
							eSIR_TX_DEFAULT) {
					key_info->defWEPIdx = i;
					break;
				}
			}
		}
	}
	adf_os_mem_set(&key_params, 0, sizeof(key_params));
	key_params.vdev_id = key_info->smesessionId;
	key_params.key_type = key_info->encType;
	key_params.singl_tid_rc = key_info->singleTidRc;
	key_params.unicast = TRUE;
	key_params.def_key_idx = key_info->defWEPIdx;
	vos_mem_copy((v_VOID_t *) key_params.peer_mac,
		     (const v_VOID_t *) key_info->peerMacAddr, ETH_ALEN);
	for (i = 0; i < num_keys; i++) {
		if (key_params.key_type != eSIR_ED_NONE &&
		    !key_info->key[i].keyLength)
			continue;
		if (key_info->encType == eSIR_ED_TKIP) {
			vos_mem_copy(key_params.key_data,
				     key_info->key[i].key, 16);
			vos_mem_copy(&key_params.key_data[16],
				     &key_info->key[i].key[24], 8);
			vos_mem_copy(&key_params.key_data[24],
				     &key_info->key[i].key[16], 8);
		} else
			vos_mem_copy(key_params.key_data, key_info->key[i].key,
				     key_info->key[i].keyLength);
		key_params.key_idx = i;
		key_params.key_len = key_info->key[i].keyLength;
		buf = wma_setup_install_key_cmd(wma_handle, &key_params, &len);
		if (!buf) {
			WMA_LOGE("%s:Failed to setup install key buf", __func__);
			key_info->status = eHAL_STATUS_FAILED_ALLOC;
			goto out;
		}

		status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
					      WMI_VDEV_INSTALL_KEY_CMDID);
		if (status) {
			adf_nbuf_free(buf);
			WMA_LOGE("%s:Failed to send install key command", __func__);
			key_info->status = eHAL_STATUS_FAILURE;
			goto out;
		}
	}

	/* TODO: Should we wait till we get HTT_T2H_MSG_TYPE_SEC_IND? */
	key_info->status = eHAL_STATUS_SUCCESS;
out:
	wma_send_msg(wma_handle, WDA_SET_STAKEY_RSP, (void *) key_info, 0);
}

static int wmi_unified_vdev_down_send(wmi_unified_t wmi, u_int8_t vdev_id)
{
	wmi_vdev_down_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len = sizeof(*cmd);

	buf = wmi_buf_alloc(wmi, len);
	if (!buf) {
		WMA_LOGP("%s : wmi_buf_alloc failed\n", __func__);
		return -ENOMEM;
	}
	cmd = (wmi_vdev_down_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_vdev_down_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(wmi_vdev_down_cmd_fixed_param));
	cmd->vdev_id = vdev_id;
	if (wmi_unified_cmd_send(wmi, buf, len, WMI_VDEV_DOWN_CMDID)) {
		WMA_LOGP("Failed to send vdev down\n");
		adf_nbuf_free(buf);
		return -EIO;
	}
	WMA_LOGD("%s: vdev_id %d\n", __func__, vdev_id);
	return 0;
}

static void wma_delete_sta_req_ap_mode(tp_wma_handle wma,
					tpDeleteStaParams del_sta)
{
	ol_txrx_pdev_handle pdev;
	struct ol_txrx_peer_t *peer;

	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);

	peer = ol_txrx_peer_find_by_local_id(pdev, del_sta->staIdx);
	if (!peer) {
		WMA_LOGE("%s: Failed to get peer handle using peer id %d\n",
			 __func__, del_sta->staIdx);
		del_sta->status = VOS_STATUS_E_FAILURE;
		goto send_del_rsp;
	}

	wma_remove_peer(wma, peer->mac_addr.raw, del_sta->smesessionId, peer);
	del_sta->status = VOS_STATUS_SUCCESS;

send_del_rsp:
	WMA_LOGD("%s: Sending del rsp to umac (status: %d)\n",
		 __func__, del_sta->status);
	wma_send_msg(wma, WDA_DELETE_STA_RSP, (void *)del_sta, 0);
}

static void wma_delete_sta_req_sta_mode(tp_wma_handle wma,
					tpDeleteStaParams params)
{
	VOS_STATUS status = VOS_STATUS_SUCCESS;

	wma_roam_scan_offload_init_connect(wma, params->smesessionId);
	if (wmi_unified_vdev_down_send(wma->wmi_handle, params->smesessionId) < 0) {
		WMA_LOGP("%s: failed to bring down vdev %d\n",
			 __func__, params->smesessionId);
		status = VOS_STATUS_E_FAILURE;
	}
	params->status = status;
	WMA_LOGD("%s: vdev_id %d status %d\n", __func__, params->smesessionId, status);
	wma_send_msg(wma, WDA_DELETE_STA_RSP, (void *)params, 0);
}

static void wma_delete_sta(tp_wma_handle wma, tpDeleteStaParams del_sta)
{
	tANI_U8 oper_mode = BSS_OPERATIONAL_MODE_STA;

	if (wma_is_vdev_in_ap_mode(wma, del_sta->smesessionId))
		oper_mode = BSS_OPERATIONAL_MODE_AP;

	switch (oper_mode) {
	case BSS_OPERATIONAL_MODE_STA:
		wma_delete_sta_req_sta_mode(wma, del_sta);
		break;

	case BSS_OPERATIONAL_MODE_AP:
		wma_delete_sta_req_ap_mode(wma, del_sta);
		break;
	}
}

static int32_t wmi_unified_vdev_stop_send(wmi_unified_t wmi, u_int8_t vdev_id)
{
	wmi_vdev_stop_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len = sizeof(*cmd);

	buf = wmi_buf_alloc(wmi, len);
	if (!buf) {
		WMA_LOGP("%s : wmi_buf_alloc failed\n", __func__);
		return -ENOMEM;
	}
	cmd = (wmi_vdev_stop_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_vdev_stop_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(wmi_vdev_stop_cmd_fixed_param));
	cmd->vdev_id = vdev_id;
	if (wmi_unified_cmd_send(wmi, buf, len, WMI_VDEV_STOP_CMDID)) {
		WMA_LOGP("Failed to send vdev stop command\n");
		adf_nbuf_free(buf);
		return -EIO;
	}
	return 0;
}

static void wma_delete_bss(tp_wma_handle wma, tpDeleteBssParams params)
{
	ol_txrx_pdev_handle pdev;
	ol_txrx_peer_handle peer;
	struct wma_target_req *msg;
	VOS_STATUS status = VOS_STATUS_SUCCESS;
	u_int8_t peer_id;

	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);

	peer = ol_txrx_find_peer_by_addr(pdev, params->bssid,
					 &peer_id);
	if (!peer) {
		WMA_LOGP("%s: Failed to find peer %pM\n", __func__,
			 params->bssid);
		status = VOS_STATUS_E_FAILURE;
		goto out;
	}

	vos_mem_zero(wma->interfaces[params->smesessionId].bssid, ETH_ALEN);
	msg = wma_fill_vdev_req(wma, params->smesessionId, WDA_DELETE_BSS_REQ,
				WMA_TARGET_REQ_TYPE_VDEV_STOP, params);
	if (!msg) {
		WMA_LOGP("%s: Failed to fill vdev request for vdev_id %d\n",
			 __func__, params->smesessionId);
		status = VOS_STATUS_E_NOMEM;
		goto detach_peer;
	}
	if (wmi_unified_vdev_stop_send(wma->wmi_handle, params->smesessionId)) {
		WMA_LOGP("%s: %d Failed to send vdev stop\n",
			 __func__, __LINE__);
		wma_remove_vdev_req(wma, params->smesessionId,
				    WMA_TARGET_REQ_TYPE_VDEV_STOP);
		status = VOS_STATUS_E_FAILURE;
		goto detach_peer;
	}
	WMA_LOGD("%s: bssid %pM vdev_id %d\n",
		__func__, params->bssid, params->smesessionId);
	return;
detach_peer:
	wma_remove_peer(wma, params->bssid, params->smesessionId, peer);
out:
	params->status = status;
	wma_send_msg(wma, WDA_DELETE_BSS_RSP, (void *)params, 0);
}

static void wma_set_linkstate(tp_wma_handle wma, tpLinkStateParams params)
{
	ol_txrx_pdev_handle pdev;
	ol_txrx_vdev_handle vdev;
	ol_txrx_peer_handle peer;
	u_int8_t vdev_id, peer_id;

	WMA_LOGD("%s: state %d selfmac %pM\n", __func__,
		 params->state, params->selfMacAddr);
	if ((params->state != eSIR_LINK_PREASSOC_STATE) &&
	    (params->state != eSIR_LINK_DOWN_STATE)) {
		WMA_LOGD("%s: unsupported link state %d\n",
			 __func__, params->state);
		goto out;
	}

	pdev = vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);
	vdev = wma_find_vdev_by_addr(wma, params->selfMacAddr, &vdev_id);
	if (!vdev) {
		WMA_LOGP("%s: vdev not found for addr: %pM\n",
			 __func__, params->selfMacAddr);
		goto out;
	}

	if (wma_is_vdev_in_ap_mode(wma, vdev_id)) {
		WMA_LOGD("%s: Ignoring set link req in ap mode\n", __func__);
		goto out;
	}

	if (params->state == eSIR_LINK_PREASSOC_STATE) {
		wma_create_peer(wma, pdev, vdev, params->bssid, vdev_id);
	}
	else {
		if (wmi_unified_vdev_stop_send(wma->wmi_handle, vdev_id)) {
			WMA_LOGP("%s: %d Failed to send vdev stop\n",
				 __func__, __LINE__);
		}
		peer = ol_txrx_find_peer_by_addr(pdev, params->bssid, &peer_id);
		if (peer) {
			WMA_LOGP("%s: Deleting peer %pM vdev id %d\n",
				 __func__, params->bssid, vdev_id);
			wma_remove_peer(wma, params->bssid, vdev_id, peer);
		}
	}
out:
	wma_send_msg(wma, WDA_SET_LINK_STATE_RSP, (void *)params, 0);
}

/*
 * Function to update per ac EDCA parameters
 */
static void wma_update_edca_params_for_ac(tSirMacEdcaParamRecord *edca_param,
					  wmi_wmm_params *wmm_param,
					  int ac)
{
	wmm_param->cwmin = edca_param->cw.min;
	wmm_param->cwmax = edca_param->cw.max;
	wmm_param->aifs = edca_param->aci.aifsn;
	wmm_param->txoplimit = edca_param->txoplimit;
	wmm_param->acm = edca_param->aci.acm;

	/* TODO: No ack is not present in EdcaParamRecord */
	wmm_param->no_ack = 0;

	WMA_LOGD("WMM PARAMS AC[%d]: AIFS %d Min %d Max %d TXOP %d ACM %d NOACK %d\n",
		 ac,
		 wmm_param->aifs,
		 wmm_param->cwmin,
		 wmm_param->cwmax,
		 wmm_param->txoplimit,
		 wmm_param->acm,
		 wmm_param->no_ack);
}

/*
 * Set TX power limit through vdev param
 */
static void wma_set_max_tx_power(WMA_HANDLE handle,
						    tMaxTxPowerParams *tx_pwr_params)
{
	tp_wma_handle wma_handle = (tp_wma_handle)handle;
	u_int8_t vdev_id;
	int ret = -1;

	if (wma_find_vdev_by_addr(wma_handle,
				tx_pwr_params->selfStaMacAddr,
				&vdev_id) != NULL) {
		WMA_LOGD("Set TX power limit [WMI_VDEV_PARAM_TX_PWRLIMIT] to %d",
				tx_pwr_params->power);
		ret = wmi_unified_vdev_set_param_send(wma_handle->wmi_handle, vdev_id,
				WMI_VDEV_PARAM_TX_PWRLIMIT,
				tx_pwr_params->power);
		if (ret)
			WMA_LOGE("Failed to set vdev param WMI_VDEV_PARAM_TX_PWRLIMIT");
	}
	else
		WMA_LOGE("Failed to find vdev to set WMI_VDEV_PARAM_TX_PWRLIMIT");
}

/*
 * Function to update the EDCA parameters to the target
 */
static VOS_STATUS wma_process_update_edca_param_req(WMA_HANDLE handle,
						    tEdcaParams *edca_params)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	u_int8_t *buf_ptr;
	wmi_buf_t buf;
	wmi_pdev_set_wmm_params_cmd_fixed_param *cmd;
	wmi_wmm_params *wmm_param;
	tSirMacEdcaParamRecord *edca_record;
	int ac;
	int len = sizeof(*cmd) + (WME_NUM_AC * sizeof(wmi_wmm_params));

	buf = wmi_buf_alloc(wma_handle->wmi_handle, len);

	if (!buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed\n", __func__);
		return VOS_STATUS_E_NOMEM;
	}

	buf_ptr = (u_int8_t *) wmi_buf_data(buf);
	cmd = (wmi_pdev_set_wmm_params_cmd_fixed_param *) buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_pdev_set_wmm_params_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_pdev_set_wmm_params_cmd_fixed_param));
	cmd->reserved0 = 0;
	buf_ptr += sizeof(wmi_pdev_set_wmm_params_cmd_fixed_param);

	for (ac = 0; ac < WME_NUM_AC; ac++) {
		wmm_param = (wmi_wmm_params *)
				(buf_ptr + ac * sizeof(wmi_wmm_params));
		WMITLV_SET_HDR(&wmm_param->tlv_header,
			       WMITLV_TAG_STRUC_wmi_wmm_params,
			       WMITLV_GET_STRUCT_TLVLEN(wmi_wmm_params));
		switch (ac) {
		case WME_AC_BE:
			edca_record = &edca_params->acbe;
			break;
		case WME_AC_BK:
			edca_record = &edca_params->acbk;
			break;
		case WME_AC_VI:
			edca_record = &edca_params->acvi;
			break;
		case WME_AC_VO:
			edca_record = &edca_params->acvo;
			break;
		default:
			goto fail;
		}

		wma_update_edca_params_for_ac(edca_record, wmm_param, ac);
	}

	if (wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
				  WMI_PDEV_SET_WMM_PARAMS_CMDID))
		goto fail;

	return VOS_STATUS_SUCCESS;

fail:
	wmi_buf_free(buf);
	WMA_LOGE("%s: Failed to set WMM Paremeters\n", __func__);
	return VOS_STATUS_E_FAILURE;
}

static void wma_send_beacon(tp_wma_handle wma, tpSendbeaconParams bcn_info)
{
	ol_txrx_vdev_handle vdev;
	u_int8_t vdev_id;
#ifndef QCA_WIFI_ISOC
	struct beacon_info *bcn;
	u_int32_t len;
	u_int8_t *bcn_payload;
	struct beacon_tim_ie *tim_ie;
#endif
	vdev = wma_find_vdev_by_addr(wma, bcn_info->bssId, &vdev_id);
	if (!vdev) {
		WMA_LOGE("%s : failed to get vdev handle\n", __func__);
		return;
	}
#ifndef QCA_WIFI_ISOC
	bcn = wma->interfaces[vdev_id].beacon;
	if (!bcn || !bcn->buf) {
		WMA_LOGE("%s: Memory is not allocated to hold bcn template\n",
			 __func__);
		return;
	}

	len = *(u32 *)&bcn_info->beacon[0];
	if (len > WMA_BCN_BUF_MAX_SIZE) {
		WMA_LOGE("%s: Received beacon len %d exceeding max limit %d\n",
			 __func__, len, WMA_BCN_BUF_MAX_SIZE);
		return;
	}
	WMA_LOGD("%s: Storing received beacon template buf to local buffer\n",
		 __func__);
	adf_os_spin_lock_bh(&bcn->lock);

	/*
	 * Copy received beacon template content in local buffer.
	 * this will be send to target on the reception of SWBA
	 * event from target.
	 */
	adf_nbuf_trim_tail(bcn->buf, adf_nbuf_len(bcn->buf));
	memcpy(adf_nbuf_data(bcn->buf),
			bcn_info->beacon + 4 /* Exclude beacon length field */,
			len);
	bcn->tim_ie_offset = bcn_info->timIeOffset - 4;

	bcn_payload = adf_nbuf_data(bcn->buf);
	tim_ie = (struct beacon_tim_ie *)(&bcn_payload[bcn->tim_ie_offset]);
	/*
	 * Intial Value of bcn->dtim_count will be 0.
	 * But if the beacon gets updated then current dtim
	 * count will be restored
	 */
	tim_ie->dtim_count = bcn->dtim_count;
	tim_ie->tim_bitctl = 0;

	adf_nbuf_put_tail(bcn->buf, len);

	adf_os_spin_unlock_bh(&bcn->lock);
	if (!bcn->len) {
#endif
		if (wmi_unified_vdev_up_send(wma->wmi_handle, vdev_id, 0,
					     bcn_info->bssId) < 0)
			WMA_LOGE("%s : failed to send vdev up\n", __func__);
#ifndef QCA_WIFI_ISOC
	}
	bcn->len = len;
#endif
	wma_set_sap_keepalive(wma, vdev_id);
}

#if !defined(REMOVE_PKT_LOG) && !defined(QCA_WIFI_ISOC)
static VOS_STATUS wma_pktlog_wmi_send_cmd(WMA_HANDLE handle,
					  struct ath_pktlog_wmi_params *params)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	WMI_PKTLOG_EVENT PKTLOG_EVENT;
	WMI_CMD_ID CMD_ID;
	wmi_pdev_pktlog_enable_cmd_fixed_param *cmd;
	wmi_pdev_pktlog_disable_cmd_fixed_param *disable_cmd;
	int len = 0;
	wmi_buf_t buf;

	PKTLOG_EVENT = params->pktlog_event;
	CMD_ID = params->cmd_id;

	switch (CMD_ID) {
	case WMI_PDEV_PKTLOG_ENABLE_CMDID:
		len = sizeof(*cmd);
		buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
		if (!buf) {
			WMA_LOGE("%s:wmi_buf_alloc failed", __func__);
			return VOS_STATUS_E_NOMEM;
		}
		cmd =
		    (wmi_pdev_pktlog_enable_cmd_fixed_param *)wmi_buf_data(buf);
		WMITLV_SET_HDR(&cmd->tlv_header,
			WMITLV_TAG_STRUC_wmi_pdev_pktlog_enable_cmd_fixed_param,
			WMITLV_GET_STRUCT_TLVLEN(
				wmi_pdev_pktlog_enable_cmd_fixed_param));
		cmd->evlist = PKTLOG_EVENT;
		if (wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
					 WMI_PDEV_PKTLOG_ENABLE_CMDID)) {
			WMA_LOGE("failed to send pktlog enable cmdid");
			goto wmi_send_failed;
		}
		break;
	case WMI_PDEV_PKTLOG_DISABLE_CMDID:
		len = sizeof(*disable_cmd);
		buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
		if (!buf) {
			WMA_LOGE("%s:wmi_buf_alloc failed", __func__);
			return VOS_STATUS_E_NOMEM;
		}
		disable_cmd = (wmi_pdev_pktlog_disable_cmd_fixed_param *)
			      wmi_buf_data(buf);
		WMITLV_SET_HDR(&disable_cmd->tlv_header,
		      WMITLV_TAG_STRUC_wmi_pdev_pktlog_disable_cmd_fixed_param,
		      WMITLV_GET_STRUCT_TLVLEN(
			      wmi_pdev_pktlog_disable_cmd_fixed_param));
		disable_cmd->reserved0 = 0;
		if (wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
					 WMI_PDEV_PKTLOG_DISABLE_CMDID)) {
			WMA_LOGE("failed to send pktlog disable cmdid");
			goto wmi_send_failed;
		}
		break;
	default:
		WMA_LOGD("%s: invalid PKTLOG command", __func__);
		break;
	}

	return VOS_STATUS_SUCCESS;

wmi_send_failed:
	wmi_buf_free(buf);
	return VOS_STATUS_E_FAILURE;
}
#endif

static int32_t wmi_unified_set_sta_ps(wmi_unified_t wmi_handle,
                               u_int32_t vdev_id, u_int8_t val)
{
        wmi_sta_powersave_mode_cmd_fixed_param *cmd;
        wmi_buf_t buf;
        int32_t len = sizeof(*cmd);

        WMA_LOGD("Set Sta Mode Ps vdevId %d val %d", vdev_id, val);

        buf = wmi_buf_alloc(wmi_handle, len);
        if (!buf) {
                WMA_LOGP("Set Sta Mode Ps Mem Alloc Failed");
                return -ENOMEM;
        }
        cmd = (wmi_sta_powersave_mode_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_sta_powersave_mode_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_sta_powersave_mode_cmd_fixed_param));
        cmd->vdev_id = vdev_id;
        if(val)
                cmd->sta_ps_mode = WMI_STA_PS_MODE_ENABLED;
        else
                cmd->sta_ps_mode = WMI_STA_PS_MODE_DISABLED;

        if(wmi_unified_cmd_send(wmi_handle, buf, len,
                       WMI_STA_POWERSAVE_MODE_CMDID))
        {
                WMA_LOGE("Set Sta Mode Ps Failed vdevId %d val %d",
                         vdev_id, val);
                adf_nbuf_free(buf);
                return -EIO;
        }
        return 0;
}

static inline u_int32_t wma_get_uapsd_mask(tpUapsd_Params uapsd_params)
{
	u_int32_t uapsd_val = 0;

	if(uapsd_params->beDeliveryEnabled)
		uapsd_val |= WMI_STA_PS_UAPSD_AC0_DELIVERY_EN;

	if(uapsd_params->beTriggerEnabled)
		uapsd_val |= WMI_STA_PS_UAPSD_AC0_TRIGGER_EN;

	if(uapsd_params->bkDeliveryEnabled)
		uapsd_val |= WMI_STA_PS_UAPSD_AC1_DELIVERY_EN;

	if(uapsd_params->bkTriggerEnabled)
		uapsd_val |= WMI_STA_PS_UAPSD_AC1_TRIGGER_EN;

	if(uapsd_params->viDeliveryEnabled)
		uapsd_val |= WMI_STA_PS_UAPSD_AC2_DELIVERY_EN;

	if(uapsd_params->viTriggerEnabled)
		uapsd_val |= WMI_STA_PS_UAPSD_AC2_TRIGGER_EN;

	if(uapsd_params->voDeliveryEnabled)
		uapsd_val |= WMI_STA_PS_UAPSD_AC3_DELIVERY_EN;

	if(uapsd_params->voTriggerEnabled)
		uapsd_val |= WMI_STA_PS_UAPSD_AC3_TRIGGER_EN;

	return uapsd_val;
}

static int32_t wma_set_force_sleep(tp_wma_handle wma, u_int32_t vdev_id, u_int8_t enable)
{
	int32_t ret;
	tANI_U32 cfg_data_val = 0;
	/* get mac to acess CFG data base */
	struct sAniSirGlobal *mac =
		(struct sAniSirGlobal*)vos_get_context(VOS_MODULE_ID_PE,
		wma->vos_context);
	u_int32_t rx_wake_policy;
	u_int32_t tx_wake_threshold;
	u_int32_t pspoll_count;
	u_int32_t inactivity_time;
	u_int32_t psmode;

	WMA_LOGE("Set Force Sleep vdevId %d val %d", vdev_id, enable);

	if (enable) {
		/* override normal configuration and force station asleep */
		rx_wake_policy = WMI_STA_PS_RX_WAKE_POLICY_POLL_UAPSD;
		tx_wake_threshold = WMI_STA_PS_TX_WAKE_THRESHOLD_NEVER;
		pspoll_count = WMI_STA_PS_PSPOLL_COUNT_NO_MAX;
		inactivity_time = 0;
		psmode = WMI_STA_PS_MODE_ENABLED;
	} else {
		/* Ps Poll Wake Policy */
		if (wlan_cfgGetInt(mac, WNI_CFG_MAX_PS_POLL,
				&cfg_data_val ) != eSIR_SUCCESS) {
			VOS_TRACE( VOS_MODULE_ID_WDA, VOS_TRACE_LEVEL_ERROR,
				"Failed to get value for WNI_CFG_MAX_PS_POLL");
		}
		if (cfg_data_val) {
			/* Ps Poll is enabled */
			rx_wake_policy = WMI_STA_PS_RX_WAKE_POLICY_POLL_UAPSD;
			pspoll_count = (u_int32_t)cfg_data_val;
			tx_wake_threshold = WMI_STA_PS_TX_WAKE_THRESHOLD_NEVER;
		} else {
			rx_wake_policy = WMI_STA_PS_RX_WAKE_POLICY_WAKE;
			pspoll_count = WMI_STA_PS_PSPOLL_COUNT_NO_MAX;
			tx_wake_threshold = WMI_STA_PS_TX_WAKE_THRESHOLD_ALWAYS;
		}
		psmode = WMI_STA_PS_MODE_ENABLED;

		/* Set Tx/Rx Data InActivity Timeout   */
		if (wlan_cfgGetInt(mac, WNI_CFG_PS_DATA_INACTIVITY_TIMEOUT,
				&cfg_data_val ) != eSIR_SUCCESS) {
			VOS_TRACE( VOS_MODULE_ID_WDA, VOS_TRACE_LEVEL_ERROR,
			"Failed to get WNI_CFG_PS_DATA_INACTIVITY_TIMEOUT");
			cfg_data_val = POWERSAVE_DEFAULT_INACTIVITY_TIME;
		}
		inactivity_time = (u_int32_t)cfg_data_val;
	}

	/* Set the Wake Policy to WMI_STA_PS_RX_WAKE_POLICY_POLL_UAPSD*/
	ret = wmi_unified_set_sta_ps_param(wma->wmi_handle, vdev_id,
					WMI_STA_PS_PARAM_RX_WAKE_POLICY,
					rx_wake_policy);

	if (ret) {
		WMA_LOGE("Setting wake policy Failed vdevId %d", vdev_id);
		return ret;
	}
	WMA_LOGD("Setting wake policy to %d vdevId %d",
		rx_wake_policy, vdev_id);

	/* Set the Tx Wake Threshold */
	ret = wmi_unified_set_sta_ps_param(wma->wmi_handle, vdev_id,
					WMI_STA_PS_PARAM_TX_WAKE_THRESHOLD,
					tx_wake_threshold);

	if (ret) {
		WMA_LOGE("Setting TxWake Threshold vdevId %d", vdev_id);
		return ret;
	}
	WMA_LOGD("Setting TxWake Threshold to %d vdevId %d",
		tx_wake_threshold, vdev_id);

	/* Set the Ps Poll Count */
	ret = wmi_unified_set_sta_ps_param(wma->wmi_handle, vdev_id,
					WMI_STA_PS_PARAM_PSPOLL_COUNT,
					pspoll_count);

	if (ret) {
		WMA_LOGE("Set Ps Poll Count Failed vdevId %d ps poll cnt %d",
			vdev_id, pspoll_count);
		return ret;
	}
	WMA_LOGD("Set Ps Poll Count vdevId %d ps poll cnt %d",
		vdev_id, pspoll_count);

	/* Set the Tx/Rx InActivity */
	ret = wmi_unified_set_sta_ps_param(wma->wmi_handle, vdev_id,
					WMI_STA_PS_PARAM_INACTIVITY_TIME,
					inactivity_time);

	if (ret) {
		WMA_LOGE("Setting Tx/Rx InActivity Failed vdevId %d InAct %d",
			vdev_id, inactivity_time);
		return ret;
	}
	WMA_LOGD("Set Tx/Rx InActivity vdevId %d InAct %d",
		vdev_id, inactivity_time);

	/* Enable Sta Mode Power save */
	ret = wmi_unified_set_sta_ps(wma->wmi_handle, vdev_id, true);

	if (ret) {
		WMA_LOGE("Enable Sta Mode Ps Failed vdevId %d", vdev_id);
		return ret;
	}

	/* Set Listen Interval */
	if (wlan_cfgGetInt(mac, WNI_CFG_LISTEN_INTERVAL,
			&cfg_data_val ) != eSIR_SUCCESS)	{
		VOS_TRACE( VOS_MODULE_ID_WDA, VOS_TRACE_LEVEL_ERROR,
			"Failed to get value for WNI_CFG_LISTEN_INTERVAL");
		cfg_data_val = POWERSAVE_DEFAULT_LISTEN_INTERVAL;
	}

	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
					WMI_VDEV_PARAM_LISTEN_INTERVAL,
					cfg_data_val);
	if (ret) {
		/* Even it fails continue Fw will take default LI */
		WMA_LOGE("Failed to Set Listen Interval vdevId %d",
			vdev_id);
	}
	WMA_LOGD("Set Listen Interval vdevId %d Listen Intv %d",
		vdev_id, cfg_data_val);
	return 0;
}

static void wma_enable_sta_ps_mode(tp_wma_handle wma, tpEnablePsParams ps_req)
{
	uint32_t vdev_id = ps_req->sessionid;
	int32_t ret;

	if (eSIR_ADDON_NOTHING == ps_req->psSetting) {
		WMA_LOGD("Enable Sta Mode Ps vdevId %d", vdev_id);
		ret = wma_set_force_sleep(wma, vdev_id, false);
		if (ret) {
			WMA_LOGE("Enable Sta Ps Failed vdevId %d", vdev_id);
			ps_req->status = VOS_STATUS_E_FAILURE;
			goto resp;
		}
	} else if (eSIR_ADDON_ENABLE_UAPSD == ps_req->psSetting) {
		u_int32_t uapsd_val = 0;
		uapsd_val = wma_get_uapsd_mask(&ps_req->uapsdParams);

		WMA_LOGD("Enable Uapsd vdevId %d Mask %d", vdev_id, uapsd_val);
		ret = wmi_unified_set_sta_ps_param(wma->wmi_handle, vdev_id,
					WMI_STA_PS_PARAM_UAPSD, uapsd_val);
		if (ret) {
			WMA_LOGE("Enable Uapsd Failed vdevId %d", vdev_id);
			ps_req->status = VOS_STATUS_E_FAILURE;
			goto resp;
		}

		WMA_LOGD("Enable Forced Sleep vdevId %d", vdev_id);
		ret = wma_set_force_sleep(wma, vdev_id, true);
		if (ret) {
			WMA_LOGE("Enable Forced Sleep Failed vdevId %d",
				vdev_id);
			ps_req->status = VOS_STATUS_E_FAILURE;
			goto resp;
		}
	}
	ps_req->status = VOS_STATUS_SUCCESS;
resp:
	wma_send_msg(wma, WDA_ENTER_BMPS_RSP, ps_req, 0);
}

static void wma_disable_sta_ps_mode(tp_wma_handle wma, tpDisablePsParams ps_req)
{
        int32_t ret;
        uint32_t vdev_id = ps_req->sessionid;

        WMA_LOGE("Disable Sta Mode Ps vdevId %d", vdev_id);

        /* Disable Sta Mode Power save */
        ret = wmi_unified_set_sta_ps(wma->wmi_handle, vdev_id, false);
        if(ret) {
                WMA_LOGE("Disable Sta Mode Ps Failed vdevId %d", vdev_id);
                ps_req->status = VOS_STATUS_E_FAILURE;
                goto resp;
        }

	/* Disable UAPSD incase if additional Req came */
	if (eSIR_ADDON_DISABLE_UAPSD == ps_req->psSetting) {
		WMA_LOGD("Disable Uapsd vdevId %d", vdev_id);
		ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
						WMI_STA_PS_PARAM_UAPSD, 0);
		if (ret) {
			WMA_LOGE("Disable Uapsd Failed vdevId %d", vdev_id);
			/*
			 * Even this fails we can proceed as success
			 * since we disabled powersave
			 */
		}
	}

        ps_req->status = VOS_STATUS_SUCCESS;
resp:
        wma_send_msg(wma, WDA_EXIT_BMPS_RSP, ps_req, 0);
}

static void wma_enable_uapsd_mode(tp_wma_handle wma,
				tpEnableUapsdParams ps_req)
{
	int32_t ret;
	u_int32_t vdev_id = ps_req->sessionid;
	u_int32_t uapsd_val = 0;

	/* Disable Sta Mode Power save */
	ret = wmi_unified_set_sta_ps(wma->wmi_handle, vdev_id, false);
	if (ret) {
		WMA_LOGE("Disable Sta Mode Ps Failed vdevId %d", vdev_id);
		ps_req->status = VOS_STATUS_E_FAILURE;
		goto resp;
	}

	uapsd_val = wma_get_uapsd_mask(&ps_req->uapsdParams);

	WMA_LOGD("Enable Uapsd vdevId %d Mask %d", vdev_id, uapsd_val);
	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
				WMI_STA_PS_PARAM_UAPSD, uapsd_val);
	if (ret) {
		WMA_LOGE("Enable Uapsd Failed vdevId %d", vdev_id);
		ps_req->status = VOS_STATUS_E_FAILURE;
		goto resp;
	}

	WMA_LOGD("Enable Forced Sleep vdevId %d", vdev_id);
	ret = wma_set_force_sleep(wma, vdev_id, true);
	if (ret) {
		WMA_LOGE("Enable Forced Sleep Failed vdevId %d", vdev_id);
		ps_req->status = VOS_STATUS_E_FAILURE;
		goto resp;
	}

	ps_req->status = VOS_STATUS_SUCCESS;
resp:
	wma_send_msg(wma, WDA_ENTER_UAPSD_RSP, ps_req, 0);
}

static void wma_disable_uapsd_mode(tp_wma_handle wma,
			tpDisableUapsdParams ps_req)
{
	int32_t ret;
	u_int32_t vdev_id = ps_req->sessionid;

	WMA_LOGD("Disable Uapsd vdevId %d", vdev_id);

	/* Disable Sta Mode Power save */
	ret = wmi_unified_set_sta_ps(wma->wmi_handle, vdev_id, false);
	if (ret) {
		WMA_LOGE("Disable Sta Mode Ps Failed vdevId %d", vdev_id);
		ps_req->status = VOS_STATUS_E_FAILURE;
		goto resp;
	}

	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
					WMI_STA_PS_PARAM_UAPSD, 0);
	if (ret) {
		WMA_LOGE("Disable Uapsd Failed vdevId %d", vdev_id);
		ps_req->status = VOS_STATUS_E_FAILURE;
		goto resp;
	}

	/* Re enable Sta Mode Powersave with proper configuration */
	ret = wma_set_force_sleep(wma, vdev_id, false);
	if (ret) {
		WMA_LOGE("Disable Forced Sleep Failed vdevId %d", vdev_id);
		ps_req->status = VOS_STATUS_E_FAILURE;
		goto resp;
	}

	ps_req->status = VOS_STATUS_SUCCESS;
resp:
	wma_send_msg(wma, WDA_EXIT_UAPSD_RSP, ps_req, 0);
}

static void wma_set_keepalive_req(tp_wma_handle wma,
				  tSirKeepAliveReq *keepalive)
{
	WMA_LOGD("KEEPALIVE:PacketType:%d", keepalive->packetType);
	wma_set_sta_keep_alive(wma, keepalive->sessionId,
				    keepalive->packetType,
				    keepalive->timePeriod,
				    keepalive->hostIpv4Addr,
				    keepalive->destIpv4Addr,
				    keepalive->destMacAddr);

	vos_mem_free(keepalive);
}
/*
 * This function sets the trigger uapsd
 * params such as service interval, delay
 * interval and suspend interval which
 * will be used by the firmware to send
 * trigger frames periodically when there
 * is no traffic on the transmit side.
 */
int32_t
wmi_unified_set_sta_uapsd_auto_trig_cmd(
        wmi_unified_t wmi_handle,
        u_int32_t vdevid,
        u_int8_t peer_addr[IEEE80211_ADDR_LEN],
        u_int8_t *autoTriggerparam,
        u_int32_t num_ac)
{
	wmi_sta_uapsd_auto_trig_cmd_fixed_param *cmd;
	int32_t ret;
	u_int32_t param_len = (num_ac - 1) *
				sizeof(wmi_sta_uapsd_auto_trig_param);
	u_int32_t cmd_len = sizeof(*cmd) + param_len + WMI_TLV_HDR_SIZE;
	u_int32_t i;
	wmi_buf_t buf;
	u_int8_t *buf_ptr;

	buf = wmi_buf_alloc(wmi_handle, cmd_len);
	if (!buf) {
		WMA_LOGE("%s:wmi_buf_alloc failed", __func__);
		return -ENOMEM;
	}

	buf_ptr = (u_int8_t *) wmi_buf_data(buf);
	cmd = (wmi_sta_uapsd_auto_trig_cmd_fixed_param *) buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_sta_uapsd_auto_trig_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
				wmi_sta_uapsd_auto_trig_cmd_fixed_param));
	cmd->vdev_id = vdevid;
	cmd->num_ac = num_ac;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(peer_addr, &cmd->peer_macaddr);

	/* TLV indicating array of structures to follow */
	buf_ptr += sizeof(*cmd);
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_STRUC, param_len);

	buf_ptr += WMI_TLV_HDR_SIZE;
	vos_mem_copy(buf_ptr, autoTriggerparam, param_len);

	/*
	 * Update tag and length for uapsd auto trigger params (this will take
	 * care of updating tag and length if it is not pre-filled by caller).
	 */
	for (i = 0; i < num_ac; i++) {
		WMITLV_SET_HDR((buf_ptr +
			       (i * sizeof(wmi_sta_uapsd_auto_trig_param))),
				WMITLV_TAG_STRUC_wmi_sta_uapsd_auto_trig_param,
				WMITLV_GET_STRUCT_TLVLEN(
					wmi_sta_uapsd_auto_trig_param));
	}

	ret = wmi_unified_cmd_send(wmi_handle, buf, cmd_len,
				WMI_STA_UAPSD_AUTO_TRIG_CMDID);
	if (ret != EOK) {
		WMA_LOGE("Failed to send set uapsd param ret = %d", ret);
		wmi_buf_free(buf);
	}
	return ret;
}

/*
 * This function sets the trigger uapsd
 * params such as service interval, delay
 * interval and suspend interval which
 * will be used by the firmware to send
 * trigger frames periodically when there
 * is no traffic on the transmit side.
 */
VOS_STATUS wma_trigger_uapsd_params(tp_wma_handle wma_handle, u_int32_t vdev_id,
			tp_wma_trigger_uapsd_params trigger_uapsd_params)
{
	int32_t ret;
	wmi_sta_uapsd_auto_trig_param uapsd_trigger_param;

	WMA_LOGD("Trigger uapsd params vdev id %d", vdev_id);

	WMA_LOGD("WMM AC %d User Priority %d SvcIntv %d DelIntv %d SusIntv %d",
		trigger_uapsd_params->wmm_ac,
		trigger_uapsd_params->user_priority,
		trigger_uapsd_params->service_interval,
		trigger_uapsd_params->delay_interval,
		trigger_uapsd_params->suspend_interval);

	if (!WMI_SERVICE_IS_ENABLED(wma_handle->wmi_service_bitmap,
				 WMI_STA_UAPSD_BASIC_AUTO_TRIG) ||
		!WMI_SERVICE_IS_ENABLED(wma_handle->wmi_service_bitmap,
				 WMI_STA_UAPSD_VAR_AUTO_TRIG)) {
		WMA_LOGD("Trigger uapsd is not supported vdev id %d", vdev_id);
		return VOS_STATUS_SUCCESS;
	}

	uapsd_trigger_param.wmm_ac =
				trigger_uapsd_params->wmm_ac;
	uapsd_trigger_param.user_priority =
				trigger_uapsd_params->user_priority;
	uapsd_trigger_param.service_interval =
				trigger_uapsd_params->service_interval;
	uapsd_trigger_param.suspend_interval =
				trigger_uapsd_params->suspend_interval;
	uapsd_trigger_param.delay_interval =
				trigger_uapsd_params->delay_interval;

	ret = wmi_unified_set_sta_uapsd_auto_trig_cmd(wma_handle->wmi_handle, vdev_id,
					wma_handle->interfaces[vdev_id].bssid,
					(u_int8_t*)(&uapsd_trigger_param),
					1);
	if (ret) {
		WMA_LOGE("Fail to send uapsd param cmd for vdevid %d ret = %d",
			ret, vdev_id);
		return VOS_STATUS_E_FAILURE;
	}
	return VOS_STATUS_SUCCESS;
}

#ifdef FEATURE_WLAN_PNO_OFFLOAD

/* Request FW to start PNO operation */
static VOS_STATUS wma_pno_start(tp_wma_handle wma, tpSirPNOScanReq pno)
{
	wmi_nlo_config_cmd_fixed_param *cmd;
	nlo_configured_parameters *nlo_list;
	u_int32_t *channel_list;
	int32_t len;
	wmi_buf_t buf;
	u_int8_t *buf_ptr;
	u_int8_t i;
	int ret;

	WMA_LOGD("PNO Start");

	len = sizeof(*cmd) +
	      WMI_TLV_HDR_SIZE + /* TLV place holder for array of structures nlo_configured_parameters(nlo_list) */
	      WMI_TLV_HDR_SIZE; /* TLV place holder for array of uint32 channel_list */

	len += sizeof(u_int32_t) * MIN(pno->aNetworks[0].ucChannelCount,
				   WMI_NLO_MAX_CHAN);
	len += sizeof(u_int32_t) * MIN(pno->ucNetworksCount, WMI_NLO_MAX_SSIDS);

	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: Failed allocate wmi buffer", __func__);
		return VOS_STATUS_E_NOMEM;
	}

	cmd = (wmi_nlo_config_cmd_fixed_param *) wmi_buf_data(buf);

	buf_ptr = (u_int8_t *) cmd;
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_nlo_config_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_nlo_config_cmd_fixed_param));
	cmd->vdev_id = pno->sessionId;
	cmd->flags = WMI_NLO_CONFIG_START;

	buf_ptr += sizeof(wmi_nlo_config_cmd_fixed_param);

	cmd->no_of_ssids = MIN(pno->ucNetworksCount, WMI_NLO_MAX_SSIDS);
	WMA_LOGD("SSID count : %d", cmd->no_of_ssids);
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_STRUC,
		       cmd->no_of_ssids * sizeof(nlo_configured_parameters));
	buf_ptr += WMI_TLV_HDR_SIZE;

	nlo_list = (nlo_configured_parameters *) buf_ptr;
	for (i = 0; i < cmd->no_of_ssids; i++) {
		/* Copy ssid and it's length */
		nlo_list[i].ssid.valid = TRUE;
		nlo_list[i].ssid.ssid.ssid_len = pno->aNetworks[i].ssId.length;
		vos_mem_copy(nlo_list[i].ssid.ssid.ssid,
			     pno->aNetworks[i].ssId.ssId,
			     nlo_list[i].ssid.ssid.ssid_len);
		WMA_LOGD("index: %d ssid: %s len: %d", i,
			 nlo_list[i].ssid.ssid.ssid,
			 nlo_list[i].ssid.ssid.ssid_len);
	}
	buf_ptr += cmd->no_of_ssids * sizeof(nlo_configured_parameters);

	/* Copy channel info */
	cmd->num_of_channels = MIN(pno->aNetworks[0].ucChannelCount,
				   WMI_NLO_MAX_CHAN);
	WMA_LOGD("Channel count: %d", cmd->num_of_channels);
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_UINT32,
		       (cmd->num_of_channels * sizeof(u_int32_t)));
	buf_ptr += WMI_TLV_HDR_SIZE;

	channel_list = (u_int32_t *) buf_ptr;
	for (i = 0; i < cmd->num_of_channels; i++) {
		channel_list[i] = pno->aNetworks[0].aChannels[i];

		if (channel_list[i] < WMA_NLO_FREQ_THRESH)
			channel_list[i] = vos_chan_to_freq(channel_list[i]);

		WMA_LOGD("Ch[%d]: %d MHz", i, channel_list[i]);
	}
	buf_ptr += cmd->num_of_channels * sizeof(u_int32_t);


	/* TODO: PNO offload present in discrete firmware is implemented
	 * by keeping Windows requirement. Following options are missing
	 * in current discrete firmware to meet linux requirement.
	 *     1) Option to configure Sched scan period.
	 *     2) Option to configure RSSI threshold.
	 *     3) Option to configure APP IE (comes from wpa_supplicant).
	 * Until firmware team brings above changes, lets live with what's
	 * available.
	 */

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_NETWORK_LIST_OFFLOAD_CONFIG_CMDID);
	if (ret) {
		WMA_LOGE("%s: Failed to send nlo wmi cmd", __func__);
		wmi_buf_free(buf);
		return VOS_STATUS_E_FAILURE;
	}

	wma->interfaces[pno->sessionId].pno_in_progress = TRUE;

	WMA_LOGD("PNO start request sent successfully for vdev %d",
		 pno->sessionId);

	return VOS_STATUS_SUCCESS;
}

/* Request FW to stop ongoing PNO operation */
static VOS_STATUS wma_pno_stop(tp_wma_handle wma, u_int8_t vdev_id)
{
	wmi_nlo_config_cmd_fixed_param *cmd;
	int32_t len = sizeof(*cmd);
	wmi_buf_t buf;
	u_int8_t *buf_ptr;
	int ret;

	if (!wma->interfaces[vdev_id].pno_in_progress) {
		WMA_LOGD("No active pno session found for vdev %d, skip pno stop request",
			 vdev_id);
		return VOS_STATUS_SUCCESS;
	}

	WMA_LOGD("PNO Stop");

	len += WMI_TLV_HDR_SIZE + /* TLV place holder for array of structures nlo_configured_parameters(nlo_list) */
	       WMI_TLV_HDR_SIZE; /* TLV place holder for array of uint32 channel_list */
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: Failed allocate wmi buffer", __func__);
		return VOS_STATUS_E_NOMEM;
	}

	cmd = (wmi_nlo_config_cmd_fixed_param *) wmi_buf_data(buf);
	buf_ptr = (u_int8_t *) cmd;
	cmd->vdev_id = vdev_id;
	cmd->flags = WMI_NLO_CONFIG_STOP;
	buf_ptr += sizeof(*cmd);

	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_STRUC, 0);
	buf_ptr += WMI_TLV_HDR_SIZE;

	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_UINT32, 0);
	buf_ptr += WMI_TLV_HDR_SIZE;

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_NETWORK_LIST_OFFLOAD_CONFIG_CMDID);
	if (ret) {
		WMA_LOGE("%s: Failed to send nlo wmi cmd", __func__);
		wmi_buf_free(buf);
		return VOS_STATUS_E_FAILURE;
	}

	wma->interfaces[vdev_id].pno_in_progress = FALSE;

	WMA_LOGD("PNO stop request sent successfully for vdev %d",
		 vdev_id);

	return VOS_STATUS_SUCCESS;
}

static void wma_config_pno(tp_wma_handle wma, tpSirPNOScanReq pno)
{
	VOS_STATUS ret;

	if (pno->enable)
		ret = wma_pno_start(wma, pno);
	else
		ret = wma_pno_stop(wma, pno->sessionId);

	if (ret)
		WMA_LOGE("%s: PNO %s failed %d", __func__,
			 pno->enable ? "start" : "stop", ret);

	/* SME expects WMA to free tpSirPNOScanReq memory after
	 * processing PNO request. */
	vos_mem_free(pno);
}

/*
 * After pushing cached scan results (that are stored in LIM) to SME,
 * PE will post WDA_SME_SCAN_CACHE_UPDATED message indication to
 * wma and intern this function handles that message. This function will
 * check for PNO completion (by checking NLO match event) and post PNO
 * completion back to SME if PNO operation is completed successfully.
 */
void wma_scan_cache_updated_ind(tp_wma_handle wma)
{
	tSirPrefNetworkFoundInd *nw_found_ind;
	VOS_STATUS status;
	vos_msg_t vos_msg;
	u_int8_t len, i;

	for (i = 0; i < wma->max_bssid; i++) {
		if (wma->interfaces[i].nlo_match_evt_received)
			break;
	}

	if (i == wma->max_bssid) {
		WMA_LOGD("PNO match event is not received in any vdev, skip scan cache update indication");
		return;
	}
	wma->interfaces[i].nlo_match_evt_received = FALSE;

	WMA_LOGD("Posting PNO completion to umac");

	len = sizeof(tSirPrefNetworkFoundInd);
	nw_found_ind = (tSirPrefNetworkFoundInd *) vos_mem_malloc(len);

	nw_found_ind->mesgType = eWNI_SME_PREF_NETWORK_FOUND_IND;
	nw_found_ind->mesgLen = len;

	vos_msg.type = eWNI_SME_PREF_NETWORK_FOUND_IND;
	vos_msg.bodyptr = (void *) nw_found_ind;
	vos_msg.bodyval = 0;

	status = vos_mq_post_message(VOS_MQ_ID_SME, &vos_msg);
	if (status != VOS_STATUS_SUCCESS) {
		WMA_LOGE("%s: Failed to post PNO completion match event to SME",
			 __func__);
		vos_mem_free(nw_found_ind);
	}
}

#endif

#define WMA_DUMP_WOW_PTRN

/* Frees memory associated to given pattern ID in wow pattern cache. */
static inline void wma_free_wow_ptrn(tp_wma_handle wma, u_int8_t ptrn_id)
{
	if (wma->wow.no_of_ptrn_cached <= 0 ||
	    !wma->wow.cache[ptrn_id])
		return;

	WMA_LOGD("Deleting wow pattern %d from cache which belongs to vdev id %d",
		 ptrn_id, wma->wow.cache[ptrn_id]->vdev_id);

	vos_mem_free(wma->wow.cache[ptrn_id]->ptrn);
	vos_mem_free(wma->wow.cache[ptrn_id]->mask);
	vos_mem_free(wma->wow.cache[ptrn_id]);
	wma->wow.cache[ptrn_id] = NULL;

	wma->wow.no_of_ptrn_cached--;
}

/* Converts wow wakeup reason code to text format */
static const u8 *wma_wow_wake_reason_str(A_INT32 wake_reason)
{
	switch (wake_reason) {
	case WOW_REASON_UNSPECIFIED:
		return "UNSPECIFIED";
	case WOW_REASON_NLOD:
		return "NLOD";
	case WOW_REASON_AP_ASSOC_LOST:
		return "AP_ASSOC_LOST";
	case WOW_REASON_LOW_RSSI:
		return "LOW_RSSI";
	case WOW_REASON_DEAUTH_RECVD:
		return "DEAUTH_RECVD";
	case WOW_REASON_DISASSOC_RECVD:
		return "DISASSOC_RECVD";
	case WOW_REASON_GTK_HS_ERR:
		return "GTK_HS_ERR";
	case WOW_REASON_EAP_REQ:
		return "EAP_REQ";
	case WOW_REASON_FOURWAY_HS_RECV:
		return "FOURWAY_HS_RECV";
	case WOW_REASON_TIMER_INTR_RECV:
		return "TIMER_INTR_RECV";
	case WOW_REASON_PATTERN_MATCH_FOUND:
		return "PATTERN_MATCH_FOUND";
	case WOW_REASON_RECV_MAGIC_PATTERN:
		return "RECV_MAGIC_PATTERN";
	case WOW_REASON_P2P_DISC:
		return "P2P_DISC";
	}

	return "unknown";
}

/*
 * Handler to catch wow wakeup host event. This event will have
 * reason why the firmware has woken the host.
 */
static int wma_wow_wakeup_host_event(void *handle, u_int8_t *event,
				     u_int32_t len)
{
	WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *param_buf;
	WOW_EVENT_INFO_fixed_param *wake_info;

	param_buf = (WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *) event;
	if (!param_buf) {
		WMA_LOGE("Invalid wow wakeup host event buf");
		return -EINVAL;
	}

	wake_info = param_buf->fixed_param;
	WMA_LOGD("WOW wakeup host event received (reason: %s)",
		 wma_wow_wake_reason_str(wake_info->wake_reason));

	return 0;
}

/* Configures wow wakeup events. */
static VOS_STATUS wma_add_wow_wakeup_event(tp_wma_handle wma,
					   WOW_WAKE_EVENT_TYPE event,
					   v_BOOL_t enable)
{
	WMI_WOW_ADD_DEL_EVT_CMD_fixed_param *cmd;
	u_int16_t len;
	wmi_buf_t buf;
	int ret;

	len = sizeof(WMI_WOW_ADD_DEL_EVT_CMD_fixed_param);
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: Failed allocate wmi buffer", __func__);
		return VOS_STATUS_E_NOMEM;
	}
	cmd = (WMI_WOW_ADD_DEL_EVT_CMD_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_WMI_WOW_ADD_DEL_EVT_CMD_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
				WMI_WOW_ADD_DEL_EVT_CMD_fixed_param));
	cmd->vdev_id = 0;
	cmd->is_add = enable;
	cmd->event_bitmap = (1 << event);

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_WOW_ENABLE_DISABLE_WAKE_EVENT_CMDID);
	if (ret) {
		WMA_LOGE("Failed to config wow wakeup event");
		wmi_buf_free(buf);
		return VOS_STATUS_E_FAILURE;
	}

	WMA_LOGD("Wakeup pattern 0x%x %s in fw", event,
		 enable ? "enabled":"disabled");

	return VOS_STATUS_SUCCESS;
}

/* Sends WOW patterns to FW. */
static VOS_STATUS wma_send_wow_patterns_to_fw(tp_wma_handle wma,
					      u_int8_t ptrn_id)
{
	WMI_WOW_ADD_PATTERN_CMD_fixed_param *cmd;
	WOW_BITMAP_PATTERN_T *bitmap_pattern;
	struct wma_wow_ptrn_cache *cache;
	wmi_buf_t buf;
	u_int8_t new_mask[SIR_WOWL_BCAST_PATTERN_MAX_SIZE];
	u_int8_t *buf_ptr, pos, bit_to_check;
#ifdef WMA_DUMP_WOW_PTRN
	u_int8_t *tmp;
#endif
	int32_t len;
	int ret;

	len = sizeof(WMI_WOW_ADD_PATTERN_CMD_fixed_param) +
		     WMI_TLV_HDR_SIZE +
		     1 * sizeof(WOW_BITMAP_PATTERN_T) +
		     WMI_TLV_HDR_SIZE +
		     0 * sizeof(WOW_IPV4_SYNC_PATTERN_T) +
		     WMI_TLV_HDR_SIZE +
		     0 * sizeof(WOW_IPV6_SYNC_PATTERN_T) +
		     WMI_TLV_HDR_SIZE +
		     0 * sizeof(WOW_MAGIC_PATTERN_CMD) +
		     WMI_TLV_HDR_SIZE +
		     0 * sizeof(A_UINT32);

	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: Failed allocate wmi buffer", __func__);
		return VOS_STATUS_E_NOMEM;
	}

	cache = wma->wow.cache[ptrn_id];
	cmd = (WMI_WOW_ADD_PATTERN_CMD_fixed_param *)wmi_buf_data(buf);
	buf_ptr = (u_int8_t *)cmd;

	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_WMI_WOW_ADD_PATTERN_CMD_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
				WMI_WOW_ADD_PATTERN_CMD_fixed_param));
	cmd->vdev_id = cache->vdev_id;
	cmd->pattern_id = ptrn_id;
	cmd->pattern_type = WOW_BITMAP_PATTERN;
	buf_ptr += sizeof(WMI_WOW_ADD_PATTERN_CMD_fixed_param);

	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_STRUC,
		       sizeof(WOW_BITMAP_PATTERN_T));
	buf_ptr += WMI_TLV_HDR_SIZE;
	bitmap_pattern = (WOW_BITMAP_PATTERN_T *)buf_ptr;

	WMITLV_SET_HDR(&bitmap_pattern->tlv_header,
		       WMITLV_TAG_STRUC_WOW_BITMAP_PATTERN_T,
		       WMITLV_GET_STRUCT_TLVLEN(WOW_BITMAP_PATTERN_T));

	vos_mem_copy(&bitmap_pattern->patternbuf[0], cache->ptrn,
		     cache->ptrn_len);
	/*
	 * Convert received pattern mask value from bit representaion
	 * to byte representation.
	 *
	 * For example, received value from umac,
	 *
	 *      Mask value    : A1 (equivalent binary is "1010 0001")
	 *      Pattern value : 12:00:13:00:00:00:00:44
	 *
	 * The value which goes to FW after the conversion from this
	 * function (1 in mask value will become FF and 0 will
	 * become 00),
	 *
	 *      Mask value    : FF:00:FF:00:0:00:00:FF
	 *      Pattern value : 12:00:13:00:00:00:00:44
	 */
	vos_mem_zero(new_mask, sizeof(new_mask));
	for (pos = 0; pos < cache->ptrn_len; pos++) {
		bit_to_check = (WMA_NUM_BITS_IN_BYTE - 1) -
					(pos % WMA_NUM_BITS_IN_BYTE);
		bit_to_check = 0x1 << bit_to_check;
		if (cache->mask[pos / WMA_NUM_BITS_IN_BYTE] & bit_to_check)
			new_mask[pos] = WMA_WOW_PTRN_MASK_VALID;
	}
	vos_mem_copy(&bitmap_pattern->bitmaskbuf[0], new_mask, cache->ptrn_len);

	bitmap_pattern->pattern_offset = cache->ptrn_offset;
	bitmap_pattern->pattern_len = cache->ptrn_len;

	if(bitmap_pattern->pattern_len > WOW_DEFAULT_BITMAP_PATTERN_SIZE)
		bitmap_pattern->pattern_len = WOW_DEFAULT_BITMAP_PATTERN_SIZE;

	if(bitmap_pattern->pattern_len > WOW_DEFAULT_BITMASK_SIZE)
		bitmap_pattern->pattern_len = WOW_DEFAULT_BITMASK_SIZE;

	bitmap_pattern->bitmask_len = bitmap_pattern->pattern_len;
	bitmap_pattern->pattern_id = ptrn_id;

	WMA_LOGD("pattern id: %d, pattern len: %d vdev id: %d",
		 cmd->pattern_id, bitmap_pattern->pattern_len, cmd->vdev_id);

#ifdef WMA_DUMP_WOW_PTRN
	printk("Pattern : ");
	tmp = (u_int8_t *) &bitmap_pattern->patternbuf[0];
	for (pos = 0; pos < bitmap_pattern->pattern_len; pos++)
		printk("%02X ", tmp[pos]);

	printk("\nMask    : ");
	tmp = (u_int8_t *) &bitmap_pattern->bitmaskbuf[0];
	for (pos = 0; pos < bitmap_pattern->pattern_len; pos++)
		printk("%02X ", tmp[pos]);
#endif

	buf_ptr += sizeof(WOW_BITMAP_PATTERN_T);

	/* Fill TLV for WMITLV_TAG_STRUC_WOW_IPV4_SYNC_PATTERN_T but no data. */
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_STRUC, 0);
	buf_ptr += WMI_TLV_HDR_SIZE;

	/* Fill TLV for WMITLV_TAG_STRUC_WOW_IPV6_SYNC_PATTERN_T but no data. */
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_STRUC, 0);
	buf_ptr += WMI_TLV_HDR_SIZE;

	/* Fill TLV for WMITLV_TAG_STRUC_WOW_MAGIC_PATTERN_CMD but no data. */
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_STRUC, 0);
	buf_ptr += WMI_TLV_HDR_SIZE;

	/* Fill TLV for pattern_info_timeout but no data. */
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_UINT32, 0);
	buf_ptr += WMI_TLV_HDR_SIZE;

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_WOW_ADD_WAKE_PATTERN_CMDID);
	if (ret) {
		WMA_LOGE("%s: Failed to send wow ptrn to fw", __func__);
		wmi_buf_free(buf);
		return VOS_STATUS_E_FAILURE;
	}

	return VOS_STATUS_SUCCESS;
}

/* Sends delete pattern request to FW for given pattern ID on particular vdev */
static VOS_STATUS wma_del_wow_pattern_in_fw(tp_wma_handle wma,
					    u_int8_t ptrn_id)
{
	WMI_WOW_DEL_PATTERN_CMD_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len;
	int ret;

	len = sizeof(WMI_WOW_DEL_PATTERN_CMD_fixed_param);

	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: Failed allocate wmi buffer", __func__);
		return VOS_STATUS_E_NOMEM;
	}

	cmd = (WMI_WOW_DEL_PATTERN_CMD_fixed_param *) wmi_buf_data(buf);

	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_WMI_WOW_DEL_PATTERN_CMD_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
				WMI_WOW_DEL_PATTERN_CMD_fixed_param));
	cmd->vdev_id = 0;
	cmd->pattern_id = ptrn_id;
	cmd->pattern_type = WOW_BITMAP_PATTERN;

	WMA_LOGD("Deleting pattern id: %d in fw", cmd->pattern_id);

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_WOW_DEL_WAKE_PATTERN_CMDID);
	if (ret) {
		WMA_LOGE("%s: Failed to delete wow ptrn from fw", __func__);
		wmi_buf_free(buf);
		return VOS_STATUS_E_FAILURE;
	}

	return VOS_STATUS_SUCCESS;
}

/* Enables WOW in firmware. */
static VOS_STATUS wma_enable_wow_in_fw(tp_wma_handle wma)
{
	wmi_wow_enable_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len;
	int ret;

	len = sizeof(wmi_wow_enable_cmd_fixed_param);

	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: Failed allocate wmi buffer", __func__);
		return VOS_STATUS_E_NOMEM;
	}

	cmd = (wmi_wow_enable_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
			WMITLV_TAG_STRUC_wmi_wow_enable_cmd_fixed_param,
			WMITLV_GET_STRUCT_TLVLEN(
					wmi_wow_enable_cmd_fixed_param));
	cmd->enable = TRUE;

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_WOW_ENABLE_CMDID);
	if (ret) {
		WMA_LOGE("Failed to enable wow in fw");
		wmi_buf_free(buf);
		return VOS_STATUS_E_FAILURE;
	}

	WMA_LOGD("WOW enabled successfully in fw");

	return VOS_STATUS_SUCCESS;
}

/*
 * Pushes wow patterns from local cache to FW and configures
 * wakeup trigger events.
 */
static VOS_STATUS wma_feed_wow_config_to_fw(tp_wma_handle wma)
{
	struct wma_txrx_node *iface;
	struct wma_wow_ptrn_cache *cache;
	VOS_STATUS ret = VOS_STATUS_SUCCESS;
	v_BOOL_t ptrn_match_event_enable = FALSE;
	u_int8_t ptrn_id;

	WMA_LOGD("Clearing already configured wow patterns in fw");

	/* Clear existing wow patterns in FW. */
	for (ptrn_id = 0; ptrn_id < WOW_MAX_BITMAP_FILTERS; ptrn_id++) {
		ret = wma_del_wow_pattern_in_fw(wma, ptrn_id);
		if(ret != VOS_STATUS_SUCCESS)
			return ret;
	}

	WMA_LOGD("Configuring wow patterns to fw");

	/* Send wow patterns to FW if there are any patterns cached
	 * in local wow pattern cache. */
	for (ptrn_id = 0; ptrn_id < WOW_MAX_BITMAP_FILTERS; ptrn_id++) {
		cache = wma->wow.cache[ptrn_id];
		if (!cache)
			continue;

		iface = &wma->interfaces[cache->vdev_id];

		/* Rule 1: vdev should be in connected state.
		 * Rule 2: Pattern match should enabled for this vdev
		 *         by the user. */
		if(!iface->ptrn_match_enable || !iface->conn_state)
			continue;

		ret = wma_send_wow_patterns_to_fw(wma, ptrn_id);
		if (ret != VOS_STATUS_SUCCESS) {
			WMA_LOGE("Failed to submit wow pattern to fw (ptrn_id %d)",
				 ptrn_id);
			return ret;
		}

		ptrn_match_event_enable = TRUE;
	}

	/*
	 * Configure pattern match wakeup event. FW does pattern match
	 * only if pattern match event is enabled.
	 */
	ret = wma_add_wow_wakeup_event(wma, WOW_PATTERN_MATCH_EVENT,
				       ptrn_match_event_enable);
	if (ret != VOS_STATUS_SUCCESS)
		return ret;

	WMA_LOGD("Pattern byte match is %s in fw",
		 ptrn_match_event_enable ? "enabled" : "disabled");

	/* Configure magic pattern wakeup event */
	ret = wma_add_wow_wakeup_event(wma, WOW_MAGIC_PKT_RECVD_EVENT,
				       wma->wow.magic_ptrn_enable);
	if (ret != VOS_STATUS_SUCCESS) {
		WMA_LOGD("Failed to configure magic pattern matching");
	} else {
		WMA_LOGD("Magic pattern is %s in fw",
			wma->wow.magic_ptrn_enable ? "enabled" : "disabled");
	}

	/* Configure deauth based wakeup */
	ret = wma_add_wow_wakeup_event(wma, WOW_DEAUTH_RECVD_EVENT,
				       wma->wow.deauth_enable);
	if (ret != VOS_STATUS_SUCCESS) {
		WMA_LOGD("Failed to configure deauth based wakeup");
	} else {
		WMA_LOGD("Deauth based wakeup is %s in fw",
			 wma->wow.deauth_enable ? "enabled" : "disabled");
	}

	/* Configure disassoc based wakeup */
	ret = wma_add_wow_wakeup_event(wma, WOW_DISASSOC_RECVD_EVENT,
				       wma->wow.disassoc_enable);
	if (ret != VOS_STATUS_SUCCESS) {
		WMA_LOGD("Failed to configure disassoc based wakeup");
	} else {
		WMA_LOGD("Disassoc based wakeup is %s in fw",
			 wma->wow.disassoc_enable ? "enabled" : "disabled");
	}

	/* Configure beacon miss based wakeup */
	ret = wma_add_wow_wakeup_event(wma, WOW_BMISS_EVENT,
				       wma->wow.bmiss_enable);
	if (ret != VOS_STATUS_SUCCESS) {
		WMA_LOGD("Failed to configure beacon miss based wakeup");
	} else {
		WMA_LOGD("Beacon miss based wakeup is %s in fw",
			 wma->wow.bmiss_enable ? "enabled" : "disabled");
	}
#ifdef WLAN_FEATURE_GTK_OFFLOAD
	/* Configure GTK based wakeup */
	ret = wma_add_wow_wakeup_event(wma, WOW_GTK_ERR_EVENT,
				       wma->wow.gtk_err_enable);
	if (ret != VOS_STATUS_SUCCESS) {
		WMA_LOGD("Failed to configure GTK based wakeup");
	} else {
		WMA_LOGD("GTK based wakeup is %s in fw",
			 wma->wow.gtk_err_enable ? "enabled" : "disabled");
	}
#endif
	/* Enable WOW in FW. */
	ret = wma_enable_wow_in_fw(wma);
	if (ret == VOS_STATUS_SUCCESS)
		wma->wow.wow_enable = TRUE;

	return ret;
}

/* Adds received wow patterns in local wow pattern cache. */
static VOS_STATUS wma_wow_add_pattern(tp_wma_handle wma,
				      tpSirWowlAddBcastPtrn ptrn)
{
	struct wma_wow_ptrn_cache *cache;

	WMA_LOGD("wow add pattern");

	/* Free if there are any pattern cached already in the same slot. */
	if (wma->wow.cache[ptrn->ucPatternId])
		wma_free_wow_ptrn(wma, ptrn->ucPatternId);

	wma->wow.cache[ptrn->ucPatternId] = (struct wma_wow_ptrn_cache *)
					     vos_mem_malloc(sizeof(*cache));

	cache = wma->wow.cache[ptrn->ucPatternId];
	if (!cache) {
		WMA_LOGE("Unable to alloc memory for wow");
		return VOS_STATUS_E_NOMEM;
	}

	cache->ptrn = (u_int8_t *) vos_mem_malloc(ptrn->ucPatternSize);
	if (!cache->ptrn) {
		WMA_LOGE("Unable to alloce memory to cache wow pattern");
		vos_mem_free(cache);
		wma->wow.cache[ptrn->ucPatternId] = NULL;
		return VOS_STATUS_E_NOMEM;
	}

	cache->mask = (u_int8_t *) vos_mem_malloc(ptrn->ucPatternMaskSize);
	if (!cache->mask) {
		WMA_LOGE("Unable to alloc memory to cache wow ptrn mask");
		vos_mem_free(cache->ptrn);
		vos_mem_free(cache);
		wma->wow.cache[ptrn->ucPatternId] = NULL;
		return VOS_STATUS_E_NOMEM;
	}

	/* Cache wow pattern info until platform goes to suspend. */
	vos_mem_copy(cache->ptrn, ptrn->ucPattern, ptrn->ucPatternSize);
	cache->vdev_id = ptrn->sessionId;
	cache->ptrn_len = ptrn->ucPatternSize;
	cache->ptrn_offset = ptrn->ucPatternByteOffset;
	vos_mem_copy(cache->mask, ptrn->ucPatternMask, ptrn->ucPatternMaskSize);
	cache->mask_len = ptrn->ucPatternMaskSize;
	wma->wow.no_of_ptrn_cached++;

	WMA_LOGD("wow pattern stored in cache (slot_id: %d, vdev id: %d)",
		 ptrn->ucPatternId, cache->vdev_id);

	return VOS_STATUS_SUCCESS;
}

/* Deletes given pattern from local wow pattern cache. */
static VOS_STATUS wma_wow_del_pattern(tp_wma_handle wma,
				      tpSirWowlDelBcastPtrn ptrn)
{
	WMA_LOGD("wow delete pattern");

	if (!wma->wow.cache[ptrn->ucPatternId]) {
		WMA_LOGE("wow pattern not found (pattern id: %d) in cache",
			 ptrn->ucPatternId);
		return VOS_STATUS_E_INVAL;
	}

	wma_free_wow_ptrn(wma, ptrn->ucPatternId);

	return VOS_STATUS_SUCCESS;
}

/*
 * Records pattern enable/disable status locally. This choice will
 * take effect when the driver enter into suspend state.
 */
static VOS_STATUS wma_wow_enter(tp_wma_handle wma,
				tpSirHalWowlEnterParams info)
{
	struct wma_txrx_node *iface;

	WMA_LOGD("wow enable req received for vdev id: %d", info->sessionId);

	if (info->sessionId > wma->max_bssid) {
		WMA_LOGE("Invalid vdev id (%d)", info->sessionId);
		vos_mem_free(info);
		return VOS_STATUS_E_INVAL;
	}

	iface = &wma->interfaces[info->sessionId];
	iface->ptrn_match_enable = info->ucPatternFilteringEnable ?
							    TRUE : FALSE;
	wma->wow.magic_ptrn_enable = info->ucMagicPktEnable ? TRUE : FALSE;
	wma->wow.deauth_enable = info->ucWowDeauthRcv ? TRUE : FALSE;
	wma->wow.disassoc_enable = info->ucWowDeauthRcv ? TRUE : FALSE;
	wma->wow.bmiss_enable = info->ucWowMaxMissedBeacons ? TRUE : FALSE;

	vos_mem_free(info);

	return VOS_STATUS_SUCCESS;
}

/* Clears all wow states */
static VOS_STATUS wma_wow_exit(tp_wma_handle wma,
			       tpSirHalWowlExitParams info)
{
	struct wma_txrx_node *iface;

	WMA_LOGD("wow disable req received for vdev id: %d", info->sessionId);

	if (info->sessionId > wma->max_bssid) {
		WMA_LOGE("Invalid vdev id (%d)", info->sessionId);
		vos_mem_free(info);
		return VOS_STATUS_E_INVAL;
	}

	iface = &wma->interfaces[info->sessionId];
	iface->ptrn_match_enable = FALSE;
	wma->wow.magic_ptrn_enable = FALSE;
	vos_mem_free(info);

	return VOS_STATUS_SUCCESS;
}

/* Handles suspend indication request received from umac. */
static VOS_STATUS wma_suspend_req(tp_wma_handle wma, tpSirWlanSuspendParam info)
{
	struct wma_txrx_node *iface;
	v_BOOL_t connected = FALSE;
	VOS_STATUS ret;
	u_int8_t i;

	if (info->sessionId > wma->max_bssid) {
		WMA_LOGE("Invalid vdev id (%d)", info->sessionId);
		vos_mem_free(info);
		return VOS_STATUS_E_INVAL;
	}

	iface = &wma->interfaces[info->sessionId];
	if (!iface) {
		WMA_LOGD("vdev %d node is not found", info->sessionId);
		vos_mem_free(info);
		return VOS_STATUS_SUCCESS;
	}

	if (!wma->wow.magic_ptrn_enable && !iface->ptrn_match_enable) {
		WMA_LOGD("Both magic and pattern byte match are disabled");
		vos_mem_free(info);
		return VOS_STATUS_SUCCESS;
	}

	iface->conn_state = (info->connectedState) ? TRUE : FALSE;

	/*
	 * Once WOW is enabled in FW, host can't send anymore
	 * data to fw. umac sends suspend indication on each
	 * vdev during platform suspend. WMA has to wait until
	 * suspend indication received on last vdev before
	 * enabling wow in fw.
	 */
	if (++wma->no_of_suspend_ind < wma_get_vdev_count(wma)) {
		vos_mem_free(info);
		return VOS_STATUS_SUCCESS;
	}

	wma->no_of_suspend_ind = 0;

	/* At-least one vdev should be in connected state to enable WOW */
	for (i = 0; i < wma->max_bssid; i++) {
		if (wma->interfaces[i].conn_state) {
			connected = TRUE;
			break;
		}
	}

	if (!connected) {
		WMA_LOGD("All vdev are in disconnected state, skipping wow");
		vos_mem_free(info);
		return VOS_STATUS_SUCCESS;
	}

	WMA_LOGD("WOW Suspend");

	/*
	 * At this point, suspend indication is received on
	 * last vdev. It's the time to enable wow in fw.
	 */
	ret = wma_feed_wow_config_to_fw(wma);
	if (ret != VOS_STATUS_SUCCESS) {
		vos_mem_free(info);
		return ret;
	}

	vos_mem_free(info);
	return VOS_STATUS_SUCCESS;
}

/*
 * Sends host wakeup indication to FW. On receiving this indication,
 * FW will come out of WOW.
 */
static VOS_STATUS wma_send_host_wakeup_ind_to_fw(tp_wma_handle wma)
{
	wmi_wow_hostwakeup_from_sleep_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int32_t len;
	int ret;

	len = sizeof(wmi_wow_hostwakeup_from_sleep_cmd_fixed_param);

	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: Failed allocate wmi buffer", __func__);
		return VOS_STATUS_E_NOMEM;
	}

	cmd = (wmi_wow_hostwakeup_from_sleep_cmd_fixed_param *)
				wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_wmi_wow_hostwakeup_from_sleep_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
				wmi_wow_hostwakeup_from_sleep_cmd_fixed_param));

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID);
	if (ret) {
		WMA_LOGE("Failed to send host wakeup indication to fw");
		wmi_buf_free(buf);
		return VOS_STATUS_E_FAILURE;
	}

	WMA_LOGD("Host wakeup indication sent to fw");

	return VOS_STATUS_SUCCESS;
}

/*
 * UMAC sends resume indication request on each vdev. This function
 * performs wow resume when very first resume indication received
 * from umac. wow resume is applicable only if the driver is in
 * wow suspend state.
 */
static VOS_STATUS wma_resume_req(tp_wma_handle wma, tpSirWlanResumeParam info)
{
	struct wma_txrx_node *iface;
	int8_t vdev_id;
	VOS_STATUS ret;

	if (!wma->wow.wow_enable) {
		vos_mem_free(info);
		return VOS_STATUS_SUCCESS;
	}

	WMA_LOGD("WOW Resume");

	wma->wow.wow_enable = FALSE;

	for (vdev_id = 0; vdev_id < wma->max_bssid; vdev_id++) {
		if (!wma->interfaces[vdev_id].handle)
			continue;

		iface = &wma->interfaces[vdev_id];
		iface->conn_state = FALSE;
	}

	ret = wma_send_host_wakeup_ind_to_fw(wma);
	vos_mem_free(info);

	return ret;
}

/*
 * Returns true if wow patterns are configured in fw and
 * wow is also enabled. Other cases, returns false.
 */
int wma_is_wow_enabled(WMA_HANDLE handle)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	return wma->wow.wow_enable;
}

/* function    : wma_get_stats_req
 * Description : return the statistics
 * Args        : wma handle, pointer to tAniGetPEStatsReq
 * Returns     : nothing
 */
static void wma_get_stats_req(WMA_HANDLE handle,
		tAniGetPEStatsReq *get_stats_param)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	tAniGetPEStatsRsp *pGetPEStatsRspParams;

	if(get_stats_param)
		vos_mem_free(get_stats_param);

	pGetPEStatsRspParams =
		(tAniGetPEStatsRsp *)vos_mem_malloc(sizeof(tAniGetPEStatsRsp));

	if(!pGetPEStatsRspParams) {
		WMA_LOGE("%s: Memory Allocation Failure", __func__);
		return;
	}

	vos_mem_zero(pGetPEStatsRspParams, sizeof(tAniGetPEStatsRsp));
	pGetPEStatsRspParams->msgLen = sizeof(tAniGetPEStatsRsp);

	/* TODO: As of now there is no WMI command to get the
	 * statistics. If WMI command for getting stats is available,
	 * then send the WMI command for getting the stats.
	 * Return status as FAILURE for now */
	pGetPEStatsRspParams->rc = eHAL_STATUS_FAILURE;

	/* send response to UMAC*/
	wma_send_msg(wma_handle, WDA_GET_STATISTICS_RSP, pGetPEStatsRspParams,
			0) ;

	return;
}

static void wma_init_scan_req(tp_wma_handle wma_handle,
				tInitScanParams *init_scan_param)
{
	WMA_LOGD("%s: Send dummy init scan response for legacy scan request",
			__func__);
	init_scan_param->status = eHAL_STATUS_SUCCESS;
	/* send ini scan response message back to PE */
	wma_send_msg(wma_handle, WDA_INIT_SCAN_RSP, (void *)init_scan_param,
			0);
}

static void wma_finish_scan_req(tp_wma_handle wma_handle,
				tFinishScanParams *finish_scan_param)
{
	WMA_LOGD("%s: Send dummy finish scan response for legacy scan request",
			__func__);
	finish_scan_param->status = eHAL_STATUS_SUCCESS;
	/* send finish scan response message back to PE */
	wma_send_msg(wma_handle, WDA_FINISH_SCAN_RSP, (void *)finish_scan_param,
			0);
}

static void wma_process_update_opmode(tp_wma_handle wma_handle,
                                tUpdateVHTOpMode *update_vht_opmode)
{
        WMA_LOGD("%s: Update Opmode", __func__);

        wma_set_peer_param(wma_handle, update_vht_opmode->peer_mac,
                           WMI_PEER_CHWIDTH, update_vht_opmode->opMode,
                           update_vht_opmode->smesessionId);
}

#ifdef FEATURE_OEM_DATA_SUPPORT
static void wma_start_oem_data_req(tp_wma_handle wma_handle,
				tStartOemDataReq *startOemDataReq)
{
	wmi_buf_t buf;
	u_int8_t *cmd;
	int ret = 0;

	WMA_LOGD("%s: Send OEM Data Request to target", __func__);

	if (!startOemDataReq)
		return;

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not send Oem data request cmd", __func__);
		return;
	}

	buf = wmi_buf_alloc(wma_handle->wmi_handle,
		                   (OEM_DATA_REQ_SIZE + WMI_TLV_HDR_SIZE));
	if (!buf) {
		WMA_LOGE("%s:wmi_buf_alloc failed", __func__);
		return;
	}

	cmd = (u_int8_t *)wmi_buf_data(buf);

	WMITLV_SET_HDR(cmd, WMITLV_TAG_ARRAY_BYTE,
			       OEM_DATA_REQ_SIZE);
	cmd += WMI_TLV_HDR_SIZE;
	vos_mem_copy(cmd, &startOemDataReq->oemDataReq[0], OEM_DATA_REQ_SIZE);

	ret = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
			(OEM_DATA_REQ_SIZE +
			 WMI_TLV_HDR_SIZE),
			WMI_OEM_DATA_REQ_CMDID);

	if (ret != EOK) {
		WMA_LOGE("%s:wmi cmd send failed", __func__);
		adf_nbuf_free(buf);
		return;
	}

	return;
}
#endif /* FEATURE_OEM_DATA_SUPPORT */
static int wma_process_receive_filter_set_filter_req(tp_wma_handle wma_handle,
						tSirRcvPktFilterCfgType *rcv_filter_param)
{
	wmi_chatter_coalescing_add_filter_cmd_fixed_param *cmd;
	chatter_pkt_coalescing_filter *cmd_filter;
	u_int8_t *buf_ptr;
	wmi_buf_t buf;
	int num_rules = 1; /* Only one rule at a time */
	int len;
	int err;
	int i;

	/* allocate the memory */
	len = sizeof(*cmd) + WMI_TLV_HDR_SIZE + sizeof(*cmd_filter) * num_rules;
	buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("Failed to allocate buffer to send set_param cmd");
		vos_mem_free(rcv_filter_param);
		return -ENOMEM;
	}
	buf_ptr = (u_int8_t *) wmi_buf_data(buf);

	/* fill the fixed part */
	cmd = (wmi_chatter_coalescing_add_filter_cmd_fixed_param *) buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
			WMITLV_TAG_STRUC_wmi_chatter_coalescing_add_filter_cmd_fixed_param,
			WMITLV_GET_STRUCT_TLVLEN(
					wmi_chatter_coalescing_add_filter_cmd_fixed_param));
	cmd->num_of_filters = num_rules;

	/* specify the type of data in the subsequent buffer */
	buf_ptr += sizeof(*cmd);
	cmd_filter = (chatter_pkt_coalescing_filter *) buf_ptr;
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_STRUC,
			num_rules * sizeof(chatter_pkt_coalescing_filter));

	/* fill the actual filter data */
	buf_ptr += WMI_TLV_HDR_SIZE;
	cmd_filter = (chatter_pkt_coalescing_filter *) buf_ptr;

	WMITLV_SET_HDR(&cmd_filter->tlv_header,
			WMITLV_TAG_STRUC_wmi_chatter_pkt_coalescing_filter,
			WMITLV_GET_STRUCT_TLVLEN(chatter_pkt_coalescing_filter));

	cmd_filter->filter_id = rcv_filter_param->filterId;
	cmd_filter->max_coalescing_delay = rcv_filter_param->coalesceTime;
	cmd_filter->pkt_type = CHATTER_COALESCING_PKT_TYPE_UNICAST |
				CHATTER_COALESCING_PKT_TYPE_MULTICAST |
				CHATTER_COALESCING_PKT_TYPE_BROADCAST;
	cmd_filter->num_of_test_field = MIN(rcv_filter_param->numFieldParams,
						CHATTER_MAX_FIELD_TEST);

	for (i = 0; i < cmd_filter->num_of_test_field; i++) {
		cmd_filter->test_fields[i].offset = rcv_filter_param->paramsData[i].dataOffset;
		cmd_filter->test_fields[i].length = MIN(rcv_filter_param->paramsData[i].dataLength,
							CHATTER_MAX_TEST_FIELD_LEN32);
		cmd_filter->test_fields[i].test = rcv_filter_param->paramsData[i].cmpFlag;
		memcpy(&cmd_filter->test_fields[i].value, rcv_filter_param->paramsData[i].compareData,
			cmd_filter->test_fields[i].length);
		memcpy(&cmd_filter->test_fields[i].mask, rcv_filter_param->paramsData[i].dataMask,
			cmd_filter->test_fields[i].length);
	}
	WMA_LOGD("Chatter packets, adding filter with id: %d, num_test_fields=%d",cmd_filter->filter_id,
		cmd_filter->num_of_test_field);
	/* send the command along with data */
	err = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
					WMI_CHATTER_ADD_COALESCING_FILTER_CMDID);
	if (err) {
		WMA_LOGE("Failed to send set_param cmd");
		wmi_buf_free(buf);
		vos_mem_free(rcv_filter_param);
		return -EIO;
	}
	vos_mem_free(rcv_filter_param);
	return 0; /* SUCCESS */
}

static int wma_process_receive_filter_clear_filter_req(tp_wma_handle wma_handle,
						tSirRcvFltPktClearParam *rcv_clear_param)
{
	wmi_chatter_coalescing_delete_filter_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int err;

	/* allocate the memory */
	buf = wmi_buf_alloc(wma_handle->wmi_handle, sizeof(*cmd));
	if (!buf) {
		WMA_LOGE("Failed to allocate buffer to send set_param cmd");
		vos_mem_free(rcv_clear_param);
		return -ENOMEM;
	}

	/* fill the fixed part */
	cmd = (wmi_chatter_coalescing_delete_filter_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
			WMITLV_TAG_STRUC_wmi_chatter_coalescing_delete_filter_cmd_fixed_param,
			WMITLV_GET_STRUCT_TLVLEN(
					wmi_chatter_coalescing_delete_filter_cmd_fixed_param));
	cmd->filter_id = rcv_clear_param->filterId;
	WMA_LOGD("Chatter packets, clearing filter with id: %d",cmd->filter_id);

	/* send the command along with data */
	err = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
				sizeof(*cmd), WMI_CHATTER_DELETE_COALESCING_FILTER_CMDID);
	if (err) {
		WMA_LOGE("Failed to send set_param cmd");
		wmi_buf_free(buf);
		vos_mem_free(rcv_clear_param);
		return -EIO;
	}
	vos_mem_free(rcv_clear_param);
	return 0; /* SUCCESS */
}

#ifdef FEATURE_WLAN_CCX

#define TSM_DELAY_HISTROGRAM_BINS 4
/*
 * @brief: A parallel function to WDA_ProcessTsmStatsReq for pronto. This
 *         function fetches stats from data path APIs and post
 *         WDA_TSM_STATS_RSP msg back to LIM.
 * @param: wma_handler - handle to wma
 * @param: pTsmStats - TSM stats struct that needs to be populated and
 *         passed in message.
 */

VOS_STATUS wma_process_tsm_stats_req(tp_wma_handle wma_handler,
	tTSMStats *pTsmStats)
{
    int tid = pTsmStats->tid;
    u_int8_t counter;
    u_int32_t queue_delay_microsec = 0;
    u_int32_t tx_delay_microsec = 0;
    u_int16_t packet_count = 0;
    u_int16_t packet_loss_count = 0;
    /*
     * The number of histrogram bin report by data path api are different
     * than required by TSM, hence different (6) size array used
     */
    u_int16_t bin_values[QCA_TX_DELAY_HIST_REPORT_BINS] = {0,};

    ol_txrx_pdev_handle pdev = vos_get_context(VOS_MODULE_ID_TXRX,
    wma_handler->vos_context);

    /* get required values from data path APIs */
    ol_tx_delay(pdev, &queue_delay_microsec, &tx_delay_microsec, tid);
    ol_tx_delay_hist(pdev, bin_values, tid);
    ol_tx_packet_count(pdev, &packet_count, &packet_loss_count, tid );

    /* populate pTsmStats */
    pTsmStats->tsmMetrics.UplinkPktQueueDly = queue_delay_microsec;
    /* store only required number of bin values */
    for ( counter = 0; counter < TSM_DELAY_HISTROGRAM_BINS; counter++)
    {
        pTsmStats->tsmMetrics.UplinkPktQueueDlyHist[counter] =
            bin_values[counter];
    }
    pTsmStats->tsmMetrics.UplinkPktTxDly = tx_delay_microsec;
    pTsmStats->tsmMetrics.UplinkPktLoss = packet_loss_count;
    pTsmStats->tsmMetrics.UplinkPktCount = packet_count;

    /*
     * No need to populate roaming delay and roaming count as they are
     * being populated just before sending IAPP frame out
     */

    /* post this message to LIM/PE */
    wma_send_msg(wma_handler, WDA_TSM_STATS_RSP, (void *)pTsmStats , 0) ;
    return VOS_STATUS_SUCCESS;
}

#endif

static void wma_add_ts_req(tp_wma_handle wma, tAddTsParams *msg)
{
#ifdef FEATURE_WLAN_CCX
    /*
     * msmt_interval is in unit called TU (1 TU = 1024 us)
     * max value of msmt_interval cannot make resulting
     * interval_miliseconds overflow 32 bit
     */
    ol_txrx_pdev_handle pdev =
        vos_get_context(VOS_MODULE_ID_TXRX, wma->vos_context);
    tANI_U32 intervalMiliseconds =
        (msg->tsm_interval*1024)/1000;
        ol_tx_set_compute_interval(pdev, intervalMiliseconds);
#endif
    msg->status = eHAL_STATUS_SUCCESS;
    wma_send_msg(wma, WDA_ADD_TS_RSP, msg, 0);
}

static void wma_data_tx_ack_work_handler(struct work_struct *ack_work)
{
	struct wma_tx_ack_work_ctx *work = container_of(ack_work,
		struct wma_tx_ack_work_ctx, ack_cmp_work);
	pWDAAckFnTxComp ack_cb =
		work->wma_handle->umac_data_ota_ack_cb;

	WMA_LOGD("Data Tx Ack Cb Status %d",
			work->status);

	/* Call the Ack Cb registered by UMAC */
	ack_cb((tpAniSirGlobal)(work->wma_handle->mac_context),
				work->status ? 0 : 1);
	work->wma_handle->umac_data_ota_ack_cb = NULL;
	adf_os_mem_free(work);
}

/**
  * wma_data_tx_ack_comp_hdlr - handles tx data ack completion
  * @context: context with which the handler is registered
  * @netbuf: tx data nbuf
  * @err: status of tx completion
  *
  * This is the cb registered with TxRx for
  * Ack Complete
  */
static void
wma_data_tx_ack_comp_hdlr(void *wma_context,
		adf_nbuf_t netbuf, int32_t status)
{
	tp_wma_handle wma_handle = (tp_wma_handle)wma_context;
	ol_txrx_pdev_handle pdev =
		vos_get_context(VOS_MODULE_ID_TXRX, wma_handle->vos_context);

	if(wma_handle && wma_handle->umac_data_ota_ack_cb) {
		struct wma_tx_ack_work_ctx *ack_work;

		ack_work =
		adf_os_mem_alloc(NULL, sizeof(struct wma_tx_ack_work_ctx));

		if(ack_work) {
			INIT_WORK(&ack_work->ack_cmp_work,
					wma_data_tx_ack_work_handler);
			ack_work->wma_handle = wma_handle;
			ack_work->sub_type = 0;
			ack_work->status = status;

			/* Schedue the Work */
			schedule_work(&ack_work->ack_cmp_work);
		}
	}

	/* unmap and freeing the tx buf as txrx is not taking care */
	adf_nbuf_unmap_single(pdev->osdev, netbuf, ADF_OS_DMA_TO_DEVICE);
	adf_nbuf_free(netbuf);
}

#ifdef WLAN_FEATURE_GTK_OFFLOAD
#define GTK_OFFLOAD_ENABLE	0
#define GTK_OFFLOAD_DISABLE	1

static VOS_STATUS wma_process_gtk_offload_req(tp_wma_handle wma,
					      tpSirGtkOffloadParams params)
{
	u_int8_t vdev_id;
	int len;
	wmi_buf_t buf;
	WMI_GTK_OFFLOAD_CMD_fixed_param *cmd;
	VOS_STATUS status = VOS_STATUS_SUCCESS;

	WMA_LOGD("%s Enter", __func__);

	/* Get the vdev id */
	if (!wma_find_vdev_by_bssid(wma, params->bssId, &vdev_id)) {
		WMA_LOGE("vdev handle is invalid for %pM", params->bssId);
		status = VOS_STATUS_E_INVAL;
		goto out;
	}

	len = sizeof(*cmd);

	/* alloc wmi buffer */
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("wmi_buf_alloc failed for WMI_GTK_OFFLOAD_CMD");
		status = VOS_STATUS_E_NOMEM;
		goto out;
	}

	cmd = (WMI_GTK_OFFLOAD_CMD_fixed_param *)wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_WMI_GTK_OFFLOAD_CMD_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
				WMI_GTK_OFFLOAD_CMD_fixed_param));

	cmd->vdev_id = vdev_id;

	/* Request target to enable GTK offload */
	if (params->ulFlags == GTK_OFFLOAD_ENABLE) {
		cmd->flags = GTK_OFFLOAD_ENABLE_OPCODE;
		wma->wow.gtk_err_enable = TRUE;

		/* Copy the keys and replay counter */
		vos_mem_copy(cmd->KCK, params->aKCK, GTK_OFFLOAD_KCK_BYTES);
		vos_mem_copy(cmd->KEK, params->aKEK, GTK_OFFLOAD_KEK_BYTES);
		vos_mem_copy(cmd->replay_counter, &params->ullKeyReplayCounter,
			     GTK_REPLAY_COUNTER_BYTES);
	} else {
		wma->wow.gtk_err_enable = FALSE;
		cmd->flags = GTK_OFFLOAD_DISABLE_OPCODE;
	}

	/* send the wmi command */
	if (wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				 WMI_GTK_OFFLOAD_CMDID)) {
		WMA_LOGE("Failed to send WMI_GTK_OFFLOAD_CMDID");
		wmi_buf_free(buf);
		status = VOS_STATUS_E_FAILURE;
	}
out:
	vos_mem_free(params);
	WMA_LOGD("%s Exit", __func__);
	return status;
}

static VOS_STATUS wma_process_gtk_offload_getinfo_req(tp_wma_handle wma,
					tpSirGtkOffloadGetInfoRspParams params)
{
	u_int8_t vdev_id;
	int len;
	wmi_buf_t buf;
	WMI_GTK_OFFLOAD_CMD_fixed_param *cmd;
	VOS_STATUS status = VOS_STATUS_SUCCESS;

	WMA_LOGD("%s Enter", __func__);

	/* Get the vdev id */
	if (!wma_find_vdev_by_bssid(wma, params->bssId, &vdev_id)) {
		WMA_LOGE("vdev handle is invalid for %pM", params->bssId);
		status = VOS_STATUS_E_INVAL;
		goto out;
	}

	len = sizeof(*cmd);

	/* alloc wmi buffer */
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("wmi_buf_alloc failed for WMI_GTK_OFFLOAD_CMD");
		status = VOS_STATUS_E_NOMEM;
		goto out;
	}

	cmd = (WMI_GTK_OFFLOAD_CMD_fixed_param *)wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_WMI_GTK_OFFLOAD_CMD_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
				WMI_GTK_OFFLOAD_CMD_fixed_param));

	/* Request for GTK offload status */
	cmd->flags = GTK_OFFLOAD_REQUEST_STATUS_OPCODE;
	cmd->vdev_id = vdev_id;

	/* send the wmi command */
	if (wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				 WMI_GTK_OFFLOAD_CMDID)) {
		WMA_LOGE("Failed to send WMI_GTK_OFFLOAD_CMDID for req info");
		wmi_buf_free(buf);
		status = VOS_STATUS_E_FAILURE;
	}
out:
	vos_mem_free(params);
	WMA_LOGD("%s Exit", __func__);
	return status;
}
#endif

/*
 * Function	:	wma_enable_arp_ns_offload
 * Description	:	To configure ARP NS off load data to firmware
 *			when target goes to wow mode.
 * Args		:	@wma - wma handle, @tpSirHostOffloadReq -
 *			pHostOffloadParams,@bool bArpOnly
 * Returns	:	Returns Failure or Success based on WMI cmd.
 * Comments	:	Since firware expects ARP and NS to be configured
 *			at a time, Arp info is cached in wma and send along
 *			with NS info to make both work.
 */
static VOS_STATUS wma_enable_arp_ns_offload(tp_wma_handle wma, tpSirHostOffloadReq pHostOffloadParams, bool bArpOnly)
{
	int32_t i;
	int32_t res;
	WMI_SET_ARP_NS_OFFLOAD_CMD_fixed_param *cmd;
	WMI_NS_OFFLOAD_TUPLE *ns_tuple;
	WMI_ARP_OFFLOAD_TUPLE *arp_tuple;
	A_UINT8* buf_ptr;
	wmi_buf_t buf;
	int32_t len;
	u_int8_t vdev_id;

	/* Get the vdev id */
	if (!wma_find_vdev_by_bssid(wma, pHostOffloadParams->bssId, &vdev_id)) {
		WMA_LOGE("vdev handle is invalid for %pM", pHostOffloadParams->bssId);
		vos_mem_free(pHostOffloadParams);
		return VOS_STATUS_E_INVAL;
	}

	len = sizeof(WMI_SET_ARP_NS_OFFLOAD_CMD_fixed_param) +
		WMI_TLV_HDR_SIZE + // TLV place holder size for array of NS tuples
		WMI_MAX_NS_OFFLOADS*sizeof(WMI_NS_OFFLOAD_TUPLE) +
		WMI_TLV_HDR_SIZE + // TLV place holder size for array of ARP tuples
		WMI_MAX_ARP_OFFLOADS*sizeof(WMI_ARP_OFFLOAD_TUPLE);
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed", __func__);
		vos_mem_free(pHostOffloadParams);
		return VOS_STATUS_E_NOMEM;
	}

	buf_ptr = (A_UINT8*)wmi_buf_data(buf);
	cmd = (WMI_SET_ARP_NS_OFFLOAD_CMD_fixed_param *)buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
			WMITLV_TAG_STRUC_WMI_SET_ARP_NS_OFFLOAD_CMD_fixed_param,
			WMITLV_GET_STRUCT_TLVLEN(WMI_SET_ARP_NS_OFFLOAD_CMD_fixed_param));
	cmd->flags = 0;
	cmd->vdev_id = vdev_id;

	WMA_LOGD("ARP NS Offload vdev_id: %d",cmd->vdev_id);

	/* Have copy of arp info to send along with NS, Since FW expects
	 * both ARP and NS info in single cmd */
	if(bArpOnly)
		vos_mem_copy(&wma->mArpInfo, pHostOffloadParams, sizeof(tSirHostOffloadReq));

	buf_ptr += sizeof(WMI_SET_ARP_NS_OFFLOAD_CMD_fixed_param);
	WMITLV_SET_HDR(buf_ptr,WMITLV_TAG_ARRAY_STRUC,(WMI_MAX_NS_OFFLOADS*sizeof(WMI_NS_OFFLOAD_TUPLE)));
	buf_ptr += WMI_TLV_HDR_SIZE;
	for(i = 0; i < WMI_MAX_NS_OFFLOADS; i++ ){
		ns_tuple = (WMI_NS_OFFLOAD_TUPLE *)buf_ptr;
		WMITLV_SET_HDR(&ns_tuple->tlv_header,
				WMITLV_TAG_STRUC_WMI_NS_OFFLOAD_TUPLE,
				(sizeof(WMI_NS_OFFLOAD_TUPLE)-WMI_TLV_HDR_SIZE));

		/* Fill data only for NS offload in the first ARP tuple for LA */
		if (!bArpOnly  &&
			(pHostOffloadParams->enableOrDisable == SIR_OFFLOAD_ENABLE && i==0)) {
			ns_tuple->flags |= WMI_NSOFF_FLAGS_VALID;

			/*Copy the target/solicitation/remote ip addr */
			if(pHostOffloadParams->nsOffloadInfo.targetIPv6AddrValid[0])
				A_MEMCPY(&ns_tuple->target_ipaddr[0],
				&pHostOffloadParams->nsOffloadInfo.targetIPv6Addr[0],sizeof(WMI_IPV6_ADDR));
			if(pHostOffloadParams->nsOffloadInfo.targetIPv6AddrValid[1])
				A_MEMCPY(&ns_tuple->target_ipaddr[1],
				&pHostOffloadParams->nsOffloadInfo.targetIPv6Addr[1],sizeof(WMI_IPV6_ADDR));
			A_MEMCPY(&ns_tuple->solicitation_ipaddr,
				&pHostOffloadParams->nsOffloadInfo.selfIPv6Addr,sizeof(WMI_IPV6_ADDR));
			WMA_LOGD("NS solicitedIp: %pI6, targetIp: %pI6",
				pHostOffloadParams->nsOffloadInfo.selfIPv6Addr,
				pHostOffloadParams->nsOffloadInfo.targetIPv6Addr[0]);

			/* target MAC is optional, check if it is valid, if this is not valid,
			* the target will use the known local MAC address rather than the tuple */
			WMI_CHAR_ARRAY_TO_MAC_ADDR(pHostOffloadParams->nsOffloadInfo.selfMacAddr,
					&ns_tuple->target_mac);
			if ((ns_tuple->target_mac.mac_addr31to0 != 0) ||
				(ns_tuple->target_mac.mac_addr47to32 != 0))
			{
				ns_tuple->flags |= WMI_NSOFF_FLAGS_MAC_VALID;
			}
		}
	        buf_ptr += sizeof(WMI_NS_OFFLOAD_TUPLE);
	}

	WMITLV_SET_HDR(buf_ptr,WMITLV_TAG_ARRAY_STRUC,(WMI_MAX_ARP_OFFLOADS*sizeof(WMI_ARP_OFFLOAD_TUPLE)));
	buf_ptr += WMI_TLV_HDR_SIZE;
	for(i = 0; i < WMI_MAX_ARP_OFFLOADS; i++){
		arp_tuple = (WMI_ARP_OFFLOAD_TUPLE *)buf_ptr;
		WMITLV_SET_HDR(&arp_tuple->tlv_header,
				WMITLV_TAG_STRUC_WMI_ARP_OFFLOAD_TUPLE,
				WMITLV_GET_STRUCT_TLVLEN(WMI_ARP_OFFLOAD_TUPLE));

		/* Fill data for ARP and NS in the first tupple for LA */
		if ((wma->mArpInfo.enableOrDisable == SIR_OFFLOAD_ENABLE) && (i==0)) {
			/*Copy the target ip addr and flags*/
			arp_tuple->flags = WMI_ARPOFF_FLAGS_VALID;
			A_MEMCPY(&arp_tuple->target_ipaddr,wma->mArpInfo.params.hostIpv4Addr,
						SIR_IPV4_ADDR_LEN);
			WMA_LOGD("ARPOffload IP4 address: %pI4",
					wma->mArpInfo.params.hostIpv4Addr);
		}
		buf_ptr += sizeof(WMI_ARP_OFFLOAD_TUPLE);
	}
	res = wmi_unified_cmd_send(wma->wmi_handle, buf, len, WMI_SET_ARP_NS_OFFLOAD_CMDID);
	if(res) {
		WMA_LOGE("Failed to enable ARP NDP/NSffload");
		wmi_buf_free(buf);
		vos_mem_free(pHostOffloadParams);
		return VOS_STATUS_E_FAILURE;
        }

	vos_mem_free(pHostOffloadParams);
	return VOS_STATUS_SUCCESS;
}

/* function   : wma_mc_process_msg
 * Descriptin :
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_mc_process_msg(v_VOID_t *vos_context, vos_msg_t *msg)
{
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
	tp_wma_handle wma_handle;
	ol_txrx_vdev_handle txrx_vdev_handle = NULL;
	extern tANI_U8* macTraceGetWdaMsgString( tANI_U16 wdaMsg );

	WMA_LOGD("%s: Enter", __func__);
	if(NULL == msg)	{
		WMA_LOGE("msg is NULL");
		VOS_ASSERT(0);
		vos_status = VOS_STATUS_E_INVAL;
		goto end;
	}

	WMA_LOGD("msg->type = %x %s", msg->type, macTraceGetWdaMsgString(msg->type));

	wma_handle = (tp_wma_handle) vos_get_context(VOS_MODULE_ID_WDA,
			vos_context);

	if (NULL == wma_handle) {
		WMA_LOGP("wma_handle is NULL");
		VOS_ASSERT(0);
		vos_mem_free(msg->bodyptr);
		vos_status = VOS_STATUS_E_INVAL;
		goto end;
	}

	switch (msg->type) {
#ifdef FEATURE_WLAN_CCX
        case WDA_TSM_STATS_REQ:
            WMA_LOGA("McThread: WDA_TSM_STATS_REQ");
            wma_process_tsm_stats_req(wma_handle, (tTSMStats *)msg->bodyptr);
        break;
#endif
		case WNI_CFG_DNLD_REQ:
			WMA_LOGA("McThread: WNI_CFG_DNLD_REQ");
			vos_status = wma_wni_cfg_dnld(wma_handle);
			if (VOS_IS_STATUS_SUCCESS(vos_status)) {
				vos_WDAComplete_cback(vos_context);
			}
			else {
				WMA_LOGD("config download failure");
			}
			break ;
		case WDA_ADD_STA_SELF_REQ:
			txrx_vdev_handle = wma_vdev_attach(wma_handle,
					(tAddStaSelfParams *)msg->bodyptr);
			if (!txrx_vdev_handle) {
				WMA_LOGE("Failed to attach vdev");
			} else {
				WLANTL_RegisterVdev(vos_context,
						    txrx_vdev_handle);
				/* Register with TxRx Module for Data Ack Complete Cb */
				wdi_in_data_tx_cb_set(txrx_vdev_handle,
					wma_data_tx_ack_comp_hdlr, wma_handle);
			}
			break;
		case WDA_DEL_STA_SELF_REQ:
			wma_vdev_detach(wma_handle, (tDelStaSelfParams *)msg->bodyptr);
			break;
		case WDA_START_SCAN_OFFLOAD_REQ:
			wma_start_scan(wma_handle, msg->bodyptr);
			break;
		case WDA_STOP_SCAN_OFFLOAD_REQ:
			wma_stop_scan(wma_handle, msg->bodyptr);
			break;
		case WDA_UPDATE_CHAN_LIST_REQ:
			wma_update_channel_list(wma_handle,
					(tSirUpdateChanList *)msg->bodyptr);
			break;
		case WDA_SET_LINK_STATE:
			wma_set_linkstate(wma_handle,
					  (tpLinkStateParams)msg->bodyptr);
			break;
		case WDA_CHNL_SWITCH_REQ:
			wma_set_channel(wma_handle,
					(tpSwitchChannelParams)msg->bodyptr);
			break;
		case WDA_ADD_BSS_REQ:
			wma_add_bss(wma_handle, (tpAddBssParams)msg->bodyptr);
			break;
		case WDA_ADD_STA_REQ:
			wma_add_sta(wma_handle, (tpAddStaParams)msg->bodyptr);
			break;
		case WDA_SET_BSSKEY_REQ:
			wma_set_bsskey(wma_handle,
					(tpSetBssKeyParams)msg->bodyptr);
			break;
		case WDA_SET_STAKEY_REQ:
			wma_set_stakey(wma_handle,
					(tpSetStaKeyParams)msg->bodyptr);
			break;
		case WDA_DELETE_STA_REQ:
			wma_delete_sta(wma_handle,
					(tpDeleteStaParams)msg->bodyptr);
			break;
		case WDA_DELETE_BSS_REQ:
			wma_delete_bss(wma_handle,
					(tpDeleteBssParams)msg->bodyptr);
			break;
		case WDA_UPDATE_EDCA_PROFILE_IND:
			wma_process_update_edca_param_req(
						wma_handle,
						(tEdcaParams *)msg->bodyptr);
			break;
		case WDA_SEND_BEACON_REQ:
			wma_send_beacon(wma_handle,
					(tpSendbeaconParams)msg->bodyptr);
			break;
		case WDA_CLI_SET_CMD:
			wma_process_cli_set_cmd(wma_handle,
					(wda_cli_set_cmd_t *)msg->bodyptr);
			break;
#if !defined(REMOVE_PKT_LOG) && !defined(QCA_WIFI_ISOC)
		case WDA_PKTLOG_ENABLE_REQ:
			wma_pktlog_wmi_send_cmd(wma_handle,
						(struct ath_pktlog_wmi_params *)
						msg->bodyptr);
			break;
#endif
#if defined(QCA_WIFI_FTM) && !defined(QCA_WIFI_ISOC)
		case WDA_FTM_CMD_REQ:
			wma_process_ftm_command(wma_handle,
				(struct ar6k_testmode_cmd_data *)msg->bodyptr);
			break;
#endif
		case WDA_ENTER_BMPS_REQ:
			wma_enable_sta_ps_mode(wma_handle,
                                        (tpEnablePsParams)msg->bodyptr);
			break;
		case WDA_EXIT_BMPS_REQ:
			wma_disable_sta_ps_mode(wma_handle,
                                        (tpDisablePsParams)msg->bodyptr);
			break;
		case WDA_ENTER_UAPSD_REQ:
			wma_enable_uapsd_mode(wma_handle,
					(tpEnableUapsdParams)msg->bodyptr);
			break;
		case WDA_EXIT_UAPSD_REQ:
			wma_disable_uapsd_mode(wma_handle,
					(tpDisableUapsdParams)msg->bodyptr);
			break;
		case WDA_SET_MAX_TX_POWER_REQ:
			wma_set_max_tx_power(wma_handle,
					(tpMaxTxPowerParams)msg->bodyptr);
			break;
		case WDA_SET_KEEP_ALIVE:
			wma_set_keepalive_req(wma_handle,
					(tSirKeepAliveReq *)msg->bodyptr);
			break;
#ifdef FEATURE_WLAN_PNO_OFFLOAD
		case WDA_SET_PNO_REQ:
			wma_config_pno(wma_handle,
				       (tpSirPNOScanReq)msg->bodyptr);
			break;

		case WDA_SME_SCAN_CACHE_UPDATED:
			wma_scan_cache_updated_ind(wma_handle);
			break;
#endif

		case WDA_GET_STATISTICS_REQ:
			wma_get_stats_req(wma_handle,
					(tAniGetPEStatsReq *) msg->bodyptr);
			break;

		case WDA_CONFIG_PARAM_UPDATE_REQ:
			wma_update_cfg_params(wma_handle,
					(tSirMsgQ *)msg);
			break;

		case WDA_INIT_SCAN_REQ:
			wma_init_scan_req(wma_handle,
					(tInitScanParams *)msg->bodyptr);
			break;

		case WDA_FINISH_SCAN_REQ:
			wma_finish_scan_req(wma_handle,
					(tFinishScanParams *)msg->bodyptr);
			break;
                case WDA_UPDATE_OP_MODE:
                        wma_process_update_opmode(wma_handle,
                                       (tUpdateVHTOpMode *)msg->bodyptr);
                        break;
		case WDA_UPDATE_BEACON_IND:
			wma_process_update_beacon_params(wma_handle,
					(tUpdateBeaconParams *)msg->bodyptr);
			break;

		case WDA_ADD_TS_REQ:
			wma_add_ts_req(wma_handle, (tAddTsParams *)msg->bodyptr);
			break;

		case WDA_RECEIVE_FILTER_SET_FILTER_REQ:
			wma_process_receive_filter_set_filter_req(wma_handle,
						(tSirRcvPktFilterCfgType *)msg->bodyptr);
			break;

		case WDA_RECEIVE_FILTER_CLEAR_FILTER_REQ:
			wma_process_receive_filter_clear_filter_req(wma_handle,
						(tSirRcvFltPktClearParam *)msg->bodyptr);
			break;

		case WDA_WOWL_ADD_BCAST_PTRN:
			wma_wow_add_pattern(wma_handle,
					   (tpSirWowlAddBcastPtrn)msg->bodyptr);
			break;
		case WDA_WOWL_DEL_BCAST_PTRN:
			wma_wow_del_pattern(wma_handle,
					   (tpSirWowlDelBcastPtrn)msg->bodyptr);
			break;
		case WDA_WOWL_ENTER_REQ:
			wma_wow_enter(wma_handle,
				      (tpSirHalWowlEnterParams)msg->bodyptr);
			break;
		case WDA_WOWL_EXIT_REQ:
			wma_wow_exit(wma_handle,
				    (tpSirHalWowlExitParams)msg->bodyptr);
			break;
		case WDA_WLAN_SUSPEND_IND:
			wma_suspend_req(wma_handle,
					(tpSirWlanSuspendParam)msg->bodyptr);
			break;
		case WDA_WLAN_RESUME_REQ:
			wma_resume_req(wma_handle,
				       (tpSirWlanResumeParam)msg->bodyptr);
			break;
#ifdef WLAN_FEATURE_GTK_OFFLOAD
		case WDA_GTK_OFFLOAD_REQ:
			wma_process_gtk_offload_req(
					wma_handle,
					(tpSirGtkOffloadParams)msg->bodyptr);
			break;

		case WDA_GTK_OFFLOAD_GETINFO_REQ:
			wma_process_gtk_offload_getinfo_req(
				wma_handle,
				(tpSirGtkOffloadGetInfoRspParams)msg->bodyptr);
			break;
#endif /* WLAN_FEATURE_GTK_OFFLOAD */
#ifdef FEATURE_OEM_DATA_SUPPORT
		case WDA_START_OEM_DATA_REQ:
			wma_start_oem_data_req(wma_handle,
					(tStartOemDataReq *)msg->bodyptr);
			break;
#endif /* FEATURE_OEM_DATA_SUPPORT */
		case WDA_SET_HOST_OFFLOAD:
			wma_enable_arp_ns_offload(wma_handle, (tpSirHostOffloadReq)msg->bodyptr, true);
			break;
#ifdef WLAN_NS_OFFLOAD
		case WDA_SET_NS_OFFLOAD:
			wma_enable_arp_ns_offload(wma_handle, (tpSirHostOffloadReq)msg->bodyptr, false);
			break;
#endif /*WLAN_NS_OFFLOAD */
		case WDA_START_ROAM_CANDIDATE_LOOKUP_REQ:
			/*
			 * Main entry point or roaming directives from CSR.
			 */
		    wma_process_roam_scan_req(wma_handle,
				(tSirRoamOffloadScanReq *)msg->bodyptr);
		    break;

		default:
			WMA_LOGD("unknow msg type %x", msg->type);
			/* Do Nothing? MSG Body should be freed at here */
			if(NULL != msg->bodyptr) {
				vos_mem_free(msg->bodyptr);
			}
	}
end:
	WMA_LOGD("%s: Exit", __func__);
	return vos_status ;
}

static int wma_scan_event_callback(WMA_HANDLE handle, u_int8_t *data,
                                    u_int32_t len)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	WMI_SCAN_EVENTID_param_tlvs *param_buf = NULL;
	wmi_scan_event_fixed_param *wmi_event = NULL;
	tSirScanOffloadEvent *scan_event;
	u_int8_t vdev_id;
	v_U32_t scan_id;

	scan_event = (tSirScanOffloadEvent *) vos_mem_malloc
                                (sizeof(tSirScanOffloadEvent));
	if (!scan_event) {
		WMA_LOGE("Memory allocation failed for tSirScanOffloadEvent");
		return -ENOMEM;
	}

	param_buf = (WMI_SCAN_EVENTID_param_tlvs *) data;
	wmi_event = param_buf->fixed_param;
	vdev_id = wmi_event->vdev_id;
	scan_id = wma_handle->interfaces[vdev_id].scan_info.scan_id;
	scan_event->event = wmi_event->event;

	WMA_LOGI("WMA <-- wmi_scan_event : event %lu, scan_id %lu, freq %lu",
			wmi_event->event, wmi_event->scan_id,
			wmi_event->channel_freq);

	scan_event->scanId = wmi_event->scan_id;
	scan_event->chanFreq = wmi_event->channel_freq;
	scan_event->p2pScanType =
		wma_handle->interfaces[vdev_id].scan_info.p2p_scan_type;
	scan_event->sessionId = vdev_id;

	if (wmi_event->reason == WMI_SCAN_REASON_COMPLETED)
		scan_event->reasonCode = eSIR_SME_SUCCESS;
	else
		scan_event->reasonCode = eSIR_SME_SCAN_FAILED;

	if (wmi_event->event == WMI_SCAN_EVENT_COMPLETED) {
		if (wmi_event->scan_id == scan_id)
			wma_reset_scan_info(wma_handle, vdev_id);
		else
			WMA_LOGE("Scan id not matched for SCAN COMPLETE event");
	}
	wma_send_msg(wma_handle, WDA_RX_SCAN_EVENT, (void *) scan_event, 0) ;
	return 0;
}

static void wma_mgmt_tx_ack_work_handler(struct work_struct *ack_work)
{
	struct wma_tx_ack_work_ctx *work = container_of(ack_work,
		struct wma_tx_ack_work_ctx, ack_cmp_work);
	pWDAAckFnTxComp ack_cb =
		work->wma_handle->umac_ota_ack_cb[work->sub_type];

	WMA_LOGD("Tx Ack Cb SubType %d Status %d",
			work->sub_type, work->status);

	/* Call the Ack Cb registered by UMAC */
	ack_cb((tpAniSirGlobal)(work->wma_handle->mac_context),
                                work->status ? 0 : 1);

	adf_os_mem_free(work);
}

/**
  * wma_mgmt_tx_ack_comp_hdlr - handles tx ack mgmt completion
  * @context: context with which the handler is registered
  * @netbuf: tx mgmt nbuf
  * @err: status of tx completion
  *
  * This is the cb registered with TxRx for
  * Ack Complete
  */
static void
wma_mgmt_tx_ack_comp_hdlr(void *wma_context,
		adf_nbuf_t netbuf, int32_t status)
{
	tpSirMacFrameCtl pFc =
		(tpSirMacFrameCtl)(adf_nbuf_data(netbuf));
	tp_wma_handle wma_handle = (tp_wma_handle)wma_context;

	if(wma_handle && wma_handle->umac_ota_ack_cb[pFc->subType]) {
		struct wma_tx_ack_work_ctx *ack_work;

		ack_work =
		adf_os_mem_alloc(NULL, sizeof(struct wma_tx_ack_work_ctx));

		if(ack_work) {
			INIT_WORK(&ack_work->ack_cmp_work,
					wma_mgmt_tx_ack_work_handler);
			ack_work->wma_handle = wma_handle;
			ack_work->sub_type = pFc->subType;
			ack_work->status = status;

			/* Schedue the Work */
			schedule_work(&ack_work->ack_cmp_work);
		}
	}
}

/**
  * wma_mgmt_tx_dload_comp_hldr - handles tx mgmt completion
  * @context: context with which the handler is registered
  * @netbuf: tx mgmt nbuf
  * @err: status of tx completion
  */
static void
wma_mgmt_tx_dload_comp_hldr(void *wma_context, adf_nbuf_t netbuf,
					int32_t status)
{
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;

	tp_wma_handle wma_handle = (tp_wma_handle)wma_context;
	void *mac_context = wma_handle->mac_context;

	WMA_LOGD("Tx Complete Status %d", status);

	if (!wma_handle->tx_frm_download_comp_cb) {
		WMA_LOGE("Tx Complete Cb not registered by umac");
		return;
	}

	/* Call Tx Mgmt Complete Callback registered by umac */
	wma_handle->tx_frm_download_comp_cb(mac_context,
					netbuf, 0);

	/* Reset Callback */
	wma_handle->tx_frm_download_comp_cb = NULL;

	/* Set the Tx Mgmt Complete Event */
	vos_status  = vos_event_set(
			&wma_handle->tx_frm_download_comp_event);
	if (!VOS_IS_STATUS_SUCCESS(vos_status))
		WMA_LOGP("Event Set failed - tx_frm_comp_event");
}

/**
  * wma_tx_attach - attaches tx fn with underlying layer
  * @pwmaCtx: wma context
  */
VOS_STATUS wma_tx_attach(tp_wma_handle wma_handle)
{
	/* Get the Vos Context */
	pVosContextType vos_handle =
		(pVosContextType)(wma_handle->vos_context);

	/* Get the txRx Pdev handle */
	ol_txrx_pdev_handle txrx_pdev =
		(ol_txrx_pdev_handle)(vos_handle->pdev_txrx_ctx);

	/* Register for Tx Management Frames */
	wdi_in_mgmt_tx_cb_set(txrx_pdev, GENERIC_NODOWLOAD_ACK_COMP_INDEX,
				NULL, wma_mgmt_tx_ack_comp_hdlr,wma_handle);

	wdi_in_mgmt_tx_cb_set(txrx_pdev, GENERIC_DOWNLD_COMP_NOACK_COMP_INDEX,
				wma_mgmt_tx_dload_comp_hldr, NULL, wma_handle);

	wdi_in_mgmt_tx_cb_set(txrx_pdev, GENERIC_DOWNLD_COMP_ACK_COMP_INDEX,
				wma_mgmt_tx_dload_comp_hldr,
				wma_mgmt_tx_ack_comp_hdlr,wma_handle);

	/* Store the Mac Context */
	wma_handle->mac_context = vos_handle->pMACContext;

	return VOS_STATUS_SUCCESS;
}

/**
 * wma_tx_detach - detaches mgmt fn with underlying layer
 * Deregister with TxRx for Tx Mgmt Download and Ack completion.
 * @tp_wma_handle: wma context
 */
static VOS_STATUS wma_tx_detach(tp_wma_handle wma_handle)
{
	u_int32_t frame_index = 0;

	/* Get the Vos Context */
	pVosContextType vos_handle =
		(pVosContextType)(wma_handle->vos_context);

	/* Get the txRx Pdev handle */
	ol_txrx_pdev_handle txrx_pdev =
		(ol_txrx_pdev_handle)(vos_handle->pdev_txrx_ctx);

	/* Deregister with TxRx for Tx Mgmt completion call back */
	for (frame_index = 0; frame_index < FRAME_INDEX_MAX; frame_index++) {
		wdi_in_mgmt_tx_cb_set(txrx_pdev, frame_index, NULL, NULL,
					txrx_pdev);
	}

	/* Destroy Tx Frame Complete event */
	vos_event_destroy(&wma_handle->tx_frm_download_comp_event);

	/* Reset Tx Frm Callbacks */
	wma_handle->tx_frm_download_comp_cb = NULL;

	/* Reset Tx Data Frame Ack Cb */
	wma_handle->umac_data_ota_ack_cb = NULL;

	return VOS_STATUS_SUCCESS;
}

static void wma_beacon_miss_handler(tp_wma_handle wma, u_int32_t vdev_id)
{
	tSirSmeMissedBeaconInd *beacon_miss_ind;

	beacon_miss_ind = (tSirSmeMissedBeaconInd *) vos_mem_malloc
		                             (sizeof(tSirSmeMissedBeaconInd));
	beacon_miss_ind->messageType = WDA_MISSED_BEACON_IND;
	beacon_miss_ind->length = sizeof(tSirSmeMissedBeaconInd);
	beacon_miss_ind->bssIdx = vdev_id;

	wma_send_msg(wma, WDA_MISSED_BEACON_IND,
		         (void *)beacon_miss_ind, 0);
}
/* function   : wma_roam_better_ap_handler
 * Descriptin : Handler for WMI_ROAM_REASON_BETTER_AP event from roam firmware in Rome.
 *            : This event means roam algorithm in Rome has found a better matching
 *            : candidate AP. The indication is sent through tl_shim as by repeating
 *            : the last beacon. Hence this routine calls a tlshim routine.
 * Args       :
 * Returns    :
 */
static void wma_roam_better_ap_handler(tp_wma_handle wma, u_int32_t vdev_id)
{
extern	int tlshim_mgmt_roam_event_ind(void *context);
	VOS_STATUS ret;
	ret = tlshim_mgmt_roam_event_ind(wma->vos_context);
}

/* function   : wma_roam_event_callback
 * Descriptin : Handler for all events from roam engine in firmware
 * Args       :
 * Returns    :
 */

static int wma_roam_event_callback(WMA_HANDLE handle, u_int8_t *event_buf,
				u_int32_t len)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	WMI_ROAM_EVENTID_param_tlvs *param_buf;
	wmi_roam_event_fixed_param *wmi_event;

	param_buf = (WMI_ROAM_EVENTID_param_tlvs *) event_buf;
	if (!param_buf) {
		WMA_LOGE("Invalid roam event buffer");
		return -EINVAL;
	}

	wmi_event = param_buf->fixed_param;
	WMA_LOGD("%s: Reason %x for vdevid %x, rssi %d",
		__func__, wmi_event->reason, wmi_event->vdev_id, wmi_event->rssi);

	switch(wmi_event->reason) {
	case WMI_ROAM_REASON_BMISS:
		WMA_LOGD("%s:Beacon Miss for vdevid %x",__func__,
			wmi_event->vdev_id);
		wma_beacon_miss_handler(wma_handle, wmi_event->vdev_id);
		break;
	case WMI_ROAM_REASON_BETTER_AP:
		WMA_LOGD("%s:Better AP found for vdevid %x, rssi %d", __func__,
			wmi_event->vdev_id, wmi_event->rssi);
		wma_roam_better_ap_handler(wma_handle, wmi_event->vdev_id);
		break;
	default:
		WMA_LOGD("%s:Unhandled Roam Event %x for vdevid %x", __func__,
		wmi_event->reason, wmi_event->vdev_id);
		break;
	}
	return 0;
}

#ifdef FEATURE_WLAN_PNO_OFFLOAD

/* Record NLO match event comes from FW. It's a indication that
 * one of the profile is matched.
 */
static int wma_nlo_match_evt_handler(void *handle, u_int8_t *event,
				     u_int32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	wmi_nlo_event *nlo_event;
	WMI_NLO_MATCH_EVENTID_param_tlvs *param_buf =
				(WMI_NLO_MATCH_EVENTID_param_tlvs *) event;
	struct wma_txrx_node *node;

	if (!param_buf) {
		WMA_LOGE("Invalid NLO match event buffer");
		return -EINVAL;
	}

	nlo_event = param_buf->fixed_param;
	WMA_LOGD("PNO match event received for vdev %d",
		 nlo_event->vdev_id);

	node = &wma->interfaces[nlo_event->vdev_id];
	if (node)
		node->nlo_match_evt_received = TRUE;

	return 0;
}

/* Handles NLO scan completion event. */
static int wma_nlo_scan_cmp_evt_handler(void *handle, u_int8_t *event,
					u_int32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	wmi_nlo_event *nlo_event = (wmi_nlo_event *) event;
	tSirScanOffloadEvent *scan_event;
	struct wma_txrx_node *node;
	VOS_STATUS status;

	WMA_LOGD("PNO scan completion event received for vdev %d",
		 nlo_event->vdev_id);

	node = &wma->interfaces[nlo_event->vdev_id];

	/* Handle scan completion event only after NLO match event. */
	if (!node || !node->nlo_match_evt_received)
		goto skip_pno_cmp_ind;

	/* FW need explict stop to really stop PNO operation */
	status = wma_pno_stop(wma, nlo_event->vdev_id);
	if (status)
		WMA_LOGE("Failed to stop PNO scan\n");

	scan_event = (tSirScanOffloadEvent *) vos_mem_malloc(
					      sizeof(tSirScanOffloadEvent));
	if (scan_event) {
		/* Posting scan completion msg would take scan cache result
		 * from LIM module and update in scan cache maintained in SME.*/
		WMA_LOGD("Posting Scan completion to umac");
		scan_event->reasonCode = eSIR_SME_SUCCESS;
		scan_event->event = SCAN_EVENT_COMPLETED;
		wma_send_msg(wma, WDA_RX_SCAN_EVENT,
			     (void *) scan_event, 0);
	} else {
		WMA_LOGE("Memory allocation failed for tSirScanOffloadEvent");
	}

skip_pno_cmp_ind:
	return 0;
}

#endif

/* function   : wma_start
 * Descriptin :
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_start(v_VOID_t *vos_ctx)
{
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
	tp_wma_handle wma_handle;
	int status;
	WMA_LOGD("%s: Enter", __func__);

	wma_handle = vos_get_context(VOS_MODULE_ID_WDA, vos_ctx);

	/* validate the wma_handle */
	if (NULL == wma_handle) {
		WMA_LOGP("Invalid handle");
		vos_status = VOS_STATUS_E_INVAL;
		goto end;
	}

#ifdef QCA_WIFI_ISOC
	vos_event_reset(&wma_handle->wma_ready_event);

	/* start cfg download to soc */
	vos_status = wma_cfg_download_isoc(wma_handle->vos_context, wma_handle);
	if (vos_status != 0) {
		WMA_LOGP("failed to download the cfg to FW");
		vos_status = VOS_STATUS_E_FAILURE;
		goto end;
	}

	/* wait until WMI_READY_EVENTID received from FW */
	vos_status = wma_wait_for_ready_event(wma_handle);
	if (vos_status == VOS_STATUS_E_FAILURE)
		goto end;
#endif

	status = wmi_unified_register_event_handler(wma_handle->wmi_handle,
						WMI_SCAN_EVENTID,
						wma_scan_event_callback);
	if (0 != status) {
		WMA_LOGP("Failed to register scan callback");
		vos_status = VOS_STATUS_E_FAILURE;
		goto end;
	}

	status = wmi_unified_register_event_handler(wma_handle->wmi_handle,
						WMI_ROAM_EVENTID,
						wma_roam_event_callback);
	if (0 != status) {
		WMA_LOGP("Failed to register Roam callback");
		vos_status = VOS_STATUS_E_FAILURE;
		goto end;
	}

	status = wmi_unified_register_event_handler(wma_handle->wmi_handle,
						WMI_WOW_WAKEUP_HOST_EVENTID,
						wma_wow_wakeup_host_event);
	if (status) {
		WMA_LOGP("Failed to register wow wakeup host event handler");
		vos_status = VOS_STATUS_E_FAILURE;
		goto end;
	}

#ifdef FEATURE_WLAN_PNO_OFFLOAD
	if (WMI_SERVICE_IS_ENABLED(wma_handle->wmi_service_bitmap,
				   WMI_SERVICE_NLO)) {

		WMA_LOGD("FW supports pno offload, registering nlo match handler");

		status = wmi_unified_register_event_handler(
				wma_handle->wmi_handle,
				WMI_NLO_MATCH_EVENTID,
				wma_nlo_match_evt_handler);
		if (status) {
			WMA_LOGE("Failed to register nlo match event cb");
			vos_status = VOS_STATUS_E_FAILURE;
			goto end;
		}

		status = wmi_unified_register_event_handler(
				wma_handle->wmi_handle,
				WMI_NLO_SCAN_COMPLETE_EVENTID,
				wma_nlo_scan_cmp_evt_handler);
		if (status) {
			WMA_LOGE("Failed to register nlo scan comp event cb");
			vos_status = VOS_STATUS_E_FAILURE;
			goto end;
		}
	}
#endif

	vos_status = VOS_STATUS_SUCCESS;

#ifdef QCA_WIFI_FTM
	/*
	 * Tx mgmt attach requires TXRX context which is not created
	 * in FTM mode as WLANTL_Open will not be called in this mode.
	 * So skip the TX mgmt attach.
	 */
	if (vos_get_conparam() == VOS_FTM_MODE)
		goto end;
#endif

	vos_status = wma_tx_attach(wma_handle);
	if(vos_status != VOS_STATUS_SUCCESS) {
		WMA_LOGP("Failed to register tx management");
		goto end;
	}

end:
	WMA_LOGD("%s: Exit", __func__);
	return vos_status;
}

/* function   : wma_stop
 * Descriptin :
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_stop(v_VOID_t *vos_ctx, tANI_U8 reason)
{
	tp_wma_handle wma_handle;
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;

	wma_handle = vos_get_context(VOS_MODULE_ID_WDA, vos_ctx);

	WMA_LOGD("%s: Enter", __func__);

	/* validate the wma_handle */
	if (NULL == wma_handle) {
		WMA_LOGP("Invalid handle");
		vos_status = VOS_STATUS_E_INVAL;
		goto end;
	}

#ifdef QCA_WIFI_ISOC
	wma_hal_stop_isoc(wma_handle);
#else
	/* Suspend the target and disable interrupt */
	if (wma_suspend_target(wma_handle, 1))
		WMA_LOGE("Failed to suspend target\n");
#endif

#ifdef QCA_WIFI_FTM
	/*
	 * Tx mgmt detach requires TXRX context which is not created
	 * in FTM mode as WLANTL_Open will not be called in this mode.
	 * So skip the TX mgmt detach.
	 */
	if (vos_get_conparam() == VOS_FTM_MODE) {
		vos_status = VOS_STATUS_SUCCESS;
		goto end;
	}
#endif

	vos_status = wma_tx_detach(wma_handle);
	if(vos_status != VOS_STATUS_SUCCESS) {
		WMA_LOGP("Failed to deregister tx management");
		goto end;
	}

end:
	WMA_LOGD("%s: Exit", __func__);
	return vos_status;
}

static void wma_cleanup_vdev_resp(tp_wma_handle wma)
{
	struct wma_target_req *msg, *tmp;

	adf_os_spin_lock_bh(&wma->vdev_respq_lock);
	list_for_each_entry_safe(msg, tmp,
				 &wma->vdev_resp_queue, node) {
		list_del(&msg->node);
		vos_timer_destroy(&msg->event_timeout);
		vos_mem_free(msg);
	}
	adf_os_spin_unlock_bh(&wma->vdev_respq_lock);
}

/* function   : wma_close
 * Descriptin :
 * Args       :
 * Returns    :
 */
VOS_STATUS wma_close(v_VOID_t *vos_ctx)
{
	tp_wma_handle wma_handle;
#if !defined(QCA_WIFI_ISOC) && !defined(CONFIG_HL_SUPPORT)
	u_int32_t idx;
#endif
	u_int8_t ptrn_id;
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;

	WMA_LOGD("%s: Enter", __func__);

	wma_handle = vos_get_context(VOS_MODULE_ID_WDA, vos_ctx);

	/* validate the wma_handle */
	if (NULL == wma_handle) {
		WMA_LOGP("Invalid handle");
		return VOS_STATUS_E_INVAL;
	}

	/* Free wow pattern cache */
	for (ptrn_id = 0; ptrn_id < WOW_MAX_BITMAP_FILTERS; ptrn_id++)
		wma_free_wow_ptrn(wma_handle, ptrn_id);

	/* unregister Firmware debug log */
	vos_status = dbglog_deinit(wma_handle->wmi_handle);
	if(vos_status != VOS_STATUS_SUCCESS)
		WMA_LOGP("dbglog_deinit failed");

	/* close the vos events */
	vos_event_destroy(&wma_handle->wma_ready_event);
	vos_event_destroy(&wma_handle->target_suspend);
	wma_cleanup_vdev_resp(wma_handle);
#ifdef QCA_WIFI_ISOC
	vos_event_destroy(&wma_handle->cfg_nv_tx_complete);
#endif
#if !defined(QCA_WIFI_ISOC) && !defined(CONFIG_HL_SUPPORT)
	for(idx = 0; idx < wma_handle->num_mem_chunks; ++idx) {
		adf_os_mem_free_consistent(
				wma_handle->adf_dev,
				wma_handle->mem_chunks[idx].len,
				wma_handle->mem_chunks[idx].vaddr,
				wma_handle->mem_chunks[idx].paddr,
				adf_os_get_dma_mem_context(
					(&(wma_handle->mem_chunks[idx])),
					memctx));
	}
#endif

#if defined(QCA_WIFI_FTM) && !defined(QCA_WIFI_ISOC)
	/* Detach UTF and unregister the handler */
	wma_utf_detach(wma_handle);
#endif

	/* dettach the wmi serice */
	if (wma_handle->wmi_handle) {
		WMA_LOGD("calling wmi_unified_detach");
		wmi_unified_detach(wma_handle->wmi_handle);
		wma_handle->wmi_handle = NULL;
	}
	vos_mem_free(wma_handle->interfaces);
	/* free the wma_handle */
	vos_free_context(wma_handle->vos_context, VOS_MODULE_ID_WDA, wma_handle);

	adf_os_mem_free(((pVosContextType) vos_ctx)->cfg_ctx);

	WMA_LOGD("%s: Exit", __func__);
	return VOS_STATUS_SUCCESS;
}

static v_VOID_t wma_update_fw_config(tp_wma_handle wma_handle,
				     struct wma_target_cap *tgt_cap)
{
	/*
	 * tgt_cap contains default target resource configuration
	 * which can be modified here, if required
	 */
	/* Override the no. of max fragments as per platform configuration */
	tgt_cap->wlan_resource_config.max_frag_entries =
		MIN(QCA_OL_11AC_TX_MAX_FRAGS, wma_handle->max_frag_entry);
	wma_handle->max_frag_entry = tgt_cap->wlan_resource_config.max_frag_entries;
}

#if !defined(QCA_WIFI_ISOC) && !defined(CONFIG_HL_SUPPORT)
/**
 * allocate a chunk of memory at the index indicated and
 * if allocation fail allocate smallest size possiblr and
 * return number of units allocated.
 */
static u_int32_t wma_alloc_host_mem_chunk(tp_wma_handle wma_handle,
					  u_int32_t req_id, u_int32_t idx,
					  u_int32_t num_units,
					  u_int32_t unit_len)
{
	adf_os_dma_addr_t paddr;
	if (!num_units  || !unit_len)  {
		return 0;
	}
	wma_handle->mem_chunks[idx].vaddr = NULL ;
	/** reduce the requested allocation by half until allocation succeeds */
	while(wma_handle->mem_chunks[idx].vaddr == NULL && num_units ) {
		wma_handle->mem_chunks[idx].vaddr = adf_os_mem_alloc_consistent(
				wma_handle->adf_dev, num_units*unit_len, &paddr,
				adf_os_get_dma_mem_context(
					(&(wma_handle->mem_chunks[idx])),
					memctx));
		if(wma_handle->mem_chunks[idx].vaddr == NULL) {
			num_units = (num_units >> 1) ; /* reduce length by half */
		} else {
			wma_handle->mem_chunks[idx].paddr = paddr;
			wma_handle->mem_chunks[idx].len = num_units*unit_len;
			wma_handle->mem_chunks[idx].req_id =  req_id;
		}
	}
	return num_units;
}

#define HOST_MEM_SIZE_UNIT 4
/*
 * allocate amount of memory requested by FW.
 */
static void wma_alloc_host_mem(tp_wma_handle wma_handle, u_int32_t req_id,
				u_int32_t num_units, u_int32_t unit_len)
{
	u_int32_t remaining_units,allocated_units, idx;

	/* adjust the length to nearest multiple of unit size */
	unit_len = (unit_len + (HOST_MEM_SIZE_UNIT - 1)) &
			(~(HOST_MEM_SIZE_UNIT - 1));
	idx = wma_handle->num_mem_chunks ;
	remaining_units = num_units;
	while(remaining_units) {
		allocated_units = wma_alloc_host_mem_chunk(wma_handle, req_id,
							   idx, remaining_units,
							   unit_len);
		if (allocated_units == 0) {
			WMA_LOGE("FAILED TO ALLOCATED memory unit len %d"
				" units requested %d units allocated %d \n",
				unit_len, num_units,
				(num_units - remaining_units));
			wma_handle->num_mem_chunks = idx;
			break;
		}
		remaining_units -= allocated_units;
		++idx;
		if (idx == MAX_MEM_CHUNKS ) {
			WMA_LOGE("RWACHED MAX CHUNK LIMIT for memory units %d"
				" unit len %d requested by FW,"
				" only allocated %d \n",
				num_units,unit_len,
				(num_units - remaining_units));
			wma_handle->num_mem_chunks = idx;
			break;
		}
	}
	wma_handle->num_mem_chunks = idx;
}
#endif

#ifndef QCA_WIFI_ISOC
static inline void wma_update_target_services(tp_wma_handle wh,
					      struct hdd_tgt_services *cfg)
{
	/* STA power save */
	cfg->sta_power_save = WMI_SERVICE_IS_ENABLED(wh->wmi_service_bitmap,
						     WMI_SERVICE_STA_PWRSAVE);

	/* Enable UAPSD */
	cfg->uapsd = WMI_SERVICE_IS_ENABLED(wh->wmi_service_bitmap,
					    WMI_SERVICE_AP_UAPSD);

	/* Update AP DFS service */
	cfg->ap_dfs = WMI_SERVICE_IS_ENABLED(wh->wmi_service_bitmap,
						    WMI_SERVICE_AP_DFS);

	/* Enable 11AC */
	cfg->en_11ac = WMI_SERVICE_IS_ENABLED(wh->wmi_service_bitmap,
					      WMI_SERVICE_11AC);
        if (cfg->en_11ac)
           gFwWlanFeatCaps |= DOT11AC;

	/* ARP offload */
	cfg->arp_offload = WMI_SERVICE_IS_ENABLED(wh->wmi_service_bitmap,
						  WMI_SERVICE_ARPNS_OFFLOAD);
#ifdef FEATURE_WLAN_PNO_OFFLOAD
	/* PNO offload */
	if (WMI_SERVICE_IS_ENABLED(wh->wmi_service_bitmap, WMI_SERVICE_NLO))
		cfg->pno_offload = TRUE;
#endif
}

static inline void wma_update_target_ht_cap(tp_wma_handle wh,
					    struct hdd_tgt_ht_cap *cfg)
{
	/* RX STBC */
	cfg->ht_rx_stbc = !!(wh->ht_cap_info & WMI_HT_CAP_RX_STBC);

	/* TX STBC */
	cfg->ht_tx_stbc = !!(wh->ht_cap_info & WMI_HT_CAP_TX_STBC);

	/* MPDU density */
	cfg->mpdu_density = wh->ht_cap_info & WMI_HT_CAP_MPDU_DENSITY;

	/* HT RX LDPC */
	cfg->ht_rx_ldpc = !!(wh->ht_cap_info & WMI_HT_CAP_LDPC);

	/* HT SGI */
	cfg->ht_sgi_20 = !!(wh->ht_cap_info & WMI_HT_CAP_HT20_SGI);

	cfg->ht_sgi_40 = !!(wh->ht_cap_info & WMI_HT_CAP_HT40_SGI);

	/* RF chains */
	cfg->num_rf_chains = wh->num_rf_chains;

        WMA_LOGD("\n%s: ht_cap_info - %x ht_rx_stbc - %d, ht_tx_stbc - %d\n\
                mpdu_density - %d ht_rx_ldpc - %d ht_sgi_20 - %d\n\
                ht_sgi_40 - %d num_rf_chains - %d \n", __func__,
                wh->ht_cap_info, cfg->ht_rx_stbc, cfg->ht_tx_stbc,
                cfg->mpdu_density, cfg->ht_rx_ldpc, cfg->ht_sgi_20,
                cfg->ht_sgi_40, cfg->num_rf_chains);

}

#ifdef WLAN_FEATURE_11AC
static inline void wma_update_target_vht_cap(tp_wma_handle wh,
					     struct hdd_tgt_vht_cap *cfg)
{
	/* Max MPDU length */
	if (wh->vht_cap_info & IEEE80211_VHTCAP_MAX_MPDU_LEN_3839)
		cfg->vht_max_mpdu = 0;
	else if (wh->vht_cap_info & IEEE80211_VHTCAP_MAX_MPDU_LEN_7935)
		cfg->vht_max_mpdu = 1;
	else if (wh->vht_cap_info & IEEE80211_VHTCAP_MAX_MPDU_LEN_11454)
		cfg->vht_max_mpdu = 2;
	else
		cfg->vht_max_mpdu = 0;

	/* supported channel width */
	if (wh->vht_cap_info & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80)
		cfg->supp_chan_width = 1 << eHT_CHANNEL_WIDTH_80MHZ;

	else if (wh->vht_cap_info & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160)
		cfg->supp_chan_width = 1 << eHT_CHANNEL_WIDTH_160MHZ;

	else if (wh->vht_cap_info & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160) {
		cfg->supp_chan_width = 1 << eHT_CHANNEL_WIDTH_80MHZ;
		cfg->supp_chan_width |= 1 << eHT_CHANNEL_WIDTH_160MHZ;
	}

	else
		cfg->supp_chan_width = 0;

	/* LDPC capability */
	cfg->vht_rx_ldpc = wh->vht_cap_info & IEEE80211_VHTCAP_RX_LDPC;

	/* Guard interval */
	cfg->vht_short_gi_80 = wh->vht_cap_info & IEEE80211_VHTCAP_SHORTGI_80;
	cfg->vht_short_gi_160 = wh->vht_cap_info & IEEE80211_VHTCAP_SHORTGI_160;

	/* TX STBC capability */
	cfg->vht_tx_stbc = wh->vht_cap_info & IEEE80211_VHTCAP_TX_STBC;

	/* RX STBC capability */
        cfg->vht_rx_stbc = wh->vht_cap_info & IEEE80211_VHTCAP_RX_STBC;

        cfg->vht_max_ampdu_len_exp = (wh->vht_cap_info &
                                     IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP)
                                      >> IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP_S;

	/* SU beamformer cap */
	cfg->vht_su_bformer = wh->vht_cap_info & IEEE80211_VHTCAP_SU_BFORMER;

	/* SU beamformee cap */
	cfg->vht_su_bformee = wh->vht_cap_info & IEEE80211_VHTCAP_SU_BFORMEE;

	/* MU beamformer cap */
	cfg->vht_mu_bformer = wh->vht_cap_info & IEEE80211_VHTCAP_MU_BFORMER;

	/* MU beamformee cap */
	cfg->vht_mu_bformee = wh->vht_cap_info & IEEE80211_VHTCAP_MU_BFORMEE;

	/* VHT Max AMPDU Len exp */
	cfg->vht_max_ampdu_len_exp = wh->vht_cap_info &
					IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP;

	/* VHT TXOP PS cap */
	cfg->vht_txop_ps = wh->vht_cap_info & IEEE80211_VHTCAP_TXOP_PS;

        WMA_LOGD("\n %s: max_mpdu %d supp_chan_width %x rx_ldpc %x\n \
                short_gi_80 %x tx_stbc %x rx_stbc %x txop_ps %x\n \
                su_bformee %x mu_bformee %x max_ampdu_len_exp %d\n",
                __func__, cfg->vht_max_mpdu, cfg->supp_chan_width,
                cfg->vht_rx_ldpc, cfg->vht_short_gi_80, cfg->vht_tx_stbc,
                cfg->vht_rx_stbc, cfg->vht_txop_ps, cfg->vht_su_bformee,
                cfg->vht_mu_bformee, cfg->vht_max_ampdu_len_exp);
}
#endif	/* #ifdef WLAN_FEATURE_11AC */

static void wma_update_hdd_cfg(tp_wma_handle wma_handle)
{
	struct hdd_tgt_cfg hdd_tgt_cfg;
	int err;
	void *hdd_ctx = vos_get_context(VOS_MODULE_ID_HDD,
					wma_handle->vos_context);

	err = regdmn_get_country_alpha2(wma_handle->reg_cap.eeprom_rd,
					hdd_tgt_cfg.alpha2);
	if (err) {
		WMA_LOGE("Invalid regulatory settings");
		return;
	}

	switch (wma_handle->phy_capability) {
	case WMI_11G_CAPABILITY:
	case WMI_11NG_CAPABILITY:
		hdd_tgt_cfg.band_cap = eCSR_BAND_24;
		break;
	case WMI_11A_CAPABILITY:
	case WMI_11NA_CAPABILITY:
	case WMI_11AC_CAPABILITY:
		hdd_tgt_cfg.band_cap = eCSR_BAND_5G;
		break;
	case WMI_11AG_CAPABILITY:
	case WMI_11NAG_CAPABILITY:
	default:
		hdd_tgt_cfg.band_cap = eCSR_BAND_ALL;
	}

	adf_os_mem_copy(hdd_tgt_cfg.hw_macaddr.bytes, wma_handle->hwaddr,
			ATH_MAC_LEN);

	wma_update_target_services(wma_handle, &hdd_tgt_cfg.services);
	wma_update_target_ht_cap(wma_handle, &hdd_tgt_cfg.ht_cap);
#ifdef WLAN_FEATURE_11AC
	wma_update_target_vht_cap(wma_handle, &hdd_tgt_cfg.vht_cap);
#endif	/* #ifdef WLAN_FEATURE_11AC */

#ifndef QCA_WIFI_ISOC
 hdd_tgt_cfg.target_fw_version = wma_handle->target_fw_version;
	wma_handle->tgt_cfg_update_cb(hdd_ctx, &hdd_tgt_cfg);
#endif
}
#endif

static wmi_buf_t wma_setup_wmi_init_msg(tp_wma_handle wma_handle,
				wmi_service_ready_event_fixed_param *ev,
				WMI_SERVICE_READY_EVENTID_param_tlvs *param_buf,
				v_SIZE_t *len)
{
	wmi_buf_t buf;
	wmi_init_cmd_fixed_param *cmd;
	wlan_host_mem_req *ev_mem_reqs;
	wmi_abi_version my_vers;
	int num_whitelist;
	u_int8_t *buf_ptr;
	wmi_resource_config *resource_cfg;
	wlan_host_memory_chunk *host_mem_chunks;
	u_int32_t mem_chunk_len = 0;
#if !defined(QCA_WIFI_ISOC) && !defined(CONFIG_HL_SUPPORT)
	u_int16_t idx;
	u_int32_t num_units;
#endif

	*len = sizeof(*cmd) + sizeof(wmi_resource_config) + WMI_TLV_HDR_SIZE;
#if !defined(QCA_WIFI_ISOC) && !defined(CONFIG_HL_SUPPORT)
	mem_chunk_len = (sizeof(wlan_host_memory_chunk) * MAX_MEM_CHUNKS);
#endif
	buf = wmi_buf_alloc(wma_handle->wmi_handle, *len + mem_chunk_len);
	if (!buf) {
		WMA_LOGP("wmi_buf_alloc failed");
		return NULL;
	}

	ev_mem_reqs = param_buf->mem_reqs;
	buf_ptr = (u_int8_t *) wmi_buf_data(buf);
	cmd = (wmi_init_cmd_fixed_param *) buf_ptr;
	resource_cfg = (wmi_resource_config *) (buf_ptr + sizeof(*cmd));
	host_mem_chunks = (wlan_host_memory_chunk*)
			  (buf_ptr + sizeof(*cmd) + sizeof(wmi_resource_config)
			  + WMI_TLV_HDR_SIZE);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_init_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(wmi_init_cmd_fixed_param));

	*resource_cfg = wma_handle->wlan_resource_config;
	WMITLV_SET_HDR(&resource_cfg->tlv_header,
		       WMITLV_TAG_STRUC_wmi_resource_config,
		       WMITLV_GET_STRUCT_TLVLEN(wmi_resource_config));

	/* allocate memory requested by FW */
	if (ev->num_mem_reqs > WMI_MAX_MEM_REQS) {
		VOS_ASSERT(0);
		adf_nbuf_free(buf);
		return NULL;
	}

	cmd->num_host_mem_chunks = 0;
#if !defined(QCA_WIFI_ISOC) && !defined(CONFIG_HL_SUPPORT)
	for(idx = 0; idx < ev->num_mem_reqs; ++idx) {
		num_units = ev_mem_reqs[idx].num_units;
		if  (ev_mem_reqs[idx].num_unit_info & NUM_UNITS_IS_NUM_PEERS) {
			/*
			 * number of units to allocate is number
			 * of peers, 1 extra for self peer on
			 * target. this needs to be fied, host
			 * and target can get out of sync
			 */
			num_units = resource_cfg->num_peers + 1;
		}
		WMA_LOGD("idx %d req %d  num_units %d num_unit_info %d unit size %d actual units %d \n",
			 idx, ev_mem_reqs[idx].req_id,
			 ev_mem_reqs[idx].num_units,
			 ev_mem_reqs[idx].num_unit_info,
			 ev_mem_reqs[idx].unit_size,
			 num_units);
		wma_alloc_host_mem(wma_handle, ev_mem_reqs[idx].req_id,
				   num_units, ev_mem_reqs[idx].unit_size);
	}
	for(idx = 0; idx < wma_handle->num_mem_chunks; ++idx) {
		WMITLV_SET_HDR(&(host_mem_chunks[idx].tlv_header),
			WMITLV_TAG_STRUC_wlan_host_memory_chunk,
			WMITLV_GET_STRUCT_TLVLEN(wlan_host_memory_chunk));
		host_mem_chunks[idx].ptr = wma_handle->mem_chunks[idx].paddr;
		host_mem_chunks[idx].size = wma_handle->mem_chunks[idx].len;
		host_mem_chunks[idx].req_id =
				wma_handle->mem_chunks[idx].req_id;
		WMA_LOGD("chunk %d len %d requested ,ptr  0x%x \n",
			 idx, host_mem_chunks[idx].size,
			 host_mem_chunks[idx].ptr) ;
	}
	cmd->num_host_mem_chunks = wma_handle->num_mem_chunks;
	len += (wma_handle->num_mem_chunks * sizeof(wlan_host_memory_chunk));
	WMITLV_SET_HDR((buf_ptr + sizeof(*cmd) + sizeof(wmi_resource_config)),
			WMITLV_TAG_ARRAY_STRUC,
			(sizeof(wlan_host_memory_chunk) *
			 wma_handle->num_mem_chunks));
#endif
	vos_mem_copy(&wma_handle->target_abi_vers,
		     &param_buf->fixed_param->fw_abi_vers,
		     sizeof(wmi_abi_version));
	num_whitelist = sizeof(version_whitelist) /
			sizeof(wmi_whitelist_version_info);
	my_vers.abi_version_0 = WMI_ABI_VERSION_0;
	my_vers.abi_version_1 = WMI_ABI_VERSION_1;
	my_vers.abi_version_ns_0 = WMI_ABI_VERSION_NS_0;
	my_vers.abi_version_ns_1 = WMI_ABI_VERSION_NS_1;
	my_vers.abi_version_ns_2 = WMI_ABI_VERSION_NS_2;
	my_vers.abi_version_ns_3 = WMI_ABI_VERSION_NS_3;

	wmi_cmp_and_set_abi_version(num_whitelist, version_whitelist,
			&my_vers, &param_buf->fixed_param->fw_abi_vers,
			&cmd->host_abi_vers);

	WMA_LOGD("%s: INIT_CMD version: %d, %d, 0x%x, 0x%x, 0x%x, 0x%x",
		 __func__, WMI_VER_GET_MAJOR(cmd->host_abi_vers.abi_version_0),
		 WMI_VER_GET_MINOR(cmd->host_abi_vers.abi_version_0),
		 cmd->host_abi_vers.abi_version_ns_0,
		 cmd->host_abi_vers.abi_version_ns_1,
		 cmd->host_abi_vers.abi_version_ns_2,
		 cmd->host_abi_vers.abi_version_ns_3);

	vos_mem_copy(&wma_handle->final_abi_vers, &cmd->host_abi_vers,
		     sizeof(wmi_abi_version));
	return buf;
}

/* Process service ready event and send wmi_init command */
v_VOID_t wma_rx_service_ready_event(WMA_HANDLE handle, void *cmd_param_info)
{
	wmi_buf_t buf;
	v_SIZE_t len;
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	struct wma_target_cap target_cap;
	WMI_SERVICE_READY_EVENTID_param_tlvs *param_buf;
	wmi_service_ready_event_fixed_param *ev;
	int status;

	WMA_LOGD("%s: Enter", __func__);

	param_buf = (WMI_SERVICE_READY_EVENTID_param_tlvs *) cmd_param_info;
	if (!(handle && param_buf)) {
		WMA_LOGP("Invalid arguments");
		return;
	}

	ev = param_buf->fixed_param;
	if (!ev) {
		WMA_LOGP("Invalid buffer");
		return;
	}

	WMA_LOGA("WMA <-- WMI_SERVICE_READY_EVENTID");

	wma_handle->phy_capability = ev->phy_capability;
	wma_handle->max_frag_entry = ev->max_frag_entry;
	vos_mem_copy(&wma_handle->reg_cap, param_buf->hal_reg_capabilities,
		     sizeof(HAL_REG_CAPABILITIES));
	wma_handle->ht_cap_info = ev->ht_cap_info;
#ifdef WLAN_FEATURE_11AC
	wma_handle->vht_cap_info = ev->vht_cap_info;
        wma_handle->vht_supp_mcs = ev->vht_supp_mcs;
#endif
	wma_handle->num_rf_chains = ev->num_rf_chains;

	wma_handle->target_fw_version = ev->fw_build_vers;

	 /* TODO: Recheck below line to dump service ready event */
	 /* dbg_print_wmi_service_11ac(ev); */

	/* wmi service is ready */
	vos_mem_copy(wma_handle->wmi_service_bitmap,
		     param_buf->wmi_service_bitmap,
		     sizeof(wma_handle->wmi_service_bitmap));
#ifndef QCA_WIFI_ISOC
	/* SWBA event handler for beacon transmission */
	status = wmi_unified_register_event_handler(wma_handle->wmi_handle,
						    WMI_HOST_SWBA_EVENTID,
						    wma_beacon_swba_handler);
	if (status) {
		WMA_LOGE("Failed to register swba beacon event cb");
		return;
	}
#endif
#ifdef WLAN_FEATURE_GTK_OFFLOAD
	if (WMI_SERVICE_IS_ENABLED(wma_handle->wmi_service_bitmap,
				   WMI_SERVICE_GTK_OFFLOAD)) {
		status = wmi_unified_register_event_handler(
						   wma_handle->wmi_handle,
						   WMI_GTK_OFFLOAD_STATUS_EVENTID,
						   wma_gtk_offload_status_event);
		if (status) {
			WMA_LOGE("Failed to register GTK offload event cb");
			return;
		}
	}
#endif
	vos_mem_copy(target_cap.wmi_service_bitmap,
		     param_buf->wmi_service_bitmap,
		     sizeof(wma_handle->wmi_service_bitmap));
	target_cap.wlan_resource_config = wma_handle->wlan_resource_config;
	wma_update_fw_config(wma_handle, &target_cap);
	vos_mem_copy(wma_handle->wmi_service_bitmap, target_cap.wmi_service_bitmap,
		     sizeof(wma_handle->wmi_service_bitmap));
	wma_handle->wlan_resource_config = target_cap.wlan_resource_config;

	buf = wma_setup_wmi_init_msg(wma_handle, ev, param_buf, &len);
	if (!buf) {
		WMA_LOGE("Failed to setup buffer for wma init command");
		return;
	}

	WMA_LOGA("WMA --> WMI_INIT_CMDID");
	status = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len, WMI_INIT_CMDID);
	if (status != EOK) {
		WMA_LOGE("Failed to send WMI_INIT_CMDID command");
		wmi_buf_free(buf);
		return;
	}
}

static void wma_set_regdomain(u_int32_t regdmn)
{
	void *vos_context = vos_get_global_context(VOS_MODULE_ID_WDA, NULL);
	tp_wma_handle wma = vos_get_context(VOS_MODULE_ID_WDA, vos_context);
	u_int32_t modeSelect = 0xFFFFFFFF;

	switch (wma->phy_capability) {
	case WMI_11G_CAPABILITY:
	case WMI_11NG_CAPABILITY:
		modeSelect &= ~(REGDMN_MODE_11A | REGDMN_MODE_TURBO |
			REGDMN_MODE_108A | REGDMN_MODE_11A_HALF_RATE |
			REGDMN_MODE_11A_QUARTER_RATE | REGDMN_MODE_11NA_HT20 |
			REGDMN_MODE_11NA_HT40PLUS | REGDMN_MODE_11NA_HT40MINUS |
			REGDMN_MODE_11AC_VHT20 | REGDMN_MODE_11AC_VHT40PLUS |
			REGDMN_MODE_11AC_VHT40MINUS | REGDMN_MODE_11AC_VHT80);
		break;
	case WMI_11A_CAPABILITY:
	case WMI_11NA_CAPABILITY:
	case WMI_11AC_CAPABILITY:
		modeSelect &= ~(REGDMN_MODE_11B | REGDMN_MODE_11G |
			REGDMN_MODE_108G | REGDMN_MODE_11NG_HT20 |
			REGDMN_MODE_11NG_HT40PLUS | REGDMN_MODE_11NG_HT40MINUS |
			REGDMN_MODE_11AC_VHT20_2G | REGDMN_MODE_11AC_VHT40_2G |
			REGDMN_MODE_11AC_VHT80_2G);
		break;
	}

	regdmn_get_ctl_info(regdmn, wma->reg_cap.wireless_modes, modeSelect);
	return;
}

/* function   : wma_rx_ready_event
 * Descriptin :
 * Args       :
 * Retruns    :
 */
v_VOID_t wma_rx_ready_event(WMA_HANDLE handle, void *cmd_param_info)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	WMI_READY_EVENTID_param_tlvs *param_buf = NULL;
	wmi_ready_event_fixed_param  *ev = NULL;

	WMA_LOGD("%s: Enter", __func__);

	param_buf = (WMI_READY_EVENTID_param_tlvs *) cmd_param_info;
	if (!(wma_handle && param_buf)) {
		WMA_LOGP("Invalid arguments");
		VOS_ASSERT(0);
		return;
	}

	WMA_LOGA("WMA <-- WMI_READY_EVENTID");

	ev = param_buf->fixed_param;
	/* Indicate to the waiting thread that the ready
	 * event was received */
	wma_handle->wmi_ready = TRUE;
	wma_handle->wlan_init_status = ev->status;

	/*
	 * We need to check the WMI versions and make sure both
	 * host and fw are compatible.
	 */
	if (!wmi_versions_are_compatible(&wma_handle->final_abi_vers,
					 &ev->fw_abi_vers)) {
		/*
		 * Error: Our host version and the given firmware version
		 * are incompatible.
		 */
		WMA_LOGE("%s: Error: Incompatible WMI version."
			"Host: %d,%d,0x%x 0x%x 0x%x 0x%x, FW: %d,%d,0x%x 0x%x 0x%x 0x%x",
			__func__,
			 WMI_VER_GET_MAJOR(
			 wma_handle->final_abi_vers.abi_version_0),
			 WMI_VER_GET_MINOR(
				 wma_handle->final_abi_vers.abi_version_0),
			 wma_handle->final_abi_vers.abi_version_ns_0,
			 wma_handle->final_abi_vers.abi_version_ns_1,
			 wma_handle->final_abi_vers.abi_version_ns_2,
			 wma_handle->final_abi_vers.abi_version_ns_3,
			 WMI_VER_GET_MAJOR(ev->fw_abi_vers.abi_version_0),
			 WMI_VER_GET_MINOR(ev->fw_abi_vers.abi_version_0),
			 ev->fw_abi_vers.abi_version_ns_0,
			 ev->fw_abi_vers.abi_version_ns_1,
			 ev->fw_abi_vers.abi_version_ns_2,
			 ev->fw_abi_vers.abi_version_ns_3);
		if (wma_handle->wlan_init_status == WLAN_INIT_STATUS_SUCCESS) {
			/* Failed this connection to FW */
			wma_handle->wlan_init_status =
						WLAN_INIT_STATUS_GEN_FAILED;
		}
	}
	vos_mem_copy(&wma_handle->final_abi_vers, &ev->fw_abi_vers,
		     sizeof(wmi_abi_version));
	vos_mem_copy(&wma_handle->target_abi_vers, &ev->fw_abi_vers,
		     sizeof(wmi_abi_version));

	/* copy the mac addr */
	WMI_MAC_ADDR_TO_CHAR_ARRAY (&ev->mac_addr, wma_handle->myaddr);
	WMI_MAC_ADDR_TO_CHAR_ARRAY (&ev->mac_addr, wma_handle->hwaddr);

#ifndef QCA_WIFI_ISOC
#ifdef QCA_WIFI_FTM
	if (vos_get_conparam() != VOS_FTM_MODE)
#endif
		wma_update_hdd_cfg(wma_handle);
#endif

	vos_event_set(&wma_handle->wma_ready_event);
	wma_set_regdomain(wma_handle->reg_cap.eeprom_rd);

	WMA_LOGD("Exit");
}

int wma_set_peer_param(void *wma_ctx, u_int8_t *peer_addr, u_int32_t param_id,
		       u_int32_t param_value, u_int32_t vdev_id)
{
	tp_wma_handle wma_handle = (tp_wma_handle) wma_ctx;
	wmi_peer_set_param_cmd_fixed_param *cmd;
	wmi_buf_t buf;
	int err;

	buf = wmi_buf_alloc(wma_handle->wmi_handle, sizeof(*cmd));
	if (!buf) {
		WMA_LOGE("Failed to allocate buffer to send set_param cmd");
		return -ENOMEM;
	}
	cmd = (wmi_peer_set_param_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
			WMITLV_TAG_STRUC_wmi_peer_set_param_cmd_fixed_param,
			WMITLV_GET_STRUCT_TLVLEN(
				wmi_peer_set_param_cmd_fixed_param));
	cmd->vdev_id = vdev_id;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(peer_addr, &cmd->peer_macaddr);
	cmd->param_id = param_id;
	cmd->param_value = param_value;
	err = wmi_unified_cmd_send(wma_handle->wmi_handle, buf,
				   sizeof(wmi_peer_set_param_cmd_fixed_param),
				   WMI_PEER_SET_PARAM_CMDID);
	if (err) {
		WMA_LOGE("Failed to send set_param cmd");
		adf_os_mem_free(buf);
		return -EIO;
	}

	return 0;
}

static void
wma_decap_to_8023 (adf_nbuf_t msdu, struct wma_decap_info_t *info)
{
	struct llc_snap_hdr_t *llc_hdr;
	u_int16_t ether_type;
	u_int16_t l2_hdr_space;
	struct ieee80211_qosframe_addr4 *wh;
	u_int8_t local_buf[ETHERNET_HDR_LEN];
	u_int8_t *buf;
	struct ethernet_hdr_t *ethr_hdr;

	buf = (u_int8_t *)adf_nbuf_data(msdu);
	llc_hdr = (struct llc_snap_hdr_t *)buf;
	ether_type = (llc_hdr->ethertype[0] << 8)|llc_hdr->ethertype[1];
	/* do llc remove if needed */
	l2_hdr_space = 0;
	if (IS_SNAP(llc_hdr)) {
		if (IS_BTEP(llc_hdr)) {
			/* remove llc*/
			l2_hdr_space += sizeof(struct llc_snap_hdr_t);
			llc_hdr = NULL;
		} else if (IS_RFC1042(llc_hdr)) {
			if (!(ether_type == ETHERTYPE_AARP ||
				ether_type == ETHERTYPE_IPX)) {
				/* remove llc*/
				l2_hdr_space += sizeof(struct llc_snap_hdr_t);
				llc_hdr = NULL;
			}
		}
	}
	if (l2_hdr_space > ETHERNET_HDR_LEN) {
		buf = adf_nbuf_pull_head(msdu, l2_hdr_space - ETHERNET_HDR_LEN);
	} else if (l2_hdr_space <  ETHERNET_HDR_LEN) {
		buf = adf_nbuf_push_head(msdu, ETHERNET_HDR_LEN - l2_hdr_space);
	}

	/* mpdu hdr should be present in info,re-create ethr_hdr based on mpdu hdr*/
	wh = (struct ieee80211_qosframe_addr4 *)info->hdr;
	ethr_hdr = (struct ethernet_hdr_t *)local_buf;
	switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) {
		case IEEE80211_FC1_DIR_NODS:
			adf_os_mem_copy(ethr_hdr->dest_addr, wh->i_addr1,
							ETHERNET_ADDR_LEN);
			adf_os_mem_copy(ethr_hdr->src_addr, wh->i_addr2,
							ETHERNET_ADDR_LEN);
			break;
		case IEEE80211_FC1_DIR_TODS:
			adf_os_mem_copy(ethr_hdr->dest_addr, wh->i_addr3,
							ETHERNET_ADDR_LEN);
			adf_os_mem_copy(ethr_hdr->src_addr, wh->i_addr2,
							ETHERNET_ADDR_LEN);
			break;
		case IEEE80211_FC1_DIR_FROMDS:
			adf_os_mem_copy(ethr_hdr->dest_addr, wh->i_addr1,
							ETHERNET_ADDR_LEN);
			adf_os_mem_copy(ethr_hdr->src_addr, wh->i_addr3,
							ETHERNET_ADDR_LEN);
			break;
		case IEEE80211_FC1_DIR_DSTODS:
			adf_os_mem_copy(ethr_hdr->dest_addr, wh->i_addr3,
							ETHERNET_ADDR_LEN);
			adf_os_mem_copy(ethr_hdr->src_addr, wh->i_addr4,
							ETHERNET_ADDR_LEN);
			break;
	}

	if (llc_hdr == NULL) {
		ethr_hdr->ethertype[0] = (ether_type >> 8) & 0xff;
		ethr_hdr->ethertype[1] = (ether_type) & 0xff;
	} else {
		u_int32_t pktlen = adf_nbuf_len(msdu) - sizeof(ethr_hdr->ethertype);
		ether_type = (u_int16_t)pktlen;
		ether_type = adf_nbuf_len(msdu) - sizeof(struct ethernet_hdr_t);
		ethr_hdr->ethertype[0] = (ether_type >> 8) & 0xff;
		ethr_hdr->ethertype[1] = (ether_type) & 0xff;
	}
	adf_os_mem_copy(buf, ethr_hdr, ETHERNET_HDR_LEN);
}

static int32_t
wma_ieee80211_hdrsize(const void *data)
{
	const struct ieee80211_frame *wh = (const struct ieee80211_frame *)data;
	int32_t size = sizeof(struct ieee80211_frame);

	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
		size += IEEE80211_ADDR_LEN;
	if (IEEE80211_QOS_HAS_SEQ(wh))
		size += sizeof(u_int16_t);
	return size;
}

/**
  * WDA_TxPacket - Sends Tx Frame to TxRx
  * This function sends the frame corresponding to the
  * given vdev id.
  * This is blocking call till the downloading of frame is complete.
  */
VOS_STATUS WDA_TxPacket(void *wma_context, void *tx_frame, u_int16_t frmLen,
			eFrameType frmType, eFrameTxDir txDir, u_int8_t tid,
			pWDATxRxCompFunc tx_frm_download_comp_cb, void *pData,
			pWDAAckFnTxComp tx_frm_ota_comp_cb, u_int8_t tx_flag,
			u_int8_t vdev_id)
{
	tp_wma_handle wma_handle = (tp_wma_handle)(wma_context);
	int32_t status;
	VOS_STATUS vos_status = VOS_STATUS_SUCCESS;
	int32_t is_high_latency;
	ol_txrx_vdev_handle txrx_vdev;
	enum frame_index tx_frm_index =
		GENERIC_NODOWNLD_NOACK_COMP_INDEX;
	tpSirMacFrameCtl pFc = (tpSirMacFrameCtl)(adf_nbuf_data(tx_frame));
	u_int8_t use_6mbps = 0;
	u_int8_t downld_comp_required = 0;

	/* Get the vdev handle from vdev id */
	txrx_vdev = wma_handle->interfaces[vdev_id].handle;

	if(!txrx_vdev) {
		WMA_LOGE("TxRx Vdev Handle is NULL");
		return VOS_STATUS_E_FAILURE;
	}

	if (frmType >= HAL_TXRX_FRM_MAX) {
		WMA_LOGE("Invalid Frame Type Fail to send Frame");
		return VOS_STATUS_E_FAILURE;
	}

	/*
	 * Currently only support to
	 * send 80211 Mgmt and 80211 Data are added.
	 */
	if (!((frmType == HAL_TXRX_FRM_802_11_MGMT) ||
		 (frmType == HAL_TXRX_FRM_802_11_DATA))) {
		WMA_LOGE("No Support to send other frames except 802.11 Mgmt/Data");
		return VOS_STATUS_E_FAILURE;
	}

	if (frmType == HAL_TXRX_FRM_802_11_DATA) {
		adf_nbuf_t ret;
		adf_nbuf_t skb = (adf_nbuf_t)tx_frame;
		ol_txrx_pdev_handle pdev =
		vos_get_context(VOS_MODULE_ID_TXRX, wma_handle->vos_context);
		struct wma_decap_info_t decap_info;
		struct ieee80211_frame *wh =
			(struct ieee80211_frame *)adf_nbuf_data(skb);

		/*
		 * 1) TxRx Module expects data input to be 802.3 format
		 * So Decapsulation has to be done.
		 * 2) Only one Outstanding Data pending for Ack is allowed
		 */
		if (tx_frm_ota_comp_cb) {
			if(wma_handle->umac_data_ota_ack_cb) {
				WMA_LOGE("Already one Data pending for Ack.Don't Allow");
				return VOS_STATUS_E_FAILURE;
			}
		} else {
			/*
			 * Data Frames are sent through TxRx Non Standard Data Path
			 * so Ack Complete Cb is must
			 */
			WMA_LOGE("No Ack Complete Cb. Don't Allow");
			return VOS_STATUS_E_FAILURE;
		}

		/* Take out 802.11 header from skb */
		decap_info.hdr_len = wma_ieee80211_hdrsize(wh);
		adf_os_mem_copy(decap_info.hdr, wh, decap_info.hdr_len);
		adf_nbuf_pull_head(skb, decap_info.hdr_len);

		/*  Decapsulate to 802.3 format */
		wma_decap_to_8023(skb, &decap_info);

		/* Zero out skb's context buffer for the driver to use */
		adf_os_mem_set(skb->cb, 0, sizeof(skb->cb));

		/* Do the DMA Mapping */
		adf_nbuf_map_single(pdev->osdev, skb, ADF_OS_DMA_TO_DEVICE);

		/* Terminate the (single-element) list of tx frames */
		skb->next = NULL;

		/* Store the Ack Complete Cb */
		wma_handle->umac_data_ota_ack_cb = tx_frm_ota_comp_cb;

		/* Send the Data frame to TxRx in Non Standard Path */
		ret = ol_tx_non_std(txrx_vdev, ol_tx_spec_no_free, skb);
		if (ret) {
			WMA_LOGE("TxRx Rejected. Fail to do Tx");
			adf_nbuf_unmap_single(pdev->osdev, skb, ADF_OS_DMA_TO_DEVICE);
			/* Call Download Cb so that umac can free the buffer */
			if (tx_frm_download_comp_cb)
				tx_frm_download_comp_cb(wma_handle->mac_context, tx_frame, 1);
			wma_handle->umac_data_ota_ack_cb = NULL;
			return VOS_STATUS_E_FAILURE;
		}

		/* Call Download Callback if passed */
		if (tx_frm_download_comp_cb)
			tx_frm_download_comp_cb(wma_handle->mac_context, tx_frame, 0);

		return VOS_STATUS_SUCCESS;
	}

	is_high_latency = wdi_out_cfg_is_high_latency(
				txrx_vdev->pdev->ctrl_pdev);

	downld_comp_required = tx_frm_download_comp_cb && is_high_latency;

	/* Fill the frame index to send */
	if(pFc->type == SIR_MAC_MGMT_FRAME) {
		if(tx_frm_ota_comp_cb) {
			if(downld_comp_required)
				tx_frm_index =
					GENERIC_DOWNLD_COMP_ACK_COMP_INDEX;
			else
				tx_frm_index =
					GENERIC_NODOWLOAD_ACK_COMP_INDEX;

			/* Store the Ack Cb sent by UMAC */
			if(pFc->subType < SIR_MAC_MGMT_RESERVED15) {
				wma_handle->umac_ota_ack_cb[pFc->subType] =
							tx_frm_ota_comp_cb;
			}
		} else {
			if(downld_comp_required)
				tx_frm_index =
					GENERIC_DOWNLD_COMP_NOACK_COMP_INDEX;
			else
				tx_frm_index =
					GENERIC_NODOWNLD_NOACK_COMP_INDEX;
		}
	}

	/*
	 * If Dowload Complete is required
	 * Wait for download complete
	 */
	if(downld_comp_required) {
		/* Store Tx Comp Cb */
		wma_handle->tx_frm_download_comp_cb = tx_frm_download_comp_cb;

		/* Reset the Tx Frame Complete Event */
		vos_status  = vos_event_reset(
				&wma_handle->tx_frm_download_comp_event);

		if (!VOS_IS_STATUS_SUCCESS(vos_status)) {
			WMA_LOGP("Event Reset failed tx comp event %x",vos_status);
			goto error;
		}
	}

	/* If the frame has to be sent at BD Rate2 inform TxRx */
	if(tx_flag & HAL_USE_BD_RATE2_FOR_MANAGEMENT_FRAME)
		use_6mbps = 1;

	/* Hand over the Tx Mgmt frame to TxRx */
	status = wdi_in_mgmt_send(txrx_vdev, tx_frame, tx_frm_index, use_6mbps);

	/*
	 * Failed to send Tx Mgmt Frame
	 * Return Failure so that umac can freeup the buf
	 */
	if (status) {
		WMA_LOGP("Failed to send Mgmt Frame");
		goto error;
	}

	if (!tx_frm_download_comp_cb)
		return VOS_STATUS_SUCCESS;

	/*
	 * Wait for Download Complete
	 * if required
	 */
	if (downld_comp_required) {
		/*
		 * Wait for Download Complete
		 * @ Integrated : Dxe Complete
		 * @ Discrete : Target Download Complete
		 */
		vos_status = vos_wait_single_event(
				&wma_handle->tx_frm_download_comp_event,
				WMA_TX_FRAME_COMPLETE_TIMEOUT);

		if (!VOS_IS_STATUS_SUCCESS(vos_status)) {
			WMA_LOGP("Wait Event failed txfrm_comp_event");
			/*
			 * @Integrated: Something Wrong with Dxe
			 *   TODO: Some Debug Code
			 * Here We need to trigger SSR since
			 * since system went into a bad state where
			 * we didn't get Download Complete for almost
			 * WMA_TX_FRAME_COMPLETE_TIMEOUT (1 sec)
			 */
		}
	} else {
		/*
		 * For Low Latency Devices
		 * Call the download complete
		 * callback once the frame is successfully
		 * given to txrx module
		 */
		tx_frm_download_comp_cb(wma_handle->mac_context, tx_frame, 0);
	}

	return VOS_STATUS_SUCCESS;

error:
	wma_handle->tx_frm_download_comp_cb = NULL;
	return VOS_STATUS_E_FAILURE;
}

/* function   :wma_setneedshutdown
 * Descriptin :
 * Args       :
 * Returns    :
 */
v_VOID_t wma_setneedshutdown(v_VOID_t *vos_ctx)
{
	tp_wma_handle wma_handle;

	WMA_LOGD("%s: Enter", __func__);

	wma_handle = vos_get_context(VOS_MODULE_ID_WDA, vos_ctx);

	if (NULL == wma_handle) {
		WMA_LOGP("Invalid arguments");
		VOS_ASSERT(0);
		return;
        }

	wma_handle->needShutdown  = TRUE;
	WMA_LOGD("%s: Exit", __func__);
}

/* function   : wma_rx_ready_event
 * Descriptin :
 * Args       :
 * Returns    :
 */
 v_BOOL_t wma_needshutdown(v_VOID_t *vos_ctx)
 {
	tp_wma_handle wma_handle;

	WMA_LOGD("%s: Enter", __func__);

	wma_handle = vos_get_context(VOS_MODULE_ID_WDA, vos_ctx);

	if (NULL == wma_handle) {
		WMA_LOGP("Invalid arguments");
		VOS_ASSERT(0);
		return 0;
        }

	WMA_LOGD("%s: Exit", __func__);
	return wma_handle->needShutdown;
}

VOS_STATUS wma_wait_for_ready_event(WMA_HANDLE handle)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	VOS_STATUS vos_status;

	/* wait until WMI_READY_EVENTID received from FW */
	vos_status = vos_wait_single_event( &(wma_handle->wma_ready_event),
			WMA_READY_EVENTID_TIMEOUT );

	if (VOS_STATUS_SUCCESS != vos_status) {
		WMA_LOGP("Timeout waiting for ready event from FW");
		vos_status = VOS_STATUS_E_FAILURE;
	}
	return vos_status;
}

#ifndef QCA_WIFI_ISOC
int wma_suspend_target(WMA_HANDLE handle, int disable_target_intr)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	wmi_pdev_suspend_cmd_fixed_param* cmd;
	wmi_buf_t wmibuf;
	u_int32_t len = sizeof(*cmd);

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE("WMA is closed. can not issue suspend cmd\n");
		return -EINVAL;
	}
	/*
	 * send the comand to Target to ignore the
	 * PCIE reset so as to ensure that Host and target
	 * states are in sync
	 */
	wmibuf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (wmibuf == NULL) {
		return -1;
	}

	cmd = (wmi_pdev_suspend_cmd_fixed_param *) wmi_buf_data(wmibuf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_pdev_suspend_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
			       wmi_pdev_suspend_cmd_fixed_param));
	if (disable_target_intr) {
		cmd->suspend_opt = WMI_PDEV_SUSPEND_AND_DISABLE_INTR;
	}
	else {
		cmd->suspend_opt = WMI_PDEV_SUSPEND;
	}

	if (wmi_unified_cmd_send(wma_handle->wmi_handle, wmibuf, len,
				    WMI_PDEV_SUSPEND_CMDID)) {
		adf_nbuf_free(wmibuf);
		return -1;
	}
	vos_event_reset(&wma_handle->target_suspend);
	return vos_wait_single_event(&wma_handle->target_suspend, 200);
}

void wma_target_suspend_complete(void *context)
{
	void *vos_context = vos_get_global_context(VOS_MODULE_ID_WDA, NULL);
	tp_wma_handle wma = vos_get_context(VOS_MODULE_ID_WDA, vos_context);

	vos_event_set(&wma->target_suspend);
}

int wma_resume_target(WMA_HANDLE handle)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	wmi_buf_t wmibuf;
	wmi_pdev_resume_cmd_fixed_param *cmd;
	int ret;

	wmibuf = wmi_buf_alloc(wma_handle->wmi_handle, sizeof(*cmd));
	if (wmibuf == NULL) {
		return  -1;
	}
	cmd = (wmi_pdev_resume_cmd_fixed_param *) wmi_buf_data(wmibuf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		   WMITLV_TAG_STRUC_wmi_pdev_resume_cmd_fixed_param,
		   WMITLV_GET_STRUCT_TLVLEN(wmi_pdev_resume_cmd_fixed_param));
	cmd->reserved0 = 0;
	ret = wmi_unified_cmd_send(wma_handle->wmi_handle, wmibuf, sizeof(*cmd),
				    WMI_PDEV_RESUME_CMDID);
	if(ret != EOK) {
		WMA_LOGE("Failed to send WMI_PDEV_RESUME_CMDID command");
		wmi_buf_free(wmibuf);
	}
	return ret;
}
#endif

void WDA_TimerTrafficStatsInd(tWDA_CbContext *pWDA)
{
}
/* TODO: Below is stub should be removed later */
void WDI_DS_ActivateTrafficStats(void)
{
}
/*
 * Function fills the rx packet meta info from the the vos packet
 */
VOS_STATUS WDA_DS_PeekRxPacketInfo(vos_pkt_t *pkt, v_PVOID_t *pkt_meta,
					v_BOOL_t  bSwap)
{
	/* Sanity Check */
	if(pkt == NULL) {
		WMA_LOGE("wma:Invalid parameter sent on wma_peek_rx_pkt_info");
		return VOS_STATUS_E_FAULT;
	}

	*pkt_meta = &(pkt->pkt_meta);

	return VOS_STATUS_SUCCESS;
}

/*
 * Function to lookup MAC address from vdev ID
 */
u_int8_t *wma_get_vdev_address_by_vdev_id(u_int8_t vdev_id)
{
	tp_wma_handle wma;

	wma = vos_get_context(VOS_MODULE_ID_WDA,
			      vos_get_global_context(VOS_MODULE_ID_WDA, NULL));
	if (!wma) {
		WMA_LOGE("%s: Invalid WMA handle", __func__);
		return NULL;
	}

	if (vdev_id >= wma->max_bssid) {
		WMA_LOGE("%s: Invalid vdev_id %u", __func__, vdev_id);
		return NULL;
	}

	return wma->interfaces[vdev_id].addr;
}

#ifndef QCA_WIFI_ISOC
/*
 * Function to get the beacon buffer from vdev ID
 * Note: The buffer returned must be freed explicitly by caller
 */
void *wma_get_beacon_buffer_by_vdev_id(u_int8_t vdev_id, u_int32_t *buffer_size)
{
	tp_wma_handle wma;
	struct beacon_info *beacon;
	u_int8_t *buf;
	u_int32_t buf_size;

	wma = vos_get_context(VOS_MODULE_ID_WDA,
			      vos_get_global_context(VOS_MODULE_ID_WDA, NULL));

	if (!wma) {
		WMA_LOGE("%s: Invalid WMA handle", __func__);
		return NULL;
	}

	if (vdev_id >= wma->max_bssid) {
		WMA_LOGE("%s: Invalid vdev_id %u", __func__, vdev_id);
		return NULL;
	}

	if (!wma_is_vdev_in_ap_mode(wma, vdev_id)) {
		WMA_LOGE("%s: vdevid %d is not in AP mode",
			 __func__, vdev_id);
		return NULL;
	}

	beacon = wma->interfaces[vdev_id].beacon;

	if (!beacon) {
		WMA_LOGE("%s: beacon invalid", __func__);
		return NULL;
	}

	adf_os_spin_lock_bh(&beacon->lock);

	buf_size = adf_nbuf_len(beacon->buf);
	buf = adf_os_mem_alloc(NULL, buf_size);

	if (!buf) {
		adf_os_spin_unlock_bh(&beacon->lock);
		WMA_LOGE("%s: alloc failed for beacon buf", __func__);
		return NULL;
	}

	adf_os_mem_copy(buf, adf_nbuf_data(beacon->buf), buf_size);

	adf_os_spin_unlock_bh(&beacon->lock);

	if (buffer_size)
		*buffer_size = buf_size;

	return buf;
}
#endif	/* QCA_WIFI_ISOC */

#if defined(QCA_WIFI_FTM) && !defined(QCA_WIFI_ISOC)
int wma_utf_rsp(tp_wma_handle wma_handle, u_int8_t **payload, u_int32_t *len)
{
	int ret = -1;
	u_int32_t payload_len;

	payload_len = wma_handle->utf_event_info.length;
	if (payload_len) {
		ret = 0;

		/*
		 * The first 4 bytes holds the payload size
		 * and the actual payload sits next to it
		 */
		*payload = (u_int8_t *)vos_mem_malloc((v_SIZE_t)payload_len
						      + sizeof(A_UINT32));
		*(A_UINT32*)&(*payload[0]) = wma_handle->utf_event_info.length;
		memcpy(*payload + sizeof(A_UINT32),
		       wma_handle->utf_event_info.data,
		       payload_len);
		wma_handle->utf_event_info.length = 0;
		*len = payload_len;
	}

	return ret;
}

static void wma_post_ftm_response(tp_wma_handle wma_handle)
{
	int ret;
	u_int8_t *payload;
	u_int32_t data_len;
	vos_msg_t msg = {0};
	VOS_STATUS status;

	ret = wma_utf_rsp(wma_handle, &payload, &data_len);

	if (ret) {
		return;
	}

	msg.type = SYS_MSG_ID_FTM_RSP;
	msg.bodyptr = payload;
	msg.bodyval = 0;
	msg.reserved = SYS_MSG_COOKIE;

	status = vos_mq_post_message(VOS_MQ_ID_SYS, &msg);

	if (status != VOS_STATUS_SUCCESS) {
		WMA_LOGE("failed to post ftm response to SYS");
		vos_mem_free(payload);
	}
}

static int
wma_process_utf_event(WMA_HANDLE handle,
		      u_int8_t *datap, u_int32_t dataplen)
{
	tp_wma_handle wma_handle = (tp_wma_handle)handle;
	SEG_HDR_INFO_STRUCT segHdrInfo;
	u_int8_t totalNumOfSegments,currentSeq;
	WMI_PDEV_UTF_EVENTID_param_tlvs *param_buf;
	u_int8_t *data;
	u_int32_t datalen;

	param_buf = (WMI_PDEV_UTF_EVENTID_param_tlvs *) datap;
	if (!param_buf) {
		WMA_LOGE("Get NULL point message from FW");
		return -EINVAL;
	}
	data = param_buf->data;
	datalen = param_buf->num_data;


	segHdrInfo = *(SEG_HDR_INFO_STRUCT *)&(data[0]);

	wma_handle->utf_event_info.currentSeq = (segHdrInfo.segmentInfo & 0xF);

	currentSeq = (segHdrInfo.segmentInfo & 0xF);
	totalNumOfSegments = (segHdrInfo.segmentInfo >> 4) & 0xF;

	datalen = datalen - sizeof(segHdrInfo);

	if (currentSeq == 0) {
		wma_handle->utf_event_info.expectedSeq = 0;
		wma_handle->utf_event_info.offset = 0;
	} else {
		if (wma_handle->utf_event_info.expectedSeq != currentSeq)
			WMA_LOGE("Mismatch in expecting seq expected"
				 " Seq %d got seq %d",
				 wma_handle->utf_event_info.expectedSeq,
				 currentSeq);
	}

	memcpy(&wma_handle->utf_event_info.data[wma_handle->utf_event_info.offset],
	       &data[sizeof(segHdrInfo)],
               datalen);
	wma_handle->utf_event_info.offset = wma_handle->utf_event_info.offset + datalen;
	wma_handle->utf_event_info.expectedSeq++;

	if (wma_handle->utf_event_info.expectedSeq == totalNumOfSegments) {
		if (wma_handle->utf_event_info.offset != segHdrInfo.len)
			WMA_LOGE("All segs received total len mismatch.."
				 " len %d total len %d",
				 wma_handle->utf_event_info.offset,
				 segHdrInfo.len);

		wma_handle->utf_event_info.length = wma_handle->utf_event_info.offset;
	}

	wma_post_ftm_response(wma_handle);

	return 0;
}

void wma_utf_detach(tp_wma_handle wma_handle)
{
    if (wma_handle->utf_event_info.data) {
        vos_mem_free(wma_handle->utf_event_info.data);
        wma_handle->utf_event_info.data = NULL;
        wma_handle->utf_event_info.length = 0;
        wmi_unified_unregister_event_handler(wma_handle->wmi_handle,
					     WMI_PDEV_UTF_EVENTID);
    }
}

void wma_utf_attach(tp_wma_handle wma_handle)
{
	int ret;

	wma_handle->utf_event_info.data = (unsigned char *)
					  vos_mem_malloc(MAX_UTF_EVENT_LENGTH);
	wma_handle->utf_event_info.length = 0;

	ret = wmi_unified_register_event_handler(wma_handle->wmi_handle,
						 WMI_PDEV_UTF_EVENTID,
						 wma_process_utf_event);

	if (ret)
		WMA_LOGP("Failed to register UTF event callback");
}

static int
wmi_unified_pdev_utf_cmd(wmi_unified_t wmi_handle, u_int8_t *utf_payload,
                         u_int16_t len)
{
	wmi_buf_t buf;
	u_int8_t *cmd;
	int ret = 0;
	static u_int8_t msgref = 1;
	u_int8_t segNumber = 0, segInfo, numSegments;
	u_int16_t chunk_len, total_bytes;
	u_int8_t *bufpos;
	SEG_HDR_INFO_STRUCT segHdrInfo;

	bufpos = utf_payload;
	total_bytes = len;
	ASSERT(total_bytes / MAX_WMI_UTF_LEN ==
	       (u_int8_t)(total_bytes / MAX_WMI_UTF_LEN));
	numSegments = (u_int8_t)(total_bytes / MAX_WMI_UTF_LEN);

	if (len - (numSegments * MAX_WMI_UTF_LEN))
		numSegments++;

	while (len) {
		if (len > MAX_WMI_UTF_LEN)
			chunk_len = MAX_WMI_UTF_LEN; /* MAX messsage */
		else
			chunk_len = len;

		buf = wmi_buf_alloc(wmi_handle,
				 (chunk_len + sizeof(segHdrInfo) +
				  WMI_TLV_HDR_SIZE));
		if (!buf) {
			WMA_LOGE("%s:wmi_buf_alloc failed", __func__);
			return -1;
		}

		cmd = (u_int8_t *)wmi_buf_data(buf);

		segHdrInfo.len = total_bytes;
		segHdrInfo.msgref =  msgref;
		segInfo = ((numSegments << 4 ) & 0xF0) | (segNumber & 0xF);
		segHdrInfo.segmentInfo = segInfo;

		WMA_LOGD("%s:segHdrInfo.len = %d, segHdrInfo.msgref = %d,"
			 " segHdrInfo.segmentInfo = %d",
			 __func__, segHdrInfo.len, segHdrInfo.msgref,
			 segHdrInfo.segmentInfo);

		WMA_LOGD("%s:total_bytes %d segNumber %d totalSegments %d"
			 "chunk len %d", __func__, total_bytes, segNumber,
			 numSegments, chunk_len);

		segNumber++;

		WMITLV_SET_HDR(cmd, WMITLV_TAG_ARRAY_BYTE,
			       (chunk_len + sizeof(segHdrInfo)));
		cmd += WMI_TLV_HDR_SIZE;
		memcpy(cmd, &segHdrInfo, sizeof(segHdrInfo)); /* 4 bytes */
		memcpy(&cmd[sizeof(segHdrInfo)], bufpos, chunk_len);

		ret = wmi_unified_cmd_send(wmi_handle, buf,
				(chunk_len + sizeof(segHdrInfo) +
				 WMI_TLV_HDR_SIZE),
				WMI_PDEV_UTF_CMDID);

		if (ret != EOK) {
			WMA_LOGE("Failed to send WMI_PDEV_UTF_CMDID command");
			wmi_buf_free(buf);
			break;
		}

		len -= chunk_len;
		bufpos += chunk_len;
	}

	msgref++;

	return ret;
}

int wma_utf_cmd(tp_wma_handle wma_handle, u_int8_t *data, u_int16_t len)
{
	wma_handle->utf_event_info.length = 0;
	return wmi_unified_pdev_utf_cmd(wma_handle->wmi_handle, data, len);
}

static VOS_STATUS
wma_process_ftm_command(tp_wma_handle wma_handle,
			struct ar6k_testmode_cmd_data *msg_buffer)
{
	u_int8_t *data = NULL;
	u_int16_t len = 0;
	int ret;

	if (!msg_buffer)
		return VOS_STATUS_E_INVAL;

	if (vos_get_conparam() != VOS_FTM_MODE) {
		WMA_LOGE("FTM command issued in non-FTM mode");
		vos_mem_free(msg_buffer->data);
		vos_mem_free(msg_buffer);
		return VOS_STATUS_E_NOSUPPORT;
	}

	data = msg_buffer->data;
	len = msg_buffer->len;

	ret = wma_utf_cmd(wma_handle, data, len);

	vos_mem_free(msg_buffer->data);
	vos_mem_free(msg_buffer);

	if (ret)
		return VOS_STATUS_E_FAILURE;

	return VOS_STATUS_SUCCESS;
}
#endif

/* Function to enable/disble Low Power Support(Pdev Specific) */
VOS_STATUS WDA_SetIdlePsConfig(void *wda_handle, tANI_U32 idle_ps)
{
	int32_t ret;
	tp_wma_handle wma = (tp_wma_handle)wda_handle;

	WMA_LOGD("WMA Set Idle Ps Config [1:set 0:clear] val %d", idle_ps);

	/* Set Idle Mode Power Save Config */
	ret = wmi_unified_pdev_set_param(wma->wmi_handle,
			WMI_PDEV_PARAM_IDLE_PS_CONFIG, idle_ps);
	if(ret) {
		WMA_LOGE("Fail to Set Idle Ps Config %d", idle_ps);
		return VOS_STATUS_E_FAILURE;
	}

	WMA_LOGD("Successfully Set Idle Ps Config %d", idle_ps);
	return VOS_STATUS_SUCCESS;
}

eHalStatus wma_set_htconfig(tANI_U8 vdev_id, tANI_U16 ht_capab, int value)
{
	void *vos_context = vos_get_global_context(VOS_MODULE_ID_WDA, NULL);
	tp_wma_handle wma = vos_get_context(VOS_MODULE_ID_WDA, vos_context);
	int ret = -EIO;

	switch (ht_capab) {
	case WNI_CFG_HT_CAP_INFO_ADVANCE_CODING:
	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
						WMI_VDEV_PARAM_LDPC, value);
	break;
	case WNI_CFG_HT_CAP_INFO_TX_STBC:
	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
						WMI_VDEV_PARAM_TX_STBC, value);
	break;
	case WNI_CFG_HT_CAP_INFO_RX_STBC:
	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
						WMI_VDEV_PARAM_RX_STBC, value);
	break;
	case WNI_CFG_HT_CAP_INFO_SHORT_GI_20MHZ:
	case WNI_CFG_HT_CAP_INFO_SHORT_GI_40MHZ:
	ret = wmi_unified_vdev_set_param_send(wma->wmi_handle, vdev_id,
						WMI_VDEV_PARAM_SGI, value);
	break;
	default:
	WMA_LOGE("%s:INVALID HT CONFIG", __func__);
	}

	return (ret)? eHAL_STATUS_FAILURE : eHAL_STATUS_SUCCESS;
}

eHalStatus WMA_SetRegDomain(void * clientCtxt, v_REGDOMAIN_t regId)
{
	if(VOS_STATUS_SUCCESS != vos_nv_setRegDomain(clientCtxt, regId))
		return eHAL_STATUS_INVALID_PARAMETER;

	return eHAL_STATUS_SUCCESS;
}

eHalStatus WMA_SetCountryCode(v_VOID_t *client_ctx, tANI_U8 *countrycode)
{
	int32_t regdmn;
	regdmn = regdmn_get_regdmn_for_country(countrycode);
	if (regdmn < 0)
		return eHAL_STATUS_FAILURE;

	wma_set_regdomain(regdmn);
	return eHAL_STATUS_SUCCESS;
}

tANI_U8 wma_getFwWlanFeatCaps(tANI_U8 featEnumValue)
{
       return gFwWlanFeatCaps & featEnumValue;
}

void wma_send_regdomain_info(u_int32_t reg_dmn, u_int16_t regdmn2G,
		u_int16_t regdmn5G, int8_t ctl2G, int8_t ctl5G)
{
	wmi_buf_t buf;
	wmi_pdev_set_regdomain_cmd_fixed_param *cmd;
	int32_t len = sizeof(*cmd);
	void *vos_context = vos_get_global_context(VOS_MODULE_ID_WDA, NULL);
	tp_wma_handle wma = vos_get_context(VOS_MODULE_ID_WDA, vos_context);

	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGP("%s : wmi_buf_alloc failed", __func__);
		return;
	}
	cmd = (wmi_pdev_set_regdomain_cmd_fixed_param *) wmi_buf_data(buf);
	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_wmi_pdev_set_regdomain_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
			wmi_pdev_set_regdomain_cmd_fixed_param));
	cmd->reg_domain = reg_dmn;
	cmd->reg_domain_2G = regdmn2G;
	cmd->reg_domain_5G = regdmn5G;
	cmd->conformance_test_limit_2G = ctl2G;
	cmd->conformance_test_limit_5G = ctl5G;

	if (wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				WMI_PDEV_SET_REGDOMAIN_CMDID)) {
		WMA_LOGP("Failed to send pdev set regdomain command");
		adf_nbuf_free(buf);
	}
	return;
}
