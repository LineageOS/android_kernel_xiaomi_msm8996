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

#include "vos_sched.h"
#include "wlan_qct_tl.h"
#include "wdi_in.h"
#include "ol_txrx_peer_find.h"
#include "tl_shim.h"
#include "wma.h"
#include "wmi_unified_api.h"
#include "vos_packet.h"
#include "vos_memory.h"
#include "adf_os_types.h"
#include "adf_nbuf.h"
#include "adf_os_mem.h"
#include "adf_os_lock.h"
#ifdef QCA_WIFI_ISOC
#include "htt_dxe_types.h"
#include "isoc_hw_desc.h"
#endif
#include "adf_nbuf.h"
#include "wma_api.h"

#define ENTER() VOS_TRACE(VOS_MODULE_ID_TL, VOS_TRACE_LEVEL_INFO, "Enter:%s", __func__)

#define TLSHIM_LOGD(args...) \
	VOS_TRACE( VOS_MODULE_ID_TL, VOS_TRACE_LEVEL_INFO, ## args)
#define TLSHIM_LOGW(args...) \
	VOS_TRACE( VOS_MODULE_ID_TL, VOS_TRACE_LEVEL_WARN, ## args)
#define TLSHIM_LOGE(args...) \
	VOS_TRACE( VOS_MODULE_ID_TL, VOS_TRACE_LEVEL_ERROR, ## args)
#define TLSHIM_LOGP(args...) \
	VOS_TRACE( VOS_MODULE_ID_TL, VOS_TRACE_LEVEL_FATAL, ## args)
/************************/
/*    Internal Func	*/
/************************/

#ifdef QCA_WIFI_ISOC
static void tlshim_mgmt_rx_dxe_handler(void *context, adf_nbuf_t buflist)
{
	adf_nbuf_t tmp_next, cur = buflist;
	isoc_rx_bd_t *rx_bd;
	vos_pkt_t *rx_packet;
	u_int8_t mpdu_header_offset = 0;
	struct txrx_tl_shim_ctx *tl_shim = (struct txrx_tl_shim_ctx *)context;
	void *vos_ctx = vos_get_global_context(VOS_MODULE_ID_TL, context);

	while(cur) {
		/* Store the next buf in the list */
		tmp_next = adf_nbuf_next(cur);

		/* Move to next nBuf in list */
		adf_nbuf_set_next(cur, NULL);

		/* Get the Rx Bd */
		rx_bd = (isoc_rx_bd_t *)adf_nbuf_data(cur);

		/* Get MPDU Offset in RxBd */
		mpdu_header_offset = rx_bd->mpdu_header_offset;

		/*
		 * Allocate memory for the Rx Packet
		 * that has to be delivered to UMAC
		 */
		rx_packet =
			(vos_pkt_t *)adf_os_mem_alloc(NULL, sizeof(vos_pkt_t));

		if(rx_packet == NULL) {
			TLSHIM_LOGE("Rx Packet Mem Alloc Failed");
			adf_nbuf_free(cur);
			goto next_nbuf;
		}

		/* Fill packet related Meta Info */
		rx_packet->pkt_meta.channel = rx_bd->rx_channel;
		rx_packet->pkt_meta.rssi = rx_bd->rssi0;
		rx_packet->pkt_meta.snr = (((rx_bd->phy_stats1) >> 24) & 0xff);
		rx_packet->pkt_meta.timestamp = rx_bd->rx_timestamp;

		rx_packet->pkt_meta.mpdu_hdr_len = rx_bd->mpdu_header_length;
		rx_packet->pkt_meta.mpdu_len = rx_bd->mpdu_length;
		rx_packet->pkt_meta.mpdu_data_len =
			rx_bd->mpdu_length - rx_bd->mpdu_header_length;

		/* set the length of the packet buffer */
		adf_nbuf_put_tail(cur,
			mpdu_header_offset + rx_bd->mpdu_length);

		/*
		 * Rx Bd is removed from adf_nbuf
		 * adf_nbuf is having only Rx Mgmt packet
		 */
		rx_packet->pkt_meta.mpdu_hdr_ptr =
				adf_nbuf_pull_head(cur,mpdu_header_offset);

		/* Store the MPDU Data Pointer in Rx Packet */
		rx_packet->pkt_meta.mpdu_data_ptr =
		rx_packet->pkt_meta.mpdu_hdr_ptr + rx_bd->mpdu_header_length;

		/*
		 * Rx Bd is removed from adf_nbuf data
		 * adf_nbuf data is having only Rx Mgmt packet
		 */
		rx_packet->pkt_buf = cur;

		/*
                 * Call the Callback registered by umac with wma
		 * for Rx Management Frames
		 */
		if(tl_shim->mgmt_rx)
			tl_shim->mgmt_rx(vos_ctx, rx_packet);
		else
			vos_pkt_return_packet(rx_packet);
next_nbuf:
		/* Move to next nBuf in the list */
		cur = tmp_next;
    }
}
#else
/*AR9888/AR6320  noise floor approx value*/
#define TLSHIM_TGT_NOISE_FLOOR_DBM (-96)

static int tlshim_mgmt_rx_wmi_handler(void *context, u_int8_t *data,
				       u_int32_t data_len)
{
	void *vos_ctx = vos_get_global_context(VOS_MODULE_ID_TL, NULL);
	struct txrx_tl_shim_ctx *tl_shim = vos_get_context(VOS_MODULE_ID_TL,
							   vos_ctx);
	WMI_MGMT_RX_EVENTID_param_tlvs *param_tlvs = NULL;
	wmi_mgmt_rx_hdr *hdr = NULL;

	vos_pkt_t *rx_pkt;
	adf_nbuf_t wbuf;
	struct ieee80211_frame *wh;

	param_tlvs = (WMI_MGMT_RX_EVENTID_param_tlvs *) data;
	if (!param_tlvs) {
		TLSHIM_LOGE("Get NULL point message from FW");
		return 0;
	}

	hdr = param_tlvs->hdr;
	if (hdr == NULL) {
		TLSHIM_LOGE("Rx event is NULL");
		return 0;
	}

	rx_pkt = vos_mem_malloc(sizeof(*rx_pkt));
	if (!rx_pkt) {
		TLSHIM_LOGE("Failed to allocate rx packet");
		return 0;
	}

	vos_mem_zero(rx_pkt, sizeof(*rx_pkt));

	/*
	 * Fill in meta information needed by pe/lim
	 * TODO: Try to maintain rx metainfo as part of skb->data.
	 */
	rx_pkt->pkt_meta.channel = hdr->channel;
	/*Get the absolute rssi value from the current rssi value
	 *the sinr value is hardcoded into 0 in the core stack*/
	rx_pkt->pkt_meta.rssi = hdr->snr + TLSHIM_TGT_NOISE_FLOOR_DBM;
	rx_pkt->pkt_meta.snr = hdr->snr;
	/*
	 * FIXME: Assigning the local timestamp as hw timestamp is not
	 * available. Need to see if pe/lim really uses this data.
	 */
	rx_pkt->pkt_meta.timestamp = (u_int32_t) jiffies;
	rx_pkt->pkt_meta.mpdu_hdr_len = sizeof(struct ieee80211_frame);
	rx_pkt->pkt_meta.mpdu_len = hdr->buf_len;
	rx_pkt->pkt_meta.mpdu_data_len = hdr->buf_len -
					 rx_pkt->pkt_meta.mpdu_hdr_len;

	/* Why not just use rx_event->hdr.buf_len? */
	wbuf = adf_nbuf_alloc(NULL,
			      roundup(hdr->buf_len, 4),
			      0, 4, FALSE);
	if (!wbuf) {
		TLSHIM_LOGE("Failed to allocate wbuf for mgmt rx");
		vos_mem_free(rx_pkt);
		return 0;
	}

	adf_nbuf_put_tail(wbuf, hdr->buf_len);
	adf_nbuf_set_protocol(wbuf, ETH_P_CONTROL);
	wh = (struct ieee80211_frame *) adf_nbuf_data(wbuf);

	rx_pkt->pkt_meta.mpdu_hdr_ptr = adf_nbuf_data(wbuf);
	rx_pkt->pkt_meta.mpdu_data_ptr = rx_pkt->pkt_meta.mpdu_hdr_ptr +
					  rx_pkt->pkt_meta.mpdu_hdr_len;
	rx_pkt->pkt_buf = wbuf;

#ifdef BIG_ENDIAN_HOST
	{
		/*
		 * for big endian host, copy engine byte_swap is enabled
		 * But the rx mgmt frame buffer content is in network byte order
		 * Need to byte swap the mgmt frame buffer content - so when
		 * copy engine does byte_swap - host gets buffer content in the
		 * correct byte order.
		 */
		int i;
		u_int32_t *destp, *srcp;
		destp = (u_int32_t *) wh;
		srcp =  (u_int32_t *) param_tlvs->bufp;
		for (i = 0;
		     i < (roundup(hdr->buf_len, sizeof(u_int32_t)) / 4);
		     i++) {
			*destp = cpu_to_le32(*srcp);
			destp++; srcp++;
		}
	}
#else
	adf_os_mem_copy(wh, param_tlvs->bufp, hdr->buf_len);
#endif

	if (!tl_shim->mgmt_rx) {
		TLSHIM_LOGE("Not registered for Mgmt rx, dropping the frame");
		vos_pkt_return_packet(rx_pkt);
		return 0;
	}

	return tl_shim->mgmt_rx(vos_ctx, rx_pkt);
}
#endif

static void tl_shim_flush_rx_frames(void *vos_ctx,
				    struct txrx_tl_shim_ctx *tl_shim,
				    u_int8_t sta_id, bool drop)
{
	struct tlshim_sta_info *sta_info = &tl_shim->sta_info[sta_id];
	struct tlshim_buf *cache_buf, *tmp;
	VOS_STATUS ret;

	if (test_and_set_bit(TLSHIM_FLUSH_CACHE_IN_PROGRESS, &sta_info->flags))
		return;

	adf_os_spin_lock_bh(&tl_shim->bufq_lock);
	list_for_each_entry_safe(cache_buf, tmp,
				 &sta_info->cached_bufq, list) {
		list_del(&cache_buf->list);
		adf_os_spin_unlock_bh(&tl_shim->bufq_lock);
		if (drop)
			adf_nbuf_free(cache_buf->buf);
		else {
			/* Flush the cached frames to HDD */
			ret = sta_info->data_rx(vos_ctx, cache_buf->buf,
						sta_id);
			if (ret != VOS_STATUS_SUCCESS)
				adf_nbuf_free(cache_buf->buf);
		}
		adf_os_mem_free(cache_buf);
		adf_os_spin_lock_bh(&tl_shim->bufq_lock);
	}
	adf_os_spin_unlock_bh(&tl_shim->bufq_lock);
	clear_bit(TLSHIM_FLUSH_CACHE_IN_PROGRESS, &sta_info->flags);
}

/*
 * Rx callback from txrx module for data reception.
 */
static void tlshim_data_rx_handler(void *context, u_int16_t staid,
				   adf_nbuf_t rx_buf_list)
{
	struct txrx_tl_shim_ctx *tl_shim;
	void *vos_ctx = vos_get_global_context(VOS_MODULE_ID_TL, context);
	struct tlshim_sta_info *sta_info;
	adf_nbuf_t buf, next_buf;

	if (staid >= WLAN_MAX_STA_COUNT) {
		TLSHIM_LOGE("Invalid sta id :%d", staid);
		goto drop_rx_buf;
	}

	tl_shim = (struct txrx_tl_shim_ctx *) context;
	sta_info = &tl_shim->sta_info[staid];

	/*
	 * If there is a data frame from peer before the peer is
	 * registered for data service, enqueue them on to pending queue
	 * which will be flushed to HDD once that station is registered.
	 */
	if (!sta_info->registered) {
		struct tlshim_buf *cache_buf;
		buf = rx_buf_list;
		while (buf) {
			next_buf = adf_nbuf_queue_next(buf);
			cache_buf = adf_os_mem_alloc(NULL, sizeof(*cache_buf));
			if (!cache_buf) {
				TLSHIM_LOGE("Failed to allocate buf to cache the rx frames");
				adf_nbuf_free(buf);
			} else {
				cache_buf->buf = buf;
				adf_os_spin_lock_bh(&tl_shim->bufq_lock);
				list_add_tail(&cache_buf->list,
					      &sta_info->cached_bufq);
				adf_os_spin_unlock_bh(&tl_shim->bufq_lock);
			}
			buf = next_buf;
		}
	} else if (sta_info->data_rx) { /* Send rx packet to HDD if there is no frame pending in cached_bufq */
		/* Suspend frames flush from timer */
		/*
		 * TODO: Need to see if acquiring/releasing lock even when
		 * there is no cached frames have any significant impact on
		 * performance.
		 */
		VOS_STATUS ret;
		adf_os_spin_lock_bh(&tl_shim->bufq_lock);
		sta_info->suspend_flush = 1;
		adf_os_spin_unlock_bh(&tl_shim->bufq_lock);

		/* Flush the cached frames to HDD before passing new rx frame */
		tl_shim_flush_rx_frames(vos_ctx, tl_shim, staid, 0);

		buf = rx_buf_list;
		while (buf) {
			next_buf = adf_nbuf_queue_next(buf);
			ret = sta_info->data_rx(vos_ctx, buf, staid);
			if (ret != VOS_STATUS_SUCCESS)
				adf_nbuf_free(buf);
			buf = next_buf;
		}
	} else /* This should not happen if sta_info->registered is true */
		goto drop_rx_buf;

	return;

drop_rx_buf:
	TLSHIM_LOGW("Dropping rx packets");
	buf = rx_buf_list;
	while (buf) {
		next_buf = adf_nbuf_queue_next(buf);
		adf_nbuf_free(buf);
		buf = next_buf;
	}
}

static void tl_shim_cache_flush_work(struct work_struct *work)
{
	struct txrx_tl_shim_ctx *tl_shim = container_of(work,
			struct txrx_tl_shim_ctx, cache_flush_work);
	void *vos_ctx = vos_get_global_context(VOS_MODULE_ID_TL, NULL);
	struct tlshim_sta_info *sta_info;
	u_int8_t i;

	for (i = 0; i < WLAN_MAX_STA_COUNT; i++) {
		sta_info = &tl_shim->sta_info[i];
		if (!sta_info->registered)
			continue;

		adf_os_spin_lock_bh(&tl_shim->bufq_lock);
		if (sta_info->suspend_flush) {
			adf_os_spin_unlock_bh(&tl_shim->bufq_lock);
			continue;
		}
		adf_os_spin_unlock_bh(&tl_shim->bufq_lock);

		tl_shim_flush_rx_frames(vos_ctx, tl_shim, i, 0);
	}
}

/*************************/
/*	TL APIs		 */
/*************************/

/*
 * TL API called from WMA to register a vdev for data service with
 * txrx. This API is called once vdev create succeeds.
 */
void WLANTL_RegisterVdev(void *vos_ctx, void *vdev)
{
	struct txrx_tl_shim_ctx *tl_shim;
	struct ol_txrx_osif_ops txrx_ops;
	struct ol_txrx_vdev_t *vdev_handle = (struct ol_txrx_vdev_t  *) vdev;

	tl_shim = vos_get_context(VOS_MODULE_ID_TL, vos_ctx);
	txrx_ops.rx.std = tlshim_data_rx_handler;
	wdi_in_osif_vdev_register(vdev_handle, tl_shim, &txrx_ops);
	/* TODO: Keep vdev specific tx callback, if needed */
	tl_shim->tx = txrx_ops.tx.std;
}

/*
 * TL API to transmit a frame given by HDD. Returns NULL
 * in case of success, skb pointer in case of failure.
 */
adf_nbuf_t WLANTL_SendSTA_DataFrame(void *vos_ctx, u_int8_t sta_id,
				    adf_nbuf_t skb)
{
	struct txrx_tl_shim_ctx *tl_shim = vos_get_context(VOS_MODULE_ID_TL,
							   vos_ctx);
	void *adf_ctx = vos_get_context(VOS_MODULE_ID_ADF, vos_ctx);
	adf_nbuf_t ret;
	struct ol_txrx_peer_t *peer;

	ENTER();

	if (vos_is_load_unload_in_progress(VOS_MODULE_ID_TL, NULL)) {
		TLSHIM_LOGP("%s: Driver load/unload in progress", __func__);
		return skb;
	}
	/*
	 * TODO: How sta_id is created and used for IBSS mode?.
	 */
	if (sta_id >= WLAN_MAX_STA_COUNT) {
		TLSHIM_LOGE("Invalid sta id for data tx");
		return skb;
	}

	if (!tl_shim->sta_info[sta_id].registered) {
		TLSHIM_LOGE("Staion is not yet registered for data service");
		return skb;
	}

	peer = ol_txrx_peer_find_by_local_id(
			((pVosContextType) vos_ctx)->pdev_txrx_ctx,
			sta_id);
	if (!peer) {
		TLSHIM_LOGE("Invalid peer");
		return skb;
	}

	/* Zero out skb's context buffer for the driver to use */
	adf_os_mem_set(skb->cb, 0, sizeof(skb->cb));

	adf_nbuf_map_single(adf_ctx, skb, ADF_OS_DMA_TO_DEVICE);

	/* Terminate the (single-element) list of tx frames */
	skb->next = NULL;
	ret = tl_shim->tx(peer->vdev, skb);
	if (ret) {
		TLSHIM_LOGW("Failed to tx");
		adf_nbuf_unmap_single(adf_ctx, ret, ADF_OS_DMA_TO_DEVICE);
		return ret;
	}

	return NULL;
}

VOS_STATUS WLANTL_ResumeDataTx(void *vos_ctx, u_int8_t *sta_id)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_SuspendDataTx(void *vos_ctx, u_int8_t *sta_id,
				WLANTL_SuspendCBType suspend_tx_cb)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_TxBAPFrm(void *vos_ctx, vos_pkt_t *buf,
			   WLANTL_MetaInfoType *meta_info,
			   WLANTL_TxCompCBType txcomp_cb)
{
	/* Not needed */
	return VOS_STATUS_SUCCESS;
}

void WLANTL_AssocFailed(u_int8_t sta_id)
{
	/* Not needed */
}

VOS_STATUS WLANTL_Finish_ULA(void (*cb) (void *cb_ctx), void *cb_ctx)
{
	/* Not needed */
	return VOS_STATUS_SUCCESS;
}

void WLANTLPrintPktsRcvdPerRssi(void *vos_ctx, u_int8_t sta_id, bool flush)
{
	/* TBD */
}

void WLANTLPrintPktsRcvdPerRateIdx(void *vos_ctx, u_int8_t sta_id, bool flush)
{
	/* TBD */
}

VOS_STATUS WLANTL_TxProcessMsg(void *vos_ctx, vos_msg_t *msg)
{
	/* Not needed */
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_McProcessMsg(void *vos_ctx, vos_msg_t *message)
{
	/* Not needed */
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_McFreeMsg(void *vos_ctx, vos_msg_t *message)
{
	/* Not needed */
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_TxFreeMsg(void *vos_ctx, vos_msg_t *message)
{
	/* Not needed */
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_RegisterBAPClient(void *vos_ctx,
				    WLANTL_BAPRxCBType bap_rx,
				    WLANTL_FlushOpCompCBType flush_cb)
{
	/* Not needed */
	return VOS_STATUS_SUCCESS;
}

/*
 * Txrx does weighted RR scheduling, set/get ac weights does not
 * apply here, this is no operation.
 */
VOS_STATUS WLANTL_SetACWeights(void *vos_ctx, u_int8_t *ac_weight)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_GetACWeights(void *vos_ctx, u_int8_t *ac_weight)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_GetSoftAPStatistics(void *vos_ctx,
				      WLANTL_TRANSFER_STA_TYPE *stats_sum,
				      v_BOOL_t reset)
{
	/* TBD */
	return VOS_STATUS_SUCCESS;
}

/*
 * Return txrx stats for a given sta_id
 */
VOS_STATUS WLANTL_GetStatistics(void *vos_ctx,
				WLANTL_TRANSFER_STA_TYPE *stats_buf,
				u_int8_t sta_id)
{
	/*
	 * TODO: Txrx to be modified to maintain per peer stats which
	 * TL shim can return whenever requested.
	 */
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_DeregRSSIIndicationCB(void *adapter, v_S7_t rssi,
					u_int8_t trig_evt,
					WLANTL_RSSICrossThresholdCBType func,
					VOS_MODULE_ID mod_id)
{
	/* TBD */
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_RegRSSIIndicationCB(void *adapter, v_S7_t rssi,
				      u_int8_t trig_evt,
				      WLANTL_RSSICrossThresholdCBType func,
				      VOS_MODULE_ID mod_id, void *usr_ctx)
{
	/* TBD */
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_EnableUAPSDForAC(void *vos_ctx, u_int8_t sta_id,
				   WLANTL_ACEnumType ac, u_int8_t tid,
				   u_int8_t pri, v_U32_t srvc_int,
				   v_U32_t sus_int, WLANTL_TSDirType dir,
				   v_U32_t sessionId)
{
	tp_wma_handle wma_handle;
	t_wma_trigger_uapsd_params uapsd_params;

	ENTER();

	wma_handle = vos_get_context(VOS_MODULE_ID_WDA, vos_ctx);

	uapsd_params.wmm_ac = ac;
	uapsd_params.user_priority = pri;
	uapsd_params.service_interval = srvc_int;

	/*
	 * Since Delayed Interval is not available
	 * use suspend interval for delayed interval
	 * for now.
	 * TODO: Need to pass Delayed Interval as well
	 */
	uapsd_params.delay_interval = sus_int;
	uapsd_params.suspend_interval = sus_int;

	if(VOS_STATUS_SUCCESS !=
		wma_trigger_uapsd_params(wma_handle, sessionId, &uapsd_params))
	{
		TLSHIM_LOGE("Failed to Trigger Uapsd params for sessionId %d",
					sessionId);
		return VOS_STATUS_E_FAILURE;
	}
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_DisableUAPSDForAC(void *vos_ctx, u_int8_t sta_id,
				    WLANTL_ACEnumType ac, v_U32_t sessionId)
{
	/* TBD */
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_DeRegisterMgmtFrmClient(void *vos_ctx)
{
	struct txrx_tl_shim_ctx *tl_shim;
#ifdef QCA_WIFI_ISOC
	ol_txrx_pdev_handle txrx_pdev;
	struct htt_dxe_pdev_t *htt_dxe_pdev;
#else
	tp_wma_handle wma_handle;
#endif

#ifdef QCA_WIFI_FTM
	if (vos_get_conparam() == VOS_FTM_MODE)
		return VOS_STATUS_SUCCESS;
#endif

	tl_shim = vos_get_context(VOS_MODULE_ID_TL,
				  vos_ctx);

#ifdef QCA_WIFI_ISOC
	txrx_pdev = vos_get_context(VOS_MODULE_ID_TXRX,
				    vos_ctx);
	htt_dxe_pdev = txrx_pdev->htt_pdev;

	if (dmux_dxe_register_callback_rx_mgmt(htt_dxe_pdev->dmux_dxe_pdev,
					       NULL, NULL) != 0) {
		TLSHIM_LOGE("Failed to Unregister rx mgmt handler with dxe");
		return VOS_STATUS_E_FAILURE;
	}
#else
	wma_handle = vos_get_context(VOS_MODULE_ID_WDA, vos_ctx);

	if (wmi_unified_unregister_event_handler(wma_handle->wmi_handle,
						 WMI_MGMT_RX_EVENTID) != 0) {
		TLSHIM_LOGE("Failed to Unregister rx mgmt handler with wmi");
		return VOS_STATUS_E_FAILURE;
	}
#endif
	tl_shim->mgmt_rx = NULL;
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_RegisterMgmtFrmClient(void *vos_ctx,
					WLANTL_MgmtFrmRxCBType mgmt_frm_rx)
{
	struct txrx_tl_shim_ctx *tl_shim = vos_get_context(VOS_MODULE_ID_TL,
							   vos_ctx);

#ifdef QCA_WIFI_ISOC
	 ol_txrx_pdev_handle txrx_pdev = vos_get_context(VOS_MODULE_ID_TXRX,
							 vos_ctx);
	 struct htt_dxe_pdev_t *htt_dxe_pdev = txrx_pdev->htt_pdev;

	if (dmux_dxe_register_callback_rx_mgmt(htt_dxe_pdev->dmux_dxe_pdev,
					       tlshim_mgmt_rx_dxe_handler,
					       tl_shim) != 0) {
		TLSHIM_LOGE("Failed to register rx mgmt handler with dxe");
		return VOS_STATUS_E_FAILURE;
	}
#else
	tp_wma_handle wma_handle = vos_get_context(VOS_MODULE_ID_WDA, vos_ctx);

	if (wmi_unified_register_event_handler(wma_handle->wmi_handle,
					       WMI_MGMT_RX_EVENTID,
					       tlshim_mgmt_rx_wmi_handler)
					       != 0) {
		TLSHIM_LOGE("Failed to register rx mgmt handler with wmi");
		return VOS_STATUS_E_FAILURE;
	}
#endif
	tl_shim->mgmt_rx = mgmt_frm_rx;

	return VOS_STATUS_SUCCESS;
}

/*
 * Return the data rssi for the given peer.
 */
VOS_STATUS WLANTL_GetRssi(void *vos_ctx, u_int8_t sta_id, v_S7_t *rssi)
{
	/* TBD */
	return VOS_STATUS_SUCCESS;
}

/*
 * HDD will directly call tx function with the skb for transmission.
 * Txrx is reponsible to enqueue the packet and schedule it for Hight
 * Latency devices, so this API is not used for CLD.
 */
VOS_STATUS WLANTL_STAPktPending(void *vos_ctx, u_int8_t sta_id,
				WLANTL_ACEnumType ac)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_UpdateSTABssIdforIBSS(void *vos_ctx, u_int8_t sta_id,
					u_int8_t *bssid)
{
	/* TBD */
	return VOS_STATUS_SUCCESS;
}

/*
 * In CLD, sec_type along with the peer_state will be used to
 * make sure EAPOL frame after PTK is installed is getting encrypted.
 * So this API is no-op.
 */
VOS_STATUS WLANTL_STAPtkInstalled(void *vos_ctx, u_int8_t sta_id)
{
	return VOS_STATUS_SUCCESS;
}

/*
 * HDD calls this to notify the state change in client.
 * Txrx will do frame filtering.
 */
VOS_STATUS WLANTL_ChangeSTAState(void *vos_ctx, u_int8_t sta_id,
				 WLANTL_STAStateType sta_state)
{
	struct ol_txrx_peer_t *peer;
	enum ol_txrx_peer_state txrx_state = ol_txrx_peer_state_invalid;
	int err;

	ENTER();
	if (sta_id >= WLAN_MAX_STA_COUNT) {
		TLSHIM_LOGE("Invalid sta id :%d", sta_id);
		return VOS_STATUS_E_INVAL;
	}
	peer = ol_txrx_peer_find_by_local_id(
			((pVosContextType) vos_ctx)->pdev_txrx_ctx,
			sta_id);
	if (!peer)
		return VOS_STATUS_E_FAULT;

	if (sta_state == WLANTL_STA_CONNECTED)
		txrx_state = ol_txrx_peer_state_conn;
	else if (sta_state == WLANTL_STA_AUTHENTICATED)
		txrx_state = ol_txrx_peer_state_auth;

	ol_txrx_peer_state_update(peer->vdev->pdev,
				  (u_int8_t *) peer->mac_addr.raw,
				  txrx_state);

	if (txrx_state == ol_txrx_peer_state_auth) {
		err = wma_set_peer_param(
				((pVosContextType) vos_ctx)->pWDAContext,
				peer->mac_addr.raw, WMI_PEER_AUTHORIZE,
				1, peer->vdev->vdev_id);
		if (err) {
			TLSHIM_LOGE("Failed to set the peer state to authorized");
			return VOS_STATUS_E_FAULT;
		}
	}
	return VOS_STATUS_SUCCESS;
}

/*
 * Clear the station information.
 */
VOS_STATUS WLANTL_ClearSTAClient(void *vos_ctx, u_int8_t sta_id)
{
	struct txrx_tl_shim_ctx *tl_shim;

	if (sta_id >= WLAN_MAX_STA_COUNT) {
		TLSHIM_LOGE("Invalid sta id :%d", sta_id);
		return VOS_STATUS_E_INVAL;
	}

	tl_shim = vos_get_context(VOS_MODULE_ID_TL, vos_ctx);
	tl_shim->sta_info[sta_id].registered = 0;

	/* Purge the cached rx frame queue */
	tl_shim_flush_rx_frames(vos_ctx, tl_shim, sta_id, 1);
	adf_os_spin_lock_bh(&tl_shim->bufq_lock);
	tl_shim->sta_info[sta_id].suspend_flush = 0;
	adf_os_spin_unlock_bh(&tl_shim->bufq_lock);

	tl_shim->sta_info[sta_id].data_rx = NULL;

	return VOS_STATUS_SUCCESS;
}

/*
 * Register a station for data service. This API gives flexibility
 * to register different callbacks for different client though it is
 * needed to register different callbacks for every vdev. Only rxcb
 * is used.
 */
VOS_STATUS WLANTL_RegisterSTAClient(void *vos_ctx,
				    WLANTL_STARxCBType rxcb,
				    WLANTL_TxCompCBType tx_comp,
				    WLANTL_STAFetchPktCBType txpkt_fetch,
				    WLAN_STADescType *sta_desc, v_S7_t rssi)
{
	struct txrx_tl_shim_ctx *tl_shim;
	struct ol_txrx_peer_t *peer;
	ol_txrx_peer_update_param_t param;

	ENTER();
	if (sta_desc->ucSTAId >= WLAN_MAX_STA_COUNT) {
		TLSHIM_LOGE("Invalid sta id :%d", sta_desc->ucSTAId);
		return VOS_STATUS_E_INVAL;
	}
	peer = ol_txrx_peer_find_by_local_id(
			((pVosContextType) vos_ctx)->pdev_txrx_ctx,
			sta_desc->ucSTAId);
	if (!peer)
		return VOS_STATUS_E_FAULT;

	tl_shim = vos_get_context(VOS_MODULE_ID_TL, vos_ctx);
	tl_shim->sta_info[sta_desc->ucSTAId].data_rx = rxcb;
	tl_shim->sta_info[sta_desc->ucSTAId].registered = true;
	param.qos_capable =  sta_desc->ucQosEnabled;
	wdi_in_peer_update(peer->vdev, peer->mac_addr.raw, &param,
			   ol_txrx_peer_update_qos_capable);
	if (sta_desc->ucIsWapiSta) {
		/* param.sec_type = ol_sec_type_wapi; */
		/*
		 * TODO: Peer update also updates the other security types
		 * but HDD will not pass this information.

		wdi_in_peer_update(peer->vdev, peer->mac_addr.raw, &param,
				   ol_txrx_peer_update_peer_security);
		 */
	}

	/* Schedule a worker to flush cached rx frames */
	schedule_work(&tl_shim->cache_flush_work);

	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_Stop(void *vos_ctx)
{
	/* Nothing to do really */
	return VOS_STATUS_SUCCESS;
}

/*
 * Make txrx module ready
 */
VOS_STATUS WLANTL_Start(void *vos_ctx)
{
	ENTER();
	if (wdi_in_pdev_attach_target(((pVosContextType)
				      vos_ctx)->pdev_txrx_ctx))
		return VOS_STATUS_E_FAULT;
	return VOS_STATUS_SUCCESS;
}

/*
 * Deinit txrx module
 */
VOS_STATUS WLANTL_Close(void *vos_ctx)
{
	struct txrx_tl_shim_ctx *tl_shim;

	ENTER();
	tl_shim = vos_get_context(VOS_MODULE_ID_TL, vos_ctx);
	wdi_in_pdev_detach(((pVosContextType) vos_ctx)->pdev_txrx_ctx, 1);
	vos_free_context(vos_ctx, VOS_MODULE_ID_TL, tl_shim);
	return VOS_STATUS_SUCCESS;
}

/*
 * Allocate and Initialize transport layer (txrx)
 */
VOS_STATUS WLANTL_Open(void *vos_ctx, WLANTL_ConfigInfoType *tl_cfg)
{
	struct txrx_tl_shim_ctx *tl_shim;
	VOS_STATUS status;
	u_int8_t i;

	ENTER();
	status = vos_alloc_context(vos_ctx, VOS_MODULE_ID_TL,
				   (void *) &tl_shim, sizeof(*tl_shim));
	if (status != VOS_STATUS_SUCCESS)
		return status;

	((pVosContextType) vos_ctx)->pdev_txrx_ctx =
				wdi_in_pdev_attach(
					((pVosContextType) vos_ctx)->cfg_ctx,
					((pVosContextType) vos_ctx)->htc_ctx,
					((pVosContextType) vos_ctx)->adf_ctx);
	if (!((pVosContextType) vos_ctx)->pdev_txrx_ctx) {
		TLSHIM_LOGE("Failed to allocate memory for pdev txrx handle");
		vos_free_context(vos_ctx, VOS_MODULE_ID_TL, tl_shim);
		return VOS_STATUS_E_NOMEM;
	}

	adf_os_spinlock_init(&tl_shim->bufq_lock);

	for (i = 0; i < WLAN_MAX_STA_COUNT; i++) {
		tl_shim->sta_info[i].suspend_flush = 0;
		tl_shim->sta_info[i].flags = 0;
		INIT_LIST_HEAD(&tl_shim->sta_info[i].cached_bufq);
	}

	INIT_WORK(&tl_shim->cache_flush_work, tl_shim_cache_flush_work);

	/*
	 * TODO: Allocate memory for tx callback for maximum supported
	 * vdevs to maintain tx callbacks per vdev.
	 */

	return status;
}

/*
 * Funtion to retrieve BSSID for peer sta.
 */
VOS_STATUS tl_shim_get_vdevid(struct ol_txrx_peer_t *peer, u_int8_t *vdev_id)
{
	if(!peer) {
		TLSHIM_LOGE("peer argument is null!!");
		return VOS_STATUS_E_FAILURE;
	}

	*vdev_id = peer->vdev->vdev_id;
	return VOS_STATUS_SUCCESS;
}
