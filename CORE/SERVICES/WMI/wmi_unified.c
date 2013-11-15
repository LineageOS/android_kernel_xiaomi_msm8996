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

/*
 * Host WMI unified implementation
 */
#include "athdefs.h"
#include "osapi_linux.h"
#include "a_types.h"
#include "a_debug.h"
#include "ol_defines.h"
#include "htc_api.h"
#include "htc_api.h"
#include "dbglog_host.h"
#include "wmi.h"
#include "wmi_unified_priv.h"
#include "wma_api.h"

#define WMI_MIN_HEAD_ROOM 64

static void __wmi_control_rx(struct wmi_unified *wmi_handle, wmi_buf_t evt_buf);
/* WMI buffer APIs */

wmi_buf_t
wmi_buf_alloc(wmi_unified_t wmi_handle, u_int16_t len)
{
	wmi_buf_t wmi_buf;

	wmi_buf = adf_nbuf_alloc(NULL, roundup(len + WMI_MIN_HEAD_ROOM, 4),
				 WMI_MIN_HEAD_ROOM, 4, FALSE);
	if (!wmi_buf)
		return NULL;

	/* Clear the wmi buffer */
	OS_MEMZERO(adf_nbuf_data(wmi_buf), len);

	/*
	 * Set the length of the buffer to match the allocation size.
	 */
	adf_nbuf_set_pktlen(wmi_buf, len);
	return wmi_buf;
}

/* WMI command API */
int wmi_unified_cmd_send(wmi_unified_t wmi_handle, wmi_buf_t buf, int len,
			 WMI_CMD_ID cmd_id)
{
	HTC_PACKET *pkt;
	A_STATUS status;

	/* Do sanity check on the TLV parameter structure. Can be #ifdef DEBUG if desired */
	{
		void *buf_ptr = (void *) adf_nbuf_data(buf);
#if 0
		if (wmitlv_check_command_tlv_params(NULL, buf_ptr, len, cmd_id) != 0)
#else
		/* TODO: Once all the TLV's are converted use #if 0 condition checking not equal to zero */
		if (wmitlv_check_command_tlv_params(NULL, buf_ptr, len, cmd_id) < 0)
#endif
		{
			adf_os_print("\nERROR: %s: Invalid WMI Parameter Buffer for Cmd:%d\n",
				     __func__, cmd_id);
			return -1;
		}
	}

	if (adf_nbuf_push_head(buf, sizeof(WMI_CMD_HDR)) == NULL) {
		pr_err("%s, Failed to send cmd %x, no memory\n",
		       __func__, cmd_id);
		return -ENOMEM;
	}

	WMI_SET_FIELD(adf_nbuf_data(buf), WMI_CMD_HDR, COMMANDID, cmd_id);

	adf_os_atomic_inc(&wmi_handle->pending_cmds);
	if (adf_os_atomic_read(&wmi_handle->pending_cmds) >= WMI_MAX_CMDS) {
		adf_os_atomic_dec(&wmi_handle->pending_cmds);
		pr_err("%s, too many pending commands\n", __func__);
		return -EBUSY;
	}

	pkt = adf_os_mem_alloc(NULL, sizeof(*pkt));
	if (!pkt) {
		pr_err("%s, Failed to alloc htc packet %x, no memory\n",
		       __func__, cmd_id);
		return -ENOMEM;
	}

	SET_HTC_PACKET_INFO_TX(pkt,
			NULL,
			adf_nbuf_data(buf),
			len + sizeof(WMI_CMD_HDR),
			/* htt_host_data_dl_len(buf)+20 */
			wmi_handle->wmi_endpoint_id,
			0/*htc_tag*/);

	SET_HTC_PACKET_NET_BUF_CONTEXT(pkt, buf);

	status = HTCSendPkt(wmi_handle->htc_handle, pkt);

	return ((status == A_OK) ? EOK : -1);
}


/* WMI Event handler register API */
int wmi_unified_get_event_handler_ix(wmi_unified_t wmi_handle,
                                       WMI_EVT_ID event_id)
{
    u_int32_t idx=0;
    for (idx=0; idx<wmi_handle->max_event_idx; ++idx) {
        if (wmi_handle->event_id[idx] == event_id &&
            wmi_handle->event_handler[idx] != NULL ) {
           return idx;
        }
    }
    return  -1;
}

int wmi_unified_register_event_handler(wmi_unified_t wmi_handle,
                                       WMI_EVT_ID event_id,
				       wmi_unified_event_handler handler_func)
{
	u_int32_t idx=0;

    if ( wmi_unified_get_event_handler_ix( wmi_handle, event_id) != -1) {
	printk("%s : event handler already registered 0x%x \n",
		__func__, event_id);
        return -1;
    }
    if ( wmi_handle->max_event_idx == WMI_UNIFIED_MAX_EVENT ) {
	printk("%s : no more event handlers 0x%x \n",
                __func__, event_id);
        return -1;
    }
    idx=wmi_handle->max_event_idx;
    wmi_handle->event_handler[idx] = handler_func;
    wmi_handle->event_id[idx] = event_id;
    wmi_handle->max_event_idx++;
    return 0;
}

int wmi_unified_unregister_event_handler(wmi_unified_t wmi_handle,
                                       WMI_EVT_ID event_id)
{
    u_int32_t idx=0;
    if ( (idx = wmi_unified_get_event_handler_ix( wmi_handle, event_id)) == -1) {
        printk("%s : event handler is not registered: event id 0x%x \n",
                __func__, event_id);
        return -1;
    }
    wmi_handle->event_handler[idx] = NULL;
    wmi_handle->event_id[idx] = 0;
    --wmi_handle->max_event_idx;
    wmi_handle->event_handler[idx] = wmi_handle->event_handler[wmi_handle->max_event_idx];
    wmi_handle->event_id[idx]  = wmi_handle->event_id[wmi_handle->max_event_idx] ;
    return 0;
}

static int wmi_unified_event_rx(struct wmi_unified *wmi_handle,
				wmi_buf_t evt_buf)
{
	u_int32_t id;
	u_int8_t *event;
	u_int16_t len;
	int status = -1;
	u_int32_t idx = 0;

	ASSERT(evt_buf != NULL);

	id = WMI_GET_FIELD(adf_nbuf_data(evt_buf), WMI_CMD_HDR, COMMANDID);

	if (adf_nbuf_pull_head(evt_buf, sizeof(WMI_CMD_HDR)) == NULL)
		goto end;

	idx = wmi_unified_get_event_handler_ix(wmi_handle, id);
	if (idx == -1) {
		pr_err("%s : event handler is not registered: event id: 0x%x\n",
		       __func__, id);
		goto end;
	}

	event = adf_nbuf_data(evt_buf);
	len = adf_nbuf_len(evt_buf);

	/* Call the WMI registered event handler */
	status = wmi_handle->event_handler[idx](wmi_handle->scn_handle,
						event, len);

end:
	adf_nbuf_free(evt_buf);
	return status;
}

/*
 * Temporarily added to support older WMI events. We should move all events to unified
 * when the target is ready to support it.
 */
void wmi_control_rx(void *ctx, HTC_PACKET *htc_packet)
{
	struct wmi_unified *wmi_handle = (struct wmi_unified *)ctx;
	wmi_buf_t evt_buf;

	evt_buf = (wmi_buf_t) htc_packet->pPktContext;

#ifdef QCA_WIFI_ISOC
	__wmi_control_rx(wmi_handle, evt_buf);
#else
	adf_os_spin_lock_bh(&wmi_handle->eventq_lock);
	adf_nbuf_queue_add(&wmi_handle->event_queue, evt_buf);
	adf_os_spin_unlock_bh(&wmi_handle->eventq_lock);

	schedule_work(&wmi_handle->rx_event_work);
#endif
}

void __wmi_control_rx(struct wmi_unified *wmi_handle, wmi_buf_t evt_buf)
{
	u_int32_t id;
	u_int8_t *data;
	u_int32_t len;
	void *wmi_cmd_struct_ptr = NULL;
	int tlv_ok_status = 0;

	id = WMI_GET_FIELD(adf_nbuf_data(evt_buf), WMI_CMD_HDR, COMMANDID);

	if (adf_nbuf_pull_head(evt_buf, sizeof(WMI_CMD_HDR)) == NULL)
		goto end;

	data = adf_nbuf_data(evt_buf);
	len = adf_nbuf_len(evt_buf);

	/* Validate and pad(if necessary) the TLVs */
	tlv_ok_status = wmitlv_check_and_pad_event_tlvs(wmi_handle->scn_handle,
							data, len, id,
							&wmi_cmd_struct_ptr);
	if (tlv_ok_status != 0) {
		if (tlv_ok_status == 1) {
			pr_err("%s No TLV definition for command %d\n",
			       __func__, id);
			wmi_cmd_struct_ptr = data;
		} else {
			pr_err("%s: Error: id=0x%d, wmitlv_check_and_pad_tlvs ret=%d\n",
				__func__, id, tlv_ok_status);
			goto end;
		}
	}

	if (id >= WMI_EVT_GRP_START_ID(WMI_GRP_START)) {
		u_int32_t idx = 0;

		idx = wmi_unified_get_event_handler_ix(wmi_handle, id) ;
		if (idx == -1) {
			pr_err("%s : event handler is not registered: event id 0x%x\n",
			       __func__, id);
			goto end;
		}

		/* Call the WMI registered event handler */
		wmi_handle->event_handler[idx](wmi_handle->scn_handle,
					       wmi_cmd_struct_ptr, len);
		goto end;
	}

	switch (id) {
	default:
		pr_info("%s: Unhandled WMI event %d\n", __func__, id);
		break;
	case WMI_SERVICE_READY_EVENTID:
		pr_info("%s: WMI UNIFIED SERVICE READY event\n", __func__);
		wma_rx_service_ready_event(wmi_handle->scn_handle,
					   wmi_cmd_struct_ptr);
		break;
	case WMI_READY_EVENTID:
		pr_info("%s:  WMI UNIFIED READY event\n", __func__);
		wma_rx_ready_event(wmi_handle->scn_handle, wmi_cmd_struct_ptr);
		break;
	}
end:
	wmitlv_free_allocated_event_tlvs(id, &wmi_cmd_struct_ptr);
	adf_nbuf_free(evt_buf);
}

#ifndef QCA_WIFI_ISOC
void wmi_rx_event_work(struct work_struct *work)
{
	struct wmi_unified *wmi = container_of(work, struct wmi_unified,
					       rx_event_work);
	wmi_buf_t buf;

	adf_os_spin_lock_bh(&wmi->eventq_lock);
	buf = adf_nbuf_queue_remove(&wmi->event_queue);
	adf_os_spin_unlock_bh(&wmi->eventq_lock);
	while (buf) {
		__wmi_control_rx(wmi, buf);
		adf_os_spin_lock_bh(&wmi->eventq_lock);
		buf = adf_nbuf_queue_remove(&wmi->event_queue);
		adf_os_spin_unlock_bh(&wmi->eventq_lock);
	}
}
#endif

/* WMI Initialization functions */

void *
wmi_unified_attach(ol_scn_t scn_handle)
{
    struct wmi_unified *wmi_handle;
    wmi_handle = (struct wmi_unified *)OS_MALLOC(NULL, sizeof(struct wmi_unified), GFP_ATOMIC);
    if (wmi_handle == NULL) {
        printk("allocation of wmi handle failed %zu \n", sizeof(struct wmi_unified));
        return NULL;
    }
    OS_MEMZERO(wmi_handle, sizeof(struct wmi_unified));
    wmi_handle->scn_handle = scn_handle;
    adf_os_atomic_init(&wmi_handle->pending_cmds);
#ifndef QCA_WIFI_ISOC
    adf_os_spinlock_init(&wmi_handle->eventq_lock);
    adf_nbuf_queue_init(&wmi_handle->event_queue);
    INIT_WORK(&wmi_handle->rx_event_work, wmi_rx_event_work);
#endif
    return wmi_handle;
}

void
wmi_unified_detach(struct wmi_unified* wmi_handle)
{
#ifndef QCA_WIFI_ISOC
    wmi_buf_t buf;
#ifdef WLAN_OPEN_SOURCE
    cancel_work_sync(&wmi_handle->rx_event_work);
#endif
    adf_os_spin_lock_bh(&wmi_handle->eventq_lock);
    buf = adf_nbuf_queue_remove(&wmi_handle->event_queue);
    while (buf) {
	adf_nbuf_free(buf);
	buf = adf_nbuf_queue_remove(&wmi_handle->event_queue);
    }
    adf_os_spin_unlock_bh(&wmi_handle->eventq_lock);
#endif
    if (wmi_handle != NULL) {
        OS_FREE(wmi_handle);
        wmi_handle = NULL;
    }
}

void wmi_htc_tx_complete(void *ctx, HTC_PACKET *htc_pkt)
{
	struct wmi_unified *wmi_handle = (struct wmi_unified *)ctx;
	wmi_buf_t wmi_cmd_buf = GET_HTC_PACKET_NET_BUF_CONTEXT(htc_pkt);

	ASSERT(wmi_cmd_buf);
	adf_nbuf_free(wmi_cmd_buf);
	adf_os_mem_free(htc_pkt);
	adf_os_atomic_dec(&wmi_handle->pending_cmds);
}

int
wmi_unified_connect_htc_service(struct wmi_unified * wmi_handle, void *htc_handle)
{

    int status;
    HTC_SERVICE_CONNECT_RESP response;
    HTC_SERVICE_CONNECT_REQ connect;

    OS_MEMZERO(&connect, sizeof(connect));
    OS_MEMZERO(&response, sizeof(response));

    /* meta data is unused for now */
    connect.pMetaData = NULL;
    connect.MetaDataLength = 0;
    /* these fields are the same for all service endpoints */
    connect.EpCallbacks.pContext = wmi_handle;
    connect.EpCallbacks.EpTxCompleteMultiple = NULL /* Control path completion ar6000_tx_complete */;
    connect.EpCallbacks.EpRecv = wmi_control_rx /* Control path rx */;
    connect.EpCallbacks.EpRecvRefill = NULL /* ar6000_rx_refill */;
    connect.EpCallbacks.EpSendFull = NULL /* ar6000_tx_queue_full */;
    connect.EpCallbacks.EpTxComplete = wmi_htc_tx_complete /* ar6000_tx_queue_full */;

    /* connect to control service */
    connect.ServiceID = WMI_CONTROL_SVC;

    if ((status = HTCConnectService(htc_handle, &connect, &response)) != EOK)
    {
        printk(" Failed to connect to WMI CONTROL  service status:%d \n",  status);
        return -1;;
    }
    wmi_handle->wmi_endpoint_id = response.Endpoint;
    wmi_handle->htc_handle = htc_handle;
    
    return EOK;
}
