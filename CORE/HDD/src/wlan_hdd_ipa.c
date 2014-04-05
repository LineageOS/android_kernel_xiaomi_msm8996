/*
 * Copyright (c) 2013-2014 The Linux Foundation. All rights reserved.
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
/*========================================================================

\file  wlan_hdd_ipa.c

\brief   WLAN HDD and ipa interface implementation

========================================================================*/

/*--------------------------------------------------------------------------
Include Files
------------------------------------------------------------------------*/
#ifdef IPA_OFFLOAD
#include <wlan_hdd_includes.h>
#include <wlan_hdd_ipa.h>

#include <linux/etherdevice.h>
#include <linux/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/debugfs.h>
#include <wlan_hdd_softap_tx_rx.h>

#include "vos_sched.h"
#include "tl_shim.h"
#include "wlan_qct_tl.h"

#define HDD_IPA_DESC_BUFFER_RATIO 4
#define HDD_IPA_IPV4_NAME_EXT "_ipv4"
#define HDD_IPA_IPV6_NAME_EXT "_ipv6"

#define HDD_IPA_RX_INACTIVITY_MSEC_DELAY 1000

struct llc_snap_hdr {
	uint8_t dsap;
	uint8_t ssap;
	uint8_t resv[4];
	__be16 eth_type;
} __packed;

struct hdd_ipa_tx_hdr {
	struct ethhdr eth;
	struct llc_snap_hdr llc_snap;
} __packed;

/* For Tx pipes, use 802.3 Header format */
static struct hdd_ipa_tx_hdr ipa_tx_hdr = {
	{
		{0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF},
		{0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF},
		0x00 /* length can be zero */
	},
	{
		/* LLC SNAP header 8 bytes */
		0xaa, 0xaa,
		{0x03, 0x00, 0x00, 0x00},
		0x0008 /* type value(2 bytes) ,filled by wlan  */
			/* 0x0800 - IPV4, 0x86dd - IPV6 */
	}
};

/*
   +----------+----------+--------------+--------+
   | Reserved | QCMAP ID | interface id | STA ID |
   +----------+----------+--------------+--------+
 */
struct hdd_ipa_cld_hdr {
	uint8_t reserved[2];
	uint8_t iface_id;
	uint8_t sta_id;
} __packed;

struct hdd_ipa_rx_hdr {
	struct hdd_ipa_cld_hdr cld_hdr;
	struct ethhdr eth;
} __packed;

#define HDD_IPA_WLAN_CLD_HDR_LEN	sizeof(struct hdd_ipa_cld_hdr)
#define HDD_IPA_WLAN_TX_HDR_LEN		sizeof(ipa_tx_hdr)
#define HDD_IPA_WLAN_RX_HDR_LEN		sizeof(struct hdd_ipa_rx_hdr)
#define HDD_IPA_WLAN_HDR_DES_MAC_OFFSET 0

#define HDD_IPA_GET_IFACE_ID(_data) \
	(((struct hdd_ipa_cld_hdr *) (_data))->iface_id)


#define HDD_IPA_LOG(LVL, fmt, args...)	VOS_TRACE(VOS_MODULE_ID_HDD, LVL, \
				"%s:%d: "fmt, __func__, __LINE__, ## args)

#define HDD_IPA_DBG_DUMP(_lvl, _prefix, _buf, _len) \
	do {\
		VOS_TRACE(VOS_MODULE_ID_HDD, _lvl, "%s:", _prefix); \
		VOS_TRACE_HEX_DUMP(VOS_MODULE_ID_HDD, _lvl, _buf, _len); \
	} while(0)

enum hdd_ipa_rm_state {
	HDD_IPA_RM_RELEASED,
	HDD_IPA_RM_GRANT_PENDING,
	HDD_IPA_RM_GRANTED,
};

#define HDD_IPA_MAX_IFACE 3
#define HDD_IPA_MAX_SYSBAM_PIPE 4
#define HDD_IPA_RX_PIPE  HDD_IPA_MAX_IFACE

static struct hdd_ipa_adapter_2_client {
	enum ipa_client_type cons_client;
	enum ipa_client_type prod_client;
} hdd_ipa_adapter_2_client[HDD_IPA_MAX_IFACE] = {
	{IPA_CLIENT_WLAN1_CONS, IPA_CLIENT_WLAN1_PROD},
	{IPA_CLIENT_WLAN2_CONS, IPA_CLIENT_WLAN1_PROD},
	{IPA_CLIENT_WLAN3_CONS, IPA_CLIENT_WLAN1_PROD},
};

struct hdd_ipa_sys_pipe {
	uint32_t conn_hdl;
	uint8_t conn_hdl_valid;
	struct ipa_sys_connect_params ipa_sys_params;
};

struct hdd_ipa_priv;

struct hdd_ipa_iface_context {
	struct hdd_ipa_priv *hdd_ipa;
	hdd_adapter_t  *adapter;
	void *tl_context;

	enum ipa_client_type cons_client;
	enum ipa_client_type prod_client;

	uint8_t iface_id; /* This iface ID */
	uint8_t sta_id; /* This iface station ID */
};


struct hdd_ipa_stats {
	uint32_t event[IPA_WLAN_EVENT_MAX];
	uint32_t send_msg;
	uint32_t free_msg;

	uint64_t prefilter;
	uint64_t rm_grant;
	uint64_t rm_release;
	uint64_t rm_grant_imm;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
	uint64_t rx_ipa_rm_qued;
#endif
	uint64_t rx_ipa_sent_desc_cnt;
	uint64_t rx_ipa_write_done;
	uint64_t rx_ipa_excep;

	uint64_t rx_ipa_hw_maxed_out;

	uint64_t freeq_empty;
	uint64_t freeq_cnt;

#ifdef HDD_IPA_EXTRA_DP_COUNTERS
	uint64_t rxt_drop;
	uint64_t rxt_recv;
	uint64_t rx_ipa_hw_max_qued;
	uint64_t rxt_d_drop;
	uint64_t rxt_dh_drop;
	uint64_t rxt_0;
	uint64_t rxt_1;
	uint64_t rxt_2;
	uint64_t rxt_3;
	uint64_t rxt_4;
	uint64_t rxt_5;
	uint64_t rxt_6;
	uint64_t freeq_use;
	uint64_t freeq_reclaim;
	uint64_t rx_ipa_dh_sent;
	uint64_t rx_ipa_dh_reclaim;
	uint64_t rx_ipa_dh_not_used;
#endif
	uint64_t ipa_lb_cnt;
	uint64_t tx_ipa_recv;
	uint64_t tx_comp_cnt;
	uint64_t tx_dp_err_cnt;
};

struct hdd_ipa_priv {
	struct hdd_ipa_sys_pipe sys_pipe[HDD_IPA_MAX_SYSBAM_PIPE];
	struct hdd_ipa_iface_context iface_context[HDD_IPA_MAX_IFACE];
	atomic_t rm_state;
	enum ipa_client_type prod_client;

	uint32_t pending_desc_cnt;
	uint32_t hw_desc_cnt;
	spinlock_t q_lock;
	struct list_head free_desc_head;
	struct list_head pend_desc_head;

	hdd_context_t *hdd_ctx;

	struct dentry *debugfs_dir;
	struct hdd_ipa_stats stats;

};

enum hdd_ipa_evt {
	HDD_IPA_RXT_EVT,
	HDD_IPA_WRITE_DONE_EVT,
	HDD_IPA_RM_GRANT_EVT
};

struct hdd_ipa_rxt {
	uint8_t sta_id;
	adf_nbuf_t rx_buf_list;
};



static struct hdd_ipa_priv *ghdd_ipa;
static void hdd_ipa_process_evt(int evt, void *priv);

bool hdd_ipa_is_enabled(hdd_context_t *hdd_ctx)
{
	return hdd_ctx->cfg_ini->IpaEnable;
}

static inline bool hdd_ipa_is_pre_filter_enabled(struct hdd_ipa_priv *hdd_ipa)
{
	hdd_context_t *hdd_ctx = hdd_ipa->hdd_ctx;
	return hdd_ctx->cfg_ini->IpaPreFilterEnable;
}

static inline bool hdd_ipa_is_ipv6_enabled(struct hdd_ipa_priv *hdd_ipa)
{
	hdd_context_t *hdd_ctx = hdd_ipa->hdd_ctx;
	return hdd_ctx->cfg_ini->IpaIPv6Enable;
}

static inline bool hdd_ipa_is_rm_enabled(struct hdd_ipa_priv *hdd_ipa)
{
	hdd_context_t *hdd_ctx = hdd_ipa->hdd_ctx;
	return hdd_ctx->cfg_ini->IpaRMEnable;
}

static inline struct ipa_tx_data_desc *hdd_ipa_get_desc_from_freeq(void)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	struct ipa_tx_data_desc *desc = NULL;

	spin_lock_bh(&ghdd_ipa->q_lock);
	if (!list_empty(&ghdd_ipa->free_desc_head)) {
		desc = list_first_entry(&ghdd_ipa->free_desc_head,
				struct ipa_tx_data_desc, link);
		list_del(&desc->link);
		hdd_ipa->stats.freeq_cnt--;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
		hdd_ipa->stats.freeq_use++;
#endif
	} else {
		hdd_ipa->stats.freeq_empty++;
	}
	spin_unlock_bh(&ghdd_ipa->q_lock);
	return desc;
}

static bool hdd_ipa_can_send_to_ipa(struct hdd_ipa_priv *hdd_ipa, void *data)
{
	struct ethhdr *eth = (struct ethhdr *)data;
	struct llc_snap_hdr *ls_hdr;
	uint16_t eth_type;

	if (!hdd_ipa_is_pre_filter_enabled(hdd_ipa))
		return true;

	eth_type = be16_to_cpu(eth->h_proto);
	if (eth_type < 0x600) {
		/* Non Ethernet II framing format */
		ls_hdr = (struct llc_snap_hdr *)((uint8_t *)data +
						sizeof(struct ethhdr));

		if (((ls_hdr->dsap == 0xAA) && (ls_hdr->ssap == 0xAA)) ||
			((ls_hdr->dsap == 0xAB) && (ls_hdr->ssap == 0xAB)))
			eth_type = be16_to_cpu(ls_hdr->eth_type);
	}

	if (eth_type == ETH_P_IP)
		return true;

	if (hdd_ipa_is_ipv6_enabled(hdd_ipa) && eth_type == ETH_P_IPV6)
		return true;

	return false;
}

static int hdd_ipa_rm_request(struct hdd_ipa_priv *hdd_ipa)
{
	int ret = 0;

	if (!hdd_ipa_is_rm_enabled(hdd_ipa)) {
		atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_GRANTED);
		return 0;
	}
	ret = ipa_rm_inactivity_timer_request_resource(
			IPA_RM_RESOURCE_WLAN_PROD);
	if (ret == 0) {
		atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_GRANTED);
		hdd_ipa->stats.rm_grant_imm++;
	}
	return ret;
}

static int hdd_ipa_rm_release(struct hdd_ipa_priv *hdd_ipa)
{
	int ret = 0;

	if (!hdd_ipa_is_rm_enabled(hdd_ipa))
		return 0;

	ret = ipa_rm_inactivity_timer_release_resource(
			IPA_RM_RESOURCE_WLAN_PROD);
	if (ret == 0) {
		atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_RELEASED);
		hdd_ipa->stats.rm_release++;
	}
	return ret;
}

static void hdd_ipa_rm_notify(void *user_data, enum ipa_rm_event event,
							unsigned long data)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	if (!hdd_ipa_is_rm_enabled(hdd_ipa))
		return;

	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "Evt: %d", event);

	switch(event) {
	case IPA_RM_RESOURCE_GRANTED:
		atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_GRANTED);
		hdd_ipa->stats.rm_grant++;
		hdd_ipa_process_evt(HDD_IPA_RM_GRANT_EVT, NULL);
		break;
	case IPA_RM_RESOURCE_RELEASED:
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "RM Release not expected!");
		break;
	default:
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Unknow RM Evt: %d", event);
		break;
	}
}

static int hdd_ipa_rm_cons_release(void)
{
	return 0;
}

static int hdd_ipa_rm_cons_request(void)
{
	return 0;
}

static int hdd_ipa_setup_rm(struct hdd_ipa_priv *hdd_ipa)
{
	struct ipa_rm_create_params create_params = {0};
	int ret;

	if (!hdd_ipa_is_rm_enabled(hdd_ipa))
		return 0;
	memset(&create_params, 0, sizeof(create_params));
	create_params.name = IPA_RM_RESOURCE_WLAN_PROD;
	create_params.reg_params.user_data = hdd_ipa;
	create_params.reg_params.notify_cb = hdd_ipa_rm_notify;

	ret = ipa_rm_create_resource(&create_params);
	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Create RM resource failed");
		goto setup_rm_fail;
	}

	memset(&create_params, 0, sizeof(create_params));
	create_params.name = IPA_RM_RESOURCE_WLAN_CONS;
	create_params.request_resource= hdd_ipa_rm_cons_request;
	create_params.release_resource= hdd_ipa_rm_cons_release;

	ret = ipa_rm_create_resource(&create_params);
	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
				"Create RM CONS resource failed");
		goto setup_rm_fail;
	}

	ipa_rm_add_dependency(IPA_RM_RESOURCE_WLAN_PROD,
			IPA_RM_RESOURCE_APPS_CONS);

	ret = ipa_rm_inactivity_timer_init(IPA_RM_RESOURCE_WLAN_PROD,
					HDD_IPA_RX_INACTIVITY_MSEC_DELAY);
	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Timer init failed");
		goto setup_rm_fail;
	}

	atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_RELEASED);

setup_rm_fail:
	return ret;
}

static void hdd_ipa_destory_rm_resource(struct hdd_ipa_priv *hdd_ipa)
{
	int ret;

	if (!hdd_ipa_is_rm_enabled(hdd_ipa))
		return;

	ipa_rm_inactivity_timer_destroy(IPA_RM_RESOURCE_WLAN_PROD);

	ret = ipa_rm_delete_resource(IPA_RM_RESOURCE_WLAN_PROD);
	if (ret)
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "RM resource delete failed");
}

static void hdd_ipa_send_skb_to_network(adf_nbuf_t skb, hdd_adapter_t *adapter)
{
	if (!adapter || adapter->magic != WLAN_HDD_ADAPTER_MAGIC) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Invalid adapter: 0x%p",
				adapter);

		adf_nbuf_free(skb);
		return;
	}
	skb->dev = adapter->dev;
	skb->protocol = eth_type_trans(skb, skb->dev);
	skb->ip_summed = CHECKSUM_NONE;
	++adapter->hdd_stats.hddTxRxStats.rxPackets;
	++adapter->stats.rx_packets;
	adapter->stats.rx_bytes += skb->len;
	if (netif_rx_ni(skb) == NET_RX_SUCCESS)
		++adapter->hdd_stats.hddTxRxStats.rxDelivered;
	else
		++adapter->hdd_stats.hddTxRxStats.rxRefused;
	adapter->dev->last_rx = jiffies;
}

static void hdd_ipa_send_pkt_to_ipa(struct ipa_tx_data_desc *send_desc_head,
							int send_desc_cnt)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	struct ipa_tx_data_desc *send_desc, *desc, *tmp;
	uint32_t cur_send_cnt = 0;
	adf_nbuf_t buf;

	/* In RM GRANT CTX send_desc_head is null */
	if (!send_desc_head) {
		send_desc_head = hdd_ipa_get_desc_from_freeq();
		if (!send_desc_head)
			return;

		INIT_LIST_HEAD(&send_desc_head->link);
	}

	spin_lock_bh(&hdd_ipa->q_lock);
	if ((hdd_ipa->pending_desc_cnt + send_desc_cnt)
			< hdd_ipa->hw_desc_cnt) {

		if (!list_empty(&hdd_ipa->pend_desc_head)) {
			list_splice_tail_init(&send_desc_head->link,
					&hdd_ipa->pend_desc_head);
			while ((hdd_ipa->pending_desc_cnt <
						hdd_ipa->hw_desc_cnt) &&
					!(list_empty(
						&hdd_ipa->pend_desc_head))) {
				send_desc = list_first_entry(
						&ghdd_ipa->pend_desc_head,
						struct ipa_tx_data_desc, link);
				list_del(&send_desc->link);
				list_add_tail(&send_desc->link,
						&send_desc_head->link);
				hdd_ipa->pending_desc_cnt++;
				cur_send_cnt++;
			}
		} else {
			hdd_ipa->pending_desc_cnt += send_desc_cnt;
			cur_send_cnt = send_desc_cnt;
		}
		hdd_ipa->stats.rx_ipa_sent_desc_cnt += cur_send_cnt;

#ifdef HDD_IPA_EXTRA_DP_COUNTERS
		hdd_ipa->stats.rx_ipa_dh_sent++; /* for desc head */
#endif
		spin_unlock_bh(&hdd_ipa->q_lock);
		if (ipa_tx_dp_mul(hdd_ipa->prod_client,
					send_desc_head) != 0) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
					"ipa_tx_dp_mul failed!!!"
					" (cur_send_cnt=%d)",
					cur_send_cnt);
			hdd_ipa->stats.tx_dp_err_cnt++;
			spin_lock_bh(&hdd_ipa->q_lock);

			list_for_each_entry_safe(desc, tmp,
					&send_desc_head->link, link) {
				list_del(&desc->link);
				buf = desc->priv;
				adf_nbuf_free(buf);
				desc->priv = NULL;
				desc->pyld_buffer = NULL;
				desc->pyld_len = 0;
				list_add_tail(&desc->link,
						&hdd_ipa->free_desc_head);
				hdd_ipa->stats.freeq_cnt++;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
				hdd_ipa->stats.freeq_reclaim++;
#endif
				spin_unlock_bh(&hdd_ipa->q_lock);
			}

			/* return anchor node */
			list_add_tail(&send_desc_head->link,
					&hdd_ipa->free_desc_head);
			hdd_ipa->stats.freeq_cnt++;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
			hdd_ipa->stats.rx_ipa_dh_reclaim++;
			hdd_ipa->stats.freeq_reclaim++;
#endif
			spin_unlock_bh(&hdd_ipa->q_lock);
		}
	} else {
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
		hdd_ipa->stats.rx_ipa_hw_max_qued += send_desc_cnt;
#endif

		hdd_ipa->stats.rx_ipa_hw_maxed_out++;
		list_splice_tail_init(&send_desc_head->link,
				&hdd_ipa->pend_desc_head);
		list_add_tail(&send_desc_head->link,
				&hdd_ipa->free_desc_head);
		hdd_ipa->stats.freeq_cnt++;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
		hdd_ipa->stats.rx_ipa_dh_not_used++;
		hdd_ipa->stats.freeq_reclaim++;
#endif
		spin_unlock_bh(&hdd_ipa->q_lock);
	}

}

static void hdd_ipa_process_evt(int evt, void *priv)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	struct hdd_ipa_rxt *rxt;
	struct ipa_tx_data_desc *send_desc_head = NULL, *send_desc,
					*done_desc_head, *done_desc, *tmp;
	hdd_adapter_t *adapter = NULL;
	struct hdd_ipa_iface_context *iface_context = NULL;
	adf_nbuf_t buf, next_buf;
	uint8_t cur_cnt = 0;
	struct hdd_ipa_cld_hdr *cld_hdr;

	switch (evt) {
	case HDD_IPA_RXT_EVT:
		rxt = priv;

		adapter = hdd_ipa->hdd_ctx->sta_to_adapter[rxt->sta_id];
		if (!adapter ||
		(adapter && adapter->magic != WLAN_HDD_ADAPTER_MAGIC)) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Invalid sta_id");
			buf = rxt->rx_buf_list;
			while (buf) {
				next_buf = adf_nbuf_queue_next(buf);
				adf_nbuf_free(buf);
				/* here if ipa is stuck we can send
				to network if required as fail safe
				*/
				buf = next_buf;
			}
			return;
		}

		iface_context =
			(struct hdd_ipa_iface_context *) adapter->ipa_context;
		/* send_desc_head is a anchor node */
		send_desc_head = hdd_ipa_get_desc_from_freeq();
		if (!send_desc_head) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_WARN,
					"send_desc_head=Null. FreeQ Empty");
			buf = rxt->rx_buf_list;
			while (buf) {
				next_buf = adf_nbuf_queue_next(buf);
				adf_nbuf_free(buf);
				/* here if ipa is stuck we can send
				to network if required as fail safe
				*/
				buf = next_buf;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
				hdd_ipa->stats.rxt_recv++;
				hdd_ipa->stats.rxt_drop++;
#endif
			}
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
			hdd_ipa->stats.rxt_dh_drop++;
#endif
			return;
		}

		INIT_LIST_HEAD(&send_desc_head->link);
		buf = rxt->rx_buf_list;
		while (buf) {
			HDD_IPA_DBG_DUMP(VOS_TRACE_LEVEL_DEBUG, "RX data",
					buf->data, 24);

			next_buf = adf_nbuf_queue_next(buf);

			/*
			 * we want to send Rx packets to IPA only when it is
			 * IPV4 or IPV6i(if IPV6 is enabled). All other packets
			 * will be sent to network stack directly.
			 */
			if (!hdd_ipa_can_send_to_ipa(hdd_ipa, buf->data)) {
				hdd_ipa->stats.prefilter++;
				hdd_ipa_send_skb_to_network(buf, adapter);
				buf = next_buf;
				continue;
			}

			cld_hdr = (struct hdd_ipa_cld_hdr *) skb_push(buf,
					HDD_IPA_WLAN_CLD_HDR_LEN);
			cld_hdr->sta_id = rxt->sta_id;
			cld_hdr->iface_id = iface_context->iface_id;

			send_desc = hdd_ipa_get_desc_from_freeq();
			if (send_desc) {
				send_desc->priv = buf;
				send_desc->pyld_buffer = buf->data;
				send_desc->pyld_len = buf->len;
				list_add_tail(&send_desc->link,
						&send_desc_head->link);
				cur_cnt++;
			} else {
				adf_nbuf_free(buf); /*No desc available; drop*/
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
				hdd_ipa->stats.rxt_drop++;
				hdd_ipa->stats.rxt_d_drop++;
#endif
			}
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
			hdd_ipa->stats.rxt_recv++;
#endif
			buf = next_buf;
		}

#ifdef HDD_IPA_EXTRA_DP_COUNTERS
		if (cur_cnt == 0)
			hdd_ipa->stats.rxt_0++;
		else if (cur_cnt == 1)
			hdd_ipa->stats.rxt_1++;
		else if (cur_cnt == 2)
			hdd_ipa->stats.rxt_2++;
		else if (cur_cnt == 3)
			hdd_ipa->stats.rxt_3++;
		else if (cur_cnt == 4)
			hdd_ipa->stats.rxt_4++;
		else if (cur_cnt == 5)
			hdd_ipa->stats.rxt_5++;
		else if (cur_cnt > 5)
			hdd_ipa->stats.rxt_6++;
#endif

		if(cur_cnt == 0){
			spin_lock_bh(&hdd_ipa->q_lock);
			list_add_tail(&send_desc_head->link,
					&hdd_ipa->free_desc_head);
			hdd_ipa->stats.freeq_cnt++;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
			hdd_ipa->stats.rx_ipa_dh_not_used++;
			hdd_ipa->stats.freeq_reclaim++;
#endif
			spin_unlock_bh(&hdd_ipa->q_lock);
			goto rxt_end;
		}

		if (atomic_read(&hdd_ipa->rm_state) == HDD_IPA_RM_GRANTED) {
			hdd_ipa_send_pkt_to_ipa(send_desc_head, cur_cnt);
		} else {
			if (atomic_read(&hdd_ipa->rm_state)
						!= HDD_IPA_RM_GRANT_PENDING) {
				atomic_set(&hdd_ipa->rm_state,
						HDD_IPA_RM_GRANT_PENDING);
				hdd_ipa_rm_request(hdd_ipa);
			}
			/* hdd_ipa_rm_request can immediately grant so check
			   again. */
			if (atomic_read(&hdd_ipa->rm_state)
						== HDD_IPA_RM_GRANT_PENDING) {
				spin_lock_bh(&hdd_ipa->q_lock);
				list_splice_tail_init(&send_desc_head->link,
						&hdd_ipa->pend_desc_head);
				/* return anchor node */
				list_add_tail(&send_desc_head->link,
						&hdd_ipa->free_desc_head);
				hdd_ipa->stats.freeq_cnt++;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
				hdd_ipa->stats.rx_ipa_dh_reclaim++;
				hdd_ipa->stats.freeq_reclaim++;
#endif
				spin_unlock_bh(&hdd_ipa->q_lock);
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
				hdd_ipa->stats.rx_ipa_rm_qued += cur_cnt;
#endif
			} else {
				hdd_ipa_send_pkt_to_ipa(send_desc_head,
								cur_cnt);
			}
		}
rxt_end:
	break;

	case HDD_IPA_RM_GRANT_EVT:
		hdd_ipa_send_pkt_to_ipa(NULL, 0);
	break;

	case HDD_IPA_WRITE_DONE_EVT:
		done_desc_head = priv;
		spin_lock_bh(&hdd_ipa->q_lock);
		list_for_each_entry_safe(done_desc, tmp,
						&done_desc_head->link, link) {
			list_del(&done_desc->link);
			buf = done_desc->priv;
			adf_nbuf_free(buf);
			done_desc->priv = NULL;
			done_desc->pyld_buffer = NULL;
			done_desc->pyld_len = 0;
			list_add_tail(&done_desc->link,
					&hdd_ipa->free_desc_head);
			hdd_ipa->stats.freeq_cnt++;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
			hdd_ipa->stats.freeq_reclaim++;
#endif
			hdd_ipa->pending_desc_cnt--;
			hdd_ipa->stats.rx_ipa_write_done++;
		}
		/* add anchor node also back to free list */
		list_add_tail(&done_desc_head->link, &hdd_ipa->free_desc_head);
		hdd_ipa->stats.freeq_cnt++;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
		hdd_ipa->stats.rx_ipa_dh_reclaim++;
		hdd_ipa->stats.freeq_reclaim++;
#endif
		spin_unlock_bh(&hdd_ipa->q_lock);

		if (list_empty(&hdd_ipa->pend_desc_head)) {
			if (atomic_read(&hdd_ipa->rm_state)
						== HDD_IPA_RM_GRANTED) {
				hdd_ipa_rm_release(hdd_ipa);
			}
		} else {
			/* no rx pkt come in so flash the last few */
			hdd_ipa_send_pkt_to_ipa(NULL, 0);
		}
	break;
	}
}

VOS_STATUS hdd_ipa_process_rxt(v_VOID_t *vosContext, adf_nbuf_t rx_buf_list,
								v_U8_t sta_id)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	struct hdd_ipa_rxt rxt;

	if (!hdd_ipa_is_enabled(hdd_ipa->hdd_ctx))
		return VOS_STATUS_E_INVAL;

	rxt.sta_id = sta_id;
	rxt.rx_buf_list = rx_buf_list;

	hdd_ipa_process_evt(HDD_IPA_RXT_EVT, &rxt);

	return VOS_STATUS_SUCCESS;
}

static void hdd_ipa_w2i_cb(void *priv, enum ipa_dp_evt_type evt,
		unsigned long data)
{
	struct hdd_ipa_priv *hdd_ipa = NULL;
	hdd_adapter_t *adapter = NULL;
	struct ipa_tx_data_desc *done_desc_head;
	adf_nbuf_t skb;
	uint8_t iface_id;

	hdd_ipa = (struct hdd_ipa_priv *)priv;

	switch (evt) {
	case IPA_RECEIVE:
		skb = (adf_nbuf_t) data;

		iface_id = HDD_IPA_GET_IFACE_ID(skb->data);
		if (iface_id >= HDD_IPA_MAX_IFACE) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
					"IPA_RECEIVE: Invalid iface_id: %u\n",
					iface_id);
			adf_nbuf_free(skb);
			return;
		}

		adapter = hdd_ipa->iface_context[iface_id].adapter;

		HDD_IPA_DBG_DUMP(VOS_TRACE_LEVEL_DEBUG, "w2i -- skb", skb->data,
				8);

		skb_pull(skb, HDD_IPA_WLAN_CLD_HDR_LEN);

		hdd_ipa->stats.rx_ipa_excep++;
		hdd_ipa_send_skb_to_network(skb, adapter);
		break;
	case IPA_WRITE_DONE:
		done_desc_head = (struct ipa_tx_data_desc *)data;
		hdd_ipa_process_evt(HDD_IPA_WRITE_DONE_EVT, done_desc_head);
		break;
	default:
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
				"w2i cb wrong event: 0x%x", evt);
		return;
	}
}

static void hdd_ipa_nbuf_cb(adf_nbuf_t skb)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;

	/* TX COMP counter at frame free location. */
	hdd_ipa->stats.tx_comp_cnt++;

	HDD_IPA_LOG(VOS_TRACE_LEVEL_DEBUG, "%lx", NBUF_OWNER_PRIV_DATA(skb));
	ipa_free_skb((struct ipa_rx_data *) NBUF_OWNER_PRIV_DATA(skb));
}

static void hdd_ipa_i2w_cb(void *priv, enum ipa_dp_evt_type evt,
		unsigned long data)
{
	struct hdd_ipa_priv *hdd_ipa = NULL;
	struct ipa_rx_data *ipa_tx_desc;
	struct hdd_ipa_iface_context *iface_context;
	adf_nbuf_t skb;

	if (evt == IPA_RECEIVE) {

		iface_context = (struct hdd_ipa_iface_context *) priv;
		ipa_tx_desc = (struct ipa_rx_data *)data;
		skb = ipa_tx_desc->skb;

		hdd_ipa = iface_context->hdd_ipa;

		adf_os_mem_set(skb->cb, 0, sizeof(skb->cb));
		NBUF_OWNER_ID(skb) = IPA_NBUF_OWNER_ID;
		NBUF_CALLBACK_FN(skb) = hdd_ipa_nbuf_cb;
		NBUF_MAPPED_PADDR_LO(skb) = ipa_tx_desc->dma_addr;

		NBUF_OWNER_PRIV_DATA(skb) = data;

		HDD_IPA_DBG_DUMP(VOS_TRACE_LEVEL_DEBUG, "i2w", skb->data, 8);

		hdd_ipa->stats.tx_ipa_recv++;

		skb = WLANTL_SendIPA_DataFrame(hdd_ipa->hdd_ctx->pvosContext,
				iface_context->tl_context, ipa_tx_desc->skb);
		if (skb) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_DEBUG, "TLSHIM tx fail");
			ipa_free_skb(ipa_tx_desc);
			return;
		}
	} else {
		skb = (adf_nbuf_t) data;
		dev_kfree_skb_any(skb);
	}
}

static int hdd_ipa_setup_sys_pipe(struct hdd_ipa_priv *hdd_ipa)
{
	int i, ret = 0;
	struct ipa_sys_connect_params *ipa;
	uint32_t desc_fifo_sz;

	/* The maximum number of descriptors that can be provided to a BAM at
	 * once is one less than the total number of descriptors that the buffer
	 * can contain.
	 * If max_num_of_descriptors = (BAM_PIPE_DESCRIPTOR_FIFO_SIZE / sizeof
	 * (SPS_DESCRIPTOR)), then (max_num_of_descriptors - 1) descriptors can
	 * be provided at once.
	 * Because of above requirement, one extra descriptor will be added to
	 * make sure hardware always has one descriptor.
	 */
	desc_fifo_sz = hdd_ipa->hdd_ctx->cfg_ini->IpaDescSize
                        + sizeof(struct sps_iovec);

	/*setup TX pipes */
	for (i = 0; i < HDD_IPA_MAX_IFACE; i++) {
		ipa = &hdd_ipa->sys_pipe[i].ipa_sys_params;

		ipa->client = hdd_ipa_adapter_2_client[i].cons_client;
		ipa->desc_fifo_sz = desc_fifo_sz;
		ipa->priv = &hdd_ipa->iface_context[i];
		ipa->notify = hdd_ipa_i2w_cb;

		ipa->ipa_ep_cfg.hdr.hdr_len = HDD_IPA_WLAN_TX_HDR_LEN;
		ipa->ipa_ep_cfg.mode.mode = IPA_BASIC;

		if (!hdd_ipa_is_rm_enabled(hdd_ipa))
			ipa->keep_ipa_awake = 1;

		ret = ipa_setup_sys_pipe(ipa, &(hdd_ipa->sys_pipe[i].conn_hdl));
		if (ret) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Failed for pipe %d"
					" ret: %d", i, ret);
			goto setup_sys_pipe_fail;
		}
		hdd_ipa->sys_pipe[i].conn_hdl_valid = 1;
	}

	/*
	 * Hard code it here, this can be extended if in case PROD pipe is also
	 * per interface. Right now there is no advantage of doing this.
	 */
	hdd_ipa->prod_client = IPA_CLIENT_WLAN1_PROD;

	ipa = &hdd_ipa->sys_pipe[HDD_IPA_RX_PIPE].ipa_sys_params;

	ipa->client = hdd_ipa->prod_client;

	ipa->desc_fifo_sz = desc_fifo_sz;
	ipa->priv = hdd_ipa;
	ipa->notify = hdd_ipa_w2i_cb;

	ipa->ipa_ep_cfg.nat.nat_en = IPA_BYPASS_NAT;
	ipa->ipa_ep_cfg.hdr.hdr_len = HDD_IPA_WLAN_RX_HDR_LEN;
	ipa->ipa_ep_cfg.hdr.hdr_ofst_metadata_valid = 1;
	ipa->ipa_ep_cfg.mode.mode = IPA_BASIC;

	if (!hdd_ipa_is_rm_enabled(hdd_ipa))
		ipa->keep_ipa_awake = 1;

	ret = ipa_setup_sys_pipe(ipa, &(hdd_ipa->sys_pipe[i].conn_hdl));
	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Failed for RX pipe: %d",
				ret);
		goto setup_sys_pipe_fail;
	}
	hdd_ipa->sys_pipe[HDD_IPA_RX_PIPE].conn_hdl_valid = 1;

	return ret;

setup_sys_pipe_fail:

	while (--i >= 0) {
		ipa_teardown_sys_pipe(hdd_ipa->sys_pipe[i].conn_hdl);
		adf_os_mem_zero(&hdd_ipa->sys_pipe[i],
				sizeof(struct hdd_ipa_sys_pipe ));
	}

	return ret;
}

/* Disconnect all the Sys pipes */
static void hdd_ipa_teardown_sys_pipe(struct hdd_ipa_priv *hdd_ipa)
{
	int ret = 0, i;
	for (i = 0; i < HDD_IPA_MAX_SYSBAM_PIPE; i++) {
		if (hdd_ipa->sys_pipe[i].conn_hdl_valid) {
			ret = ipa_teardown_sys_pipe(
						hdd_ipa->sys_pipe[i].conn_hdl);
			if (ret)
				HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Failed: %d",
						ret);

			hdd_ipa->sys_pipe[i].conn_hdl_valid = 0;
		}
	}
}

static int hdd_ipa_register_interface(struct hdd_ipa_priv *hdd_ipa,
		struct hdd_ipa_iface_context *iface_context)
{
	struct ipa_tx_intf tx_intf;
	struct ipa_rx_intf rx_intf;
	struct ipa_ioc_tx_intf_prop *tx_prop = NULL;
	struct ipa_ioc_rx_intf_prop *rx_prop = NULL;
	char *ifname = iface_context->adapter->dev->name;

	char ipv4_hdr_name[IPA_RESOURCE_NAME_MAX];
	char ipv6_hdr_name[IPA_RESOURCE_NAME_MAX];

	int num_prop = 1;
	int ret = 0;

	if (hdd_ipa_is_ipv6_enabled(hdd_ipa))
		num_prop++;

	/* Allocate TX properties for TOS categories, 1 each for IPv4 & IPv6 */
	tx_prop = adf_os_mem_alloc(NULL,
			sizeof(struct ipa_ioc_tx_intf_prop) * num_prop);
	if (!tx_prop) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "tx_prop allocation failed");
		goto register_interface_fail;
	}

	/* Allocate RX properties, 1 each for IPv4 & IPv6 */
	rx_prop = adf_os_mem_alloc(NULL,
			sizeof(struct ipa_ioc_rx_intf_prop) * num_prop);
	if (!rx_prop) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "rx_prop allocation failed");
		goto register_interface_fail;
	}

	adf_os_mem_zero(&tx_intf, sizeof(tx_intf));
	adf_os_mem_zero(&rx_intf, sizeof(rx_intf));

	snprintf(ipv4_hdr_name, IPA_RESOURCE_NAME_MAX, "%s%s",
		ifname, HDD_IPA_IPV4_NAME_EXT);
	snprintf(ipv6_hdr_name, IPA_RESOURCE_NAME_MAX, "%s%s",
		ifname, HDD_IPA_IPV6_NAME_EXT);

	rx_prop[IPA_IP_v4].ip = IPA_IP_v4;
	rx_prop[IPA_IP_v4].src_pipe = iface_context->prod_client;

	rx_prop[IPA_IP_v4].attrib.attrib_mask = IPA_FLT_META_DATA;

	/*
	 * Interface ID is 3rd byte in the CLD header. Add the meta data and
	 * mask to identify the interface in IPA hardware
	 */
	rx_prop[IPA_IP_v4].attrib.meta_data =
		htonl(iface_context->iface_id << 16);
	rx_prop[IPA_IP_v4].attrib.meta_data_mask = htonl(0x00FF0000);

	rx_intf.num_props++;
	if (hdd_ipa_is_ipv6_enabled(hdd_ipa)) {
		rx_prop[IPA_IP_v6].ip = IPA_IP_v6;
		rx_prop[IPA_IP_v6].src_pipe = iface_context->prod_client;

		rx_prop[IPA_IP_v4].attrib.attrib_mask = IPA_FLT_META_DATA;
		rx_prop[IPA_IP_v4].attrib.meta_data =
			htonl(iface_context->iface_id << 16);
		rx_prop[IPA_IP_v4].attrib.meta_data_mask = htonl(0x00FF0000);

		rx_intf.num_props++;
	}

	tx_prop[IPA_IP_v4].ip = IPA_IP_v4;
	tx_prop[IPA_IP_v4].dst_pipe = iface_context->cons_client;
	strlcpy(tx_prop[IPA_IP_v4].hdr_name, ipv4_hdr_name,
			IPA_RESOURCE_NAME_MAX);
	tx_intf.num_props++;

	if (hdd_ipa_is_ipv6_enabled(hdd_ipa)) {
		tx_prop[IPA_IP_v6].ip = IPA_IP_v6;
		tx_prop[IPA_IP_v6].dst_pipe = iface_context->cons_client;
		strlcpy(tx_prop[IPA_IP_v6].hdr_name, ipv6_hdr_name,
				IPA_RESOURCE_NAME_MAX);
		tx_intf.num_props++;
	}

	tx_intf.prop = tx_prop;
	rx_intf.prop = rx_prop;

	/* Call the ipa api to register interface */
	ret = ipa_register_intf(ifname, &tx_intf, &rx_intf);

register_interface_fail:
	adf_os_mem_free(tx_prop);
	adf_os_mem_free(rx_prop);
	return ret;
}

static void hdd_remove_ipa_header(char *name)
{
	struct ipa_ioc_get_hdr hdrlookup;
	int ret = 0, len;
	struct ipa_ioc_del_hdr *ipa_hdr;

	adf_os_mem_zero(&hdrlookup, sizeof(hdrlookup));
	strlcpy(hdrlookup.name, name, sizeof(hdrlookup.name));
	ret = ipa_get_hdr(&hdrlookup);
	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "Hdr deleted already %s, %d",
				name, ret);
		return;
	}


	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "hdl: 0x%x", hdrlookup.hdl);
	len = sizeof(struct ipa_ioc_del_hdr) + sizeof(struct ipa_hdr_del)*1;
	ipa_hdr = (struct ipa_ioc_del_hdr *) adf_os_mem_alloc(NULL, len);
	if (ipa_hdr == NULL) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "ipa_hdr allocation failed");
		return;
	}
	ipa_hdr->num_hdls = 1;
	ipa_hdr->commit = 0;
	ipa_hdr->hdl[0].hdl = hdrlookup.hdl;
	ipa_hdr->hdl[0].status = -1;
	ret = ipa_del_hdr(ipa_hdr);
	if (ret != 0)
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Delete header failed: %d",
				ret);

	adf_os_mem_free(ipa_hdr);
}


static int hdd_ipa_add_header_info(struct hdd_ipa_priv *hdd_ipa,
		struct hdd_ipa_iface_context *iface_context, uint8_t *mac_addr)
{
	hdd_adapter_t *adapter = iface_context->adapter;
	char *ifname;
	struct ipa_ioc_add_hdr *ipa_hdr = NULL;
	int ret = -EINVAL;
	struct hdd_ipa_tx_hdr *tx_hdr = NULL;

	ifname = adapter->dev->name;


	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "Add Partial hdr: %s, %pM",
			ifname, mac_addr);

	/* dynamically allocate the memory to add the hdrs */
	ipa_hdr = adf_os_mem_alloc(NULL, sizeof(struct ipa_ioc_add_hdr)
			+ sizeof(struct ipa_hdr_add));
	if (!ipa_hdr) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
				"%s: ipa_hdr allocation failed", ifname);
		ret = -ENOMEM;
		goto end;
	}

	ipa_hdr->commit = 0;
	ipa_hdr->num_hdrs = 1;

	tx_hdr = (struct hdd_ipa_tx_hdr *)ipa_hdr->hdr[0].hdr;

	/* Set the Source MAC */
	memcpy(tx_hdr, &ipa_tx_hdr, HDD_IPA_WLAN_TX_HDR_LEN);
	memcpy(tx_hdr->eth.h_source, mac_addr, ETH_ALEN);

	snprintf(ipa_hdr->hdr[0].name, IPA_RESOURCE_NAME_MAX, "%s%s",
			ifname, HDD_IPA_IPV4_NAME_EXT);
	ipa_hdr->hdr[0].hdr_len = HDD_IPA_WLAN_TX_HDR_LEN;
	ipa_hdr->hdr[0].is_partial = 1;
	ipa_hdr->hdr[0].hdr_hdl = 0;

	/* Set the type to IPV4 in the header*/
	tx_hdr->llc_snap.eth_type = cpu_to_be16(ETH_P_IP);

	ret = ipa_add_hdr(ipa_hdr);

	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "%s IPv4 add hdr failed: %d",
				ifname, ret);
		goto end;
	}

	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%s: IPv4 hdr_hdl: 0x%x",
			ipa_hdr->hdr[0].name, ipa_hdr->hdr[0].hdr_hdl);

	if (hdd_ipa_is_ipv6_enabled(hdd_ipa)) {
		snprintf(ipa_hdr->hdr[0].name, IPA_RESOURCE_NAME_MAX, "%s%s",
				ifname, HDD_IPA_IPV6_NAME_EXT);

		/* Set the type to IPV6 in the header*/
		tx_hdr->llc_snap.eth_type = cpu_to_be16(ETH_P_IPV6);

		ret = ipa_add_hdr(ipa_hdr);

		if (ret) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
					"%s: IPv6 add hdr failed: %d",
					ifname, ret);
			goto clean_ipv4_hdr;
		}

		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%s: IPv6 hdr_hdl: 0x%x",
				ipa_hdr->hdr[0].name, ipa_hdr->hdr[0].hdr_hdl);
	}

	adf_os_mem_free(ipa_hdr);

	return ret;

clean_ipv4_hdr:
	snprintf(ipa_hdr->hdr[0].name, IPA_RESOURCE_NAME_MAX, "%s%s",
			ifname, HDD_IPA_IPV4_NAME_EXT);
	hdd_remove_ipa_header(ipa_hdr->hdr[0].name);
end:
	if(ipa_hdr)
		adf_os_mem_free(ipa_hdr);

	return ret;
}

static void hdd_ipa_clean_hdr(hdd_adapter_t *adapter)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	int ret;
	char name_ipa[IPA_RESOURCE_NAME_MAX];

	/* Remove the headers */
	snprintf(name_ipa, IPA_RESOURCE_NAME_MAX, "%s%s",
		adapter->dev->name, HDD_IPA_IPV4_NAME_EXT);
	hdd_remove_ipa_header(name_ipa);

	if (hdd_ipa_is_ipv6_enabled(hdd_ipa)) {
		snprintf(name_ipa, IPA_RESOURCE_NAME_MAX, "%s%s",
			adapter->dev->name, HDD_IPA_IPV6_NAME_EXT);
		hdd_remove_ipa_header(name_ipa);
	}
	/* unregister the interface with IPA */
	ret = ipa_deregister_intf(adapter->dev->name);
	if (ret)
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO,
				"%s: ipa_deregister_intf fail: %d",
				adapter->dev->name, ret);
}

static void hdd_ipa_cleanup_iface(struct hdd_ipa_iface_context *iface_context)
{
	if (iface_context == NULL)
		return;

	hdd_ipa_clean_hdr(iface_context->adapter);

	iface_context->adapter->ipa_context = NULL;
	iface_context->adapter = NULL;
	iface_context->tl_context = NULL;
}


static int hdd_ipa_setup_iface(struct hdd_ipa_priv *hdd_ipa,
		hdd_adapter_t *adapter, uint8_t sta_id)
{
	struct hdd_ipa_iface_context *iface_context = NULL;
	void *tl_context = NULL;
	int i, ret = 0;

	for (i = 0; i < HDD_IPA_MAX_IFACE; i++) {
		if (hdd_ipa->iface_context[i].adapter == NULL) {
			iface_context = &(hdd_ipa->iface_context[i]);
			break;
		}
	}

	if (iface_context == NULL) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
				"All the IPA interfaces are in use");
		ret = -ENOMEM;
		goto end;
	}


	adapter->ipa_context = iface_context;
	iface_context->adapter = adapter;
	iface_context->sta_id = sta_id;
	tl_context = tl_shim_get_vdev_by_sta_id(hdd_ipa->hdd_ctx->pvosContext,
			sta_id);

	if (tl_context == NULL) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
				"Not able to get TL context sta_id: %d",
				sta_id);
		ret = -EINVAL;
		goto end;
	}

	iface_context->tl_context = tl_context;

	ret = hdd_ipa_add_header_info(hdd_ipa, iface_context,
			adapter->dev->dev_addr);

	if (ret)
		goto end;

	/* Configure the TX and RX pipes filter rules */
	ret = hdd_ipa_register_interface(hdd_ipa, iface_context);
	if (ret)
		goto cleanup_header;

	return ret;

cleanup_header:

	hdd_ipa_clean_hdr(adapter);
end:
	if (iface_context)
		hdd_ipa_cleanup_iface(iface_context);
	return ret;
}


static void hdd_ipa_msg_free_fn(void *buff, uint32_t len, uint32_t type)
{
	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "msg type:%d, len:%d", type, len);
	ghdd_ipa->stats.free_msg++;
	adf_os_mem_free(buff);
}

int hdd_ipa_wlan_evt(hdd_adapter_t *adapter, uint8_t sta_id,
			enum ipa_wlan_event type, uint8_t *mac_addr)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	struct ipa_msg_meta meta;
	struct ipa_wlan_msg *msg;
	struct ipa_wlan_msg_ex *msg_ex = NULL;
	int ret;
	const char *hdd_ipa_event_name[IPA_WLAN_EVENT_MAX] = {
	__stringify(WLAN_CLIENT_CONNECT),
	__stringify(WLAN_CLIENT_DISCONNECT),
	__stringify(WLAN_CLIENT_POWER_SAVE_MODE),
	__stringify(WLAN_CLIENT_NORMAL_MODE),
	__stringify(SW_ROUTING_ENABLE),
	__stringify(SW_ROUTING_DISABLE),
	__stringify(WLAN_AP_CONNECT),
	__stringify(WLAN_AP_DISCONNECT),
	__stringify(WLAN_STA_CONNECT),
	__stringify(WLAN_STA_DISCONNECT),
	__stringify(WLAN_CLIENT_CONNECT_EX),
	};

	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%s: %s evt, MAC: %pM sta_id: %d",
			adapter->dev->name, hdd_ipa_event_name[type], mac_addr,
			sta_id);

	if (type >= IPA_WLAN_EVENT_MAX)
		return -EINVAL;

	if (WARN_ON(is_zero_ether_addr(mac_addr)))
		return -EINVAL;

	hdd_ipa->stats.event[type]++;

	switch (type) {
	case WLAN_STA_CONNECT:
	case WLAN_AP_CONNECT:
		ret = hdd_ipa_setup_iface(hdd_ipa, adapter, sta_id);
		if (ret)
			goto end;
		break;

	case WLAN_STA_DISCONNECT:
	case WLAN_AP_DISCONNECT:
		hdd_ipa_cleanup_iface(adapter->ipa_context);
		break;

	case WLAN_CLIENT_CONNECT_EX:
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%d %d",
				adapter->dev->ifindex, sta_id);

		meta.msg_type = type;
		meta.msg_len = (sizeof(struct ipa_wlan_msg_ex) +
				sizeof(struct ipa_wlan_hdr_attrib_val));
		msg_ex = adf_os_mem_alloc (NULL, meta.msg_len);

		if (msg_ex == NULL) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
					"msg_ex allocation failed");
			return -ENOMEM;
		}
		strlcpy(msg_ex->name, adapter->dev->name,
				IPA_RESOURCE_NAME_MAX);
		msg_ex->num_of_attribs = 1;
		msg_ex->attribs[0].attrib_type = WLAN_HDR_ATTRIB_MAC_ADDR;
		msg_ex->attribs[0].offset = HDD_IPA_WLAN_HDR_DES_MAC_OFFSET;
		memcpy(msg_ex->attribs[0].u.mac_addr, mac_addr,
				IPA_MAC_ADDR_SIZE);

		ret = ipa_send_msg(&meta, msg_ex, hdd_ipa_msg_free_fn);

		if (ret) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%s: Evt: %d : %d",
					msg_ex->name, meta.msg_type,  ret);
			adf_os_mem_free(msg_ex);
			return ret;
		}
		hdd_ipa->stats.send_msg++;

		return 0;
	case WLAN_CLIENT_DISCONNECT:
		break;

	default:
		return 0;
	}

	meta.msg_len = sizeof(struct ipa_wlan_msg);
	msg = adf_os_mem_alloc(NULL, meta.msg_len);
	if (msg == NULL) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "msg allocation failed");
		return -ENOMEM;
	}

	meta.msg_type = type;
	strlcpy(msg->name, adapter->dev->name, IPA_RESOURCE_NAME_MAX);
	memcpy(msg->mac_addr, mac_addr, ETH_ALEN);

	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%s: Evt: %d",
					msg->name, meta.msg_type);

	ret = ipa_send_msg(&meta, msg, hdd_ipa_msg_free_fn);

	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%s: Evt: %d fail:%d",
					msg->name, meta.msg_type,  ret);
		adf_os_mem_free(msg);
		return ret;
	}

	hdd_ipa->stats.send_msg++;

end:
	return ret;
}


static void hdd_ipa_rx_pipe_desc_free(void)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	uint32_t i = 0, max_desc_cnt;
	struct ipa_tx_data_desc *desc, *tmp;

	max_desc_cnt = hdd_ipa->hw_desc_cnt * HDD_IPA_DESC_BUFFER_RATIO;

	spin_lock_bh(&hdd_ipa->q_lock);
	list_for_each_entry_safe(desc, tmp, &hdd_ipa->free_desc_head, link) {
		list_del(&desc->link);
		spin_unlock_bh(&hdd_ipa->q_lock);
		adf_os_mem_free(desc);
		spin_lock_bh(&hdd_ipa->q_lock);
		i++;
	}
	spin_unlock_bh(&hdd_ipa->q_lock);

	if (i != max_desc_cnt)
		HDD_IPA_LOG(VOS_TRACE_LEVEL_FATAL, "free desc leak");

}


static int hdd_ipa_rx_pipe_desc_alloc(void)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	uint32_t i, max_desc_cnt;
	int ret = 0;
	struct ipa_tx_data_desc *tmp_desc;

	hdd_ipa->hw_desc_cnt = IPA_NUM_OF_FIFO_DESC(
				hdd_ipa->hdd_ctx->cfg_ini->IpaDescSize);
	max_desc_cnt = hdd_ipa->hw_desc_cnt * HDD_IPA_DESC_BUFFER_RATIO;

	spin_lock_init(&hdd_ipa->q_lock);

	INIT_LIST_HEAD(&hdd_ipa->free_desc_head);
	INIT_LIST_HEAD(&hdd_ipa->pend_desc_head);
	hdd_ipa->stats.freeq_cnt = max_desc_cnt;
	for (i = 0; i < max_desc_cnt; i++) {
		tmp_desc = adf_os_mem_alloc(NULL,
				sizeof(struct ipa_tx_data_desc));
		if (!tmp_desc) {
			ret = -ENOMEM;

			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
					"Descriptor allocation failed\n");
			goto fail;
		}
		spin_lock_bh(&hdd_ipa->q_lock);
		list_add_tail(&tmp_desc->link, &hdd_ipa->free_desc_head);
		spin_unlock_bh(&hdd_ipa->q_lock);
	}


	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO,
		"Desc sz:%d h_desc_cnt:%d freeq_cnt:%llu",
		hdd_ipa->hdd_ctx->cfg_ini->IpaDescSize, hdd_ipa->hw_desc_cnt,
						hdd_ipa->stats.freeq_cnt);
	return ret;
fail:
	hdd_ipa_rx_pipe_desc_free();
	return ret;
}

static ssize_t hdd_ipa_debugfs_read_ipa_stats(struct file *file,
		char __user *user_buf, size_t count, loff_t *ppos)
{
	struct  hdd_ipa_priv *hdd_ipa = file->private_data;
	char *buf;
	unsigned int len = 0, buf_len = 1500;
	ssize_t ret_cnt;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%25s\n",
	 "IPA stats");
	len += scnprintf(buf + len, buf_len - len, "%25s\n\n",
	 "===========");

	len += scnprintf(buf + len, buf_len - len, "%20s %10d\n",
	 "RM State: ", atomic_read(&hdd_ipa->rm_state));
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RM Grants: ", hdd_ipa->stats.rm_grant);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RM Releases: ", hdd_ipa->stats.rm_release);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RM Grants Imm: ", hdd_ipa->stats.rm_grant_imm);
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "IPA RM Qued:", hdd_ipa->stats.rx_ipa_rm_qued);
#endif
	len += scnprintf(buf + len, buf_len - len, "%20s %10u\n\n",
	 "Pending cnt:", hdd_ipa->pending_desc_cnt);

#ifdef HDD_IPA_EXTRA_DP_COUNTERS
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "IPA HW Max Qued:", hdd_ipa->stats.rx_ipa_hw_max_qued);
#endif
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
	"IPA HW Maxed out", hdd_ipa->stats.rx_ipa_hw_maxed_out);

	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"IPA RX Prefilter: ", hdd_ipa->stats.prefilter);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"IPA RX send cnt:", hdd_ipa->stats.rx_ipa_sent_desc_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"IPA RX Write done:", hdd_ipa->stats.rx_ipa_write_done);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"IPA RX Exception: ", hdd_ipa->stats.rx_ipa_excep);
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"RXT recv:", hdd_ipa->stats.rxt_recv);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"RXT drop:", hdd_ipa->stats.rxt_drop);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"RXT desc drop:", hdd_ipa->stats.rxt_d_drop);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"RXT desc head drop:", hdd_ipa->stats.rxt_dh_drop);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"DH sent:", hdd_ipa->stats.rx_ipa_dh_sent);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"DH reclaim:", hdd_ipa->stats.rx_ipa_dh_reclaim);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"DH not used:", hdd_ipa->stats.rx_ipa_dh_not_used);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RXT 0 skb:", hdd_ipa->stats.rxt_0);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RXT 1 skb:", hdd_ipa->stats.rxt_1);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RXT 2 skb:", hdd_ipa->stats.rxt_2);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RXT 3 skb:", hdd_ipa->stats.rxt_3);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RXT 4 skb:", hdd_ipa->stats.rxt_4);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RXT 5 skb:", hdd_ipa->stats.rxt_5);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
	"RXT > 5 skb:", hdd_ipa->stats.rxt_6);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"Free Queue use:", hdd_ipa->stats.freeq_use);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"Free Queue reclaim:", hdd_ipa->stats.freeq_reclaim);
#endif
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"Free Queue Empty:", hdd_ipa->stats.freeq_empty);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
	"Free Queue cnt:", hdd_ipa->stats.freeq_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
	"IPA LB Count:", hdd_ipa->stats.ipa_lb_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
	"IPA TX Recieve:", hdd_ipa->stats.tx_ipa_recv);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
	"TX COMP Count:", hdd_ipa->stats.tx_comp_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
	"TX DP Err Count:", hdd_ipa->stats.tx_dp_err_cnt);

	if (len > buf_len)
		len = buf_len;

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_ipa_stats = {
		.read = hdd_ipa_debugfs_read_ipa_stats,
		.open = simple_open,
		.owner = THIS_MODULE,
		.llseek = default_llseek,
};


static int hdd_ipa_debugfs_init(struct hdd_ipa_priv *hdd_ipa)
{
#ifdef WLAN_OPEN_SOURCE
	hdd_ipa->debugfs_dir = debugfs_create_dir("cld",
					hdd_ipa->hdd_ctx->wiphy->debugfsdir);
	if (!hdd_ipa->debugfs_dir)
		return -ENOMEM;

	debugfs_create_file("ipa-stats", S_IRUSR, hdd_ipa->debugfs_dir,
						hdd_ipa, &fops_ipa_stats);
#endif
	return 0;
}

static void hdd_ipa_debugfs_remove(struct hdd_ipa_priv *hdd_ipa)
{
#ifdef WLAN_OPEN_SOURCE
	debugfs_remove_recursive(hdd_ipa->debugfs_dir);
#endif
}

/**
* hdd_ipa_init() - Allocate hdd_ipa resources, ipa pipe resource and register
* wlan interface with IPA module.
* @param
* hdd_ctx  : [in] pointer to HDD context
* @return         : VOS_STATUS_E_FAILURE - Errors
*                 : VOS_STATUS_SUCCESS - Ok
*/
VOS_STATUS hdd_ipa_init(hdd_context_t *hdd_ctx)
{
	struct hdd_ipa_priv *hdd_ipa = NULL;
	int ret, i;
	struct hdd_ipa_iface_context *iface_context = NULL;

	if (!hdd_ipa_is_enabled(hdd_ctx))
		return VOS_STATUS_SUCCESS;

	hdd_ipa = adf_os_mem_alloc(NULL, sizeof(struct hdd_ipa_priv));
	if (!hdd_ipa) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_FATAL, "hdd_ipa allocation failed");
		goto fail_setup_rm;
	}

	hdd_ctx->hdd_ipa = hdd_ipa;
	ghdd_ipa = hdd_ipa;
	hdd_ipa->hdd_ctx = hdd_ctx;

	/* Create the interface context */
	for (i = 0; i < HDD_IPA_MAX_IFACE; i++) {
		iface_context = &hdd_ipa->iface_context[i];
		iface_context->hdd_ipa = hdd_ipa;
		iface_context->cons_client =
			hdd_ipa_adapter_2_client[i].cons_client;
		iface_context->prod_client =
			hdd_ipa_adapter_2_client[i].prod_client;
		iface_context->iface_id = i;
	}

	ret = hdd_ipa_setup_rm(hdd_ipa);
	if (ret)
		goto fail_setup_rm;

	ret = hdd_ipa_setup_sys_pipe(hdd_ipa);
	if (ret)
		goto fail_create_sys_pipe;

	ret = hdd_ipa_rx_pipe_desc_alloc();
	if (ret)
		goto fail_alloc_rx_pipe_desc;

	ret = hdd_ipa_debugfs_init(hdd_ipa);
	if (ret)
		goto fail_alloc_rx_pipe_desc;

	return VOS_STATUS_SUCCESS;
fail_alloc_rx_pipe_desc:
	hdd_ipa_rx_pipe_desc_free();
fail_create_sys_pipe:
	hdd_ipa_destory_rm_resource(hdd_ipa);
fail_setup_rm:
	if (hdd_ipa)
		adf_os_mem_free(hdd_ipa);

	return VOS_STATUS_E_FAILURE;
}

VOS_STATUS hdd_ipa_cleanup(hdd_context_t *hdd_ctx)
{
	struct hdd_ipa_priv *hdd_ipa = hdd_ctx->hdd_ipa;

	if (!hdd_ipa_is_enabled(hdd_ctx))
		return VOS_STATUS_SUCCESS;

	hdd_ipa_debugfs_remove(hdd_ipa);

	if (hdd_ipa->pending_desc_cnt != 0) {
		msleep(5);
		HDD_IPA_LOG(VOS_TRACE_LEVEL_FATAL, "IPA Pending");
	}
	hdd_ipa_rx_pipe_desc_free();
	hdd_ipa_teardown_sys_pipe(hdd_ipa);
	hdd_ipa_destory_rm_resource(hdd_ipa);

	adf_os_mem_free(hdd_ipa);
	hdd_ctx->hdd_ipa = NULL;

	return VOS_STATUS_SUCCESS;
}
#endif
