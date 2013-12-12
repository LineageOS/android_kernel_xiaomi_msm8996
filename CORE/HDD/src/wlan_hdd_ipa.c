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

#define HDD_IPA_DESC_BUFFER_RATIO 4
#define HDD_IPA_IPV4_NAME_EXT "_ipv4"
#define HDD_IPA_IPV6_NAME_EXT "_ipv6"

#define HDD_IPA_RX_INACTIVITY_MSEC_DELAY 2000

const uint8_t ipa_set_hdr[] = {
/*IPA-WLAN HDR */
	0x00, 0x00,  /* Reserved */
#define HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET 2
#define HDD_IPA_WLAN_HDR_DEV_TYPE_MASK	0x80
#define HDD_IPA_WLAN_HDR_DEV_TYPE_AP	0x80
#define HDD_IPA_WLAN_HDR_DEV_TYPE_STA	0x00
#define HDD_IPA_WLAN_HDR_DEV_ID_MASK	0x7F
#define HDD_IPA_WLAN_HDR_STA_ID_OFFSET	3
	0x00, 0x00,
	/* dev_id and sta_id filled by wlan*/

	/* 802.3 header - 14 bytes*/
#define HDD_IPA_WLAN_HDR_DES_MAC_OFFSET 4
	0x00, 0x03, 0x7f, 0xaa, 0xbb, 0xcc,
	/* Des_MAC filled by IPA */
#define HDD_IPA_WLAN_HDR_SRC_MAC_OFFSET	10
	0x00, 0x03, 0x7f, 0xdd, 0xee, 0xff,
	/* Src. MAC filled by IPA */
	0x00, 0x00,
	/* length can be zero */

	0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00,
	/* LLC SNAP header 8 bytes */
#define HDD_IPA_WLAN_HDR_IP_VER_OFFSET 24
	0x08, 0x00
	/* type value(2 bytes) ,filled by wlan  */
	/* 0x0800 - IPV4, 0x86dd - IPV6 */
};


#define HDD_IPA_WLAN_HDR_LEN sizeof(ipa_set_hdr)
#define HDD_IPA_WLAN_HDR_ONLY_LEN 4
#define HDD_IPA_MAX_TX_PIPE_MAP	8
#define HDD_IPA_WLAN_HDR_PARTIAL 1

#define HDD_IPA_LOG(LVL, fmt, args...)	VOS_TRACE(VOS_MODULE_ID_HDD, LVL, \
				"%s:%d "fmt"\n", __func__, __LINE__, ## args)

enum hdd_ipa_rm_state {
	HDD_IPA_RM_RELEASED,
	HDD_IPA_RM_GRANT_PENDING,
	HDD_IPA_RM_GRANTED,
	HDD_IPA_RM_RELEASE_PENDING,
};

enum hdd_ipa_pipe_index {
	HDD_IPA_TX_VI_PIPE,
	HDD_IPA_TX_VO_PIPE,
	HDD_IPA_TX_BE_PIPE,
	HDD_IPA_TX_BK_PIPE,
	HDD_IPA_RX_PIPE,
	HDD_IPA_MAX_PIPE
};

enum hdd_ipa_ip_ver {
	HDD_IPA_IPV4 = 1,
	HDD_IPA_IPV6 = 2
};

uint8_t hdd_ipa_pipe_client[HDD_IPA_MAX_PIPE] = {
	IPA_CLIENT_WLAN1_CONS,
	IPA_CLIENT_WLAN2_CONS,
	IPA_CLIENT_WLAN3_CONS,
	IPA_CLIENT_WLAN4_CONS,
	IPA_CLIENT_WLAN1_PROD
};

uint8_t hdd_ipa_pipe_client_AC[] = {
	HDD_LINUX_AC_VI,
	HDD_LINUX_AC_VO,
	HDD_LINUX_AC_BE,
	HDD_LINUX_AC_BK
};

static struct hdd_ipa_tx_pipe_map{
	uint8_t tos_value;
	enum ipa_client_type client;
	uint8_t ac;
} hdd_ipa_tx_pipe_map_info[HDD_IPA_MAX_TX_PIPE_MAP] = {
	/* BK */
	{1, IPA_CLIENT_WLAN1_CONS, HDD_LINUX_AC_BK},
	{2, IPA_CLIENT_WLAN1_CONS, HDD_LINUX_AC_BK},
	/* BE */
	{0, IPA_CLIENT_WLAN2_CONS, HDD_LINUX_AC_BE},
	{3, IPA_CLIENT_WLAN2_CONS, HDD_LINUX_AC_BE},
	/* VI */
	{4, IPA_CLIENT_WLAN3_CONS, HDD_LINUX_AC_VI},
	{5, IPA_CLIENT_WLAN3_CONS, HDD_LINUX_AC_VI},
	/* VO */
	{6, IPA_CLIENT_WLAN4_CONS, HDD_LINUX_AC_VO},
	{7, IPA_CLIENT_WLAN4_CONS, HDD_LINUX_AC_VO},
};

struct hdd_ipa_sys_pipe {
	uint32_t conn_hdl;
	uint8_t conn_hdl_valid;
	struct ipa_sys_connect_params ipa_sys_params;
};

struct hdd_ipa_priv {
	struct hdd_ipa_sys_pipe sys_pipe[HDD_IPA_MAX_PIPE];
	atomic_t rm_state;
#ifndef HDD_IPA_USE_IPA_RM_TIMER
	struct timer_list rm_timer;
	uint8_t rm_timer_on;
#endif
	uint32_t pending_desc_cnt;
	uint32_t hw_desc_cnt;
	spinlock_t q_lock;
	struct list_head free_desc_head;
	struct list_head pend_desc_head;

	hdd_context_t *hdd_ctx;

	struct dentry *debugfs_dir;
	struct {
		uint64_t prefilter;
		uint64_t rm_grant;
		uint64_t rm_release;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
		uint64_t rx_ipa_rm_qued;
#endif
		uint64_t rx_ipa_sent_desc_cnt;
		uint64_t rx_ipa_write_done;
		uint64_t rx_ipa_excep;

		uint64_t rx_ipa_hw_maxed_out;

		uint64_t tx_ipa_recv;
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
	}stats;
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

static inline void *hdd_ipa_kzalloc(uint32_t size)
{
	void *data = NULL;

	data = adf_os_mem_alloc(NULL, size);
	return data;
}

static inline struct ipa_tx_data_desc * hdd_ipa_get_desc_from_freeq(void)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	struct ipa_tx_data_desc *desc = NULL;

	spin_lock_bh(&ghdd_ipa->q_lock);
	if(!list_empty(&ghdd_ipa->free_desc_head)) {
		desc = list_first_entry(&ghdd_ipa->free_desc_head, struct ipa_tx_data_desc, link);
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

static inline bool hdd_ipa_can_pre_filter(struct hdd_ipa_priv *hdd_ipa)
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

static int hdd_ipa_rm_request(struct hdd_ipa_priv *hdd_ipa)
{
	int ret = 0;

	if (!hdd_ipa_is_rm_enabled(hdd_ipa)) {
		atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_GRANTED);
		return 0;
	}
#ifdef HDD_IPA_USE_IPA_RM_TIMER
	ret = ipa_rm_inactivity_timer_request_resource(
						IPA_RM_RESOURCE_WLAN_PROD);
#else
	ret = ipa_rm_request_resource(IPA_RM_RESOURCE_WLAN_PROD);
#endif
	if (ret == 0) {
		atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_GRANTED);
		hdd_ipa->stats.rm_grant++;
	}
	return ret;
}

static int hdd_ipa_rm_release(struct hdd_ipa_priv *hdd_ipa)
{
	int ret = 0;

	if (!hdd_ipa_is_rm_enabled(hdd_ipa))
		return 0;

#ifdef HDD_IPA_USE_IPA_RM_TIMER
	ret = ipa_rm_inactivity_timer_release_resource(
						IPA_RM_RESOURCE_WLAN_PROD);
#else
	ret = ipa_rm_release_resource(IPA_RM_RESOURCE_WLAN_PROD);
#endif
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

	if (event == IPA_RM_RESOURCE_GRANTED) {
		atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_GRANTED);
		hdd_ipa->stats.rm_grant++;
		hdd_ipa_process_evt(HDD_IPA_RM_GRANT_EVT, NULL);
	} else {
		if (event == IPA_RM_RESOURCE_RELEASED) {
			atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_RELEASED);
			hdd_ipa->stats.rm_release++;
		}
	}
}

static int hdd_ipa_setup_rm(struct hdd_ipa_priv *hdd_ipa)
{
	struct ipa_rm_create_params create_params = {0};
	int ret;

	if (!hdd_ipa_is_rm_enabled(hdd_ipa))
		return 0;
	create_params.name = IPA_RM_RESOURCE_WLAN_PROD;
	create_params.reg_params.user_data = hdd_ipa;
	create_params.reg_params.notify_cb = hdd_ipa_rm_notify;
	create_params.request_resource = NULL;
	create_params.release_resource = NULL;

	ret = ipa_rm_create_resource(&create_params);
	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "create resource fail");
		goto setup_rm_fail;
	}

#ifdef HDD_IPA_USE_IPA_RM_TIMER
	ret = ipa_rm_inactivity_timer_init(IPA_RM_RESOURCE_WLAN_PROD,
					HDD_IPA_RX_INACTIVITY_MSEC_DELAY);
	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "timer fail");
		goto setup_rm_fail;
	}
#endif

setup_rm_fail:
	return ret;
}

static void hdd_ipa_destory_rm_resource(struct hdd_ipa_priv *hdd_ipa)
{
	int ret;

	if (!hdd_ipa_is_rm_enabled(hdd_ipa))
		return;

	ipa_rm_delete_dependency(IPA_RM_RESOURCE_WLAN_PROD,
						IPA_RM_RESOURCE_A2_CONS);
#ifdef HDD_IPA_USE_IPA_RM_TIMER
	ipa_rm_inactivity_timer_destroy(IPA_RM_RESOURCE_WLAN_PROD);
#endif
	ret = ipa_rm_delete_resource(IPA_RM_RESOURCE_WLAN_PROD);
	if (ret)
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "fail");
}

void hdd_ipa_rm_timer_handler(unsigned long ptr)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	atomic_set(&hdd_ipa->rm_state,
			 HDD_IPA_RM_RELEASE_PENDING);
	hdd_ipa_rm_release(hdd_ipa);
}

void hdd_ipa_send_skb_to_network(adf_nbuf_t skb, hdd_adapter_t *adap_dev)
{
		if (!adap_dev || (adap_dev &&
				adap_dev->magic != WLAN_HDD_ADAPTER_MAGIC)) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Invalid sta_id");
			adf_nbuf_free(skb);
			return;
		}
		skb->dev = adap_dev->dev;
		skb->protocol = eth_type_trans(skb, skb->dev);
		skb->ip_summed = CHECKSUM_NONE;
		++adap_dev->hdd_stats.hddTxRxStats.rxPackets;
		++adap_dev->stats.rx_packets;
		adap_dev->stats.rx_bytes += skb->len;
		if (netif_rx_ni(skb) == NET_RX_SUCCESS)
			++adap_dev->hdd_stats.hddTxRxStats.rxDelivered;
		else
			++adap_dev->hdd_stats.hddTxRxStats.rxRefused;
		adap_dev->dev->last_rx = jiffies;
}

static void hdd_ipa_send_pkt_to_ipa(struct ipa_tx_data_desc *send_desc_head,
							int send_desc_cnt)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	struct ipa_tx_data_desc *send_desc;
	uint32_t cur_send_cnt = 0;
#ifndef HDD_IPA_USE_IPA_RM_TIMER
		if (hdd_ipa->rm_timer_on) {
			del_timer(&hdd_ipa->rm_timer);
			hdd_ipa->rm_timer_on = 0;
		}
#endif
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
			spin_unlock_bh(&hdd_ipa->q_lock);
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
			hdd_ipa->stats.rx_ipa_dh_sent++; //for desc head
#endif
			ipa_tx_dp_mul(hdd_ipa_pipe_client[HDD_IPA_RX_PIPE],
							send_desc_head);
		} else {
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
			hdd_ipa->stats.rx_ipa_hw_max_qued += send_desc_cnt;
#endif

			hdd_ipa->stats.rx_ipa_hw_maxed_out++;
			list_splice_tail_init(&send_desc_head->link,
					&hdd_ipa->pend_desc_head);
			list_add_tail(&send_desc_head->link, &hdd_ipa->free_desc_head);
			hdd_ipa->stats.freeq_cnt++;
#ifdef HDD_IPA_EXTRA_DP_COUNTERS
			hdd_ipa->stats.rx_ipa_dh_not_used++;
			hdd_ipa->stats.freeq_reclaim++;
#endif
			spin_unlock_bh(&hdd_ipa->q_lock);
		}

}

static int hdd_ipa_is_ip_pkt(void *data, uint8_t ip_ver)
{
	struct ethhdr *eth = data;
	struct llc_snap_hdr {
		uint8_t dsap;
		uint8_t ssap;
		uint8_t resv[4];
		__be16 eth_type;
	} __packed;
	struct llc_snap_hdr *ls_hdr;
	uint16_t eth_type;
	int ret = 0;

	eth_type = be16_to_cpu(eth->h_proto);
	if (eth_type < 0x600) {
		/* Non Ethernet II framing format */
		ls_hdr = (struct llc_snap_hdr *)((uint8_t *)data +
						sizeof(struct ethhdr));
		/* TODO Is this needed
		if ((ls_hdr->dsap == 0xAA && ls_hdr->ssap == 0xAA) ||
			(ls_hdr->dsap == 0xAB && ls_hdr->ssap == 0xAB))
		*/
		eth_type = be16_to_cpu(ls_hdr->eth_type);
	}

	if (eth_type == 0x0800 && ip_ver == HDD_IPA_IPV4)
		ret = 1;
	else if (eth_type == 0x86dd && ip_ver == HDD_IPA_IPV6)
		ret = 1;

	return ret;
}


static void hdd_ipa_process_evt(int evt, void *priv)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	struct hdd_ipa_rxt *rxt;
	struct ipa_tx_data_desc *send_desc_head = NULL, *send_desc,
					*done_desc_head, *done_desc, *tmp;
	hdd_adapter_t *adap_dev = NULL;
	adf_nbuf_t buf, next_buf;
	uint8_t dev_id, cur_cnt = 0, iftype;

	switch (evt) {
	case HDD_IPA_RXT_EVT:
		rxt = priv;

		adap_dev = hdd_ipa->hdd_ctx->sta_to_adapter[rxt->sta_id];
		if (!adap_dev ||
		(adap_dev && adap_dev->magic != WLAN_HDD_ADAPTER_MAGIC)) {
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
		dev_id = adap_dev->dev->ifindex;
		iftype = adap_dev->wdev.iftype;
		/* send_desc_head is a anchor node */
		send_desc_head = hdd_ipa_get_desc_from_freeq();
		if (!send_desc_head) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "send_desc_head=Null. FreeQ Empty");
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
			next_buf = adf_nbuf_queue_next(buf);
			if (hdd_ipa_can_pre_filter(hdd_ipa) &&
				(!hdd_ipa_is_ip_pkt(buf->data, HDD_IPA_IPV4) ||
				(!hdd_ipa_is_ipv6_enabled(hdd_ipa) &&
				hdd_ipa_is_ip_pkt(buf->data, HDD_IPA_IPV6)))) {
				hdd_ipa->stats.prefilter++;
				hdd_ipa_send_skb_to_network(buf, adap_dev);
				buf = next_buf;
				continue;
			}

			skb_push(buf, HDD_IPA_WLAN_HDR_ONLY_LEN);
			memset(buf->data, 0, HDD_IPA_WLAN_HDR_ONLY_LEN);
			buf->data[HDD_IPA_WLAN_HDR_STA_ID_OFFSET] = rxt->sta_id;
			buf->data[HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET] |=
					dev_id & HDD_IPA_WLAN_HDR_DEV_ID_MASK;
			if (iftype == NL80211_IFTYPE_AP ||
					iftype == NL80211_IFTYPE_P2P_GO) {
				buf->data[HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET] |=
						HDD_IPA_WLAN_HDR_DEV_TYPE_AP;
			} else {
				buf->data[HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET] |=
						HDD_IPA_WLAN_HDR_DEV_TYPE_STA;
			}

			/* TODO Chk if needed
				if (hdd_ipa_is_ip_pkt(buf->data, HDD_IPA_IPV6) {
				buf->data[HDD_IPA_WLAN_HDR_IP_VER_OFFSET]
									= 0x86;
				buf->data[HDD_IPA_WLAN_HDR_IP_VER_OFFSET + 1]
									= 0xdd;
			}
			skb_pull(buf, HDD_IPA_WLAN_HDR_LEN);
			skb_push(buf, HDD_IPA_WLAN_HDR_ONLY_LEN);*/
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
			list_add_tail(&send_desc_head->link, &hdd_ipa->free_desc_head);
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
			//hdd_ipa_rm_request can immediately grant so check again.
			if (atomic_read(&hdd_ipa->rm_state)
						== HDD_IPA_RM_GRANT_PENDING) {
				spin_lock_bh(&hdd_ipa->q_lock);
				list_splice_tail_init(&send_desc_head->link,
						&hdd_ipa->pend_desc_head);
				/* return anchor node */
				list_add_tail(&send_desc_head->link,
						&hdd_ipa->free_desc_head);
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
			list_add_tail(&done_desc->link, &hdd_ipa->free_desc_head);
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
						!= HDD_IPA_RM_RELEASE_PENDING) {
#ifndef HDD_IPA_USE_IPA_RM_TIMER
				del_timer(&hdd_ipa->rm_timer);
				mod_timer(&hdd_ipa->rm_timer,
					jiffies +
					msecs_to_jiffies(
					HDD_IPA_RX_INACTIVITY_MSEC_DELAY));
				hdd_ipa->rm_timer_on = 1;
#else
				atomic_set(&hdd_ipa->rm_state,
						 HDD_IPA_RM_RELEASE_PENDING);
				hdd_ipa_rm_release(hdd_ipa);
#endif
			}
		} else {
			/* no rx pkt come in so flash the last few */
			hdd_ipa_send_pkt_to_ipa(NULL, 0);
		}
	break;
	}
}

static void hdd_ipa_w2i_write_done_handler(
					struct ipa_tx_data_desc *done_desc_head)
{
	hdd_ipa_process_evt(HDD_IPA_WRITE_DONE_EVT, done_desc_head);
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



void hdd_ipa_w2i_cb(void *priv, enum ipa_dp_evt_type evt, unsigned long data)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	uint8_t client;
	struct ipa_tx_data_desc *done_desc_head;
	adf_nbuf_t skb;
	uint8_t sta_id, dev_id;
	hdd_adapter_t *adap_dev;

	client = *((uint8_t *)priv);
	if (client != hdd_ipa_pipe_client[HDD_IPA_RX_PIPE]) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR,
				"w2i cb wrong pipe: %d %x %x",
				client, priv,
				&hdd_ipa_pipe_client[HDD_IPA_RX_PIPE]);
		return;
	}

	switch (evt) {
	case IPA_RECEIVE:
		skb = (adf_nbuf_t) data;
		sta_id = skb->data[HDD_IPA_WLAN_HDR_STA_ID_OFFSET];
		dev_id = skb->data[HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET];
		adap_dev = hdd_ipa->hdd_ctx->sta_to_adapter[sta_id];
		skb_pull(skb, HDD_IPA_WLAN_HDR_ONLY_LEN);
		hdd_ipa->stats.rx_ipa_excep++;
		hdd_ipa_send_skb_to_network(skb, adap_dev);
		break;
	case IPA_WRITE_DONE:
		done_desc_head = (struct ipa_tx_data_desc *)data;
		hdd_ipa_w2i_write_done_handler(done_desc_head);
	break;
	}
}

void hdd_ipa_nbuf_cb(adf_nbuf_t skb)
{
	ipa_free_skb(skb);
}

void hdd_ipa_tx_process(adf_nbuf_t skb, uint8_t ac)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	uint8_t sta_id;
	hdd_adapter_t *adap_dev;

	skb->queue_mapping = ac;
	sta_id = skb->data[HDD_IPA_WLAN_HDR_STA_ID_OFFSET];
	adap_dev = hdd_ipa->hdd_ctx->sta_to_adapter[sta_id];
	if (!adap_dev
		|| (adap_dev && adap_dev->magic != WLAN_HDD_ADAPTER_MAGIC)) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Invalid sta_id %d", sta_id);
		ipa_free_skb(skb);
		return;
	}
	skb->dev = adap_dev->dev;
	NBUF_OWNER_ID(skb) = IPA_NBUF_OWNER_ID;
	NBUF_CALLBACK_FN(skb) = hdd_ipa_nbuf_cb;
	skb_pull(skb, HDD_IPA_WLAN_HDR_ONLY_LEN);
	(adap_dev->dev->netdev_ops->ndo_start_xmit)(skb, adap_dev->dev);
}

void hdd_ipa_i2w_cb(void *priv, enum ipa_dp_evt_type evt, unsigned long data)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	adf_nbuf_t skb;
	uint8_t client;
	uint8_t i, ac = HDD_LINUX_AC_BE;

	if (evt == IPA_RECEIVE) {
		client = *((uint8_t *)priv);
		skb = (adf_nbuf_t) data;
		for (i = 0; i < HDD_IPA_MAX_TX_PIPE_MAP; i++) {
			if (client == hdd_ipa_tx_pipe_map_info[i].client) {
				ac = hdd_ipa_tx_pipe_map_info[i].ac;
				break;
			}
		}
		hdd_ipa->stats.tx_ipa_recv++;
		hdd_ipa_tx_process(skb, ac);
	} else
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "i2w cb wrong evt: %d", evt);
}

static int hdd_ipa_setup_sys_pipe(struct hdd_ipa_priv *hdd_ipa)
{
	int i, ret = 0;
	struct ipa_sys_connect_params *ipa;

	/*setup TX pipes */
	for (i = 0; i < HDD_IPA_RX_PIPE; i++) {
		ipa = &hdd_ipa->sys_pipe[i].ipa_sys_params;

		ipa->client = hdd_ipa_pipe_client[i];
		ipa->desc_fifo_sz = hdd_ipa->hdd_ctx->cfg_ini->IpaDescSize;
		ipa->priv = &hdd_ipa_pipe_client[i];
		ipa->notify = hdd_ipa_i2w_cb;

		ipa->ipa_ep_cfg.hdr.hdr_len = HDD_IPA_WLAN_HDR_LEN;
		ipa->ipa_ep_cfg.mode.mode = IPA_BASIC;

		ret = ipa_setup_sys_pipe(ipa, &(hdd_ipa->sys_pipe[i].conn_hdl));
		if (ret) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Fail: %d", ret);
			goto setup_sys_pipe_fail;
		}
		hdd_ipa->sys_pipe[i].conn_hdl_valid = 1;
	}

	ipa = &hdd_ipa->sys_pipe[HDD_IPA_RX_PIPE].ipa_sys_params;

	ipa->client = hdd_ipa_pipe_client[HDD_IPA_RX_PIPE];
	ipa->desc_fifo_sz = hdd_ipa->hdd_ctx->cfg_ini->IpaDescSize;
	ipa->priv = &hdd_ipa_pipe_client[HDD_IPA_RX_PIPE];
	ipa->notify = hdd_ipa_w2i_cb;

	ipa->ipa_ep_cfg.nat.nat_en = IPA_BYPASS_NAT;
	ipa->ipa_ep_cfg.hdr.hdr_len = HDD_IPA_WLAN_HDR_LEN;
	ipa->ipa_ep_cfg.hdr.hdr_ofst_metadata_valid = 1;
	ipa->ipa_ep_cfg.mode.mode = IPA_BASIC;

	ret = ipa_setup_sys_pipe(ipa, &(hdd_ipa->sys_pipe[i].conn_hdl));
	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "Fail: %d", ret);
		goto setup_sys_pipe_fail;
	}
	hdd_ipa->sys_pipe[HDD_IPA_RX_PIPE].conn_hdl_valid = 1;

setup_sys_pipe_fail:
	return ret;
}

/* Disconnect all the Sys pipes */
void hdd_ipa_teardown_sys_pipe(struct hdd_ipa_priv *hdd_ipa)
{
	int ret = 0, i;
	for (i = 0; i < HDD_IPA_MAX_PIPE; i++) {
		if (hdd_ipa->sys_pipe[i].conn_hdl_valid) {
			ret = ipa_teardown_sys_pipe(
						hdd_ipa->sys_pipe[i].conn_hdl);
			if (ret)
				HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "fail: %d",
									 ret);

			hdd_ipa->sys_pipe[i].conn_hdl_valid = 0;
		}
	}
}

int hdd_ipa_register_interface(struct hdd_ipa_priv *hdd_ipa, uint8_t iftype,
					uint8_t sta_id, const char *ifname)
{
#define HDD_IPA_TOS_MASK	0xE0
	struct ipa_tx_intf tx_intf;
	struct ipa_rx_intf rx_intf;
	struct ipa_ioc_tx_intf_prop *tx_prop = NULL;
	struct ipa_ioc_rx_intf_prop *rx_prop = NULL;

	char ipv4_hdr_name[IPA_RESOURCE_NAME_MAX];
	char ipv6_hdr_name[IPA_RESOURCE_NAME_MAX];

	int i, j, ip_max = HDD_IPA_IPV4;
	int ret = 0;

	if (hdd_ipa_is_ipv6_enabled(hdd_ipa))
		ip_max = HDD_IPA_IPV6;

	/* Allocate TX properties for TOS categories, 1 each for IPv4 & IPv6 */
	tx_prop = hdd_ipa_kzalloc(sizeof(struct ipa_ioc_tx_intf_prop) *
					HDD_IPA_MAX_TX_PIPE_MAP * ip_max);
	if (!tx_prop) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "ENOMEM");
		goto register_interface_fail;
	}

	/* Allocate RX properties, 1 each for IPv4 & IPv6 */
	rx_prop = hdd_ipa_kzalloc(sizeof(struct ipa_ioc_rx_intf_prop)
								 * ip_max);
	if (!rx_prop) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "ENOMEM");
		goto register_interface_fail;
	}
	vos_mem_zero(&tx_intf, sizeof(tx_intf));
	vos_mem_zero(&rx_intf, sizeof(rx_intf));

	snprintf(ipv4_hdr_name, IPA_RESOURCE_NAME_MAX, "%s%s",
		ifname, HDD_IPA_IPV4_NAME_EXT);
	rx_prop[IPA_IP_v4].ip = IPA_IP_v4;
	if (hdd_ipa_is_ipv6_enabled(hdd_ipa)) {
		snprintf(ipv6_hdr_name, IPA_RESOURCE_NAME_MAX, "%s%s",
			ifname, HDD_IPA_IPV6_NAME_EXT);
		rx_prop[IPA_IP_v6].ip = IPA_IP_v6;
	}
	/*
	TOS value: 1, 2 - > Maps to BK pipe [WLAN1_CONS]
	TOS value: 0, 3 - > Maps to BE pipe [WLAN2_CONS]
	TOS value: 4, 5 - > Maps to VI pipe [WLAN3_CONS]
	TOS Value: 6, 7 - > Maps to VO pipe [WLAN4_CONS]
	*/

	/*
	IP-TOS - 8bits
	: DSCP(6-bits) ECN(2-bits)
	: DSCP - P2 P1 P0 X X X
	where (P2 P1 P0) form 802.1D
	So shifting tos_value by 5 bits before passing to IPA. Also IPA
	required mask to be set for 3 MSB bits.
	*/

	for (i = 0; i < HDD_IPA_MAX_TX_PIPE_MAP; i++) {
		tx_prop[i].ip = IPA_IP_v4;
		tx_prop[i].attrib.attrib_mask = IPA_FLT_TOS_MASKED;
		tx_prop[i].attrib.tos_value =
				hdd_ipa_tx_pipe_map_info[i].tos_value << 5;
		tx_prop[i].attrib.tos_mask = HDD_IPA_TOS_MASK;
		tx_prop[i].dst_pipe = hdd_ipa_tx_pipe_map_info[i].client;
		strlcpy(tx_prop[i].hdr_name, ipv4_hdr_name,
							IPA_RESOURCE_NAME_MAX);
		tx_intf.num_props++;
		if (hdd_ipa_is_ipv6_enabled(hdd_ipa)) {
			j = i + HDD_IPA_MAX_TX_PIPE_MAP;

			tx_prop[j].ip = IPA_IP_v6;
			tx_prop[j].attrib.attrib_mask = IPA_FLT_TOS_MASKED;
			tx_prop[j].attrib.tos_value =
				hdd_ipa_tx_pipe_map_info[i].tos_value << 5;
			tx_prop[j].attrib.tos_mask = HDD_IPA_TOS_MASK;
			tx_prop[j].dst_pipe =
					hdd_ipa_tx_pipe_map_info[i].client;
			strlcpy(tx_prop[j].hdr_name, ipv6_hdr_name,
							IPA_RESOURCE_NAME_MAX);
			tx_intf.num_props++;
		}
	}

	for (i = 0; i < ip_max; i++) {
		rx_prop[i].attrib.attrib_mask = IPA_FLT_META_DATA;
		if (iftype == NL80211_IFTYPE_AP ||
					iftype == NL80211_IFTYPE_P2P_GO) {
			rx_prop[i].attrib.meta_data =
				HDD_IPA_WLAN_HDR_DEV_TYPE_AP
				<< ((HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET-1) * 8);
		} else {
			rx_prop[i].attrib.meta_data =
				HDD_IPA_WLAN_HDR_DEV_TYPE_STA
				<< ((HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET-1) * 8);
		}
		rx_prop[i].attrib.meta_data_mask =
				HDD_IPA_WLAN_HDR_DEV_TYPE_MASK
				<< ((HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET-1) * 8);
		rx_prop[i].src_pipe = IPA_CLIENT_WLAN1_PROD;

		rx_intf.num_props++;
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

static int hdd_ipa_add_header_info(uint8_t sta_id, uint8_t *mac_addr)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	uint8_t dev_id, wlan_iftype;
	char *ifname;
	struct ipa_ioc_add_hdr *ipahdr = NULL;
	int ret = -EINVAL;
	hdd_adapter_t *adap_dev;

	adap_dev = hdd_ipa->hdd_ctx->sta_to_adapter[sta_id];
	if (!adap_dev) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "adap_dev NULL");
		goto add_header_info_ctx_fail;
	}

	dev_id = adap_dev->dev->ifindex;
	wlan_iftype = adap_dev->wdev.iftype;
	ifname = adap_dev->dev->name;

	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "Mode: %d Add Partial hdr: %s, %p\n",
						wlan_iftype, ifname, mac_addr);
	if (ifname == NULL) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "ifname NULL");
		goto add_header_info_ctx_fail;
	}

	/* dynamically allocate the memory to add the hdrs */
	ipahdr = hdd_ipa_kzalloc(sizeof(struct ipa_ioc_add_hdr) +
						sizeof(struct ipa_hdr_add));
	if (!ipahdr) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "%s: ENOMEM", ifname);
		return -ENOMEM;
	}

	ipahdr->commit = 0;
	ipahdr->num_hdrs = 1;
	/* Set the Source MAC */
	memcpy(ipahdr->hdr[0].hdr, ipa_set_hdr, HDD_IPA_WLAN_HDR_LEN);
	memcpy(&ipahdr->hdr[0].hdr[HDD_IPA_WLAN_HDR_SRC_MAC_OFFSET], mac_addr,
								ETH_ALEN);

	/* Check the interface is AP OR STA mode, and set the station ID */
	ipahdr->hdr[0].hdr[HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET] |=
					dev_id & HDD_IPA_WLAN_HDR_DEV_ID_MASK;
	ipahdr->hdr[0].hdr[HDD_IPA_WLAN_HDR_STA_ID_OFFSET] = sta_id;
	if (wlan_iftype == NL80211_IFTYPE_AP ||
		wlan_iftype == NL80211_IFTYPE_P2P_GO) {
		ipahdr->hdr[0].hdr[HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET] |=
						HDD_IPA_WLAN_HDR_DEV_TYPE_AP;
	} else {
		ipahdr->hdr[0].hdr[HDD_IPA_WLAN_HDR_DEV_INFO_OFFSET] |=
						HDD_IPA_WLAN_HDR_DEV_TYPE_STA;
	}

	snprintf(ipahdr->hdr[0].name, IPA_RESOURCE_NAME_MAX, "%s%s",
		ifname, HDD_IPA_IPV4_NAME_EXT);
	ipahdr->hdr[0].hdr_len = HDD_IPA_WLAN_HDR_LEN;
	ipahdr->hdr[0].is_partial = HDD_IPA_WLAN_HDR_PARTIAL;
	ipahdr->hdr[0].hdr_hdl = 0;

	ret = ipa_add_hdr(ipahdr);

	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_ERROR, "%s IPv4 fail: %d", ifname
									, ret);
		goto add_header_info_fail;
	}

	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%s: IPv4 hdr_hdl: %x",
				ipahdr->hdr[0].name, ipahdr->hdr[0].hdr_hdl);
	if (hdd_ipa_is_ipv6_enabled(hdd_ipa)) {
		snprintf(ipahdr->hdr[0].name, IPA_RESOURCE_NAME_MAX, "%s%s",
			ifname, HDD_IPA_IPV6_NAME_EXT);
		/* Set the type to IPV6 in the header*/
		ipahdr->hdr[0].hdr[HDD_IPA_WLAN_HDR_IP_VER_OFFSET] = 0x86;
		ipahdr->hdr[0].hdr[HDD_IPA_WLAN_HDR_IP_VER_OFFSET + 1] = 0xdd;

		ret = ipa_add_hdr(ipahdr);
		if (ret) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO,
					"%s: IPv6 hdr fail: %d", ifname, ret);
			goto add_header_info_fail;
		}

		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%s: IPv6 hdr_hdl: %x",
				ipahdr->hdr[0].name, ipahdr->hdr[0].hdr_hdl);
	}
	/* Configure the TX and RX pipes filter rules */
	ret = hdd_ipa_register_interface(hdd_ipa, wlan_iftype, sta_id, ifname);

add_header_info_fail:
	adf_os_mem_free(ipahdr);
add_header_info_ctx_fail:
	return ret;
}

void hdd_remove_ipa_header(char *name)
{
	struct ipa_ioc_get_hdr hdrlookup;
	int ret = 0, len;
	struct ipa_ioc_del_hdr *ipahdr;

	vos_mem_zero(&hdrlookup, sizeof(hdrlookup));
	strlcpy(hdrlookup.name, name, sizeof(hdrlookup.name));
	ret = ipa_get_hdr(&hdrlookup);
	if (ret) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "Hdr deleted already %s, %d",
								 name, ret);
		return;
	}


	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "hdl: %x", hdrlookup.hdl);
	len = sizeof(struct ipa_ioc_del_hdr) + sizeof(struct ipa_hdr_del)*1;
	ipahdr = (struct ipa_ioc_del_hdr *) hdd_ipa_kzalloc(len);
	if (ipahdr == NULL) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "ENOMEM");
		return;
	}
	ipahdr->num_hdls = 1;
	ipahdr->commit = 0;
	ipahdr->hdl[0].hdl = hdrlookup.hdl;
	ipahdr->hdl[0].status = -1;
	ret = ipa_del_hdr(ipahdr);
	if (ret != 0)
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "Fail: %d", ret);

	adf_os_mem_free(ipahdr);
}

void hdd_ipa_clean_hdr(hdd_adapter_t *adap_dev, uint8_t sta_id)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	int ret;
	char name_ipa[IPA_RESOURCE_NAME_MAX];

	/* Remove the headers */
	snprintf(name_ipa, IPA_RESOURCE_NAME_MAX, "%s%s",
		adap_dev->dev->name, HDD_IPA_IPV4_NAME_EXT);
	hdd_remove_ipa_header(name_ipa);

	if (hdd_ipa_is_ipv6_enabled(hdd_ipa)) {
		snprintf(name_ipa, IPA_RESOURCE_NAME_MAX, "%s%s",
			adap_dev->dev->name, HDD_IPA_IPV6_NAME_EXT);
		hdd_remove_ipa_header(name_ipa);
	}
	/* unregister the interface with IPA */
	ret = ipa_deregister_intf(adap_dev->dev->name);
	if (ret)
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO,
		"%s: ipa_deregister_intf fail: %d", adap_dev->dev->name, ret);
}


static void hdd_ipa_msg_free_fn(void *buff, uint32_t len, uint32_t type)
{
	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "msg type:%d, len:%d\n", type, len);
	adf_os_mem_free(buff);
}

int hdd_ipa_wlan_evt(void *Adapter, uint8_t sta_id,
			enum ipa_wlan_event type, uint8_t *mac_addr)
{
	hdd_adapter_t *adap_dev = Adapter;
	struct ipa_msg_meta meta;
	struct ipa_wlan_msg *msg;
	struct ipa_wlan_msg_ex *msg_ex = NULL;
	int ret;
	const char *hdd_ipa_event_name[IPA_EVENT_MAX] = {
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
			adap_dev->dev->name, hdd_ipa_event_name[type],
							mac_addr, sta_id);
	if (type >= IPA_EVENT_MAX)
		return -EINVAL;

	if (WARN_ON(is_zero_ether_addr(mac_addr)))
		return -EINVAL;

	switch (type) {
	case WLAN_STA_CONNECT:
	case WLAN_AP_CONNECT:
		hdd_ipa_add_header_info(sta_id, mac_addr);
		break;

	case WLAN_STA_DISCONNECT:
	case WLAN_AP_DISCONNECT:
		hdd_ipa_clean_hdr(adap_dev, sta_id);
		break;

	case WLAN_CLIENT_CONNECT_EX:
		meta.msg_type = type;
		meta.msg_len = (sizeof(struct ipa_wlan_msg_ex) +
				sizeof(struct ipa_wlan_hdr_attrib_val) * 2);
		msg_ex = hdd_ipa_kzalloc (meta.msg_len);
		if (msg_ex == NULL) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "ENOMEM");
			return -ENOMEM;
		}
		strlcpy(msg_ex->name, adap_dev->dev->name, IPA_RESOURCE_NAME_MAX);
		msg_ex->num_of_attribs = 2;
		msg_ex->attribs[0].attrib_type = WLAN_HDR_ATTRIB_MAC_ADDR;
		msg_ex->attribs[0].offset = HDD_IPA_WLAN_HDR_DES_MAC_OFFSET;
		memcpy(msg_ex->attribs[0].u.mac_addr, mac_addr,
							IPA_MAC_ADDR_SIZE);

		msg_ex->attribs[1].attrib_type = WLAN_HDR_ATTRIB_STA_ID;
		msg_ex->attribs[1].offset = HDD_IPA_WLAN_HDR_STA_ID_OFFSET;
		msg_ex->attribs[1].u.sta_id = sta_id;
		ret = ipa_send_msg(&meta, msg_ex, hdd_ipa_msg_free_fn);

		if (ret) {
			HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "%s: Evt: %d : %d",
					msg_ex->name, meta.msg_type,  ret);
			adf_os_mem_free(msg_ex);
			return ret;
		}
		return 0;
	case WLAN_CLIENT_DISCONNECT:
		break;

	default:
		return 0;
	}

	meta.msg_len = sizeof(struct ipa_wlan_msg);
	msg = hdd_ipa_kzalloc(meta.msg_len);
	if (msg == NULL) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO, "ENOMEM");
		return -ENOMEM;
	}

	meta.msg_type = type;
	strlcpy(msg->name, adap_dev->dev->name, IPA_RESOURCE_NAME_MAX);
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

	return ret;
}


static int hdd_ipa_rx_pipe_desc_alloc(void)
{
	struct hdd_ipa_priv *hdd_ipa = ghdd_ipa;
	uint32_t i, max_desc_cnt;
	int ret =0;
	struct ipa_tx_data_desc *tmp_desc;

	hdd_ipa->hw_desc_cnt = IPA_NUM_OF_FIFO_DESC(
				hdd_ipa->hdd_ctx->cfg_ini->IpaDescSize);
	max_desc_cnt = hdd_ipa->hw_desc_cnt * HDD_IPA_DESC_BUFFER_RATIO;

	spin_lock_init(&hdd_ipa->q_lock);
	spin_lock_bh(&hdd_ipa->q_lock);
	INIT_LIST_HEAD(&hdd_ipa->free_desc_head);
	INIT_LIST_HEAD(&hdd_ipa->pend_desc_head);
	hdd_ipa->stats.freeq_cnt = max_desc_cnt;
	for (i = 0; i < max_desc_cnt; i++) {
		tmp_desc = hdd_ipa_kzalloc(sizeof(struct
							ipa_tx_data_desc));
		if (!tmp_desc) {
			ret = -1;
			break;
		}
		list_add_tail(&tmp_desc->link, &hdd_ipa->free_desc_head);
	}
	spin_unlock_bh(&hdd_ipa->q_lock);
	HDD_IPA_LOG(VOS_TRACE_LEVEL_INFO,
		"Desc sz:%d h_desc_cnt:%d freeq_cnt:%llu",
		hdd_ipa->hdd_ctx->cfg_ini->IpaDescSize, hdd_ipa->hw_desc_cnt,
						hdd_ipa->stats.freeq_cnt);
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
		adf_os_mem_free(desc);
		i++;
	}
	spin_unlock_bh(&hdd_ipa->q_lock);

	if (i != max_desc_cnt)
		HDD_IPA_LOG(VOS_TRACE_LEVEL_FATAL, "free mem leak");

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

	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RM Grants: ", hdd_ipa->stats.rm_grant);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	 "RM Releases: ", hdd_ipa->stats.rm_release);
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
#endif
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
	"IPA TX Recieve:", hdd_ipa->stats.tx_ipa_recv);

#ifdef HDD_IPA_EXTRA_DP_COUNTERS
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"Free Queue use:", hdd_ipa->stats.freeq_use);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"Free Queue reclaim:", hdd_ipa->stats.freeq_reclaim);
#endif
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
	"Free Queue Empty:", hdd_ipa->stats.freeq_empty);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
	"Free Queue cnt:", hdd_ipa->stats.freeq_cnt);


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


int hdd_ipa_debugfs_init(struct hdd_ipa_priv *hdd_ipa)
{
#ifdef WLAN_OPEN_SOURCE
	hdd_ipa->debugfs_dir = debugfs_create_dir("cld",
					hdd_ipa->hdd_ctx->wiphy->debugfsdir);
	if(!hdd_ipa->debugfs_dir)
		return -ENOMEM;

	debugfs_create_file("ipa-stats", S_IRUSR, hdd_ipa->debugfs_dir,
						hdd_ipa, &fops_ipa_stats);
#endif
	return 0;
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
	int ret;
	if (!hdd_ipa_is_enabled(hdd_ctx))
		return 0;

	hdd_ipa = hdd_ipa_kzalloc(sizeof(struct hdd_ipa_priv));
	if (!hdd_ipa) {
		HDD_IPA_LOG(VOS_TRACE_LEVEL_FATAL, "ENOMEM");
		goto fail_setup_rm;
	}
	hdd_ctx->hdd_ipa = hdd_ipa;
	ghdd_ipa = hdd_ipa;
	hdd_ipa->hdd_ctx = hdd_ctx;

	ret = hdd_ipa_setup_rm(hdd_ipa);
	if (ret)
		goto fail_setup_rm;

	ret = hdd_ipa_setup_sys_pipe(hdd_ipa);
	if (ret)
		goto fail_create_sys_pipe;

	atomic_set(&hdd_ipa->rm_state, HDD_IPA_RM_RELEASED);

	ret = hdd_ipa_rx_pipe_desc_alloc();
	if (ret)
		goto fail_alloc_rx_pipe_desc;

	ret = hdd_ipa_debugfs_init(hdd_ipa);
	if (ret)
		goto fail_alloc_rx_pipe_desc;

	HDD_IPA_LOG(VOS_TRACE_LEVEL_FATAL, "IPA Init Done");
#ifndef HDD_IPA_USE_IPA_RM_TIMER
	setup_timer(&hdd_ipa->rm_timer, hdd_ipa_rm_timer_handler,
						 (unsigned long) &hdd_ipa);
#endif
	return VOS_STATUS_SUCCESS;
fail_alloc_rx_pipe_desc:
	hdd_ipa_rx_pipe_desc_free();
fail_create_sys_pipe:
	hdd_ipa_destory_rm_resource(hdd_ipa);
fail_setup_rm:
	return VOS_STATUS_E_FAILURE;
}

VOS_STATUS hdd_ipa_cleanup(hdd_context_t *hdd_ctx)
{
	struct hdd_ipa_priv *hdd_ipa = hdd_ctx->hdd_ipa;

	if (!hdd_ipa_is_enabled(hdd_ctx))
		return VOS_STATUS_SUCCESS;

#ifndef HDD_IPA_USE_IPA_RM_TIMER
	del_timer(&hdd_ipa->rm_timer);
#endif
	if (hdd_ipa->pending_desc_cnt != 0) {
		msleep(5);
		HDD_IPA_LOG(VOS_TRACE_LEVEL_FATAL, "IPA Pending");
	}
	hdd_ipa_rx_pipe_desc_free();
	hdd_ipa_teardown_sys_pipe(hdd_ipa);
	hdd_ipa_destory_rm_resource(hdd_ipa);

	adf_os_mem_free(hdd_ctx->hdd_ipa);

	return VOS_STATUS_SUCCESS;
}

#endif


