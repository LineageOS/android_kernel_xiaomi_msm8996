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

#ifndef HDD_TGT_CFG_H
#define HDD_TGT_CFG_H

/* TODO: Find it from the max number of supported vdev */
#define INTF_MACADDR_MASK	0x7

struct hdd_tgt_services {
	u_int32_t sta_power_save;
	u_int32_t uapsd;
	u_int32_t ap_dfs;
	u_int32_t en_11ac;
	u_int32_t arp_offload;
#if defined (QCA_WIFI_2_0) && defined(FEATURE_WLAN_PNO_OFFLOAD)
	v_BOOL_t  pno_offload;
#endif
};

struct hdd_tgt_ht_cap {
	u_int32_t mpdu_density;
	bool ht_rx_stbc;
	bool ht_tx_stbc;
	bool ht_rx_ldpc;
	bool ht_sgi_20;
	bool ht_sgi_40;
	u_int32_t num_rf_chains;
};

#ifdef WLAN_FEATURE_11AC
struct hdd_tgt_vht_cap {
	u_int32_t vht_max_mpdu;
	u_int32_t supp_chan_width;
	u_int32_t vht_rx_ldpc;
	u_int32_t vht_short_gi_80;
	u_int32_t vht_short_gi_160;
	u_int32_t vht_tx_stbc;
	u_int32_t vht_rx_stbc;
	u_int32_t vht_su_bformer;
	u_int32_t vht_su_bformee;
	u_int32_t vht_mu_bformer;
	u_int32_t vht_mu_bformee;
	u_int32_t vht_max_ampdu_len_exp;
	u_int32_t vht_txop_ps;
};
#endif

struct hdd_tgt_cfg {
	u_int32_t target_fw_version;
	u_int8_t band_cap;
	u_int8_t alpha2[3];
	v_MACADDR_t hw_macaddr;
	struct hdd_tgt_services services;
	struct hdd_tgt_ht_cap ht_cap;
#ifdef WLAN_FEATURE_11AC
	struct hdd_tgt_vht_cap vht_cap;
#endif
};

#endif /* HDD_TGT_CFG_H */
