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
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

 /*
  * This file has the implementation of TXRX api for HDD<->TXRX and
  * SME/PE<->TXRX.
  */
#include <ol_txrx_types.h>

VOS_STATUS wlan_txrx_register_client(void *txrx_handle,
				     v_MACADDR_t *mac_addr,
				     u_int8_t sta_id)
{
	struct ol_txrx_vdev_t *vdev = (struct ol_txrx_vdev_t *) txrx_handle;
	struct ol_txrx_pdev_t *txrx_pdev = vdev->pdev;
	u_int8_t *macaddr = (u_int8_t *) mac_addr;


	if (txrx_pdev->mac_to_staid[sta_id].mac_addr)
		return VOS_STATUS_E_FAILURE;

	adf_os_mem_copy(txrx_pdev->mac_to_staid[sta_id].mac_addr, macaddr,
			OL_TXRX_MAC_ADDR_LEN);
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS wlan_txrx_clear_client(void *txrx_handle, u_int8_t sta_id)
{
	struct ol_txrx_vdev_t *vdev = (struct ol_txrx_vdev_t *) txrx_handle;
	struct ol_txrx_pdev_t *txrx_pdev = vdev->pdev;


	if (!txrx_pdev->mac_to_staid[sta_id].mac_addr)
		return VOS_STATUS_E_FAILURE;

	adf_os_mem_set(txrx_pdev->mac_to_staid[sta_id].mac_addr, 0,
		       OL_TXRX_MAC_ADDR_LEN);
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS wlan_txrx_start_xmit(void *txrx_handle, adf_nbuf_t msdu)
{
	struct ol_txrx_vdev_t *vdev = (struct ol_txrx_vdev_t *) txrx_handle;

	if (vdev->tx(vdev, msdu) != NULL) {
		adf_nbuf_free(msdu);
		return VOS_STATUS_E_FAILURE;
	}

	return VOS_STATUS_SUCCESS;
}

void wlan_txrx_deliver_rx(struct ol_txrx_vdev_t *vdev,
			  adf_nbuf_t rx_buf_list, unsigned tid,
			  u_int8_t *peer_mac,
			  u16 dest_staid)
{
	struct ol_txrx_pdev_t *txrx_pdev = vdev->pdev;
	struct txrx_rx_metainfo rx_meta_info;
	adf_nbuf_t msdu, tmp;
	u_int8_t sta_id, i;

	/* TODO:Fill ac and dest_staid for AP mode */
	adf_os_mem_set(&rx_meta_info, 0, sizeof(rx_meta_info));

	for (i = 0; i < WLAN_MAX_STA_COUNT; i++) {
		if (!adf_os_mem_cmp(txrx_pdev->mac_to_staid[i].mac_addr,
				    peer_mac, OL_TXRX_MAC_ADDR_LEN)) {
			sta_id = i;
			break;
		}
	}

	if (i != WLAN_MAX_STA_COUNT) {
		vdev->osif_rx(vdev->osif_dev, rx_buf_list);
		return;
	}

	/* Free the rx buf list in case we could not find the peer sta_id */
	msdu = rx_buf_list;
	while (msdu) {
		tmp = msdu;
		msdu = adf_nbuf_next(msdu);
		adf_nbuf_free(tmp);
	}
}

VOS_STATUS wlan_register_mgmt_client(void *txrx_pdev_handle,
				     VOS_STATUS (*rx_mgmt) (void *g_vosctx,
				     void *buf))
{
	struct ol_txrx_pdev_t *pdev_txrx =
				(struct ol_txrx_pdev_t *) txrx_pdev_handle;

	/*
	 * NOTE: rx_mgmt cb will be called from
	 * wmi_unified_mgmt_rx_event_handler().
	 */
	pdev_txrx->rx_mgmt = rx_mgmt;

	return VOS_STATUS_SUCCESS;
}
