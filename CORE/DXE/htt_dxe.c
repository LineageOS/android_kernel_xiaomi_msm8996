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

/**
 * @file htt_dxe.c
 * @brief Provide functions to create+init and destroy a HTT instance.
 * @details
 *  This file contains functions for creating a HTT instance; initializing
 *  the HTT instance, e.g. by allocating a pool of HTT tx descriptors, and
 *  and deleting a HTT instance.
 */

#include <adf_os_mem.h>      /* adf_os_mem_alloc */
#include <adf_os_types.h>    /* adf_os_device_t, adf_os_print */

#include <ol_cfg.h>          /* ol_cfg_max_vdevs, etc. */
#include <ol_htt_api.h>
#include <ol_txrx_htt_api.h> /* ol_tx_target_credit_update */

#include <htt_dxe_types.h>
#include <htt_dxe_internal.h>

#define htt_dxe_attach          htt_attach
#define htt_dxe_attach_target   htt_attach_target
#define htt_dxe_detach          htt_detach
#define htt_dxe_detach_target   htt_detach_target
#define htt_dxe_vdev_attach     htt_vdev_attach
#define htt_dxe_vdev_detach     htt_vdev_detach
#define htt_dxe_peer_qos_update htt_peer_qos_update
#define htt_dxe_peer_uapsdmask_update htt_peer_uapsdmask_update
#define htt_dxe_display         htt_display


htt_pdev_handle
htt_dxe_attach(
    ol_txrx_pdev_handle txrx_pdev,
    ol_pdev_handle ctrl_pdev,
    HTC_HANDLE htc_pdev,
    adf_os_device_t osdev,
    int desc_pool_size)
{
    int i;
    int tx_credit;
    A_STATUS status;
    struct htt_dxe_pdev_t *pdev;
    S_HIFDXE_CALLBACK hif_dxe_cbs = {0};

    pdev = adf_os_mem_alloc(osdev, sizeof(*pdev));
    if (!pdev) {
        return NULL;
    }

    /*
     * Zero out all pointers within the pdev object, so it will be
     * obvious which pointers have been initialized and which haven't.
     * This allows the htt_dxe_detach function to be used to clean up
     * when the htt_dxe_attach initializations fail halfway through.
     */
    adf_os_mem_zero(pdev, sizeof(*pdev));

    pdev->osdev = osdev;
    pdev->ctrl_pdev = ctrl_pdev;
    pdev->txrx_pdev = txrx_pdev;

    pdev->vdevs = adf_os_mem_alloc(osdev,
        sizeof(struct htt_dxe_vdev_t) * ol_cfg_max_vdevs(ctrl_pdev));
    if (!pdev->vdevs) {
        goto fail;
    }
    for (i = 0; i < ol_cfg_max_vdevs(ctrl_pdev); i++) {
        pdev->vdevs[i].valid = 0;
    }

    pdev->peers = adf_os_mem_alloc(osdev,
        sizeof(struct htt_dxe_peer_t) * (ol_cfg_max_peer_id(ctrl_pdev) + 1));
    if (!pdev->peers) {
        goto fail;
    }
    for (i = 0; i <= ol_cfg_max_peer_id(ctrl_pdev); i++) {
        pdev->peers[i].valid = 0;
        pdev->peers[i].qos_capable = 0; /* default */
    }

    if (htt_dxe_tx_attach(pdev, desc_pool_size)) {
        goto fail;
    }

    if (htt_dxe_rx_attach(pdev)) {
        goto fail;
    }

    adf_os_spinlock_init(&pdev->tx_mutex); 
    pdev->tx_mutex_valid = 1;

    pdev->hif_dxe_pdev = hif_dxe_attach(osdev);

    if (!pdev->hif_dxe_pdev) {
        goto fail;
    }

    hif_dxe_cbs.HifTxCompleteCb   = htt_dxe_tx_download_done;
    hif_dxe_cbs.HifTxCompleteCtx  = pdev;
    hif_dxe_cbs.HifLowResourceCb  = htt_dxe_tx_low_rsrc;
    hif_dxe_cbs.HifLowResourceCtx = pdev;

    status = hif_dxe_client_registration(pdev->hif_dxe_pdev, &hif_dxe_cbs);
    if (status != A_OK) {
        goto fail;
    }

    pdev->dmux_dxe_pdev = dmux_dxe_attach(pdev->osdev);
    if (!pdev->dmux_dxe_pdev) {
        goto fail;
    }
    if ((dmux_dxe_register_callback_rx_data(
             pdev->dmux_dxe_pdev, htt_dxe_rx, (void *) pdev) != A_OK) ||
        (dmux_dxe_register_callback_rx_ctrl(
             pdev->dmux_dxe_pdev, htt_dxe_rx_ctrl, (void *) pdev) != A_OK) ||
        (dmux_dxe_register_callback_msg(
            pdev->dmux_dxe_pdev, htt_dxe_t2h_msg_handler, (void *) pdev)
            != A_OK))
    {
        goto fail;
    }

    pdev->cfg.flags.sw_tx_encap = ol_cfg_tx_encap(pdev->ctrl_pdev);
    /*
     * For Riva, don't use HW frame translation.
     * NOTE: for Pronto and Northstar we'll want to enable HW frame
     * translation for certain cases.
     * In particular, if the input frame format is 802.3, we'll enable
     * the HW's frame translation, but if the input frame format is
     * native WiFi (basic 802.11), we'll disable HW frame translation,
     * and rely on SW to add a QoS control field when appropriate.
     */
    pdev->cfg.flags.do_frame_translate = 0; // FOR NOW

    /* initialize the txrx credit count */
    /*
     * FOR NOW, consider only the space in the LOW_PRI ring.
     * We eventually want to manage the credit such that we can avoid
     * overflowing the target and thus stalling the DXE download ring.
     * Once this is done, then we don't need separate LOW_PRI vs. HIGH_PRI
     * channels, since there will be a negligible delay to download data
     * through the single channel, since it will never stall.
     */
    tx_credit = hif_dxe_get_resources(
        pdev->hif_dxe_pdev, HIFDXE_CHANNEL_TX_LOW_PRI);
    ol_tx_target_credit_update(pdev->txrx_pdev, tx_credit);

    return pdev;

fail:
    htt_dxe_detach(pdev);
    return NULL;
}

A_STATUS
htt_dxe_attach_target(htt_pdev_handle pdev)
{
    A_STATUS status;
    status = hif_dxe_start(pdev->hif_dxe_pdev);
    return status;
}

void
htt_dxe_vdev_attach(
    htt_pdev_handle pdev,
    u_int8_t vdev_id,
    enum htt_op_mode op_mode)
{
    pdev->vdevs[vdev_id].valid = 1;
    pdev->vdevs[vdev_id].op_mode = op_mode;
}


void
htt_vdev_detach(htt_pdev_handle pdev, u_int8_t vdev_id)
{
    pdev->vdevs[vdev_id].valid = 0;
}

void htt_dxe_peer_qos_update(
    struct htt_dxe_pdev_t *pdev, int peer_id, u_int8_t qos_capable)
{
    struct htt_dxe_peer_t *peer;

    HTT_DXE_ASSERT3(peer_id <= ol_cfg_max_peer_id(pdev->ctrl_pdev));
    peer = &pdev->peers[peer_id];
    HTT_DXE_ASSERT2(peer->valid);
    peer->qos_capable = qos_capable;
}

void htt_dxe_peer_uapsdmask_update(
    struct htt_dxe_pdev_t *pdev, int peer_id, u_int8_t uapsd_mask)
{
    /* TO be implemented */
    return;
}

void
htt_dxe_detach(htt_pdev_handle pdev)
{
    htt_dxe_rx_detach(pdev);
    htt_dxe_tx_detach(pdev);
    if (pdev->dmux_dxe_pdev) {
        dmux_dxe_detach(pdev->dmux_dxe_pdev);
    }
    if (pdev->hif_dxe_pdev) {
        hif_dxe_detach(pdev->hif_dxe_pdev);
    }
    if (pdev->tx_mutex_valid) {
        adf_os_spinlock_destroy(&pdev->tx_mutex);
    }
    if (pdev->peers) {
        adf_os_mem_free(pdev->peers);
    }
    if (pdev->vdevs) {
        adf_os_mem_free(pdev->vdevs);
    }
    /*
     * Zero out the pdev object before freeing it.
     * This will make it more obvious if anyone tries to use it
     * after it has been freed.
     */
    adf_os_mem_zero(pdev, sizeof(*pdev));
    adf_os_mem_free(pdev);
}

void
htt_dxe_detach_target(htt_pdev_handle pdev)
{
    /* FILL HERE */
    return;
}

static void
htt_dxe_vdev_display(
    struct htt_dxe_pdev_t *pdev,
    int vdev_id,
    int indent)
{
    struct htt_dxe_vdev_t *vdev = &pdev->vdevs[vdev_id];
    adf_os_print(
        "%*sID: %d, op mode: %s, self-peer ID: %d, bcast peer ID: %d\n",
        indent, " ",
        vdev_id,
        (vdev->op_mode == htt_op_mode_ap) ? "AP" :
            (vdev->op_mode == htt_op_mode_sta) ? "STA" :
                (vdev->op_mode == htt_op_mode_ibss) ? "IBSS" :
                    "other",
        vdev->self_peer_id, vdev->bcast_peer_id);
}

static void
htt_dxe_peer_display(
    struct htt_dxe_pdev_t *pdev,
    int peer_id,
    int indent)
{
    struct htt_dxe_peer_t *peer = &pdev->peers[peer_id];
    adf_os_print(
        "%*sID: %d, type: %s, QoS capable: %d, robust mgmt: %d\n",
        indent, " ",
        peer_id,
        (peer->type == HTT_ISOC_T2H_PEER_TYPE_ASSOC) ? "real peer" :
            (peer->type == HTT_ISOC_T2H_PEER_TYPE_SELF) ? "self peer" :
                (peer->type == HTT_ISOC_T2H_PEER_TYPE_BCAST) ? "bcast peer" :
                    "(other)",
        peer->qos_capable,
        peer->robust_mgmt);
}

void
htt_dxe_display(htt_pdev_handle pdev, int indent)
{
    int i;
    struct htt_dxe_tx_desc_t *sw_desc;
    char *vaddr;
    u_int32_t paddr;

    adf_os_print(
        "HTT tx descs: %d bytes each (HW desc), %d total, %d allocated\n",
        pdev->tx_descs.size,
        pdev->tx_descs.pool_elems,
        pdev->tx_descs.alloc_cnt);
    sw_desc = pdev->tx_descs.sw_descs_pool;
    vaddr = pdev->tx_descs.tx_bds.pool_vaddr;
    paddr = pdev->tx_descs.tx_bds.pool_paddr;
    for (i = 0; i < pdev->tx_descs.pool_elems; i++) {
        if (pdev->tx_descs.pool_elems > 10) {
            if (i == 4) {
                adf_os_print("    ...\n");
            }
            if (i >= 4 && i < pdev->tx_descs.pool_elems - 4) {
                continue;
            }
        }
        adf_os_print("    %d: sw desc = %p, hw desc vaddr = %p, paddr = %#x\n",
            i, sw_desc, vaddr, paddr);
        sw_desc++;
        vaddr += pdev->tx_descs.size;
        paddr += pdev->tx_descs.size;
    }
    adf_os_print("HTT vdevs:\n");
    for (i = 0; i < ol_cfg_max_vdevs(pdev->ctrl_pdev); i++) {
        if (pdev->vdevs[i].valid) {
            htt_dxe_vdev_display(pdev, i, indent+4);
        }
    }
    adf_os_print("HTT peers:\n");
    for (i = 0; i <= ol_cfg_max_peer_id(pdev->ctrl_pdev); i++) {
        if (pdev->peers[i].valid) {
            htt_dxe_peer_display(pdev, i, indent+4);
        }
    }
}
