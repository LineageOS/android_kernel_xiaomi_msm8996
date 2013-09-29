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
 * @file htt_dxe_t2h.c
 * @brief Provide functions to process target->host HTT messages.
 * @details
 *  This file contains functions related to target->host HTT messages.
 *  There are two categories of functions:
 *  1.  A function that receives a HTT message from HTC, and dispatches it
 *      based on the HTT message type.
 *  2.  functions that provide the info elements from specific HTT messages.
 */

#include <htt_isoc.h>        /* HTT_ISOC_T2H_MSG_TYPE, etc. */
#include <adf_os_util.h>     /* adf_os_assert */
#include <adf_nbuf.h>        /* adf_nbuf_t */

#include <ol_htt_rx_api.h>
#include <ol_txrx_htt_api.h> /* htt_tx_status */

#include <ol_cfg.h>          /* ol_cfg_max_peer_id */

/* internal header files */
#include <htt_dxe_types.h>
#include <htt_dxe_internal.h>


/* 
 * The HTT_T2H message payload will arrive at the host in big-endian order.
 *
 * Firmware - creates HTT_T2H message in little-endian order.
 * DXE      - byteswap while copying. HTT_T2H message now in big-endian order.
 */
#ifdef BIG_ENDIAN_HOST
/* big-endian - bytes are naturally in the correct order, no swap needed */
#define HTT_DXE_T2H_MSG_BYTESWAP(msg, bytes) /* no-op */
#else
/* little-endian - byte swap */
static inline void
HTT_DXE_T2H_MSG_BYTESWAP(u_int8_t *msg, int bytes)
{
    isoc_hw_bd_swap_bytes32((char *) msg, bytes);
}
#endif /* BIG_ENDIAN_HOST */


static u_int8_t *
htt_t2h_mac_addr_deswizzle(u_int8_t *tgt_mac_addr, u_int8_t *buffer)
{
#ifdef BIG_ENDIAN_HOST
    /*
     * The host endianness is opposite of the target endianness.
     * To make u_int32_t elements come out correctly, the target->host
     * upload has swizzled the bytes in each u_int32_t element of the
     * message.
     * For byte-array message fields like the MAC address, this
     * upload swizzling puts the bytes in the wrong order, and needs
     * to be undone.
     */
    buffer[0] = tgt_mac_addr[3];
    buffer[1] = tgt_mac_addr[2];
    buffer[2] = tgt_mac_addr[1];
    buffer[3] = tgt_mac_addr[0];
    buffer[4] = tgt_mac_addr[7];
    buffer[5] = tgt_mac_addr[6];
    return buffer;
#else
    /*
     * The host endianness matches the target endianness -
     * we can use the mac addr directly from the message buffer.
     */
    return tgt_mac_addr;
#endif
}

void
htt_dxe_t2h_msg_handler(void *context, adf_nbuf_t htt_t2h_msg)
{
    struct htt_dxe_pdev_t *pdev = (struct htt_dxe_pdev_t *) context;
    enum htt_isoc_t2h_msg_type msg_type;
    isoc_rx_bd_t *rx_bd;
    u_int8_t *msg_addr;

    rx_bd = (isoc_rx_bd_t *)adf_nbuf_data(htt_t2h_msg);
    msg_addr = (u_int8_t *)rx_bd + rx_bd->mpdu_data_offset;

    /* confirm alignment */
    HTT_DXE_ASSERT3((((unsigned long) msg_addr) & 0x3) == 0);

    /* Convert HTT_T2H message from little-endian to host format */
    HTT_DXE_T2H_MSG_BYTESWAP(msg_addr, (rx_bd->mpdu_length + 3) & (~0x3));

    msg_type = HTT_ISOC_T2H_MSG_TYPE_GET(msg_addr);

    switch (msg_type) {
    case HTT_ISOC_T2H_MSG_TYPE_RX_ADDBA:
        {
            u_int16_t peer_id;
            u_int16_t start_seq_num, reorder_idx;
            u_int8_t tid;
            u_int8_t win_sz;
            u_int8_t status;

            peer_id = HTT_ISOC_T2H_ADDBA_PEER_ID_GET(msg_addr);
            tid = HTT_ISOC_T2H_ADDBA_TID_GET(msg_addr);
            start_seq_num = HTT_ISOC_T2H_ADDBA_START_SEQ_NUM_GET(msg_addr);
            win_sz = HTT_ISOC_T2H_ADDBA_WIN_SIZE_GET(msg_addr);
            status = HTT_ISOC_T2H_ADDBA_STATUS_GET(msg_addr);

            if (status == htt_isoc_addba_success) {
                /*
                 * Remember which peer-TIDs are doing aggregation, to see
                 * whether the aggregation-related parts of the Rx BD
                 * (reorder_opcode, reorder_slot_idx, reorder_fwd_idx)
                 * are valid.
                 */
                pdev->peers[peer_id].rx_aggr_enabled_tids_bitmap |= (1 << tid);
            }
            reorder_idx = start_seq_num % win_sz;
            ol_rx_addba_handler(
                pdev->txrx_pdev, peer_id, tid, win_sz, reorder_idx,
                status != htt_isoc_addba_success);
            break;
        }
    case HTT_ISOC_T2H_MSG_TYPE_RX_DELBA:
        {
            u_int16_t peer_id;
            u_int8_t tid;

            peer_id = HTT_ISOC_T2H_DELBA_PEER_ID_GET(msg_addr);
            tid = HTT_ISOC_T2H_DELBA_TID_GET(msg_addr);

            pdev->peers[peer_id].rx_aggr_enabled_tids_bitmap &= ~(1 << tid);

            /*
             * Before deleting the rx reorder array, we need to
             * flush (i.e. release, not drop) any rx MPDUs that are
             * currently waiting in the rx reorder array for missing
             * prior MPDUs to arrive.
             * Now that the rx aggregation is terminated, the missing
             * MPDUs will not arrive, so any waiting MPDUs should be
             * released for the remaining steps of rx processing.
             */
            HTT_DXE_RX_REORDER_LOG_ADD(pdev, peer_id, tid, NULL);
            ol_rx_flush_handler(
                pdev->txrx_pdev, peer_id, tid,
                0xffff, 0xffff, htt_rx_flush_release);
            ol_rx_delba_handler(pdev->txrx_pdev, peer_id, tid);

            break;
        }
    case HTT_ISOC_T2H_MSG_TYPE_PEER_INFO:
        {
            struct htt_dxe_peer_t *peer;
            u_int8_t mac_addr_deswizzle_buf[HTT_MAC_ADDR_LEN];
            u_int8_t *peer_mac_addr;
            u_int16_t peer_id;
            u_int8_t vdev_id;

            /* extract fields relevent for txrx */
            peer_id = HTT_ISOC_T2H_PEER_INFO_PEER_ID_GET(msg_addr);
            HTT_DXE_ASSERT3(peer_id <= ol_cfg_max_peer_id(pdev->ctrl_pdev));
            vdev_id = HTT_ISOC_T2H_PEER_INFO_VDEV_ID_GET(msg_addr);
            HTT_DXE_ASSERT3(vdev_id < ol_cfg_max_vdevs(pdev->ctrl_pdev));
            peer_mac_addr = htt_t2h_mac_addr_deswizzle(
                msg_addr + sizeof(u_int32_t) *
                HTT_ISOC_T2H_PEER_INFO_MAC_ADDR_L16_OFFSET32 +
                (HTT_ISOC_T2H_PEER_INFO_MAC_ADDR_L16_S >> 3),
                mac_addr_deswizzle_buf);

            /* extract fields relevant just for htt_dxe */
            peer = &pdev->peers[peer_id];
            peer->vdev_id = vdev_id;
            peer->type = HTT_ISOC_T2H_PEER_INFO_PEER_TYPE_GET(msg_addr);

            peer->security[HTT_DXE_PEER_KEY_UCAST].id =
                HTT_ISOC_T2H_PEER_INFO_DPU_IDX_GET(msg_addr);
            peer->security[HTT_DXE_PEER_KEY_UCAST].signature =
                HTT_ISOC_T2H_PEER_INFO_DPU_SIG_GET(msg_addr);

            peer->security[HTT_DXE_PEER_KEY_MCAST].id =
                HTT_ISOC_T2H_PEER_INFO_BCAST_DPU_IDX_GET(msg_addr);
            peer->security[HTT_DXE_PEER_KEY_MCAST].signature =
                HTT_ISOC_T2H_PEER_INFO_BCAST_DPU_SIG_GET(msg_addr);

            peer->security[HTT_DXE_PEER_KEY_MGMT].id =
                HTT_ISOC_T2H_PEER_INFO_MGMT_DPU_IDX_GET(msg_addr);
            peer->security[HTT_DXE_PEER_KEY_MGMT].signature =
                HTT_ISOC_T2H_PEER_INFO_MGMT_DPU_SIG_GET(msg_addr);

            /*
             * The qos_capable flag is already set to its default: 0
             * If the peer is found to be QoS capable, then this will
             * be specified through a call to htt_dxe_peer_qos_update.
             */

            peer->robust_mgmt =
                HTT_ISOC_T2H_PEER_INFO_RMF_ENABLED_GET(msg_addr);

            peer->rx_aggr_enabled_tids_bitmap = 0x0; /* no aggr until ADDBA */

            /* if this is a real peer, inform txrx */
            /* peer_info may come multiple times for the same peer.
               we shall only pass it once to upper layer*/
            /* ToDO: We need to check if a peer needs to be updated multiple times
               If not, this check for valid bit is not needed. With other fixes, FW 
               only sends one indication per peer.
            */
            if (peer->type == HTT_ISOC_T2H_PEER_TYPE_ASSOC && !peer->valid) {
                /*Assign it here to keep the sequence intact*/
                peer->valid = 1;
                ol_rx_peer_map_handler(
                    pdev->txrx_pdev, peer_id, vdev_id, peer_mac_addr,
                    0 /* no tx until PEER_TX_READY is received */);
            } else if (peer->type == HTT_ISOC_T2H_PEER_TYPE_SELF) {
                pdev->vdevs[vdev_id].self_peer_id = peer_id;
            } else if (peer->type == HTT_ISOC_T2H_PEER_TYPE_BCAST) {
                pdev->vdevs[vdev_id].bcast_peer_id = peer_id;
            }
            peer->valid = 1;
            break;
        }
    case HTT_ISOC_T2H_MSG_TYPE_PEER_TX_READY:
        {
            struct htt_dxe_peer_t *peer;
            u_int16_t peer_id;

            peer_id = HTT_ISOC_T2H_PEER_TX_READY_PEER_ID_GET(msg_addr);
            HTT_DXE_ASSERT3(peer_id <= ol_cfg_max_peer_id(pdev->ctrl_pdev));
            peer = &pdev->peers[peer_id];
            HTT_DXE_ASSERT3(peer->valid);

            /* if this is a real peer, inform txrx */
            if (peer->type == HTT_ISOC_T2H_PEER_TYPE_ASSOC) {
                ol_txrx_peer_tx_ready_handler(pdev->txrx_pdev, peer_id);
            }
            break;
        }
    case HTT_ISOC_T2H_MSG_TYPE_PEER_UNMAP:
        {
            struct htt_dxe_peer_t *peer;
            u_int16_t peer_id;

            peer_id = HTT_ISOC_T2H_PEER_UNMAP_PEER_ID_GET(msg_addr);
            HTT_DXE_ASSERT3(peer_id <= ol_cfg_max_peer_id(pdev->ctrl_pdev));
            peer = &pdev->peers[peer_id];
            peer->valid = 0;
            /*
             * Set the qos_capable flag back to its default value (0).
             */
            peer->qos_capable = 0;

            /* if this is a real peer, inform txrx */
            if (peer->type == HTT_ISOC_T2H_PEER_TYPE_ASSOC) {
                ol_rx_peer_unmap_handler(pdev->txrx_pdev, peer_id);
            }
            break;
        }
    case HTT_ISOC_T2H_MSG_TYPE_TX_COMPL_IND:
        {
/* FILL IN HERE */
            break;
        }
    case HTT_ISOC_T2H_MSG_TYPE_SEC_IND:
        {
            u_int16_t peer_id;
            enum htt_sec_type sec_type;
            int is_unicast;
            u_int32_t mic_key[2];

            peer_id = HTT_ISOC_T2H_SEC_IND_PEER_ID_GET(msg_addr);
            sec_type = HTT_ISOC_T2H_SEC_IND_SEC_TYPE_GET(msg_addr);
            is_unicast = HTT_ISOC_T2H_SEC_IND_IS_UNICAST_GET(msg_addr);
            mic_key[0] = HTT_ISOC_T2H_SEC_IND_MIC1_GET(msg_addr);
            mic_key[1] = HTT_ISOC_T2H_SEC_IND_MIC2_GET(msg_addr);

            adf_os_print("SEC_IND (%d) peer_id %d sec_type %d is_unicast %d\n", msg_type, peer_id,sec_type, is_unicast );
            
            ol_rx_sec_ind_handler(pdev->txrx_pdev, peer_id, sec_type, 
                is_unicast, mic_key, NULL);
            
            break;
        }
    default:
        adf_os_print("Error: Unknown HTT_T2H message type = %d\n", msg_type);
        adf_os_assert(0);
        break;
    };

    /* Free the indication buffer */
    adf_nbuf_free(htt_t2h_msg);
}

/*--- target->host HTT message Info Element access methods ------------------*/

/* htt_rx_frag_ind -
 * The fragment indication not relevant for htt_dxe, since defragmentation
 * is handled within the HW.
 * Just provide a dummy function for txrx to link against.
 */
void
htt_rx_frag_ind_flush_seq_num_range(
    struct htt_dxe_pdev_t *pdev,
    adf_nbuf_t rx_frag_ind_msg,
    int *seq_num_start,
    int *seq_num_end)
{
    adf_os_assert(0);
}

