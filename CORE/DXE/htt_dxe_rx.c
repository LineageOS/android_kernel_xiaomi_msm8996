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
 * @file htt_dxe_rx.c
 * @brief Implement receive aspects of HTT.
 * @details
 *  This file contains three categories of HTT rx code:
 *  1.  An abstraction of the rx descriptor
 *  2.  Functions for providing access to the (series of)
 *      rx descriptor(s) and rx frame(s) associated with
 *      an rx indication message.
 *  3.  Functions for receiving rx callbacks from the underlying
 *      dmux_dxe and hif_dxe layers.
 */

/* OS utility / primitive abstraction header files */
#include <adf_os_mem.h>   /* adf_os_mem_alloc,free, etc. */
#include <adf_os_util.h>  /* adf_os_assert */
#include <adf_os_types.h> /* adf_os_print */
#include <adf_nbuf.h>     /* adf_nbuf_t, etc. */

#include <athdefs.h>        /* A_STATUS */
#include <isoc_hw_desc.h>   /* isoc_rx_bd_t, etc. */
#include <ieee80211.h>      /* IEEE80211_FC0_SUBTYPE_BAR, ieee80211_frame */
#include <enet.h>           /* ethernet_hdr_t */

/* API header files to other modules called from this file */
#include <dmux_dxe_api.h>    /* dmux_dxe_attach, etc. */
#include <htt_isoc.h>        /* Rx BD format */
#include <hif_dxe.h>         /* E_HIFDXE_CHANNELTYPE */
#include <ol_htt_rx_api.h>   /* htt_rx_msdu_desc_free */
#include <ol_txrx_htt_api.h> /* ol_rx_indication_handler */

/* internal header files */
#include <htt_dxe_types.h>    /* htt_dxe_pdev_t, etc */
#include <htt_dxe_internal.h> /* HTT_DXE_ASSERT */


/*
 * If bit 0 of the first byte of the MAC address is set, then the address
 * is multicast or broadcast rather than unicast.
 */
#define HTT_DXE_IS_MCAST_MAC_ADDR(mac_addr) ((*mac_addr) & 0x1)

static int
htt_dxe_reorder_opcode_is_flush(isoc_rx_opcode reorder_opcode);


#if HTT_DXE_RX_LOG
#define HTT_DXE_RX_PSEUDO_OPCODE_DELBA 99
char *htt_dxe_rx_reorder_opcode_str(unsigned reorder_opcode)
{
    switch (reorder_opcode) {
    case ISOC_RX_OPCODE_INVALID:
        return "invld";
    case ISOC_RX_OPCODE_QUEUECUR_FWDBUF:
        return "QC,FB";
    case ISOC_RX_OPCODE_FWDBUF_FWDCUR:
        return "FB,FC";
    case ISOC_RX_OPCODE_QUEUECUR:
        return " QC  ";
    case ISOC_RX_OPCODE_FWDBUF_QUEUECUR:
        return "FB,QC";
    case ISOC_RX_OPCODE_FWDBUF_DROPCUR:
        return "FB,DC";
    case ISOC_RX_OPCODE_FWDALL_DROPCUR:
        return "FA,DC";
    case ISOC_RX_OPCODE_FWDALL_QUEUECUR:
        return "FA,QC";
    case ISOC_RX_OPCODE_TEARDOWN:
        return "trdwn";
    case ISOC_RX_OPCODE_DROPCUR:
        return " DC  ";
    case HTT_DXE_RX_PSEUDO_OPCODE_DELBA:
        return "delba";
    default:
        return " n/a ";
    };
}
#endif /* HTT_DXE_RX_LOG */

void
htt_dxe_rx_frm_dump(adf_nbuf_t rx_msdu, int max)
{
    u_int8_t *data;
    int i;

    if (adf_nbuf_len(rx_msdu) < max) {
        max = adf_nbuf_len(rx_msdu);
    }
    adf_os_print("rx frame contents (bytes 0-%d of %d):\n    ",
        max - 1, (int) adf_nbuf_len(rx_msdu));
    data = adf_nbuf_data(rx_msdu);
    for (i = 1; max > 0; i++, max--) {
        adf_os_print("0x%02x ", *data++);
        if (i == 12) {
            i = 0;
            adf_os_print("\n    ");
        }
    }
    adf_os_print("\n");
}


/*--- rx indication event functions -----------------------------------------*/

static inline isoc_rx_bd_t *
htt_dxe_rx_nbuf_prep(adf_nbuf_t rx_msdu)
{
    isoc_rx_bd_t *rx_bd;


    /* the rx descriptor (Rx BD) is at the front of the rx network buffer */
    rx_bd = (isoc_rx_bd_t *) adf_nbuf_data(rx_msdu);

    /* FOR NOW, operate on the Rx BD in its original location.
     * TBD:
     * If the original location is uncacheable, make a copy in regular memory,
     * and operate on that copy?
     */

    /*
     * The dmux_dxe code already handled endianness conversion on the Rx BD;
     * no further endianness correction is needed.
     */

    /* set the length of the network buffer */
    adf_nbuf_put_tail(rx_msdu, rx_bd->mpdu_header_offset + rx_bd->mpdu_length);

    /* advance the data pointer to the L2 header (skip the Rx BD) */
    adf_nbuf_pull_head(rx_msdu, rx_bd->mpdu_header_offset);

    //isoc_rx_bd_dump(rx_bd);
    //htt_dxe_rx_frm_dump(rx_msdu, 64);

    return rx_bd;
}

void
htt_dxe_rx_discard_pending(struct htt_pdev_t *pdev, int chan_idx)
{
    adf_nbuf_t pending = pdev->rx.pending_amsdus[chan_idx].head;
    while (pending) {
        adf_nbuf_t next = adf_nbuf_next(pending);
        htt_rx_msdu_desc_free(pdev, pending);
        pending = next;
    }
    pdev->rx.pending_amsdus[chan_idx].head =
        pdev->rx.pending_amsdus[chan_idx].tail = NULL;
}

static inline void
htt_dxe_rx_pending_append(
    struct htt_dxe_pdev_t *pdev,
    int chan_idx,
    adf_nbuf_t rx_msdu)
{
    if (!pdev->rx.pending_amsdus[chan_idx].head) {
        pdev->rx.pending_amsdus[chan_idx].head = rx_msdu;
    } else {
        adf_nbuf_set_next(pdev->rx.pending_amsdus[chan_idx].tail, rx_msdu);
    }
    pdev->rx.pending_amsdus[chan_idx].tail = rx_msdu;
}

#if 1 /* for now, support 2 parallel rx data channels */
#define HTT_DXE_RX_CHAN(chan) ((chan) == HIFDXE_CHANNEL_RX_LOW_PRI ? 0 : 1)
#else
#define HTT_DXE_RX_CHAN(chan) \
     0; \
     adf_os_assert((chan) == HIFDXE_CHANNEL_RX_LOW_PRI)
#endif

void
htt_dxe_rx(void *context, adf_nbuf_t rx_msdu, E_HIFDXE_CHANNELTYPE chan)
{
    struct htt_pdev_t *pdev = (struct htt_pdev_t *) context;
    int chan_idx;

    chan_idx = HTT_DXE_RX_CHAN(chan);

    /* the delivery list should start empty and end up empty */
    adf_os_assert(pdev->rx.delivery.head == NULL);

    while (rx_msdu) {
        u_int16_t peer_id;
        u_int8_t vdev_id;
        isoc_rx_bd_t *rx_bd;
        adf_nbuf_t next;
        struct htt_dxe_peer_t *peer;
        struct htt_dxe_vdev_t *vdev;

        next = adf_nbuf_next(rx_msdu);
        adf_nbuf_set_next(rx_msdu, NULL);

        rx_bd = htt_dxe_rx_nbuf_prep(rx_msdu);

        HTT_DXE_ASSERT2(
            rx_bd->reorder_opcode != ISOC_RX_OPCODE_TEARDOWN &&
            rx_bd->reorder_opcode != ISOC_RX_OPCODE_DROPCUR &&
            rx_bd->reorder_opcode != ISOC_RX_OPCODE_FWDBUF_DROPCUR &&
            rx_bd->reorder_opcode != ISOC_RX_OPCODE_FWDALL_DROPCUR);

        HTT_DXE_ASSERT2(!rx_bd->addr2_invalid);
        peer_id = rx_bd->addr2_index;
        peer = &pdev->peers[peer_id];
        vdev_id = peer->vdev_id;
        vdev = &pdev->vdevs[vdev_id];

        /*
         * STA: discard multicasts that are echoes of frames the STA sent.
         */
        if (vdev->op_mode == htt_op_mode_sta &&
            rx_bd->not_unicast &&
            rx_bd->addr3_index == vdev_id)
        {
            rx_bd->sw_flag_discard = 1;
        } else {
            rx_bd->sw_flag_discard = 0;
        }

        /*
         * If this is an AP and it has received a frame with a
         * multicast/broadcast destination address, then it needs to
         * transmit this received frame, so that it will be broadcast
         * throughout the BSS (the rx frame was unicast to the AP's RA).
         * This is referred to as "multicast echo".
         */
        if (vdev->op_mode == htt_op_mode_ap) {
            u_int8_t *dest_addr;
            u_int8_t *l2_hdr_ptr;

            l2_hdr_ptr = ((u_int8_t *) rx_bd) + rx_bd->mpdu_header_offset;
            if (rx_bd->frame_translate) {
                /* frame is in 802.3 format */
                dest_addr = ((struct ethernet_hdr_t *) l2_hdr_ptr)->dest_addr;
            } else {
                if ((!rx_bd->amsdu) || rx_bd->amsdu_first) {
                    /*
                     * initial MSDU of an A-MSDU is in 802.11 format;
                     * for STA->AP, DA is addr3
                     */
                    dest_addr =
                        ((struct ieee80211_frame *) l2_hdr_ptr)->i_addr3;
                } else {
                    /* subsequent MSDUs of an A-MSU are in 802.3 format */
                    dest_addr =
                        ((struct ethernet_hdr_t *) l2_hdr_ptr)->dest_addr;
                }
            }
            rx_bd->sw_flag_forward =
                HTT_DXE_IS_MCAST_MAC_ADDR(dest_addr) ? 1 : 0;
        } else {
            rx_bd->sw_flag_forward = 0;
        }

        /* determine whether this MSDU completes a MPDU / A-MSDU */
        if (!rx_bd->amsdu) {
            /* there should be no old subframes in the pending list */
            if (pdev->rx.pending_amsdus[chan_idx].head) {
                adf_os_print(
                    "Error: discarding incomplete A-MSDU "
                    "that was followed by non-A-MSDU\n");
                htt_dxe_rx_discard_pending(pdev, chan_idx);
            }
            pdev->rx.delivery.head =
                pdev->rx.delivery.tail = rx_msdu;
        } else {
            /*
             * Sanity checks:
             * If this is the first subframe, then the pending list
             * should be empty.
             * If this is not the first subframe, the pending list
             * should not be empty.
             */
            if (rx_bd->amsdu_first) {
                if (pdev->rx.pending_amsdus[chan_idx].head) {
                    adf_os_print(
                        "Error: discarding incomplete A-MSDU "
                        "that was followed by a new A-MSDU\n");
                    htt_dxe_rx_discard_pending(pdev, chan_idx);
                }
            } else {
                if (!pdev->rx.pending_amsdus[chan_idx].head) {
                    adf_os_print(
                        "Error: discarding non-initial A-MSDU subframe "
                        "which had no initial subframe\n");
                    htt_rx_msdu_desc_free(pdev, rx_msdu);
                    goto loop_end;
                }
            }

            htt_dxe_rx_pending_append(pdev, chan_idx, rx_msdu);

            if (rx_bd->amsdu_last) {
                /*
                 * Move the complete MPDU from the pending location
                 * to the delivery location.
                 */
                pdev->rx.delivery.head = pdev->rx.pending_amsdus[chan_idx].head;
                pdev->rx.delivery.tail = pdev->rx.pending_amsdus[chan_idx].tail;
                pdev->rx.pending_amsdus[chan_idx].head =
                    pdev->rx.pending_amsdus[chan_idx].tail = NULL;
            }
        }
        if (pdev->rx.delivery.head) {
            u_int8_t tid;
            /*
             * Send an rx indication for the completed A-MSDU to txrx.
             * Note that the txrx SW will issue several calls to htt_dxe
             * inside this function call.
             */
            rx_bd = (isoc_rx_bd_t *) adf_nbuf_head(pdev->rx.delivery.head);

            /*
             * The TA (transmitter address) specifies which peer sent
             * this data frame.
             * Since we only can receive data frames once we're
             * associated, the peer index based on the TA should always
             * be valid.
             */
            /*
             * There should never be a frame rx from an uninitialized
             * peer object.  Do a sanity check that the peer object
             * has been initialized via a PEER_INFO message.
             */
            HTT_DXE_ASSERT2(pdev->peers[peer_id].valid);

            /* TID */
            if (rx_bd->frame_type_subtype & IEEE80211_FC0_SUBTYPE_QOS) {
                tid = rx_bd->tid;
            } else {
                tid = rx_bd->not_unicast ? OL_HTT_TID_NON_QOS_MCAST_BCAST : 
                                           OL_HTT_TID_NON_QOS_UNICAST;
            }
            HTT_DXE_RX_REORDER_LOG_ADD(pdev, peer_id, tid, rx_bd);

            /* remember which rx ind is being handled */
            pdev->rx.cur.rx_bd = rx_bd;
            pdev->rx.cur.peer_id = peer_id;
            pdev->rx.cur.tid = tid;
            pdev->rx.cur.rx_aggr_enabled =
                ((pdev->peers[peer_id].rx_aggr_enabled_tids_bitmap >> tid) & 0x1);

            if (pdev->rx.cur.rx_aggr_enabled && 
                (rx_bd->reorder_opcode == ISOC_RX_OPCODE_INVALID)) 
            {
                adf_os_print(
                    "Error: discarding frame "
                    "with reorder_opcode = ISOC_RX_OPCODE_INVALID\n");
                HTT_DXE_ASSERT2(pdev->rx.cur.rx_aggr_enabled && rx_bd->reorder_opcode != ISOC_RX_OPCODE_INVALID);
                htt_rx_msdu_desc_free(pdev, rx_msdu);
                goto loop_end;
            }

            ol_rx_indication_handler(
                pdev->txrx_pdev, NULL, peer_id, tid, 1);
        }
loop_end:
        rx_msdu = next;
    }
}

void
htt_dxe_rx_ctrl(void *context, adf_nbuf_t rx_ctrl_msg)
{
    struct htt_pdev_t *pdev = (struct htt_pdev_t *) context;

    /* we expect a single control frame at a time, but iterate just in case */
    while (rx_ctrl_msg) {
        isoc_rx_bd_t *rx_bd;
        adf_nbuf_t next;
        unsigned ctrl_bar_subtype;
        u_int16_t peer_id;
        unsigned idx_start, idx_end;

        /* the only control frames we expect are BAR */
        next = adf_nbuf_next(rx_ctrl_msg);
        adf_nbuf_set_next(rx_ctrl_msg, NULL);

        rx_bd = (isoc_rx_bd_t *) adf_nbuf_data(rx_ctrl_msg);

        if (rx_bd->reorder_opcode != ISOC_RX_OPCODE_FWDBUF_DROPCUR &&
            rx_bd->reorder_opcode != ISOC_RX_OPCODE_FWDALL_DROPCUR)
        {
            adf_os_print("Warning: unexpected rx reorder opcode (%d)",
                rx_bd->reorder_opcode);
            goto loop_end;
        }

        ctrl_bar_subtype = IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_BAR;
        if (rx_bd->frame_type_subtype != ctrl_bar_subtype) {
            adf_os_print("Warning: unexpected control frame (%#x)",
                rx_bd->frame_type_subtype);
            goto loop_end;
        }

        /*
         * Flush MPDUs queued in the rx reorder array which are not covered
         * by the repositioned block ack window.
         */
        peer_id = rx_bd->addr2_index;
        idx_start = 0xffff; /* start from where the last release left off */
        idx_end = (rx_bd->reorder_opcode == ISOC_RX_OPCODE_FWDBUF_DROPCUR) ?
            rx_bd->reorder_fwd_idx : /* flush only to the specified index */
            0xffff;                  /* flush entire reorder array */

        HTT_DXE_RX_REORDER_LOG_ADD(pdev, peer_id, rx_bd->tid, rx_bd);

        ol_rx_flush_handler(
            pdev->txrx_pdev, peer_id, rx_bd->tid,
            idx_start, idx_end, htt_rx_flush_release);

loop_end:
        htt_rx_desc_frame_free(pdev, rx_ctrl_msg);
        rx_ctrl_msg = next;
    }
}

/*--- rx indication info functions ------------------------------------------*/

static int
htt_dxe_reorder_opcode_is_flush(isoc_rx_opcode reorder_opcode)
{
    switch (reorder_opcode)
    {
    case ISOC_RX_OPCODE_QUEUECUR_FWDBUF:
    case ISOC_RX_OPCODE_QUEUECUR:
        return 0;
    case ISOC_RX_OPCODE_FWDBUF_FWDCUR:
    case ISOC_RX_OPCODE_FWDBUF_QUEUECUR:
    case ISOC_RX_OPCODE_FWDBUF_DROPCUR:
    case ISOC_RX_OPCODE_FWDALL_DROPCUR:
    case ISOC_RX_OPCODE_FWDALL_QUEUECUR:
        return 1;
    default:
        adf_os_print(
            "Warning: %s unexpected opcode (%d)\n", __func__, reorder_opcode);
        return 0;
    };
}

static int
htt_dxe_reorder_opcode_is_release(isoc_rx_opcode reorder_opcode)
{
    switch (reorder_opcode)
    {
    case ISOC_RX_OPCODE_QUEUECUR_FWDBUF:
    case ISOC_RX_OPCODE_FWDBUF_FWDCUR:
        return 1;
    case ISOC_RX_OPCODE_FWDBUF_QUEUECUR:
    case ISOC_RX_OPCODE_QUEUECUR:
    case ISOC_RX_OPCODE_FWDBUF_DROPCUR:
    case ISOC_RX_OPCODE_FWDALL_DROPCUR:
    case ISOC_RX_OPCODE_FWDALL_QUEUECUR:
        return 0;
    default:
        adf_os_print(
            "Warning: %s unexpected opcode (%d)\n", __func__, reorder_opcode);
        return 0;
     
    };
}

int
htt_rx_ind_flush(struct htt_pdev_t *pdev, adf_nbuf_t rx_ind_msg)
{
    /* check whether the current peer-TID has aggregation enabled */
    if (!pdev->rx.cur.rx_aggr_enabled) {
        return 0; /* flush doesn't apply unless aggregation is enabled */
    }

    /*
     * The rx opcode specifies whether to flush old MPDUs before processing
     * new ones.
     */
    return htt_dxe_reorder_opcode_is_flush(pdev->rx.cur.rx_bd->reorder_opcode);
}

void
htt_rx_ind_flush_seq_num_range(
    struct htt_pdev_t *pdev,
    adf_nbuf_t rx_ind_msg,
    unsigned *seq_num_start,
    unsigned *seq_num_end)
{
    isoc_rx_opcode reorder_opcode = pdev->rx.cur.rx_bd->reorder_opcode;

    /* see if the opcode specifies to release all the queued MPDUs */
    if (/* reorder_opcode == ISOC_RX_OPCODE_FWDALL_DROPCUR || */ // n/a - BAR
        reorder_opcode == ISOC_RX_OPCODE_FWDALL_QUEUECUR) {
        *seq_num_start = 0xffff;
        *seq_num_end = 0xffff;
        return;
    }

    /* the range to flush is specified by the reorder_fwd_idx */
    *seq_num_start = 0xffff; /* start from the last-released sequence number */
    *seq_num_end = pdev->rx.cur.rx_bd->reorder_fwd_idx;
}

int
htt_rx_ind_release(struct htt_pdev_t *pdev, adf_nbuf_t rx_ind_msg)
{
    /* check whether the current peer-TID has aggregation enabled */
    if (!pdev->rx.cur.rx_aggr_enabled) {
        return 1; /* release always applies if aggregation is not enabled */
    }

    /* the rx opcode specifies whether to release queued MPDUs */
    return
        htt_dxe_reorder_opcode_is_release(pdev->rx.cur.rx_bd->reorder_opcode);
}

void
htt_rx_ind_release_seq_num_range(
    struct htt_pdev_t *pdev,
    adf_nbuf_t rx_ind_msg,
    unsigned *seq_num_start,
    unsigned *seq_num_end)
{
    if (!pdev->rx.cur.rx_aggr_enabled) {
        /*
         * For non-aggregation, rx reorder array has a single element, so
         * the sequence number range is not relevant.
         * Just for clarity, return a well-defined value (0).
         */
        *seq_num_start = 0;
        *seq_num_end = 1;
        return;
    }

    /* release up to (but not including) the reorder_fwd_idx */
    *seq_num_start = 0xffff; /* start from the last-released sequence number */
    *seq_num_end = pdev->rx.cur.rx_bd->reorder_fwd_idx;
}

void
htt_rx_ind_mpdu_range_info(
    struct htt_pdev_t *pdev,
    adf_nbuf_t rx_ind_msg,
    int mpdu_range_num,
    enum htt_rx_status *status,
    int *mpdu_count)
{
    *mpdu_count = 1;            /* htt_dxe_rx delivers one MPDU at a time */
    *status = htt_rx_status_ok; /* error frames are filtered out by HW */
}

int16_t
htt_rx_ind_rssi_dbm(htt_pdev_handle pdev, adf_nbuf_t rx_ind_msg)
{
    /*
     * The RSSIs only come from the rx descriptors (Rx BDs).
     * Return an invalid value to show that there is no separate
     * RSSI provided as a field in the HTT T2H RX_IND message.
     */
    return HTT_RSSI_INVALID;
}

/*--- rx descriptor field access functions ----------------------------------*/
/*
 * These functions need to use bit masks and shifts to extract fields
 * from the rx descriptors, rather than directly using the bitfields.
 * For example, use
 *     (desc & FIELD_MASK) >> FIELD_LSB
 * rather than
 *     desc.field
 * This allows the functions to work correctly on either little-endian
 * machines (no endianness conversion needed) or big-endian machines
 * (endianness conversion provided automatically by the HW DMA's
 * byte-swizzling).
 */
u_int16_t
(*htt_rx_mpdu_desc_seq_num)(htt_pdev_handle pdev, void *mpdu_desc);
u_int16_t
_htt_rx_mpdu_desc_seq_num(htt_pdev_handle pdev, void *mpdu_desc)
{
    isoc_rx_bd_t *rx_bd = mpdu_desc;
    return (u_int16_t)rx_bd->current_pkt_seqno;
}

int
htt_rx_mpdu_desc_reorder_idx(htt_pdev_handle pdev, void *mpdu_desc)
{
    isoc_rx_bd_t *rx_bd;

    if (!pdev->rx.cur.rx_aggr_enabled) {
        /* no aggregation - rx reorder array only has a single element (0) */
        return 0;
    }
    rx_bd = mpdu_desc;
    return rx_bd->reorder_slot_idx;
}

void
(*htt_rx_mpdu_desc_pn)(
    htt_pdev_handle pdev,
    void *mpdu_desc,
    union htt_rx_pn_t *pn,
    int pn_len_bits);
void
_htt_rx_mpdu_desc_pn(
    htt_pdev_handle pdev,
    void *mpdu_desc,
    union htt_rx_pn_t *pn,
    int pn_len_bits)
{
    isoc_rx_bd_t *rx_bd = mpdu_desc;
    u_int32_t iv32;
    u_int16_t iv16;

    switch (pn_len_bits) {
        case 24:
            adf_os_print(
                "Error: PN length (%d bits) not implemented\n", pn_len_bits);
            pn->pn24 = 0;
            adf_os_assert(0);
            break;
        case 48:
            /* 
             * 48-bit replay counter is created as follows
             * from RX BD 6 byte PMI command:
             * Addr : AES/TKIP
             * 0x38 : pn3/tsc3
             * 0x39 : pn2/tsc2
             * 0x3a : pn1/tsc1
             * 0x3b : pn0/tsc0
             *
             * 0x3c : pn5/tsc5
             * 0x3d : pn4/tsc4 
             */
            iv32 = rx_bd->pmi_cmd4to23[4];  /* PN0-3 */
            iv16 = rx_bd->pmi_cmd24to25;    /* PN4-5 */
            pn->pn48 = (((u_int64_t)iv16) << 32) | iv32;
            break;

        case 128:
            adf_os_print(
                "Error: PN length (%d bits) not implemented\n", pn_len_bits);
            pn->pn128[0] = 0;
            pn->pn128[1] = 0;
            adf_os_assert(0);
            break;
        default:
            adf_os_print(
                "Error: invalid length spec (%d bits) for PN\n", pn_len_bits);
    };
}

u_int32_t
htt_rx_mpdu_desc_tsf32(
    htt_pdev_handle pdev,
    void *mpdu_desc)
{
    isoc_rx_bd_t *rx_bd = mpdu_desc;
    return rx_bd->rx_timestamp;
}

a_bool_t
(*htt_rx_msdu_desc_completes_mpdu)(htt_pdev_handle pdev, void *msdu_desc);
a_bool_t
_htt_rx_msdu_desc_completes_mpdu(htt_pdev_handle pdev, void *msdu_desc)
{
    isoc_rx_bd_t *rx_bd = msdu_desc;

    if (!rx_bd->amsdu) {
        return A_TRUE;
    } else {
        return rx_bd->amsdu_last ? A_TRUE : A_FALSE;
    }
}

a_bool_t
(*htt_rx_mpdu_is_encrypted)(htt_pdev_handle pdev, void *mpdu_desc);
a_bool_t
_htt_rx_mpdu_is_encrypted(htt_pdev_handle pdev, void *msdu_desc)
{
    isoc_rx_bd_t *rx_bd = msdu_desc;
    /* FIXME: Does this flag mean that this RX packet is a encrypted pakcet */
    return rx_bd->dpu_no_encrypt ? A_FALSE : A_TRUE;
}

a_bool_t
(*htt_rx_msdu_first_msdu_flag)(htt_pdev_handle pdev, void *msdu_desc);
a_bool_t
_htt_rx_msdu_first_msdu_flag(htt_pdev_handle pdev, void *msdu_desc)
{
    isoc_rx_bd_t *rx_bd = msdu_desc;
    return (a_bool_t)(rx_bd->amsdu_first);     // This casts is safe only because
                                               // amsdu_first is one bit wide
                                               // and a_bool_t is only 0 or 1
}

#define HTT_DXE_RSSI_TO_DBM(rssi) rssi /* FIX THIS */
int16_t
htt_rx_mpdu_desc_rssi_dbm(htt_pdev_handle pdev, void *mpdu_desc)
{
    isoc_rx_bd_t *rx_bd = mpdu_desc;
    u_int8_t rssi;

    /*
     * * Return the RSSI only for the first MPDU within an A-MPDU, and the
     * * first MSDU within an A-MSDU.
     * */
    if ((rx_bd->rxp_flags_ampdu_flag && ! rx_bd->rxp_flags_first_mpdu) ||
            (rx_bd->amsdu && ! rx_bd->amsdu_first))
    {
        /* not the initial subframe */
        return HTT_RSSI_INVALID;
    }
    /* CHECK THIS - choose whether to use rssi0, rssi1, rssi2, or rssi3 */
    rssi = rx_bd->rssi0;
    if (rssi < rx_bd->rssi1) {
        rssi = rx_bd->rssi1;
    }
    if (rssi < rx_bd->rssi2) {
        rssi = rx_bd->rssi2;
    }
    if (rssi < rx_bd->rssi3) {
        rssi = rx_bd->rssi3;
    }

    return HTT_DXE_RSSI_TO_DBM(rssi);
}

int
(*htt_rx_msdu_has_wlan_mcast_flag)(htt_pdev_handle pdev, void *msdu_desc);
int
_htt_rx_msdu_has_wlan_mcast_flag(htt_pdev_handle pdev, void *msdu_desc)
{
    isoc_rx_bd_t *rx_bd = msdu_desc;
    /*
     * If this is a standalone MPDU or the initial subframe of an A-MSDU,
     * the frame had a 802.11 MAC header, and based on the RA in the
     * 802.11 header the frame has a valid specification of WLAN multicast
     * vs. unicast.
     */
    return (!rx_bd->amsdu) || (rx_bd->amsdu_first);
}

a_bool_t
(*htt_rx_msdu_is_wlan_mcast)(htt_pdev_handle pdev, void *msdu_desc);
a_bool_t
_htt_rx_msdu_is_wlan_mcast(htt_pdev_handle pdev, void *msdu_desc)
{
    isoc_rx_bd_t *rx_bd = msdu_desc;
    return rx_bd->not_unicast ? A_TRUE : A_FALSE;
}

int
(*htt_rx_msdu_is_frag)(htt_pdev_handle pdev, void *msdu_desc);
int
_htt_rx_msdu_is_frag(htt_pdev_handle pdev, void *msdu_desc)
{
    return 0;
}

static inline int
_htt_rx_msdu_discard(htt_pdev_handle pdev, void *msdu_desc)
{
    /* check if this frame was flagged as a multicast echo - if so, discard */
    isoc_rx_bd_t *rx_bd = msdu_desc;
    return rx_bd->sw_flag_discard;
}

int
htt_rx_msdu_discard(htt_pdev_handle pdev, void *msdu_desc)
{
    return _htt_rx_msdu_discard(pdev, msdu_desc);
}

int
_htt_rx_msdu_forward(htt_pdev_handle pdev, void *msdu_desc)
{
    /*
     * Check if this frame was flagged for forwarding, due to:
     * 1. AP echo of multicast frames, i.e. transmission of unicast
     *    rx frames that carry a multicast DA
     * 2. STA to STA forwarding within an AP (NOT CURRENTLY SUPPORTED)
     */
    isoc_rx_bd_t *rx_bd = msdu_desc;
    return rx_bd->sw_flag_forward;
}

int
htt_rx_msdu_forward(htt_pdev_handle pdev, void *msdu_desc)
{
    return _htt_rx_msdu_forward(pdev, msdu_desc);
}

int
htt_rx_msdu_inspect(htt_pdev_handle pdev, void *msdu_desc)
{
/* FIX THIS (probably okay as is) */
    return 0;
}

void
htt_rx_msdu_actions(
    htt_pdev_handle pdev,
    void *msdu_desc,
    int *discard,
    int *forward,
    int *inspect)
{
    *discard = _htt_rx_msdu_discard(pdev, msdu_desc);
    *forward = _htt_rx_msdu_forward(pdev, msdu_desc);
/* FIX THIS (probably okay as is) */
    *inspect = 0;
}

int
(*htt_rx_amsdu_pop)(
    htt_pdev_handle pdev,
    adf_nbuf_t rx_ind_msg,
    adf_nbuf_t *head_msdu,
    adf_nbuf_t *tail_msdu);
int
_htt_rx_amsdu_pop(
    htt_pdev_handle pdev,
    adf_nbuf_t rx_ind_msg,
    adf_nbuf_t *head_msdu,
    adf_nbuf_t *tail_msdu)
{
    *head_msdu = pdev->rx.delivery.head;
    *tail_msdu = pdev->rx.delivery.tail;
    return 0;
}

int
(*htt_rx_offload_msdu_pop)(
    htt_pdev_handle pdev,
    adf_nbuf_t offload_deliver_msg,
    int *vdev_id,
    int *peer_id,
    int *tid,
    u_int8_t *fw_desc,
    adf_nbuf_t *head_buf,
    adf_nbuf_t *tail_buf);

int
_htt_rx_offload_msdu_pop(
    htt_pdev_handle pdev,
    adf_nbuf_t offload_deliver_msg,
    int *vdev_id,
    int *peer_id,
    int *tid,
    u_int8_t *fw_desc,
    adf_nbuf_t *head_buf,
    adf_nbuf_t *tail_buf)
{
    return 0;
}


void *
(*htt_rx_mpdu_desc_list_next)(htt_pdev_handle pdev, adf_nbuf_t rx_ind_msg);
void *
_htt_rx_mpdu_desc_list_next(htt_pdev_handle pdev, adf_nbuf_t rx_ind_msg)
{
    adf_nbuf_t rx_msdu;

    adf_os_assert(pdev->rx.delivery.head);
    rx_msdu = pdev->rx.delivery.head;

    /*
     * If this MPDU is an A-MSDU, then rx.delivery.head points to the
     * head of a linked-list of MSDUs comprising the A-MSDU.
     * Since htt_dxe_rx currently indicates one A-MSDU at a time,
     * there is no further MPDU chained on the rx.delivery list,
     * so just set rx.delivery to NULL.
     * If, for some reason htt_dxe_rx were changed to deliver multiple
     * MPDUs at a time, then this would need to be changed to walk the
     * list of MSDUs until the MSDU with rx_bd->amsdu_last is seen.
     */
    pdev->rx.delivery.head = NULL;

    /* the rx netbuf has the Rx BD in its headroom */
    return adf_nbuf_head(rx_msdu);
}

void *
(*htt_rx_msdu_desc_retrieve)(htt_pdev_handle pdev, adf_nbuf_t msdu);
void *
_htt_rx_msdu_desc_retrieve(htt_pdev_handle pdev, adf_nbuf_t msdu)
{
    /* the rx netbuf has the Rx BD in its headroom */
    return adf_nbuf_head(msdu);
}

void
htt_rx_desc_frame_free(
    htt_pdev_handle htt_pdev,
    adf_nbuf_t msdu)
{
    adf_nbuf_free(msdu);
}

void
htt_rx_msdu_desc_free(htt_pdev_handle htt_pdev, adf_nbuf_t msdu)
{
}

void
htt_rx_msdu_buff_replenish(htt_pdev_handle pdev)
{
}

void
htt_rx_get_vowext_stats(adf_nbuf_t msdu, struct vow_extstats *vowstats)
{
    /* FIXME: Need to set vowstats correctly */
}

u_int16_t
htt_rx_msdu_rx_desc_size_hl(
        htt_pdev_handle pdev,
        void *msdu_desc)
{
/* HACK WORKAROUND
 * The HL TXRX SW assumes the rx desc is present at adf_nbuf_data.
 * Until that is fixed, pretend that the descriptor is zero size,
 * so the call to adf_nbuf_pull_head in ol_rx_deliver will have no
 * effect.
 */
return 0;
}

adf_nbuf_t
htt_rx_restitch_mpdu_from_msdus(
    htt_pdev_handle pdev,
    adf_nbuf_t head_msdu,
    struct ieee80211_rx_status *rx_status,
    unsigned clone_not_reqd)
{
    adf_os_assert(0);
    return NULL;
}

/*--- setup / tear-down functions -------------------------------------------*/

A_STATUS
htt_dxe_rx_attach(struct htt_pdev_t *pdev)
{
    htt_rx_mpdu_desc_seq_num        = _htt_rx_mpdu_desc_seq_num;
    htt_rx_msdu_desc_completes_mpdu = _htt_rx_msdu_desc_completes_mpdu;
    htt_rx_msdu_has_wlan_mcast_flag = _htt_rx_msdu_has_wlan_mcast_flag;
    htt_rx_msdu_is_wlan_mcast       = _htt_rx_msdu_is_wlan_mcast;
    htt_rx_mpdu_desc_pn = _htt_rx_mpdu_desc_pn;
    htt_rx_amsdu_pop = _htt_rx_amsdu_pop;
    htt_rx_offload_msdu_pop = _htt_rx_offload_msdu_pop;
    htt_rx_mpdu_desc_list_next = _htt_rx_mpdu_desc_list_next;
    htt_rx_msdu_desc_retrieve = _htt_rx_msdu_desc_retrieve;
    htt_rx_msdu_is_frag = _htt_rx_msdu_is_frag;
    htt_rx_mpdu_is_encrypted = _htt_rx_mpdu_is_encrypted;
    htt_rx_msdu_first_msdu_flag = _htt_rx_msdu_first_msdu_flag;

    HTT_DXE_RX_REORDER_LOG_INIT(pdev);

    /* The pdev object was already set to zero in htt_dxe_attach,
     * so the following explicit inits of pdev->rx fields are not needed.
     * pdev->rx.delivery.head = NULL;
     * pdev->rx.delivery.tail = NULL;
     * adf_os_mem_zero(
     *     &pdev->rx.pending_amsdus[0], sizeof(pdev->rx.pending_amsdus));
     */

    return A_OK;
}

void
htt_dxe_rx_detach(struct htt_dxe_pdev_t *pdev)
{
}


char * 
htt_rx_mpdu_wifi_hdr_retrieve(htt_pdev_handle pdev, void *mpdu_desc) 
{
    //ToDO: Need to fix this function 
    adf_os_print( 
                "Error: %s is not implemented\n", __FUNCTION__); 
    return NULL; 
} 

/*--- debug functions -------------------------------------------------------*/

#if HTT_DXE_RX_LOG

void
htt_dxe_rx_reorder_log_init(struct htt_pdev_t *pdev)
{
    pdev->reorder_log.idx = 0;
    pdev->reorder_log.wrap = 1; /* ?? */
    pdev->reorder_log.wrapped = 0;
    pdev->reorder_log.enable = 1;
}

void
htt_dxe_rx_reorder_log_add(
    struct htt_pdev_t *pdev,
    u_int16_t peer_id,
    u_int8_t tid,
    isoc_rx_bd_t *rx_bd)
{
    struct htt_dxe_rx_log_elem_t *log_elem;

    if (!pdev->reorder_log.enable ||
        pdev->reorder_log.idx >= HTT_DXE_RX_LOG_LEN)
    {
        return;
    }
    log_elem = &pdev->reorder_log.data[pdev->reorder_log.idx];

    log_elem->peer_id = peer_id;
    log_elem->tid = tid;

    if (rx_bd) { /* rx frame */
        log_elem->seq_num = rx_bd->current_pkt_seqno;
        log_elem->reorder_opcode = rx_bd->reorder_opcode;
        log_elem->slot_idx = rx_bd->reorder_slot_idx;
        log_elem->fwd_idx =  rx_bd->reorder_fwd_idx;
    } else { /* DELBA message */
        log_elem->seq_num = -1;
        log_elem->reorder_opcode = HTT_DXE_RX_PSEUDO_OPCODE_DELBA;
        log_elem->slot_idx = -1;
        log_elem->fwd_idx = -1;
    }

    pdev->reorder_log.idx++;
    if (pdev->reorder_log.idx == HTT_DXE_RX_LOG_LEN && pdev->reorder_log.wrap) {
        pdev->reorder_log.idx = 0;
        pdev->reorder_log.wrapped = 1;
    }
}

#define htt_dxe_rx_reorder_log_print htt_rx_reorder_log_print
void
htt_dxe_rx_reorder_log_print(struct htt_pdev_t *pdev)
{
    int num, idx;

    if (pdev->reorder_log.wrapped) {
        idx = pdev->reorder_log.idx;
        num = HTT_DXE_RX_LOG_LEN;
    } else {
        idx = 0;
        num = pdev->reorder_log.idx;
    }

    if (num > 0) {
        adf_os_print(
            "htt_dxe_rx reorder log:\n"
            "    "
            "peer |     |  seq |        | slot | fwd |  flush  | release |\n"
            "    "
            " id  | TID |  num | opcode | idx  | idx | y? | to | y? | to |\n"
            "    "
            "-------------------------------------------------------------\n");
    }
    while (num-- > 0) {
        int is_flush, is_rel, seq_num;
        unsigned reorder_opcode;
        struct htt_dxe_rx_log_elem_t *log_elem;

        log_elem = &pdev->reorder_log.data[idx];

        seq_num = log_elem->seq_num;
        reorder_opcode = log_elem->reorder_opcode;
        if (reorder_opcode == HTT_DXE_RX_PSEUDO_OPCODE_DELBA) {
            is_flush = 1;
            is_rel = 0;
        } else {
            is_flush = htt_dxe_reorder_opcode_is_flush(reorder_opcode);
            is_rel = htt_dxe_reorder_opcode_is_release(reorder_opcode);
        }
        if (reorder_opcode == ISOC_RX_OPCODE_FWDBUF_DROPCUR ||
            reorder_opcode == ISOC_RX_OPCODE_FWDALL_DROPCUR)
        {
            seq_num = -1;
        }
        adf_os_print(
            "    %3d  | %2d  | %4d |  %s |  %2d  | %2d  |"
            " %s  | %2d | %s  | %2d |\n",
            log_elem->peer_id,
            log_elem->tid,
            seq_num,
            htt_dxe_rx_reorder_opcode_str(reorder_opcode),
            log_elem->slot_idx,
            log_elem->fwd_idx,
            is_flush ? "Y" : "n",
            is_flush ? log_elem->fwd_idx : -1,
            is_rel ? "Y" : "n",
            is_rel ? log_elem->fwd_idx : -1);
        idx++;
        idx &= HTT_DXE_RX_LOG_LEN_MASK;
    }
}

#endif /* HTT_DXE_RX_LOG */
