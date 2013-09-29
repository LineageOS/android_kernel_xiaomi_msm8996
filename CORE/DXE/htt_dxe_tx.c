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
 * @file htt_dxe_tx.c
 * @brief Implement transmit aspects of HTT.
 * @details
 *  This file contains three categories of HTT tx code:
 *  1.  An abstraction of the tx descriptor
 *  2.  Functions for allocating and freeing HTT tx descriptors.
 *  3.  The function that accepts a tx frame from txrx and sends the
 *      tx frame to hif_dxe.
 */
#include <osdep.h>           /* u_int32_t, offsetof, etc. */
#include <adf_os_types.h>    /* adf_os_dma_addr_t */
#include <adf_os_mem.h>      /* adf_os_mem_alloc_consistent,free_consistent */
#include <adf_os_util.h>     /* adf_os_likely */
#include <adf_nbuf.h>        /* adf_nbuf_t, etc. */

#include <athdefs.h>         /* A_STATUS */

#include <ol_cfg.h>          /* ol_cfg_sw_encap_hdr_max_size */
#include <hif_dxe.h>         /* hif_dxe_send */
#include <isoc_hw_desc.h>    /* isoc_tx_bd_t, etc. */
#include <ol_htt_tx_api.h>
#include <ol_txrx_htt_api.h> /* ol_tx_download_done_hl_free, etc. */

#include <htt_dxe_internal.h> /* HTT_DXE_ASSERT */

/*--- utilities -------------------------------------------------------------*/

#ifndef ARRAY_LEN
#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))
#endif


/*--- constants -------------------------------------------------------------*/

enum {
    HTT_DXE_TX_SSN_FILL_HOST        = 0,
    HTT_DXE_TX_SSN_FILL_DPU_NON_QOS = 1,
    HTT_DXE_TX_SSN_FILL_DPU_QOS     = 2,
};

enum {
    HTT_DXE_TX_BDRATE_DEFAULT      = 0,
    HTT_DXE_TX_BDRATE_BCDATA_FRAME = 1, /* unused */
    HTT_DXE_TX_BDRATE_BCMGMT_FRAME = 2,
    HTT_DXE_TX_BDRATE_CTRL_FRAME   = 3,
};

enum {
    HTT_DXE_ACK_POLICY_ACK    = 0,
    HTT_DXE_ACK_POLICY_NO_ACK = 1,
};

enum {
    HTT_DXE_TX_BTQM_QID0  = 0,
    HTT_DXE_TX_BTQM_QID1  = 1,
    HTT_DXE_TX_BTQM_QID2  = 2,
    HTT_DXE_TX_BTQM_QID3  = 3,
    HTT_DXE_TX_BTQM_QID4  = 4,
    HTT_DXE_TX_BTQM_QID5  = 5,
    HTT_DXE_TX_BTQM_QID6  = 6,
    HTT_DXE_TX_BTQM_QID7  = 7,
    HTT_DXE_TX_BTQM_QID8  = 8,
    HTT_DXE_TX_BTQM_QID9  = 9,
    HTT_DXE_TX_BTQM_QID10 = 10,

    HTT_DXE_TX_BTQM_QUEUE_SELF_STA_BCAST_MGMT = HTT_DXE_TX_BTQM_QID10,
    HTT_DXE_TX_BTQM_QUEUE_SELF_STA_UCAST_MGMT = HTT_DXE_TX_BTQM_QID9,
    HTT_DXE_TX_BTQM_QUEUE_SELF_STA_UCAST_DATA = HTT_DXE_TX_BTQM_QID9,
    HTT_DXE_TX_BTQM_QUEUE_TX_NON_QOS = HTT_DXE_TX_BTQM_QID8,

};

enum {
    HTT_DXE_TX_BMUWQ_BTQM_TX_MGMT = 25,
};

/*--- utility functions -----------------------------------------------------*/

static inline u_int16_t *
htt_dxe_tx_msdu_id_storage(adf_nbuf_t msdu)
{
    adf_os_assert(adf_nbuf_headroom(msdu) >= (sizeof(u_int16_t) * 2 - 1));
    return (u_int16_t *) (((adf_os_size_t) (adf_nbuf_head(msdu) + 1)) & ~0x1);
}

/*
 * The Tx BD is supposed to be in big-endian format.
 * On a little endian host, the Tx BD is produced in the expected format by
 * 1.  using the conditionally-compiled Tx BD bitfield defs from
 *     isoc_hw_desc.h to make sure the bitfields are at the correct positions
 *     within a 32-bit word.
 * 2.  Using the HTT_DXE_TX_BD_BYTESWAP function to swap the bytes within each
 *     32-bit word of the Tx BD, so when the Tx BD is stored in little-endian
 *     order, the shuffled bytes will end up in big-endian order.
 *     (The byte-shuffling will cancel out the little-endian byte ordering
 *     that occurs as the 32-bit words are stored into bytes of memory.)
 */
#ifndef BIG_ENDIAN_HOST
/* little-endian - swap the bytes */
static inline void
HTT_DXE_TX_BD_BYTESWAP(isoc_tx_bd_t *tx_bd)
{
    isoc_hw_bd_swap_bytes32((char *) tx_bd, sizeof(*tx_bd));
}
#else
/* big-endian - bytes are naturally in the correct order, no swap needed */
#define HTT_DXE_TX_BD_BYTESWAP(tx_bd) /* no-op */
#endif /* BIG_ENDIAN_HOST */

/*--- debug functions -------------------------------------------------------*/

#ifdef HTT_DBG
#define htt_dxe_tx_desc_display htt_tx_desc_display
void
htt_tx_desc_display(void *tx_desc)
{
    struct htt_dxe_tx_desc_t *sw_tx_desc = (struct htt_dxe_tx_desc_t *) desc;
    isoc_tx_bd_dump((isoc_tx_bd_t *) sw_tx_desc->tx_bd_buf);
}
#endif

#ifndef HTT_DXE_TX_DEBUG_LEVEL
#define HTT_DXE_TX_DEBUG_LEVEL 1 /* default */
#endif

#if defined(HTT_DBG) || HTT_DXE_TX_DEBUG_LEVEL > 1

void HTT_DXE_TX_BD_DUMP(isoc_tx_bd_t *tx_bd)
{
    isoc_tx_bd_t tmp_tx_bd;

    /*
     * Make our own copy of the Tx BD.
     * This is mainly so we can convert the Tx BD back to little-endian
     * format for a printout, if the host is little-endian.
     * A secondary purpose is to do a single block-copy from the
     * real Tx BD in non-cacheable memory into a cacheable location,
     * before reading and printing fields of the struct.
     */
    tmp_tx_bd = *tx_bd;
    /* undo the endianness fix */
    HTT_DXE_TX_BD_BYTESWAP(&tmp_tx_bd);
    isoc_tx_bd_dump(&tmp_tx_bd);
}
#else
#define HTT_DXE_TX_BD_DUMP(tx_bd) /* no-op */
#endif

/*--- setup / tear-down functions -------------------------------------------*/

A_STATUS
htt_dxe_tx_attach(struct htt_dxe_pdev_t *pdev, int desc_pool_elems)
{
    int i, pool_size;
    adf_os_dma_addr_t pool_paddr;
    struct htt_dxe_tx_desc_t *sw_desc;
    char *tx_bd_buf;

    pdev->tx_descs.sw_descs_pool = NULL;
    pdev->tx_descs.tx_bds.pool_vaddr = NULL;

    /*--- allocate the pool of SW tx descs ---*/
    pool_size = sizeof(struct htt_dxe_tx_desc_t) * desc_pool_elems;
    pdev->tx_descs.sw_descs_pool = adf_os_mem_alloc(pdev->osdev, pool_size);
    if (!pdev->tx_descs.sw_descs_pool) {
        goto fail;
    }

    /*--- allocate the pool of HW tx descs ---*/
    pdev->tx_descs.size =
        ol_cfg_sw_encap_hdr_max_size(pdev->ctrl_pdev) +
        sizeof(isoc_tx_bd_t);
    if (pdev->tx_descs.size < sizeof(u_int32_t *)) {
        pdev->tx_descs.size = sizeof(u_int32_t *);
    }
    /*
     * Make sure tx_descs.size is a multiple of 4-bytes.
     * It should be, but round up just to be sure.
     */
    pdev->tx_descs.size = (pdev->tx_descs.size + 3) & (~0x3);

    pdev->tx_descs.pool_elems = desc_pool_elems;
    pdev->tx_descs.alloc_cnt = 0;

    pool_size = pdev->tx_descs.pool_elems * pdev->tx_descs.size;

/* allocate extra, for alignment padding? */
    pdev->tx_descs.tx_bds.pool_vaddr = adf_os_mem_alloc_consistent(
        pdev->osdev, pool_size, &pool_paddr,
        adf_os_get_dma_mem_context((&pdev->tx_descs), memctx));
    pdev->tx_descs.tx_bds.pool_paddr = pool_paddr;

    if (!pdev->tx_descs.tx_bds.pool_vaddr) {
        goto fail;
    }

    /*-- link HW descs with SW descs, and link SW descs into a freelist ---*/
    pdev->tx_descs.freelist = NULL;
    tx_bd_buf = pdev->tx_descs.tx_bds.pool_vaddr;
    sw_desc = pdev->tx_descs.sw_descs_pool;
    for (i = 0; i < desc_pool_elems; i++) {
        sw_desc->tx_bd_buf = tx_bd_buf; 
        htt_dxe_tx_desc_free(pdev, sw_desc);

        sw_desc++;
        tx_bd_buf += pdev->tx_descs.size;
    }

    /* program the constant fields within the template Tx BD */
    /* currently, nearly all constant fields need to be set to zero */
    adf_os_mem_zero(&pdev->template_tx_bd, sizeof(pdev->template_tx_bd));
    pdev->template_tx_bd.mpdu_header_offset = sizeof(isoc_tx_bd_t);

    /* initialize the Tx BD serial number */
    pdev->tx_bd_sig_serial_num = 0;

    return A_OK; /* success */

fail:
    /* clean up any partial inits */
    htt_dxe_tx_detach(pdev);
    return A_ERROR;
}

void
htt_dxe_tx_detach(struct htt_dxe_pdev_t *pdev)
{
    if (pdev->tx_descs.sw_descs_pool) {
        adf_os_mem_free(pdev->tx_descs.sw_descs_pool);
    }
    if (pdev->tx_descs.tx_bds.pool_vaddr) {
        adf_os_mem_free_consistent(
            pdev->osdev,
            pdev->tx_descs.pool_elems * pdev->tx_descs.size, /* pool_size */
            pdev->tx_descs.tx_bds.pool_vaddr,
            pdev->tx_descs.tx_bds.pool_paddr,
            adf_os_get_dma_mem_context((&pdev->tx_descs), memctx));
    }
}

/*--- descriptor allocation functions ---------------------------------------*/

void *
htt_dxe_tx_desc_alloc(struct htt_dxe_pdev_t *pdev, u_int32_t *paddr_lo)
{
    struct htt_dxe_tx_desc_t *sw_desc;
    u_int32_t offset;

    sw_desc = pdev->tx_descs.freelist;
    if (! sw_desc) {
        return NULL; /* pool is exhausted */
    }

    pdev->tx_descs.freelist = sw_desc->u.next;
    pdev->tx_descs.alloc_cnt++;

    offset = (u_int32_t)
        (((char *) sw_desc->tx_bd_buf) -
         ((char *) pdev->tx_descs.tx_bds.pool_vaddr));
    *paddr_lo = ((u_int32_t) pdev->tx_descs.tx_bds.pool_paddr) + offset;
    return (void *) sw_desc;
}

void
htt_dxe_tx_desc_free(struct htt_dxe_pdev_t *pdev, void *abstract_desc)
{
    struct htt_dxe_tx_desc_t *sw_desc;

    sw_desc = (struct htt_dxe_tx_desc_t *) abstract_desc;
    sw_desc->u.next = pdev->tx_descs.freelist;
    pdev->tx_descs.freelist = sw_desc;
    pdev->tx_descs.alloc_cnt--;
}

#define htt_dxe_tx_desc_mpdu_header htt_tx_desc_mpdu_header
volatile char *
htt_dxe_tx_desc_mpdu_header(void *abstract_desc, u_int8_t new_l2_hdr_size)
{
    struct htt_dxe_tx_desc_t *sw_desc;

    sw_desc = (struct htt_dxe_tx_desc_t *) abstract_desc;
    sw_desc->u.info.l2_hdr_size = new_l2_hdr_size;
    return sw_desc->tx_bd_buf + sizeof(isoc_tx_bd_t);
}


#ifdef HTT_DBG
void
htt_dxe_tx_desc_display(void *tx_desc)
{
}
#endif

/*--- tx descriptor programming functions -----------------------------------*/

static u_int16_t
htt_dxe_tx_select_peer(
    struct htt_dxe_pdev_t *pdev,
    struct htt_msdu_info_t *msdu_info,
    int is_robust_mgmt)
{
    struct htt_dxe_vdev_t *vdev;

    vdev = &pdev->vdevs[msdu_info->info.vdev_id];
    if (vdev->op_mode == htt_op_mode_sta) {
        if (msdu_info->info.frame_type == htt_frm_type_data) {
            /* use the real peer object */
            return msdu_info->info.peer_id;
        } else if (is_robust_mgmt) {
            /* for robust management, use the real peer object */
            return msdu_info->info.peer_id;
        } else {
            /* regular management - use self-peer */
            return vdev->self_peer_id;
        }
    } else {
        /* AP */
        if (msdu_info->info.is_unicast) {
            if (msdu_info->info.frame_type == htt_frm_type_data) {
                /* use the real peer object */
                return msdu_info->info.peer_id;
            } else {
                /*
                 * unicast management -
                 * Is there a valid peer?  If so, use it.
                 * If not (probe-resp or assoc-resp), use the self-peer.
                 */
                return msdu_info->info.peer_id == HTT_INVALID_PEER_ID ?
                    vdev->self_peer_id : msdu_info->info.peer_id;
            }
        } else {
            /* use broadcast self-STA */
            return vdev->bcast_peer_id;
        }
    }
}

static u_int8_t
htt_dxe_tx_tid_translate(u_int8_t ext_tid, int is_mgmt)
{
    if (is_mgmt) return 7;
    if (ext_tid > 7) return 0;
    return ext_tid;
}

static inline u_int8_t
htt_dxe_tx_qos_queue_id(u_int8_t tid)
{
    static u_int8_t tid_queue_ids[] = {
        HTT_DXE_TX_BTQM_QID0, HTT_DXE_TX_BTQM_QID1,
        HTT_DXE_TX_BTQM_QID2, HTT_DXE_TX_BTQM_QID3,
        HTT_DXE_TX_BTQM_QID4, HTT_DXE_TX_BTQM_QID5,
        HTT_DXE_TX_BTQM_QID6, HTT_DXE_TX_BTQM_QID7 };
    /*
     * Confirm this is a UP TID (0-7), not a regular TID (0-15)
     * or extended TID (0-17).
     */
    adf_os_assert(tid < ARRAY_LEN(tid_queue_ids));

    return tid_queue_ids[tid];
}

enum {
    HTT_DXE_TXBD_SIG_SERIAL_NUM_SHIFT    =  0,
    HTT_DXE_TXBD_SIG_TID_SHIFT           =  8,
    HTT_DXE_TXBD_SIG_UCAST_SHIFT         =  9,
    HTT_DXE_TXBD_SIG_DEST_MAC_ADDR_SHIFT = 16,
};
#define HTT_DXE_TXBD_SIG_MGMT_MAGIC 0xbdbdbdbd

/*
 * NOTE: this Tx BD signature computation function is currently not used.
 * Its purpose is to show whether the prior contents of a Tx BD can be
 * reused for a new frame.
 * This optimization is not currently utilized, nor are there plans to
 * utilize it.
 * However, this function is being left in place just in case this
 * optimization is utilized in the future.
 */
static inline u_int32_t
htt_dxe_tx_bd_signature(
    struct htt_dxe_pdev_t *pdev,
    u_int8_t *dest_mac_addr,
    u_int8_t tid,
    u_int8_t is_unicast,
    int is_data)
{
    u_int16_t *dest_mac_addr16 = (u_int16_t *) dest_mac_addr;
    u_int16_t dest_mac_addr_hash16;

    if ((!is_data) || (!pdev->cfg.flags.do_frame_translate)) {
        return HTT_DXE_TXBD_SIG_MGMT_MAGIC;
    }

    /* confirm dest addr has 2-byte alignment, so the above typecast is safe */
    adf_os_assert(((unsigned) dest_mac_addr & 0x1) == 0);

    dest_mac_addr_hash16 =
        dest_mac_addr16[0] ^ dest_mac_addr16[1] ^ dest_mac_addr[2];
    return
        (dest_mac_addr_hash16 << HTT_DXE_TXBD_SIG_DEST_MAC_ADDR_SHIFT)    |
        // FIX THIS: update tx_bd_sig_serial_num
        (pdev->tx_bd_sig_serial_num << HTT_DXE_TXBD_SIG_SERIAL_NUM_SHIFT) |
        (tid << HTT_DXE_TXBD_SIG_TID_SHIFT)                               |
        (is_unicast << HTT_DXE_TXBD_SIG_UCAST_SHIFT);
}

static void
htt_dxe_tx_bd_fill(
    struct htt_dxe_pdev_t *pdev,
    struct htt_dxe_tx_desc_t *sw_tx_desc,
    int msdu_len,
    struct htt_msdu_info_t *msdu_info)
{
    struct htt_dxe_peer_t *peer;
    isoc_tx_bd_t shadow_tx_bd = pdev->template_tx_bd;
    int tid;
    int peer_id;
    int which_key;
    int l2_hdr_size;
    int is_data;
    int is_robust_mgmt;

    /*
     * The following Tx BD fields are only used internally within the
     * target.  The host does not need to program these fields.
     *     adu_feedback
     *     dpu_feedback
     *     head_pdu_idx
     *     tail_pdu_idx
     *     pdu_count
     *     dxe_h2b_start_timestamp
     *     dxe_h2b_end_timestamp
     *
     * The following Tx BD fields are constant, and are copied from the
     * template:
     *     fw_tx_complete_intr (value = 0)
     *     bd_type (value = 0)
     *     mpdu_header_offset (value = sizeof(isoc_tx_bd_t))
     *     reserved fields (some of these need to be 0)
     *     tx_bd_signature (value = 0)
     *         The tx_bd_signature is a reserved field that can be used
     *         by the host SW to determine whether the new tx frame is
     *         similar enough to the prior tx frame described by this
     *         Tx BD to avoid reprogramming the Tx BD from scratch.
     *         The htt_dxe module doesn't attempt this optimization.
     */

    is_data = msdu_info->info.frame_type == htt_frm_type_data;
    sw_tx_desc->u.info.is_mgmt = !is_data;
    tid = htt_dxe_tx_tid_translate(msdu_info->info.ext_tid, !is_data);
    is_robust_mgmt =
        (!is_data) &&
        /*
         * The peer ID will be HTT_INVALID_PEER_ID if either this is a
         * multicast / broadcast frame, or if this is a unicast frame
         * to an unassociated peer (probe req/resp, assoc req/resp).
         * Thus, it's not necessary to separately check is_unicast.
         */
        (msdu_info->info.peer_id != HTT_INVALID_PEER_ID) &&
        (pdev->peers[msdu_info->info.peer_id].robust_mgmt) &&
        (msdu_info->info.frame_subtype == htt_frm_subtype_mgmt_action ||
         msdu_info->info.frame_subtype == htt_frm_subtype_mgmt_deauth ||
         msdu_info->info.frame_subtype == htt_frm_subtype_mgmt_disassoc);

    /*
     * Decide whether to use the peer ID provided by txrx,
     * or use the self or BSS peer.
     */
    peer_id = htt_dxe_tx_select_peer(pdev, msdu_info, is_robust_mgmt);
    peer = &pdev->peers[peer_id];
    /*
     * There should never be a transmission that uses an uninitialized
     * real-peer or self-peer object.  Do a sanity check that the peer
     * object has been initialized via a PEER_INFO message.
     */
    HTT_DXE_ASSERT2(peer->valid);
    /*
     * The msdu_info's l3_hdr_offset is always valid, and thus can be used
     * as the l2_hdr_size.
     * For data frames without SW encap, the l3_hdr_offset is the offset
     * within the tx MSDU's netbuf from the start of the L2 header.
     * For data frames with SW encap, the old L2 header has been removed
     * from the netbuf (by pulling the data pointer past the old L2 header),
     * but the l3_hdr_offset still accounts for the new L2 header, even though
     * that new L2 header is stored in a buffer provided by HTT, rather than
     * in the tx netbuf.
     * For management frames, the 802.11 L2 header is present in the netbuf,
     * and the msdu_info's l3_hdr_offset has been set to
     * sizeof(ieee80211_frame).
     */
    l2_hdr_size = msdu_info->info.l3_hdr_offset;

    if (adf_os_likely(msdu_info->info.is_unicast)) {
        /*=== unicast data and mgmt ===*/
        // TBD:
        //check consistency with frame hdr ack policy field, if SW tx encap?
        shadow_tx_bd.ack_policy = HTT_DXE_ACK_POLICY_ACK;
        which_key = HTT_DXE_PEER_KEY_UCAST;

        if (adf_os_likely(is_data)) {
            shadow_tx_bd.queue_id = (peer->qos_capable) ?
                htt_dxe_tx_qos_queue_id(tid) : HTT_DXE_TX_BTQM_QUEUE_TX_NON_QOS;
        } else {
            /*--- unicast mgmt ---*/
            int is_associated = msdu_info->info.peer_id == HTT_INVALID_PEER_ID;
            shadow_tx_bd.queue_id = (is_associated) ?
                /* regular unicast mgmt frames - expect ack */
                HTT_DXE_TX_BTQM_QUEUE_SELF_STA_UCAST_MGMT :
                /* probe request/response, assoc request/response - no ack */
                HTT_DXE_TX_BTQM_QUEUE_SELF_STA_BCAST_MGMT;
        }
    } else {
        /*=== multicast data and mgmt ===*/
        //TBD:
        //check consistency with frame hdr ack policy field, if SW tx encap?
        shadow_tx_bd.ack_policy = HTT_DXE_ACK_POLICY_NO_ACK;
        if (is_data) {
            /*--- multicast data ---*/
            which_key = HTT_DXE_PEER_KEY_MCAST;
            shadow_tx_bd.queue_id = HTT_DXE_TX_BTQM_QID0;
        } else {
            /*--- multicast mgmt ---*/
            which_key = HTT_DXE_PEER_KEY_MGMT;
            shadow_tx_bd.queue_id = HTT_DXE_TX_BTQM_QUEUE_SELF_STA_BCAST_MGMT;
        }
    }

    if (is_data) {
        /*=== multicast and unicast data ===*/
        shadow_tx_bd.bd_seq_num_src = (peer->qos_capable) ?
            HTT_DXE_TX_SSN_FILL_DPU_QOS : HTT_DXE_TX_SSN_FILL_DPU_NON_QOS;
        shadow_tx_bd.bd_rate = HTT_DXE_TX_BDRATE_DEFAULT;

        /*
         * riva: no frame translation (tx encap done by SW)
         * pronto + northstar:
         * depending on frame format, enable HW frm translate
         */
        shadow_tx_bd.frame_translate = pdev->cfg.flags.do_frame_translate;
    } else {
        /*=== multicast and unicast mgmt ===*/
        if (is_robust_mgmt) {
            shadow_tx_bd.robust_mgmt = 1;
            /* make sure the "no_encrypt" flag gets turned off */
            msdu_info->action.do_encrypt = 1;
        } else {
            /* besides the robust mgmt case, mgmt frames are not encrypted */
            msdu_info->action.do_encrypt = 0;
        }
        shadow_tx_bd.bd_seq_num_src = HTT_DXE_TX_SSN_FILL_DPU_NON_QOS;
        /*
         * bd_rate:
         * Check if the rate is forced to 6 Mbps (for mgmt frames in the
         * 5 GHz band, or for mgmt frames sent by P2P devices).
         * Otherwise, unicast mgmt frames will go at lower rate
         * (multicast rate).  Multicast mgmt frames will go at the
         * STA rate as in AP mode.  Buffering has an issue at HW
         * if BD rate is used.
         */
        if (msdu_info->action.use_6mbps) {
            shadow_tx_bd.bd_rate = HTT_DXE_TX_BDRATE_CTRL_FRAME;
        } else {
            shadow_tx_bd.bd_rate = (msdu_info->info.is_unicast) ?
                HTT_DXE_TX_BDRATE_BCMGMT_FRAME : HTT_DXE_TX_BDRATE_DEFAULT;
        }
        /* mgmt frames already have a 802.11 header - no frame translation */
        shadow_tx_bd.frame_translate = 0;
    }

    shadow_tx_bd.dpu_no_encrypt = ! msdu_info->action.do_encrypt;
    if(msdu_info->action.do_tx_complete) {
        adf_os_print("*** WARNING: Pronto SW for OTA tx ack is incomplete!\n");
    }
    shadow_tx_bd.tx_complete_intr = msdu_info->action.do_tx_complete;
    shadow_tx_bd.not_unicast = ! msdu_info->info.is_unicast;
    shadow_tx_bd.sta_index = peer_id;
    shadow_tx_bd.tid = tid;
    shadow_tx_bd.mpdu_header_length = l2_hdr_size;
    shadow_tx_bd.mpdu_data_offset = sizeof(isoc_tx_bd_t) + l2_hdr_size;
    shadow_tx_bd.mpdu_length = msdu_len + sw_tx_desc->u.info.l2_hdr_size;
    shadow_tx_bd.dpu_signature = peer->security[which_key].signature;
    shadow_tx_bd.dpu_desc_idx = peer->security[which_key].id;

    // FIX THIS
    #if 0
    shadow_tx_bd.dpu_routing_flag = (trigger-enabled frame & U-APSD mode on) ?
        BMUWQ_FW_DPU_TX : HTT_DXE_TX_BMUWQ_BTQM_TX_MGMT;
    #else
    // TEMPORARY: default to HTT_DXE_TX_BMUWQ_BTQM_TX_MGMT
    shadow_tx_bd.dpu_routing_flag = HTT_DXE_TX_BMUWQ_BTQM_TX_MGMT;
    #endif

    /* fix endianness */
    HTT_DXE_TX_BD_BYTESWAP(&shadow_tx_bd);

    /* signature uses native endianness */
    #if 0 /* using signature to avoid reprogramming Tx BD is not supported */
    shadow_tx_bd.tx_bd_signature = htt_dxe_tx_bd_signature(
        pdev, msdu_info->info.dest_addr, tid, msdu_info->info.is_unicast,
        is_data);
    #endif

    adf_os_mem_copy(
        (char *) sw_tx_desc->tx_bd_buf, &shadow_tx_bd, sizeof(shadow_tx_bd));
}

void htt_tx_desc_set_peer_id(u_int32_t *htt_tx_desc, u_int16_t peer_id)
{
    /* FILL IN HERE */
    return;
}

void
htt_tx_desc_init(
    htt_pdev_handle pdev,
    void *desc,
    u_int32_t htt_tx_desc_paddr_lo,
    u_int16_t msdu_id,
    adf_nbuf_t msdu,
    struct htt_msdu_info_t *msdu_info)
{
    struct htt_dxe_tx_desc_t *sw_tx_desc = (struct htt_dxe_tx_desc_t *) desc;
    int frag_size;

#if defined(HTT_DBG) || HTT_DXE_TX_DEBUG_LEVEL > 1
    htt_msdu_info_dump(msdu_info);
#endif
    htt_dxe_tx_bd_fill(pdev, sw_tx_desc, adf_nbuf_len(msdu), msdu_info);

    /* store the TID for later so we can determine which frames are mgmt */
    sw_tx_desc->u.info.ext_tid = msdu_info->info.ext_tid;

    /* add Tx BD as initial fragment to the netbuf */
    frag_size = sizeof(isoc_tx_bd_t);
    /* account for the L2 encapsulation header, if any */
    frag_size += sw_tx_desc->u.info.l2_hdr_size;
    adf_nbuf_frag_push_head(
        msdu,
        frag_size,
        /*
         * Pass in the address of the SW tx descriptor rather than the
         * virtual address of the Tx BD itself.
         * The underlying layers don't need to use the Tx BD virtual address;
         * they only care about the physical address.
         * If this layer needs need to find the Tx BD, it can use the
         * sw_tx_desc->tx_bd_buf
         * We retrieve this SW tx descriptor pointer later during the tx_send
         * function, e.g. to check whether the frame is data or mgmt.
         */
        (char *) sw_tx_desc, //sw_tx_desc->tx_bd_buf, /* virtual addr */
        htt_tx_desc_paddr_lo/*phy addr LSBs*/, 0 /* phys addr MSBs - n/a */);
}

/*--- tx send function ------------------------------------------------------*/

#define htt_dxe_tx_send_std htt_tx_send_std
int
htt_dxe_tx_send_std(
    struct htt_dxe_pdev_t *pdev,
    adf_nbuf_t msdu,
    u_int16_t msdu_id)
{
    struct htt_dxe_tx_desc_t *sw_tx_desc;
    u_int16_t *msdu_id_storage;
    int is_mgmt;
    E_HIFDXE_CHANNELTYPE dxe_chan;

    /*
     * The HTT tx descriptor was attached as the prefix fragment to the
     * msdu netbuf during the call to htt_tx_desc_init.
     * Retrieve it so we can check whether the frame is data or mgmt.
     */
    sw_tx_desc = (struct htt_dxe_tx_desc_t *) adf_nbuf_get_frag_vaddr(msdu, 0);

    is_mgmt = sw_tx_desc->u.info.is_mgmt;

    /* for debugging, optionally show Tx BD contents */
    HTT_DXE_TX_BD_DUMP((isoc_tx_bd_t *) sw_tx_desc->tx_bd_buf);

    /* store MSDU ID */
    msdu_id_storage = htt_dxe_tx_msdu_id_storage(msdu);
    *msdu_id_storage = msdu_id;

    /* send the frame to hif_dxe */
    dxe_chan = (is_mgmt) ?
        HIFDXE_CHANNEL_TX_HIGH_PRI : HIFDXE_CHANNEL_TX_LOW_PRI;

    /* FOR NOW, send only one frame at a time */
    adf_nbuf_set_next(msdu, NULL);

    return hif_dxe_send(pdev->hif_dxe_pdev, dxe_chan, msdu) != A_OK;
}

#define htt_dxe_tx_send_nonstd htt_tx_send_nonstd
int
htt_dxe_tx_send_nonstd(
    struct htt_dxe_pdev_t *pdev,
    adf_nbuf_t msdu,
    u_int16_t msdu_id,
    enum htt_pkt_type pkt_type)
{
    /*
     * Since the whole frame gets downloaded, frames with a non-standard
     * L2 header are handled the same as any other frame.
     */
    return htt_dxe_tx_send_std(pdev, msdu, msdu_id);
}

#define htt_dxe_tx_send_batch htt_tx_send_batch
adf_nbuf_t
htt_dxe_tx_send_batch(
    struct htt_dxe_pdev_t *pdev,
    adf_nbuf_t head_msdu,int num_msdus)
{
    /* FILL IN HERE */
    adf_os_assert(0);
    return NULL;
}

#define htt_dxe_tx_msdu_credit htt_tx_msdu_credit
u_int32_t htt_dxe_tx_msdu_credit(adf_nbuf_t msdu)
{
    /*
     * Credits represent the number of spaces available in the DXE ring.
     * Each frame consumes one DXE descriptor for each of its fragments.
     * Hence, return the number of fragments in the frame.
     */
    return adf_nbuf_get_num_frags(msdu);
}

/*--- callback functions ----------------------------------------------------*/

A_STATUS
htt_dxe_tx_download_done(
    void *context,
    adf_nbuf_t msdus,
    E_HIFDXE_CHANNELTYPE chan,
    A_STATUS status)
{
    struct htt_dxe_pdev_t *pdev = (struct htt_dxe_pdev_t *) context;
    u_int16_t *msdu_id_storage;
    u_int16_t msdu_id;

    while (msdus) {
        adf_nbuf_t msdu;
        msdu = msdus;
        msdus = adf_nbuf_next(msdus);
        adf_nbuf_set_next(msdu, NULL);

        msdu_id_storage = htt_dxe_tx_msdu_id_storage(msdu);
        msdu_id = *msdu_id_storage;

        ol_tx_download_done_hl_retain(pdev->txrx_pdev, A_OK, msdu, msdu_id);
        /*
         * For now, as soon as one frame is downloaded, allow another frame's
         * download to begin, by immediately updating by the full credit.
         */
        ol_tx_target_credit_update(
            pdev->txrx_pdev, htt_dxe_tx_msdu_credit(msdu));
        /*
         * TO DO:
         * Don't give a completion callback here at download completion
         * if this frame is tagged for OTA tx completion.
         */
        ol_tx_completion_handler(
            pdev->txrx_pdev, 1/*num_msdus*/, htt_tx_status_ok, &msdu_id);
    }

    return A_OK;
}

A_STATUS
htt_dxe_tx_low_rsrc(
    void *context,
    E_HIFDXE_CHANNELTYPE chan,
    A_BOOL is_low_resource)
{
/* FILL IN HERE */
    return A_OK;
}
