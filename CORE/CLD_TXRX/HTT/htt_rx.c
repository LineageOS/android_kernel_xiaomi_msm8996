/*
 * Copyright (c) 2011-2014 The Linux Foundation. All rights reserved.
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
 * @file htt_rx.c
 * @brief Implement receive aspects of HTT.
 * @details
 *  This file contains three categories of HTT rx code:
 *  1.  An abstraction of the rx descriptor, to hide the
 *      differences between the HL vs. LL rx descriptor.
 *  2.  Functions for providing access to the (series of)
 *      rx descriptor(s) and rx frame(s) associated with
 *      an rx indication message.
 *  3.  Functions for setting up and using the MAC DMA
 *      rx ring (applies to LL only).
 */

#include <adf_os_mem.h>   /* adf_os_mem_alloc,free, etc. */
#include <adf_os_types.h> /* adf_os_print, a_bool_t */
#include <adf_nbuf.h>     /* adf_nbuf_t, etc. */
#include <adf_os_timer.h> /* adf_os_timer_free */

#include <htt.h>          /* HTT_HL_RX_DESC_SIZE */
#include <ol_cfg.h>
#include <ol_htt_rx_api.h>
#include <htt_internal.h> /* HTT_ASSERT, htt_pdev_t, HTT_RX_BUF_SIZE */
#include "regtable.h"

#include <ieee80211_common.h>         /* ieee80211_frame, ieee80211_qoscntl */
#include <ieee80211_defines.h> /* ieee80211_rx_status */

#ifdef DEBUG_DMA_DONE
#include <asm/barrier.h>
#include <wma_api.h>
#endif

#ifdef DEBUG_DMA_DONE
extern int process_wma_set_command(int sessid, int paramid,
                                   int sval, int vpdev);
#endif

/* AR9888v1 WORKAROUND for EV#112367 */
/* FIX THIS - remove this WAR when the bug is fixed */
#define PEREGRINE_1_0_ZERO_LEN_PHY_ERR_WAR

/*--- setup / tear-down functions -------------------------------------------*/

#ifndef HTT_RX_RING_SIZE_MIN
#define HTT_RX_RING_SIZE_MIN 128  /* slightly larger than one large A-MPDU */
#endif

#ifndef HTT_RX_RING_SIZE_MAX
#define HTT_RX_RING_SIZE_MAX 2048 /* roughly 20 ms @ 1 Gbps of 1500B MSDUs */
#endif

#ifndef HTT_RX_AVG_FRM_BYTES
#define HTT_RX_AVG_FRM_BYTES 1000
#endif

#ifndef HTT_RX_HOST_LATENCY_MAX_MS
#define HTT_RX_HOST_LATENCY_MAX_MS 20 /* ms */ /* very conservative */
#endif

#ifndef HTT_RX_HOST_LATENCY_WORST_LIKELY_MS
#define HTT_RX_HOST_LATENCY_WORST_LIKELY_MS 10 /* ms */ /* conservative */
#endif

#ifndef HTT_RX_RING_REFILL_RETRY_TIME_MS
#define HTT_RX_RING_REFILL_RETRY_TIME_MS    50
#endif

static int
CEIL_PWR2(int value)
{
    int log2;
    if (IS_PWR2(value)) {
        return value;
    }
    log2 = 0;
    while (value) {
        value >>= 1;
        log2++;
    }
    return (1 << log2);
}

/*
 * This function is used both below within this file (which the compiler
 * will hopefully inline), and out-line from other files via the
 * htt_rx_msdu_first_msdu_flag function pointer.
 */
static inline a_bool_t
htt_rx_msdu_first_msdu_flag_hl(htt_pdev_handle pdev, void *msdu_desc)
{
    return ((u_int8_t*)msdu_desc - sizeof(struct hl_htt_rx_ind_base))
        [HTT_ENDIAN_BYTE_IDX_SWAP(HTT_RX_IND_HL_FLAG_OFFSET)] &
        HTT_RX_IND_HL_FLAG_FIRST_MSDU ? A_TRUE : A_FALSE;
}

static a_bool_t
htt_rx_msdu_first_msdu_flag_ll(htt_pdev_handle pdev, void *msdu_desc)
{
    struct htt_host_rx_desc_base *rx_desc =
        (struct htt_host_rx_desc_base *) msdu_desc;
    return (a_bool_t)
        (((*(((u_int32_t *) &rx_desc->msdu_end) + 4)) &
        RX_MSDU_END_4_FIRST_MSDU_MASK) >>
        RX_MSDU_END_4_FIRST_MSDU_LSB);
}

u_int16_t
htt_rx_msdu_rx_desc_size_hl(
    htt_pdev_handle pdev,
    void *msdu_desc
    )
{
	return ((u_int8_t*)(msdu_desc) - HTT_RX_IND_HL_BYTES)
        [HTT_ENDIAN_BYTE_IDX_SWAP(HTT_RX_IND_HL_RX_DESC_LEN_OFFSET)];
}

static int
htt_rx_ring_size(struct htt_pdev_t *pdev)
{
    int size;

    /*
     * It is expected that the host CPU will typically be able to service
     * the rx indication from one A-MPDU before the rx indication from
     * the subsequent A-MPDU happens, roughly 1-2 ms later.
     * However, the rx ring should be sized very conservatively, to
     * accomodate the worst reasonable delay before the host CPU services
     * a rx indication interrupt.
     * The rx ring need not be kept full of empty buffers.  In theory,
     * the htt host SW can dynamically track the low-water mark in the
     * rx ring, and dynamically adjust the level to which the rx ring
     * is filled with empty buffers, to dynamically meet the desired
     * low-water mark.
     * In contrast, it's difficult to resize the rx ring itself, once
     * it's in use.
     * Thus, the ring itself should be sized very conservatively, while
     * the degree to which the ring is filled with empty buffers should
     * be sized moderately conservatively.
     */
    size =
        ol_cfg_max_thruput_mbps(pdev->ctrl_pdev) *
        1000 /* 1e6 bps/mbps / 1e3 ms per sec = 1000 */ /
        (8 * HTT_RX_AVG_FRM_BYTES) *
        HTT_RX_HOST_LATENCY_MAX_MS;

    if (size < HTT_RX_RING_SIZE_MIN) {
        size = HTT_RX_RING_SIZE_MIN;
    }
    if (size > HTT_RX_RING_SIZE_MAX) {
        size = HTT_RX_RING_SIZE_MAX;
    }
    size = CEIL_PWR2(size);
    return size;
}

static int
htt_rx_ring_fill_level(struct htt_pdev_t *pdev)
{
    int size;

    size =
        ol_cfg_max_thruput_mbps(pdev->ctrl_pdev)  *
        1000 /* 1e6 bps/mbps / 1e3 ms per sec = 1000 */ /
        (8 * HTT_RX_AVG_FRM_BYTES) *
        HTT_RX_HOST_LATENCY_WORST_LIKELY_MS;
    /*
     * Make sure the fill level is at least 1 less than the ring size.
     * Leaving 1 element empty allows the SW to easily distinguish
     * between a full ring vs. an empty ring.
     */
    if (size >= pdev->rx_ring.size) {
        size = pdev->rx_ring.size - 1;
    }
    return size;
}

static void
htt_rx_ring_refill_retry(void *arg)
{
    htt_pdev_handle pdev = (htt_pdev_handle)arg;
    htt_rx_msdu_buff_replenish(pdev);
}

void
htt_rx_ring_fill_n(struct htt_pdev_t *pdev, int num)
{
    int idx;
    a_status_t status;
    struct htt_host_rx_desc_base *rx_desc;

    idx = *(pdev->rx_ring.alloc_idx.vaddr);
    while (num > 0) {
        u_int32_t paddr;
        adf_nbuf_t rx_netbuf;
        int headroom;

        rx_netbuf = adf_nbuf_alloc(pdev->osdev, HTT_RX_BUF_SIZE, 0, 4, FALSE);
        if (!rx_netbuf) {
            adf_os_timer_cancel(&pdev->rx_ring.refill_retry_timer);
            /*
             * Failed to fill it to the desired level -
             * we'll start a timer and try again next time.
             * As long as enough buffers are left in the ring for
             * another A-MPDU rx, no special recovery is needed.
             */
#ifdef DEBUG_DMA_DONE
            pdev->rx_ring.dbg_refill_cnt++;
#endif
            adf_os_timer_start(&pdev->rx_ring.refill_retry_timer,
                               HTT_RX_RING_REFILL_RETRY_TIME_MS);
            goto fail;
        }

        /* Clear rx_desc attention word before posting to Rx ring */
        rx_desc = htt_rx_desc(rx_netbuf);
        *(u_int32_t *)&rx_desc->attention = 0;

#ifdef DEBUG_DMA_DONE
        *(u_int32_t *)&rx_desc->msdu_end = 1;

        #define MAGIC_PATTERN 0xDEADBEEF
        *(u_int32_t *)&rx_desc->msdu_start = MAGIC_PATTERN;

        /* To ensure that attention bit is reset and msdu_end is set before
           calling dma_map */
        smp_mb();
#endif
        /*
         * Adjust adf_nbuf_data to point to the location in the buffer
         * where the rx descriptor will be filled in.
         */
        headroom = adf_nbuf_data(rx_netbuf) - (u_int8_t *) rx_desc;
        adf_nbuf_push_head(rx_netbuf, headroom);

        status = adf_nbuf_map(pdev->osdev, rx_netbuf, ADF_OS_DMA_FROM_DEVICE);
        if (status != A_STATUS_OK) {
            adf_nbuf_free(rx_netbuf);
            goto fail;
        }
        paddr = adf_nbuf_get_frag_paddr_lo(rx_netbuf, 0);
        pdev->rx_ring.buf.netbufs_ring[idx] = rx_netbuf;
        pdev->rx_ring.buf.paddrs_ring[idx] = paddr;
        pdev->rx_ring.fill_cnt++;

        num--;
        idx++;
        idx &= pdev->rx_ring.size_mask;
    }

fail:
    *(pdev->rx_ring.alloc_idx.vaddr) = idx;
    return;
}

unsigned
htt_rx_ring_elems(struct htt_pdev_t *pdev)
{
    return
        (*pdev->rx_ring.alloc_idx.vaddr - pdev->rx_ring.sw_rd_idx.msdu_payld) &
        pdev->rx_ring.size_mask;
}

void
htt_rx_detach(struct htt_pdev_t *pdev)
{
    int sw_rd_idx = pdev->rx_ring.sw_rd_idx.msdu_payld;

    if (pdev->cfg.is_high_latency) {
        return;
    }

    while (sw_rd_idx != *(pdev->rx_ring.alloc_idx.vaddr)) {
        adf_nbuf_unmap(
            pdev->osdev, pdev->rx_ring.buf.netbufs_ring[sw_rd_idx],
            ADF_OS_DMA_FROM_DEVICE);
        adf_nbuf_free(pdev->rx_ring.buf.netbufs_ring[sw_rd_idx]);
        sw_rd_idx++;
        sw_rd_idx &= pdev->rx_ring.size_mask;
    }

    adf_os_timer_cancel(&pdev->rx_ring.refill_retry_timer);
    adf_os_timer_free(&pdev->rx_ring.refill_retry_timer);

    adf_os_mem_free_consistent(
        pdev->osdev,
        sizeof(u_int32_t),
        pdev->rx_ring.alloc_idx.vaddr,
        pdev->rx_ring.alloc_idx.paddr,
        adf_os_get_dma_mem_context((&pdev->rx_ring.alloc_idx), memctx));
    adf_os_mem_free_consistent(
        pdev->osdev,
        pdev->rx_ring.size * sizeof(u_int32_t),
        pdev->rx_ring.buf.paddrs_ring,
        pdev->rx_ring.base_paddr,
        adf_os_get_dma_mem_context((&pdev->rx_ring.buf), memctx));
    adf_os_mem_free(pdev->rx_ring.buf.netbufs_ring);
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
/* FIX THIS: APPLIES TO LL ONLY */
u_int16_t
htt_rx_mpdu_desc_seq_num_ll(htt_pdev_handle pdev, void *mpdu_desc)
{
    struct htt_host_rx_desc_base *rx_desc =
        (struct htt_host_rx_desc_base *) mpdu_desc;

    return
        (u_int16_t)(((*((u_int32_t *) &rx_desc->mpdu_start)) &
        RX_MPDU_START_0_SEQ_NUM_MASK) >>
        RX_MPDU_START_0_SEQ_NUM_LSB);
}

u_int16_t
htt_rx_mpdu_desc_seq_num_hl(htt_pdev_handle pdev, void *mpdu_desc)
{
    if (pdev->rx_desc_size_hl) {
        return pdev->cur_seq_num_hl =
            (u_int16_t)(HTT_WORD_GET(*(A_UINT32*)mpdu_desc,
                    HTT_HL_RX_DESC_MPDU_SEQ_NUM));
    } else {
        return (u_int16_t)(pdev->cur_seq_num_hl);
    }
}

/* FIX THIS: APPLIES TO LL ONLY */
void
htt_rx_mpdu_desc_pn_ll(
    htt_pdev_handle pdev,
    void *mpdu_desc,
    union htt_rx_pn_t *pn,
    int pn_len_bits)
{
    struct htt_host_rx_desc_base *rx_desc =
        (struct htt_host_rx_desc_base *) mpdu_desc;

    switch (pn_len_bits) {
        case 24:
            /* bits 23:0 */
            pn->pn24 =
                rx_desc->mpdu_start.pn_31_0 & 0xffffff;
            break;
        case 48:
            /* bits 31:0 */
            pn->pn48 = rx_desc->mpdu_start.pn_31_0;
            /* bits 47:32 */
            pn->pn48 |=
                ((u_int64_t) ((*(((u_int32_t *) &rx_desc->mpdu_start) + 2))
                & RX_MPDU_START_2_PN_47_32_MASK))
                << (32 - RX_MPDU_START_2_PN_47_32_LSB);
            break;
        case 128:
            /* bits 31:0 */
            pn->pn128[0] = rx_desc->mpdu_start.pn_31_0;
            /* bits 47:32 */
            pn->pn128[0] |=
                ((u_int64_t) ((*(((u_int32_t *) &rx_desc->mpdu_start) + 2))
                & RX_MPDU_START_2_PN_47_32_MASK))
                << (32 - RX_MPDU_START_2_PN_47_32_LSB);
            /* bits 63:48 */
            pn->pn128[0] |=
                ((u_int64_t) ((*(((u_int32_t *) &rx_desc->msdu_end) + 2))
                & RX_MSDU_END_1_EXT_WAPI_PN_63_48_MASK))
                << (48 - RX_MSDU_END_1_EXT_WAPI_PN_63_48_LSB);
            /* bits 95:64 */
            pn->pn128[1] = rx_desc->msdu_end.ext_wapi_pn_95_64;
            /* bits 127:96 */
            pn->pn128[1] |=
                ((u_int64_t) rx_desc->msdu_end.ext_wapi_pn_127_96) << 32;
            break;
        default:
            adf_os_print(
                "Error: invalid length spec (%d bits) for PN\n", pn_len_bits);
    };
}

/* HL case */
void
htt_rx_mpdu_desc_pn_hl(
    htt_pdev_handle pdev,
    void *mpdu_desc,
    union htt_rx_pn_t *pn,
    int pn_len_bits)
{
    if (htt_rx_msdu_first_msdu_flag_hl(pdev, mpdu_desc) == A_TRUE) {
        /* Fix Me: only for little endian */
        struct hl_htt_rx_desc_base *rx_desc =
            (struct hl_htt_rx_desc_base *) mpdu_desc;
        u_int32_t *word_ptr = (u_int32_t *)pn->pn128;

        /* TODO: for Host of big endian */
        switch (pn_len_bits) {
            case 128:
                /* bits 128:64 */
                *(word_ptr + 3) = rx_desc->pn_127_96;
                /* bits 63:0 */
                *(word_ptr + 2) = rx_desc->pn_95_64;
            case 48:
                /* bits 48:0
                 * copy 64 bits
                 */
                *(word_ptr + 1) = rx_desc->u0.pn_63_32;
            case 24:
                /* bits 23:0
                 * copy 32 bits
                 */
                *(word_ptr + 0) = rx_desc->pn_31_0;
                break;
            default:
                adf_os_print(
                        "Error: invalid length spec (%d bits) for PN\n", pn_len_bits);
                adf_os_assert(0);
        };
    } else {
        /* not first msdu, no pn info */
        adf_os_print(
                "Error: get pn from a not-first msdu.\n");
        adf_os_assert(0);
    }
}

u_int32_t
htt_rx_mpdu_desc_tsf32(
    htt_pdev_handle pdev,
    void *mpdu_desc)
{
/* FIX THIS */
return 0;
}

/* FIX THIS: APPLIES TO LL ONLY */
char *
htt_rx_mpdu_wifi_hdr_retrieve(htt_pdev_handle pdev, void *mpdu_desc)
{
    struct htt_host_rx_desc_base *rx_desc =
        (struct htt_host_rx_desc_base *) mpdu_desc;
    return rx_desc->rx_hdr_status;
}

/* FIX THIS: APPLIES TO LL ONLY */
a_bool_t
htt_rx_msdu_desc_completes_mpdu_ll(htt_pdev_handle pdev, void *msdu_desc)
{
    struct htt_host_rx_desc_base *rx_desc =
        (struct htt_host_rx_desc_base *) msdu_desc;
    return (a_bool_t)
        (((*(((u_int32_t *) &rx_desc->msdu_end) + 4)) &
        RX_MSDU_END_4_LAST_MSDU_MASK) >>
        RX_MSDU_END_4_LAST_MSDU_LSB);
}

a_bool_t
htt_rx_msdu_desc_completes_mpdu_hl(htt_pdev_handle pdev, void *msdu_desc)
{
    return (
            ((u_int8_t*)(msdu_desc) - sizeof(struct hl_htt_rx_ind_base))
            [HTT_ENDIAN_BYTE_IDX_SWAP(HTT_RX_IND_HL_FLAG_OFFSET)]
            & HTT_RX_IND_HL_FLAG_LAST_MSDU)
        ? A_TRUE : A_FALSE;
}

/* FIX THIS: APPLIES TO LL ONLY */
int
htt_rx_msdu_has_wlan_mcast_flag_ll(htt_pdev_handle pdev, void *msdu_desc)
{
    struct htt_host_rx_desc_base *rx_desc =
        (struct htt_host_rx_desc_base *) msdu_desc;
    /* HW rx desc: the mcast_bcast flag is only valid if first_msdu is set */
    return
        ((*(((u_int32_t *) &rx_desc->msdu_end) + 4)) &
        RX_MSDU_END_4_FIRST_MSDU_MASK) >>
        RX_MSDU_END_4_FIRST_MSDU_LSB;
}

int
htt_rx_msdu_has_wlan_mcast_flag_hl(htt_pdev_handle pdev, void *msdu_desc)
{
    /* currently, only first msdu has hl rx_desc */
    return htt_rx_msdu_first_msdu_flag_hl(pdev, msdu_desc) == A_TRUE;
}

/* FIX THIS: APPLIES TO LL ONLY */
a_bool_t
htt_rx_msdu_is_wlan_mcast_ll(htt_pdev_handle pdev, void *msdu_desc)
{
    struct htt_host_rx_desc_base *rx_desc =
        (struct htt_host_rx_desc_base *) msdu_desc;
    return
        ((*((u_int32_t *) &rx_desc->attention)) &
        RX_ATTENTION_0_MCAST_BCAST_MASK) >>
        RX_ATTENTION_0_MCAST_BCAST_LSB;
}

a_bool_t
htt_rx_msdu_is_wlan_mcast_hl(htt_pdev_handle pdev, void *msdu_desc)
{
    struct hl_htt_rx_desc_base *rx_desc =
        (struct hl_htt_rx_desc_base *) msdu_desc;
    return
        HTT_WORD_GET(*(u_int32_t*)rx_desc, HTT_HL_RX_DESC_MCAST_BCAST);
}

/* FIX THIS: APPLIES TO LL ONLY */
int
htt_rx_msdu_is_frag_ll(htt_pdev_handle pdev, void *msdu_desc)
{
    struct htt_host_rx_desc_base *rx_desc =
        (struct htt_host_rx_desc_base *) msdu_desc;
    return
        ((*((u_int32_t *) &rx_desc->attention)) &
        RX_ATTENTION_0_FRAGMENT_MASK) >>
        RX_ATTENTION_0_FRAGMENT_LSB;
}

int
htt_rx_msdu_is_frag_hl(htt_pdev_handle pdev, void *msdu_desc)
{
    struct hl_htt_rx_desc_base *rx_desc =
        (struct hl_htt_rx_desc_base *) msdu_desc;

    return
        HTT_WORD_GET(*(u_int32_t*)rx_desc, HTT_HL_RX_DESC_MCAST_BCAST);
}

static inline
u_int8_t
htt_rx_msdu_fw_desc_get(htt_pdev_handle pdev, void *msdu_desc)
{
    /*
     * HL and LL use the same format for FW rx desc, but have the FW rx desc
     * in different locations.
     * In LL, the FW rx descriptor has been copied into the same
     * htt_host_rx_desc_base struct that holds the HW rx desc.
     * In HL, the FW rx descriptor, along with the MSDU payload,
     * is in the same buffer as the rx indication message.
     *
     * Use the FW rx desc offset configured during startup to account for
     * this difference between HL vs. LL.
     *
     * An optimization would be to define the LL and HL msdu_desc pointer
     * in such a way that they both use the same offset to the FW rx desc.
     * Then the following functions could be converted to macros, without
     * needing to expose the htt_pdev_t definition outside HTT.
     */
    return *(((u_int8_t *) msdu_desc) + pdev->rx_fw_desc_offset);
}

int
htt_rx_msdu_discard(htt_pdev_handle pdev, void *msdu_desc)
{
    return htt_rx_msdu_fw_desc_get(pdev, msdu_desc) & FW_RX_DESC_DISCARD_M;
}

int
htt_rx_msdu_forward(htt_pdev_handle pdev, void *msdu_desc)
{
    return htt_rx_msdu_fw_desc_get(pdev, msdu_desc) & FW_RX_DESC_FORWARD_M;
}

int
htt_rx_msdu_inspect(htt_pdev_handle pdev, void *msdu_desc)
{
    return htt_rx_msdu_fw_desc_get(pdev, msdu_desc) & FW_RX_DESC_INSPECT_M;
}

void
htt_rx_msdu_actions(
    htt_pdev_handle pdev,
    void *msdu_desc,
    int *discard,
    int *forward,
    int *inspect)
{
    u_int8_t rx_msdu_fw_desc = htt_rx_msdu_fw_desc_get(pdev, msdu_desc);
#ifdef HTT_DEBUG_DATA
    HTT_PRINT("act:0x%x ",rx_msdu_fw_desc);
#endif
    *discard = rx_msdu_fw_desc & FW_RX_DESC_DISCARD_M;
    *forward = rx_msdu_fw_desc & FW_RX_DESC_FORWARD_M;
    *inspect = rx_msdu_fw_desc & FW_RX_DESC_INSPECT_M;
}

static inline adf_nbuf_t
htt_rx_netbuf_pop(
    htt_pdev_handle pdev)
{
    int idx;
    adf_nbuf_t msdu;

    HTT_ASSERT1(htt_rx_ring_elems(pdev) != 0);

#ifdef DEBUG_DMA_DONE
    pdev->rx_ring.dbg_ring_idx++;
    pdev->rx_ring.dbg_ring_idx &= pdev->rx_ring.size_mask;
#endif

    idx = pdev->rx_ring.sw_rd_idx.msdu_payld;
    msdu = pdev->rx_ring.buf.netbufs_ring[idx];
    idx++;
    idx &= pdev->rx_ring.size_mask;
    pdev->rx_ring.sw_rd_idx.msdu_payld = idx;
    pdev->rx_ring.fill_cnt--;
    return msdu;
}

/* FIX ME: this function applies only to LL rx descs. An equivalent for HL rx descs is needed. */
#ifdef CHECKSUM_OFFLOAD
static inline
void
htt_set_checksum_result_ll(htt_pdev_handle pdev, adf_nbuf_t msdu,
                           struct htt_host_rx_desc_base *rx_desc)
{
#define MAX_IP_VER          2
#define MAX_PROTO_VAL       4
    struct rx_msdu_start *rx_msdu = &rx_desc->msdu_start;
    unsigned int proto = (rx_msdu->tcp_proto) | (rx_msdu->udp_proto << 1);

    /*
     * HW supports TCP & UDP checksum offload for ipv4 and ipv6
     */
    static const adf_nbuf_l4_rx_cksum_type_t
        cksum_table[][MAX_PROTO_VAL][MAX_IP_VER] =
    {
        {
            /* non-fragmented IP packet */
            /* non TCP/UDP packet */
            { ADF_NBUF_RX_CKSUM_NONE, ADF_NBUF_RX_CKSUM_NONE },
            /* TCP packet */
            { ADF_NBUF_RX_CKSUM_TCP,  ADF_NBUF_RX_CKSUM_TCPIPV6},
            /* UDP packet */
            { ADF_NBUF_RX_CKSUM_UDP,  ADF_NBUF_RX_CKSUM_UDPIPV6 },
            /* invalid packet type */
            { ADF_NBUF_RX_CKSUM_NONE, ADF_NBUF_RX_CKSUM_NONE },
        },
        {
            /* fragmented IP packet */
            { ADF_NBUF_RX_CKSUM_NONE, ADF_NBUF_RX_CKSUM_NONE },
            { ADF_NBUF_RX_CKSUM_NONE, ADF_NBUF_RX_CKSUM_NONE },
            { ADF_NBUF_RX_CKSUM_NONE, ADF_NBUF_RX_CKSUM_NONE },
            { ADF_NBUF_RX_CKSUM_NONE, ADF_NBUF_RX_CKSUM_NONE },
        }
    };

    adf_nbuf_rx_cksum_t cksum = {
        cksum_table[rx_msdu->ip_frag][proto][rx_msdu->ipv6_proto],
        ADF_NBUF_RX_CKSUM_NONE,
        0
    } ;

    if (cksum.l4_type != (adf_nbuf_l4_rx_cksum_type_t)ADF_NBUF_RX_CKSUM_NONE) {
        cksum.l4_result = ((*(u_int32_t *) &rx_desc->attention) &
                RX_ATTENTION_0_TCP_UDP_CHKSUM_FAIL_MASK) ?
                    ADF_NBUF_RX_CKSUM_NONE :
                    ADF_NBUF_RX_CKSUM_TCP_UDP_UNNECESSARY;
    }
    adf_nbuf_set_rx_cksum(msdu, &cksum );
#undef MAX_IP_VER
#undef MAX_PROTO_VAL
}

static inline
void
htt_set_checksum_result_hl(adf_nbuf_t msdu,
                           struct htt_host_rx_desc_base *rx_desc)
{
    u_int8_t flag = ((u_int8_t*)rx_desc - sizeof(struct hl_htt_rx_ind_base))[HTT_ENDIAN_BYTE_IDX_SWAP(HTT_RX_IND_HL_FLAG_OFFSET)];
    int is_ipv6 = flag & HTT_RX_IND_HL_FLAG_IPV6 ? 1:0;
    int is_tcp = flag & HTT_RX_IND_HL_FLAG_TCP ? 1:0;
    int is_udp = flag & HTT_RX_IND_HL_FLAG_UDP ? 1:0;

    adf_nbuf_rx_cksum_t cksum = {
        ADF_NBUF_RX_CKSUM_NONE,
        ADF_NBUF_RX_CKSUM_NONE,
        0
    } ;

    switch ((is_udp << 2) | (is_tcp << 1) | (is_ipv6 << 0)) {
        case 0x4:
            cksum.l4_type = ADF_NBUF_RX_CKSUM_UDP;
            break;
        case 0x2:
            cksum.l4_type = ADF_NBUF_RX_CKSUM_TCP;
            break;
        case 0x5:
            cksum.l4_type = ADF_NBUF_RX_CKSUM_UDPIPV6;
            break;
        case 0x3:
            cksum.l4_type = ADF_NBUF_RX_CKSUM_TCPIPV6;
            break;
        default:
            cksum.l4_type = ADF_NBUF_RX_CKSUM_NONE;
            break;
    }
    if (cksum.l4_type != (adf_nbuf_l4_rx_cksum_type_t)ADF_NBUF_RX_CKSUM_NONE) {
        cksum.l4_result = flag & HTT_RX_IND_HL_FLAG_C4_FAILED ?
                    ADF_NBUF_RX_CKSUM_NONE : ADF_NBUF_RX_CKSUM_TCP_UDP_UNNECESSARY;
    }
    adf_nbuf_set_rx_cksum(msdu, &cksum );
}

#else
#define htt_set_checksum_result_ll(pdev, msdu, rx_desc) /* no-op */
#define htt_set_checksum_result_hl(msdu, rx_desc) /* no-op */
#endif

#ifdef DEBUG_DMA_DONE
void
htt_rx_print_rx_indication(
   adf_nbuf_t rx_ind_msg,
   htt_pdev_handle pdev)
{
    u_int32_t *msg_word;
    int byte_offset;
    int mpdu_range, num_mpdu_range;

    msg_word = (u_int32_t *)adf_nbuf_data(rx_ind_msg);

    adf_os_print("------------------HTT RX IND-----------------------------\n");
    adf_os_print("alloc idx paddr %x (*vaddr) %d\n",
                  pdev->rx_ring.alloc_idx.paddr,
                  *pdev->rx_ring.alloc_idx.vaddr);

    adf_os_print("sw_rd_idx msdu_payld %d msdu_desc %d\n",
                 pdev->rx_ring.sw_rd_idx.msdu_payld,
                 pdev->rx_ring.sw_rd_idx.msdu_desc);

    adf_os_print("dbg_ring_idx %d\n", pdev->rx_ring.dbg_ring_idx);

    adf_os_print("fill_level %d fill_cnt %d\n",pdev->rx_ring.fill_level,
                  pdev->rx_ring.fill_cnt);

    adf_os_print("initial msdu_payld %d curr mpdu range %d curr mpdu cnt %d\n",
                  pdev->rx_ring.dbg_initial_msdu_payld,
                  pdev->rx_ring.dbg_mpdu_range,
                  pdev->rx_ring.dbg_mpdu_count);

    /* Print the RX_IND contents */

    adf_os_print("peer id %x RV %x FV %x ext_tid %x msg_type %x\n",
                  HTT_RX_IND_PEER_ID_GET(*msg_word),
                  HTT_RX_IND_REL_VALID_GET(*msg_word),
                  HTT_RX_IND_FLUSH_VALID_GET(*msg_word),
                  HTT_RX_IND_EXT_TID_GET(*msg_word),
                  HTT_T2H_MSG_TYPE_GET(*msg_word));

    adf_os_print("num_mpdu_ranges %x rel_seq_num_end %x rel_seq_num_start %x\n"
                 " flush_seq_num_end %x flush_seq_num_start %x\n",
                  HTT_RX_IND_NUM_MPDU_RANGES_GET(*(msg_word + 1)),
                  HTT_RX_IND_REL_SEQ_NUM_END_GET(*(msg_word + 1)),
                  HTT_RX_IND_REL_SEQ_NUM_START_GET(*(msg_word + 1)),
                  HTT_RX_IND_FLUSH_SEQ_NUM_END_GET(*(msg_word + 1)),
                  HTT_RX_IND_FLUSH_SEQ_NUM_START_GET(*(msg_word + 1)));

    adf_os_print("fw_rx_desc_bytes %x\n", HTT_RX_IND_FW_RX_DESC_BYTES_GET(
       *(msg_word + 2 + HTT_RX_PPDU_DESC_SIZE32)));

    /* receive MSDU desc for current frame */
    byte_offset = HTT_ENDIAN_BYTE_IDX_SWAP(HTT_RX_IND_FW_RX_DESC_BYTE_OFFSET +
                                            pdev->rx_ind_msdu_byte_idx);

    adf_os_print("msdu byte idx %x msdu desc %x\n", pdev->rx_ind_msdu_byte_idx,
                  HTT_RX_IND_FW_RX_DESC_BYTES_GET(
                     *(msg_word + 2 + HTT_RX_PPDU_DESC_SIZE32)));

    num_mpdu_range = HTT_RX_IND_NUM_MPDU_RANGES_GET(*(msg_word + 1));

    for (mpdu_range = 0; mpdu_range < num_mpdu_range; mpdu_range++) {
        enum htt_rx_status status;
        int num_mpdus;

        htt_rx_ind_mpdu_range_info(
            pdev, rx_ind_msg, mpdu_range, &status, &num_mpdus);

        adf_os_print("mpdu_range %x status %x num_mpdus %x\n",
                      pdev->rx_ind_msdu_byte_idx, status, num_mpdus);
    }
    adf_os_print("---------------------------------------------------------\n");
}
#endif

#ifdef DEBUG_DMA_DONE
#define MAX_DONE_BIT_CHECK_ITER 5
#endif

int
htt_rx_amsdu_pop_ll(
    htt_pdev_handle pdev,
    adf_nbuf_t rx_ind_msg,
    adf_nbuf_t *head_msdu,
    adf_nbuf_t *tail_msdu)
{
    int msdu_len, msdu_chaining = 0;
    adf_nbuf_t msdu;
    struct htt_host_rx_desc_base *rx_desc;
    u_int8_t *rx_ind_data;
    u_int32_t *msg_word, num_msdu_bytes;

    HTT_ASSERT1(htt_rx_ring_elems(pdev) != 0);
    rx_ind_data = adf_nbuf_data(rx_ind_msg);
    msg_word = (u_int32_t *)rx_ind_data;
    num_msdu_bytes = HTT_RX_IND_FW_RX_DESC_BYTES_GET(
       *(msg_word + HTT_RX_IND_HDR_PREFIX_SIZE32 + HTT_RX_PPDU_DESC_SIZE32));

    msdu = *head_msdu = htt_rx_netbuf_pop(pdev);
    while (1) {
        int last_msdu, msdu_len_invalid, msdu_chained;
        int byte_offset;

        /*
         * Set the netbuf length to be the entire buffer length initially,
         * so the unmap will unmap the entire buffer.
         */
        adf_nbuf_set_pktlen(msdu, HTT_RX_BUF_SIZE);
        adf_nbuf_unmap(pdev->osdev, msdu, ADF_OS_DMA_FROM_DEVICE);

        /* cache consistency has been taken care of by the adf_nbuf_unmap */

        /*
         * Now read the rx descriptor.
         * Set the length to the appropriate value.
         * Check if this MSDU completes a MPDU.
         */
        rx_desc = htt_rx_desc(msdu);

        /*
         * Make the netbuf's data pointer point to the payload rather
         * than the descriptor.
         */
        adf_nbuf_pull_head(msdu, HTT_RX_STD_DESC_RESERVATION);

        /*
         * Sanity check - confirm the HW is finished filling in the rx data.
         * If the HW and SW are working correctly, then it's guaranteed that
         * the HW's MAC DMA is done before this point in the SW.
         * To prevent the case that we handle a stale Rx descriptor, just
         * assert for now until we have a way to recover.
         */

#ifdef DEBUG_DMA_DONE
        if (adf_os_unlikely(!((*(u_int32_t *) &rx_desc->attention)
                            & RX_ATTENTION_0_MSDU_DONE_MASK))) {

            int dbg_iter = MAX_DONE_BIT_CHECK_ITER;


            adf_os_print("malformed frame\n");

            while (dbg_iter &&
                   (!((*(u_int32_t *) &rx_desc->attention) &
                      RX_ATTENTION_0_MSDU_DONE_MASK))) {
                adf_os_mdelay(1);

                adf_os_invalidate_range((void *)rx_desc,
                                    (void*)((char *)rx_desc +
                                            HTT_RX_STD_DESC_RESERVATION));

                adf_os_print("debug iter %d success %d\n", dbg_iter,
                     pdev->rx_ring.dbg_sync_success);

                dbg_iter--;
            }

            if (adf_os_unlikely(!((*(u_int32_t *) &rx_desc->attention)
                                  & RX_ATTENTION_0_MSDU_DONE_MASK)))
            {

#ifdef HTT_RX_RESTORE
                adf_os_print("RX done bit error detected!\n");
                adf_nbuf_set_next(msdu, NULL);
                *tail_msdu = msdu;
                pdev->rx_ring.rx_reset = 1;
                return msdu_chained;
#else
                process_wma_set_command(0,(int)GEN_PARAM_CRASH_INJECT,
                                        0, GEN_CMD);
                HTT_ASSERT_ALWAYS(0);
#endif
            }
            pdev->rx_ring.dbg_sync_success++;
            adf_os_print("debug iter %d success %d\n", dbg_iter,
                 pdev->rx_ring.dbg_sync_success);
        }
#else
                HTT_ASSERT_ALWAYS(
                   (*(u_int32_t *) &rx_desc->attention) &
                   RX_ATTENTION_0_MSDU_DONE_MASK);
#endif
        /*
         * Copy the FW rx descriptor for this MSDU from the rx indication
         * message into the MSDU's netbuf.
         * HL uses the same rx indication message definition as LL, and
         * simply appends new info (fields from the HW rx desc, and the
         * MSDU payload itself).
         * So, the offset into the rx indication message only has to account
         * for the standard offset of the per-MSDU FW rx desc info within
         * the message, and how many bytes of the per-MSDU FW rx desc info
         * have already been consumed.  (And the endianness of the host,
         * since for a big-endian host, the rx ind message contents,
         * including the per-MSDU rx desc bytes, were byteswapped during
         * upload.)
         */
        if (pdev->rx_ind_msdu_byte_idx < num_msdu_bytes) {
            byte_offset = HTT_ENDIAN_BYTE_IDX_SWAP(
                HTT_RX_IND_FW_RX_DESC_BYTE_OFFSET +
                pdev->rx_ind_msdu_byte_idx);
            *((u_int8_t *) &rx_desc->fw_desc.u.val) = rx_ind_data[byte_offset];
            /*
             * The target is expected to only provide the basic per-MSDU rx
             * descriptors.  Just to be sure, verify that the target has not
             * attached extension data (e.g. LRO flow ID).
             */
            /*
             * The assertion below currently doesn't work for RX_FRAG_IND
             * messages, since their format differs from the RX_IND format
             * (no FW rx PPDU desc in the current RX_FRAG_IND message).
             * If the RX_FRAG_IND message format is updated to match the
             * RX_IND message format, then the following assertion can be
             * restored.
             */
            //adf_os_assert((rx_ind_data[byte_offset] & FW_RX_DESC_EXT_M) == 0);
            pdev->rx_ind_msdu_byte_idx += 1; // or more, if there's ext data
        } else {
            /*
             * When an oversized AMSDU happened, FW will lost some of
             * MSDU status - in this case, the FW descriptors provided
             * will be less than the actual MSDUs inside this MPDU.
             * Mark the FW descriptors so that it will still deliver to
             * upper stack, if no CRC error for this MPDU.
             *
             * FIX THIS - the FW descriptors are actually for MSDUs in
             * the end of this A-MSDU instead of the beginning.
             */
            *((u_int8_t *) &rx_desc->fw_desc.u.val) = 0;
        }

        /*
         *  TCP/UDP checksum offload support
         */
        htt_set_checksum_result_ll(pdev, msdu, rx_desc);

        msdu_len_invalid = (*(u_int32_t *) &rx_desc->attention) &
            RX_ATTENTION_0_MPDU_LENGTH_ERR_MASK;
        msdu_chained = (((*(u_int32_t *) &rx_desc->frag_info) &
                         RX_FRAG_INFO_0_RING2_MORE_COUNT_MASK) >>
                        RX_FRAG_INFO_0_RING2_MORE_COUNT_LSB);
        msdu_len =
            ((*((u_int32_t *) &rx_desc->msdu_start)) &
             RX_MSDU_START_0_MSDU_LENGTH_MASK) >>
            RX_MSDU_START_0_MSDU_LENGTH_LSB;

        do {
            if (!msdu_len_invalid && !msdu_chained) {
#if defined(PEREGRINE_1_0_ZERO_LEN_PHY_ERR_WAR)
                if (msdu_len > 0x3000) {
                    break;
                }
#endif
                adf_nbuf_trim_tail(
                    msdu, HTT_RX_BUF_SIZE - (RX_STD_DESC_SIZE + msdu_len));
            }
        } while (0);

        while (msdu_chained--) {
            adf_nbuf_t next =
                htt_rx_netbuf_pop(pdev);
            adf_nbuf_set_pktlen(next, HTT_RX_BUF_SIZE);
            msdu_len -= HTT_RX_BUF_SIZE;
            adf_nbuf_set_next(msdu, next);
            msdu = next;
            msdu_chaining = 1;

            if (msdu_chained == 0) {
                /* Trim the last one to the correct size - accounting for
                 * inconsistent HW lengths cuasing length overflows and
                 * underflows
                 */
                if (((unsigned)msdu_len) >
                    ((unsigned)(HTT_RX_BUF_SIZE - RX_STD_DESC_SIZE))) {
                    msdu_len = (HTT_RX_BUF_SIZE - RX_STD_DESC_SIZE);
                }

                adf_nbuf_trim_tail(
                        next, HTT_RX_BUF_SIZE - (RX_STD_DESC_SIZE + msdu_len));
            }
        }

        last_msdu =
            ((*(((u_int32_t *) &rx_desc->msdu_end) + 4)) &
            RX_MSDU_END_4_LAST_MSDU_MASK) >>
            RX_MSDU_END_4_LAST_MSDU_LSB;

        if (last_msdu) {
            adf_nbuf_set_next(msdu, NULL);
            break;
        } else {
            adf_nbuf_t next = htt_rx_netbuf_pop(pdev);
            adf_nbuf_set_next(msdu, next);
            msdu = next;
        }
    }
    *tail_msdu = msdu;

    /*
     * Don't refill the ring yet.
     * First, the elements popped here are still in use - it is
     * not safe to overwrite them until the matching call to
     * mpdu_desc_list_next.
     * Second, for efficiency it is preferable to refill the rx ring
     * with 1 PPDU's worth of rx buffers (something like 32 x 3 buffers),
     * rather than one MPDU's worth of rx buffers (something like 3 buffers).
     * Consequently, we'll rely on the txrx SW to tell us when it is done
     * pulling all the PPDU's rx buffers out of the rx ring, and then
     * refill it just once.
     */
    return msdu_chaining;
}

int
htt_rx_amsdu_pop_hl(
    htt_pdev_handle pdev,
    adf_nbuf_t rx_ind_msg,
    adf_nbuf_t *head_msdu,
    adf_nbuf_t *tail_msdu)
{
    pdev->rx_desc_size_hl =
        (adf_nbuf_data(rx_ind_msg))
        [HTT_ENDIAN_BYTE_IDX_SWAP(
            HTT_RX_IND_HL_RX_DESC_LEN_OFFSET)];

    /* point to the rx desc */
    adf_nbuf_pull_head(rx_ind_msg,
            sizeof(struct hl_htt_rx_ind_base));
    *head_msdu = *tail_msdu = rx_ind_msg;

#ifdef CHECKSUM_OFFLOAD
    htt_set_checksum_result_hl(rx_ind_msg, (struct htt_host_rx_desc_base *)(adf_nbuf_data(rx_ind_msg)));
#endif

    adf_nbuf_set_next(*tail_msdu, NULL);
    return 0;
}

int
htt_rx_frag_pop_hl(
    htt_pdev_handle pdev,
    adf_nbuf_t frag_msg,
    adf_nbuf_t *head_msdu,
    adf_nbuf_t *tail_msdu)
{
    adf_nbuf_pull_head(frag_msg, HTT_RX_FRAG_IND_BYTES);
    pdev->rx_desc_size_hl =
        (adf_nbuf_data(frag_msg))
        [HTT_ENDIAN_BYTE_IDX_SWAP(
             HTT_RX_IND_HL_RX_DESC_LEN_OFFSET)];

    /* point to the rx desc */
    adf_nbuf_pull_head(frag_msg,
                       sizeof(struct hl_htt_rx_ind_base));
    *head_msdu = *tail_msdu = frag_msg;

    adf_nbuf_set_next(*tail_msdu, NULL);
    return 0;
}

int
htt_rx_offload_msdu_pop_ll(
    htt_pdev_handle pdev,
    adf_nbuf_t offload_deliver_msg,
    int *vdev_id,
    int *peer_id,
    int *tid,
    u_int8_t *fw_desc,
    adf_nbuf_t *head_buf,
    adf_nbuf_t *tail_buf)
{
    adf_nbuf_t buf;
    A_UINT32 *msdu_hdr, msdu_len;

    *head_buf = *tail_buf = buf = htt_rx_netbuf_pop(pdev);
    /* Fake read mpdu_desc to keep desc ptr in sync */
    htt_rx_mpdu_desc_list_next(pdev, NULL);
    adf_nbuf_set_pktlen(buf, HTT_RX_BUF_SIZE);
    adf_nbuf_unmap(pdev->osdev, buf, ADF_OS_DMA_FROM_DEVICE);
    msdu_hdr = (A_UINT32 *)adf_nbuf_data(buf);

    /* First dword */
    msdu_len = HTT_RX_OFFLOAD_DELIVER_IND_MSDU_LEN_GET(*msdu_hdr);
    *peer_id = HTT_RX_OFFLOAD_DELIVER_IND_MSDU_PEER_ID_GET(*msdu_hdr);

    /* Second dword */
    msdu_hdr++;
    *vdev_id = HTT_RX_OFFLOAD_DELIVER_IND_MSDU_VDEV_ID_GET(*msdu_hdr);
    *tid = HTT_RX_OFFLOAD_DELIVER_IND_MSDU_TID_GET(*msdu_hdr);
    *fw_desc = HTT_RX_OFFLOAD_DELIVER_IND_MSDU_DESC_GET(*msdu_hdr);

    adf_nbuf_pull_head(buf, HTT_RX_OFFLOAD_DELIVER_IND_MSDU_HDR_BYTES);
    adf_nbuf_set_pktlen(buf, msdu_len);
    return 0;
}

int
htt_rx_offload_msdu_pop_hl(
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

/* Util fake function that has same prototype as adf_nbuf_clone that just
 * retures the same nbuf
 */
adf_nbuf_t
htt_rx_adf_noclone_buf(adf_nbuf_t buf)
{
    return buf;
}

/* FIXME: This is a HW definition not provded by HW, where does it go ? */
enum {
    HW_RX_DECAP_FORMAT_RAW = 0,
    HW_RX_DECAP_FORMAT_NWIFI,
    HW_RX_DECAP_FORMAT_8023,
    HW_RX_DECAP_FORMAT_ETH2,
};

#define HTT_FCS_LEN (4)

static void
htt_rx_parse_ppdu_start_status(
    struct htt_host_rx_desc_base *rx_desc,
    struct ieee80211_rx_status *rs)
{

    struct rx_ppdu_start *ppdu_start = &rx_desc->ppdu_start;

    /* RSSI */
    rs->rs_rssi = ppdu_start->rssi_comb;

    /* PHY rate */
    /* rs_ratephy coding
       [b3 - b0]
        0 -> OFDM
        1 -> CCK
        2 -> HT
        3 -> VHT
      OFDM / CCK
      [b7  - b4 ] => LSIG rate
      [b23 - b8 ] => service field (b'12 static/dynamic, b'14..b'13 BW for VHT)
      [b31 - b24 ] => Reserved
      HT / VHT
      [b15 - b4 ] => SIG A_2 12 LSBs
      [b31 - b16] => SIG A_1 16 LSBs

    */
    if (ppdu_start->preamble_type == 0x4 ) {
        rs->rs_ratephy = ppdu_start->l_sig_rate_select;
        rs->rs_ratephy |= ppdu_start->l_sig_rate << 4;
        rs->rs_ratephy |= ppdu_start->service << 8;
    }  else {
        rs->rs_ratephy =
            (ppdu_start->preamble_type & 0x4) ? 3 : 2;
        rs->rs_ratephy |=
            (ppdu_start->ht_sig_vht_sig_a_2 & 0xFFF) << 4;
        rs->rs_ratephy |=
            (ppdu_start->ht_sig_vht_sig_a_1 & 0xFFFF) << 16;
    }

    return;
}


/* This function is used by montior mode code to restitch an MSDU list
 * corresponding to an MPDU back into an MPDU by linking up the skbs.
 */
adf_nbuf_t
htt_rx_restitch_mpdu_from_msdus(
    htt_pdev_handle pdev,
    adf_nbuf_t head_msdu,
    struct ieee80211_rx_status *rx_status,
    unsigned clone_not_reqd)
{

    adf_nbuf_t msdu, mpdu_buf, prev_buf, msdu_orig, head_frag_list_cloned;
    adf_nbuf_t (*clone_nbuf_fn)(adf_nbuf_t buf);
    unsigned decap_format, wifi_hdr_len, sec_hdr_len, msdu_llc_len,
        mpdu_buf_len, decap_hdr_pull_bytes, frag_list_sum_len, dir,
        is_amsdu, is_first_frag, amsdu_pad, msdu_len;
    struct htt_host_rx_desc_base *rx_desc;
    char *hdr_desc;
    unsigned char *dest;
    struct ieee80211_frame *wh;
    struct ieee80211_qoscntl*qos;

    /* If this packet does not go up the normal stack path we dont need to
     * waste cycles cloning the packets
     */
    clone_nbuf_fn =
        clone_not_reqd ? htt_rx_adf_noclone_buf : adf_nbuf_clone;

    /* The nbuf has been pulled just beyond the status and points to the
     * payload
     */
    msdu_orig = head_msdu;
    rx_desc = htt_rx_desc(msdu_orig);

    /* Fill out the rx_status from the PPDU start and end fields */
    if (rx_desc->attention.first_mpdu) {
        htt_rx_parse_ppdu_start_status(rx_desc, rx_status);

        /* The timestamp is no longer valid - It will be valid only for the
         * last MPDU
         */
        rx_status->rs_tstamp.tsf = ~0;
    }

    decap_format =
        GET_FIELD(&rx_desc->msdu_start, RX_MSDU_START_2_DECAP_FORMAT);

    head_frag_list_cloned = NULL;

    /* Easy case - The MSDU status indicates that this is a non-decapped
     * packet in RAW mode.
     * return
     */
    if (decap_format == HW_RX_DECAP_FORMAT_RAW) {
        /* Note that this path might suffer from headroom unavailabilty -
         * but the RX status is usually enough
         */
        mpdu_buf = clone_nbuf_fn(head_msdu);

        prev_buf = mpdu_buf;

        frag_list_sum_len = 0;
        is_first_frag = 1;
        msdu_len = adf_nbuf_len(mpdu_buf);

        /* Drop the zero-length msdu */
        if (!msdu_len) {
            goto mpdu_stitch_fail;
        }
        msdu_orig = adf_nbuf_next(head_msdu);

        while (msdu_orig) {

            /* TODO: intra AMSDU padding - do we need it ??? */
            msdu = clone_nbuf_fn(msdu_orig);
            if (!msdu) {
                goto mpdu_stitch_fail;
            }

            if (is_first_frag) {
                is_first_frag = 0;
                head_frag_list_cloned  = msdu;
            }

            msdu_len = adf_nbuf_len(msdu);
            /* Drop the zero-length msdu */
            if (!msdu_len) {
                goto mpdu_stitch_fail;
            }

            frag_list_sum_len += msdu_len;

            /* Maintain the linking of the cloned MSDUS */
            adf_nbuf_set_next_ext(prev_buf, msdu);

            /* Move to the next */
            prev_buf = msdu;
            msdu_orig = adf_nbuf_next(msdu_orig);
        }

        /* The last msdu length need be larger than HTT_FCS_LEN */
        if (msdu_len < HTT_FCS_LEN) {
            goto mpdu_stitch_fail;
        }

        adf_nbuf_trim_tail(prev_buf, HTT_FCS_LEN);

        /* If there were more fragments to this RAW frame */
        if (head_frag_list_cloned) {
            adf_nbuf_append_ext_list(mpdu_buf, head_frag_list_cloned,
                    frag_list_sum_len);
        }

        goto mpdu_stitch_done;
    }

    /* Decap mode:
     * Calculate the amount of header in decapped packet to knock off based
     * on the decap type and the corresponding number of raw bytes to copy
     * status header
     */

    hdr_desc = &rx_desc->rx_hdr_status[0];

    /* Base size */
    wifi_hdr_len = sizeof(struct ieee80211_frame);
    wh = (struct ieee80211_frame*)hdr_desc;

    dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
    if (dir == IEEE80211_FC1_DIR_DSTODS) {
        wifi_hdr_len += 6;
    }

    is_amsdu = 0;
    if (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_QOS) {
        qos = (struct ieee80211_qoscntl*)
                (hdr_desc + wifi_hdr_len);
        wifi_hdr_len += 2;

        is_amsdu = (qos->i_qos[0] & IEEE80211_QOS_AMSDU);
    }

    /* TODO: Any security headers associated with MPDU */
    sec_hdr_len = 0;

    /* MSDU related stuff LLC - AMSDU subframe header etc */
    msdu_llc_len = is_amsdu ? (14 + 8) : 8;

    mpdu_buf_len = wifi_hdr_len + sec_hdr_len + msdu_llc_len;

    /* "Decap" header to remove from MSDU buffer */
    decap_hdr_pull_bytes = 14;

    /* Allocate a new nbuf for holding the 802.11 header retrieved from the
     * status of the now decapped first msdu. Leave enough headroom for
     * accomodating any radio-tap /prism like PHY header
     */
#define HTT_MAX_MONITOR_HEADER (512)
    mpdu_buf = adf_nbuf_alloc(pdev->osdev,
        HTT_MAX_MONITOR_HEADER + mpdu_buf_len,
        HTT_MAX_MONITOR_HEADER, 4, FALSE);

    if (!mpdu_buf) {
        goto mpdu_stitch_fail;
    }

    /* Copy the MPDU related header and enc headers into the first buffer
     * - Note that there can be a 2 byte pad between heaader and enc header
     */

    prev_buf = mpdu_buf;
    dest = adf_nbuf_put_tail(prev_buf, wifi_hdr_len);
    if (!dest) {
        goto mpdu_stitch_fail;
    }
    adf_os_mem_copy(dest, hdr_desc, wifi_hdr_len);
    hdr_desc += wifi_hdr_len;

    /* NOTE - This padding is present only in the RAW header status - not
     * when the MSDU data payload is in RAW format.
     */
    /* Skip the "IV pad" */
    if (wifi_hdr_len & 0x3) {
        hdr_desc += 2;
    }

#if 0
    dest = adf_nbuf_put_tail(prev_buf, sec_hdr_len);
    adf_os_mem_copy(dest, hdr_desc, sec_hdr_len);
    hdr_desc += sec_hdr_len;
#endif

    /* The first LLC len is copied into the MPDU buffer */
    frag_list_sum_len = 0;
    frag_list_sum_len -= msdu_llc_len;

    msdu_orig = head_msdu;
    is_first_frag = 1;
    amsdu_pad = 0;

    while (msdu_orig) {

        /* TODO: intra AMSDU padding - do we need it ??? */

        msdu = clone_nbuf_fn(msdu_orig);
        if (!msdu) {
            goto mpdu_stitch_fail;
        }

        if (is_first_frag) {
            is_first_frag = 0;
            head_frag_list_cloned  = msdu;
        } else {

            /* Maintain the linking of the cloned MSDUS */
            adf_nbuf_set_next_ext(prev_buf, msdu);

            /* Reload the hdr ptr only on non-first MSDUs */
            rx_desc = htt_rx_desc(msdu_orig);
            hdr_desc = &rx_desc->rx_hdr_status[0];

        }

        /* Copy this buffers MSDU related status into the prev buffer */
        dest = adf_nbuf_put_tail(prev_buf, msdu_llc_len + amsdu_pad);
        dest += amsdu_pad;
        adf_os_mem_copy(dest, hdr_desc, msdu_llc_len);


        /* Push the MSDU buffer beyond the decap header */
        adf_nbuf_pull_head(msdu, decap_hdr_pull_bytes);
        frag_list_sum_len += msdu_llc_len + adf_nbuf_len(msdu) + amsdu_pad;

        /* Set up intra-AMSDU pad to be added to start of next buffer -
         * AMSDU pad is 4 byte pad on AMSDU subframe */
        amsdu_pad = (msdu_llc_len + adf_nbuf_len(msdu)) & 0x3;
        amsdu_pad = amsdu_pad ? ( 4 - amsdu_pad) : 0;

        /* TODO FIXME How do we handle MSDUs that have fraglist - Should
         * probably iterate all the frags cloning them along the way and
         * and also updating the prev_buf pointer
         */

        /* Move to the next */
        prev_buf = msdu;
        msdu_orig = adf_nbuf_next(msdu_orig);

    }

#if 0
    /* Add in the trailer section - encryption trailer + FCS */
    adf_nbuf_put_tail(prev_buf, HTT_FCS_LEN);
    frag_list_sum_len += HTT_FCS_LEN;
#endif

    /* TODO: Convert this to suitable adf routines */
    adf_nbuf_append_ext_list(mpdu_buf, head_frag_list_cloned,
            frag_list_sum_len);

mpdu_stitch_done:
    /* Check if this buffer contains the PPDU end status for TSF */
    if (rx_desc->attention.last_mpdu) {
        rx_status->rs_tstamp.tsf = rx_desc->ppdu_end.tsf_timestamp;
    }

    /* All the nbufs have been linked into the ext list and then unlink the nbuf list */
    if (clone_not_reqd) {
        msdu = head_msdu;
        while (msdu) {
            msdu_orig = msdu;
            msdu = adf_nbuf_next(msdu);
            adf_nbuf_set_next(msdu_orig, NULL);
        }
    }

    return (mpdu_buf);


mpdu_stitch_fail:
    /* Free these alloced buffers and the orig buffers in non-clone case */
    if (!clone_not_reqd) {
        /* Free the head buffer */
        if (mpdu_buf) {
            adf_nbuf_free(mpdu_buf);
        }

        /* Free the partial list */
        while (head_frag_list_cloned) {
            msdu = head_frag_list_cloned;
            head_frag_list_cloned = adf_nbuf_next_ext(head_frag_list_cloned);
            adf_nbuf_free(msdu);
        }
    }  else {
        /* Free the alloced head buffer */
        if (decap_format != HW_RX_DECAP_FORMAT_RAW) {
            if (mpdu_buf) {
                adf_nbuf_free(mpdu_buf);
            }
        }

        /* Free the orig buffers */
        msdu = head_msdu;
        while (msdu) {
            msdu_orig = msdu;
            msdu = adf_nbuf_next(msdu);
            adf_nbuf_free(msdu_orig);
        }
    }

    return NULL;
}

int16_t
htt_rx_mpdu_desc_rssi_dbm(htt_pdev_handle pdev, void *mpdu_desc)
{
    /*
     * Currently the RSSI is provided only as a field in the
     * HTT_T2H_RX_IND message, rather than in each rx descriptor.
     */
    return HTT_RSSI_INVALID;
}


/*
 * htt_rx_amsdu_pop -
 * global function pointer that is programmed during attach to point
 * to either htt_rx_amsdu_pop_ll or htt_rx_amsdu_pop_hl.
 */
int (*htt_rx_amsdu_pop)(
    htt_pdev_handle pdev,
    adf_nbuf_t rx_ind_msg,
    adf_nbuf_t *head_msdu,
    adf_nbuf_t *tail_msdu);

/*
 * htt_rx_frag_pop -
 * global function pointer that is programmed during attach to point
 * to either htt_rx_amsdu_pop_ll or htt_rx_frag_pop_hl.
 */
int (*htt_rx_frag_pop)(
    htt_pdev_handle pdev,
    adf_nbuf_t rx_ind_msg,
    adf_nbuf_t *head_msdu,
    adf_nbuf_t *tail_msdu);

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

void *(*htt_rx_mpdu_desc_list_next)(
    htt_pdev_handle pdev,
    adf_nbuf_t rx_ind_msg);

u_int16_t (*htt_rx_mpdu_desc_seq_num)(
    htt_pdev_handle pdev, void *mpdu_desc);

void (*htt_rx_mpdu_desc_pn)(
    htt_pdev_handle pdev,
    void *mpdu_desc,
    union htt_rx_pn_t *pn,
    int pn_len_bits);

a_bool_t (*htt_rx_msdu_desc_completes_mpdu)(
    htt_pdev_handle pdev, void *msdu_desc);

a_bool_t (*htt_rx_msdu_first_msdu_flag)(
    htt_pdev_handle pdev, void *msdu_desc);

int (*htt_rx_msdu_has_wlan_mcast_flag)(
    htt_pdev_handle pdev, void *msdu_desc);

a_bool_t (*htt_rx_msdu_is_wlan_mcast)(
    htt_pdev_handle pdev, void *msdu_desc);

int (*htt_rx_msdu_is_frag)(
    htt_pdev_handle pdev, void *msdu_desc);

void *(*htt_rx_msdu_desc_retrieve)(
    htt_pdev_handle pdev, adf_nbuf_t msdu);

a_bool_t (*htt_rx_mpdu_is_encrypted)(
    htt_pdev_handle pdev,
    void *mpdu_desc);

a_bool_t (*htt_rx_msdu_desc_key_id)(
    htt_pdev_handle pdev,
    void *mpdu_desc, u_int8_t *key_id);

void *
htt_rx_mpdu_desc_list_next_ll(htt_pdev_handle pdev, adf_nbuf_t rx_ind_msg)
{
    int idx = pdev->rx_ring.sw_rd_idx.msdu_desc;
    adf_nbuf_t netbuf = pdev->rx_ring.buf.netbufs_ring[idx];
    pdev->rx_ring.sw_rd_idx.msdu_desc = pdev->rx_ring.sw_rd_idx.msdu_payld;
    return (void *) htt_rx_desc(netbuf);
}

void *
htt_rx_mpdu_desc_list_next_hl(htt_pdev_handle pdev, adf_nbuf_t rx_ind_msg)
{
    /*
     * for HL, the returned value is not mpdu_desc,
     * it's translated hl_rx_desc just after the hl_ind_msg
     */
    void *mpdu_desc = (void *) adf_nbuf_data(rx_ind_msg);

    /* for HL AMSDU, we can't point to payload now, because
     * hl rx desc is not fixed, we can't retrive the desc
     * by minus rx_desc_size when release. keep point to hl rx desc
     * now.
     */
#if 0
	adf_nbuf_pull_head(rx_ind_msg, pdev->rx_desc_size_hl);
#endif

    return mpdu_desc;
}

void *
htt_rx_msdu_desc_retrieve_ll(htt_pdev_handle pdev, adf_nbuf_t msdu)
{
    return htt_rx_desc(msdu);
}

void *
htt_rx_msdu_desc_retrieve_hl(htt_pdev_handle pdev, adf_nbuf_t msdu)
{
    /* currently for HL AMSDU, we don't point to payload.
     * we shift to payload in ol_rx_deliver later
     */
    return adf_nbuf_data(msdu);
}

a_bool_t htt_rx_mpdu_is_encrypted_ll(htt_pdev_handle pdev, void *mpdu_desc)
{
    struct htt_host_rx_desc_base *rx_desc = (struct htt_host_rx_desc_base *) mpdu_desc;

    return  (((*((u_int32_t *) &rx_desc->mpdu_start)) &
        RX_MPDU_START_0_ENCRYPTED_MASK) >>
        RX_MPDU_START_0_ENCRYPTED_LSB) ? A_TRUE : A_FALSE;
}

a_bool_t htt_rx_mpdu_is_encrypted_hl(htt_pdev_handle pdev, void *mpdu_desc)
{
    if (htt_rx_msdu_first_msdu_flag_hl(pdev, mpdu_desc) == A_TRUE) {
        /* Fix Me: only for little endian */
        struct hl_htt_rx_desc_base *rx_desc =
            (struct hl_htt_rx_desc_base *) mpdu_desc;

        return HTT_WORD_GET(*(u_int32_t*)rx_desc, HTT_HL_RX_DESC_MPDU_ENC);
    }else {
        /* not first msdu, no encrypt info for hl */
        adf_os_print(
                "Error: get encrypted from a not-first msdu.\n");
        adf_os_assert(0);
		return -1;
    }
}

a_bool_t
htt_rx_msdu_desc_key_id_ll(htt_pdev_handle pdev, void *mpdu_desc,
                           u_int8_t *key_id)
{
    struct htt_host_rx_desc_base *rx_desc = (struct htt_host_rx_desc_base *)
                                             mpdu_desc;

    if (!htt_rx_msdu_first_msdu_flag_ll(pdev, mpdu_desc))
        return A_FALSE;

    *key_id = ((*(((u_int32_t *) &rx_desc->msdu_end) + 1)) &
               (RX_MSDU_END_1_KEY_ID_OCT_MASK >> RX_MSDU_END_1_KEY_ID_OCT_LSB));

    return A_TRUE;
}

a_bool_t
htt_rx_msdu_desc_key_id_hl(htt_pdev_handle htt_pdev, void *mpdu_desc, u_int8_t *key_id)
{
    if (htt_rx_msdu_first_msdu_flag_hl(htt_pdev, mpdu_desc) == A_TRUE) {
        /* Fix Me: only for little endian */
        struct hl_htt_rx_desc_base *rx_desc =
            (struct hl_htt_rx_desc_base *) mpdu_desc;

        *key_id = rx_desc->key_id_oct;
        return A_TRUE;
    }

    return A_FALSE;
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
    /*
     * The rx descriptor is in the same buffer as the rx MSDU payload,
     * and does not need to be freed separately.
     */
}

void
htt_rx_msdu_buff_replenish(htt_pdev_handle pdev)
{
    if (adf_os_atomic_dec_and_test(&pdev->rx_ring.refill_ref_cnt)) {
        if (!pdev->cfg.is_high_latency) {
            int num_to_fill;
            num_to_fill = pdev->rx_ring.fill_level - pdev->rx_ring.fill_cnt;
            htt_rx_ring_fill_n(pdev, num_to_fill /* okay if <= 0 */);
        }
    }
    adf_os_atomic_inc(&pdev->rx_ring.refill_ref_cnt);
}

#define AR600P_ASSEMBLE_HW_RATECODE(_rate, _nss, _pream)     \
            (((_pream) << 6) | ((_nss) << 4) | (_rate))

enum AR600P_HW_RATECODE_PREAM_TYPE {
    AR600P_HW_RATECODE_PREAM_OFDM,
    AR600P_HW_RATECODE_PREAM_CCK,
    AR600P_HW_RATECODE_PREAM_HT,
    AR600P_HW_RATECODE_PREAM_VHT,
};

#if 0
void htt_rx_get_vowext_stats(adf_nbuf_t msdu, struct vow_extstats *vowstats)
{
    u_int32_t *ppdu;
    u_int8_t preamble_type;
    u_int8_t rate = 0, nss=0, bw=0, sgi = 0, mcs = 0, rs_flags=0;
    struct htt_host_rx_desc_base *rx_desc;
    rx_desc = htt_rx_desc(msdu);

    ppdu = ((u_int32_t *)&rx_desc->ppdu_start);
    preamble_type = (ppdu[5] & 0xff000000) >> 24;
    switch(preamble_type)
    {
        /* HT */
        case 8: /* HT w/o TxBF */
        case 9:/* HT w/ TxBF */
            mcs = (u_int8_t)(ppdu[6] & 0x7f);
            nss = mcs>>3;
            mcs %= 8;
            bw  = (u_int8_t)((ppdu[6] >> 7) & 1);
            sgi = (u_int8_t)((ppdu[6] >> 7) & 1);
            rate = AR600P_ASSEMBLE_HW_RATECODE(mcs, nss, AR600P_HW_RATECODE_PREAM_HT);
            if (bw) {
                rs_flags |= HAL_RX_40;
            }
            if (sgi) {
                rs_flags |= HAL_RX_GI;
            }
            break;
            /* VHT */
        case 0x0c: /* VHT w/o TxBF */
        case 0x0d: /* VHT w/ TxBF */
            mcs = (u_int8_t)((ppdu[7] >> 4) & 0xf);
            nss = (u_int8_t)((ppdu[6] >> 10) & 0x7);
            bw  = (u_int8_t)((ppdu[6] & 3));
            sgi = (u_int8_t)((ppdu[7]) & 1);
            rate = AR600P_ASSEMBLE_HW_RATECODE(mcs, nss, AR600P_HW_RATECODE_PREAM_VHT);
            break;
    }

    vowstats->rx_bw = bw; /* band width 0 - 20 , 1 - 40 , 2 - 80 */
    vowstats->rx_sgi = sgi; /* 1 - short GI */
    vowstats->rx_nss= nss; /* Nss */
    vowstats->rx_mcs = mcs;
    vowstats->rx_ratecode = rate;
    vowstats->rx_rs_flags= rs_flags; /* rsflags */

    vowstats->rx_rssi_ctl0 = (ppdu[0] & 0x000000ff); /* rssi ctl0 */
    vowstats->rx_rssi_ctl1 = (ppdu[1] & 0x000000ff); /* rssi ctl1 */
    vowstats->rx_rssi_ctl2 = (ppdu[2] & 0x000000ff); /* rssi ctl2 */
    vowstats->rx_rssi_ext0 = (ppdu[0] & 0x0000ff00) >> 8; /* rssi ext0 */
    vowstats->rx_rssi_ext1 = (ppdu[1] & 0x0000ff00) >> 8; /* rssi ext1 */
    vowstats->rx_rssi_ext2 = (ppdu[2] & 0x0000ff00) >> 8; /* rssi ext2 */
    vowstats->rx_rssi_comb = (ppdu[4] & 0x000000ff); /* rssi comb */

    ppdu = ((u_int32_t *)&rx_desc->ppdu_end);
    /* Time stamp */
    vowstats->rx_macTs = ppdu[16];

    ppdu = ((u_int32_t *)&rx_desc->attention);
    /* more data */
    vowstats->rx_moreaggr = (ppdu[0] & RX_ATTENTION_0_MORE_DATA_MASK);

    /* sequence number */
    ppdu = ((u_int32_t *)&rx_desc->mpdu_start);
    vowstats->rx_seqno = (ppdu[0] & 0x0fff0000) >> 16;

}

#endif
/* move the function to the end of file
 * to omit ll/hl pre-declaration
 */
int
htt_rx_attach(struct htt_pdev_t *pdev)
{
    adf_os_dma_addr_t paddr;
    if (!pdev->cfg.is_high_latency) {
#ifdef HTT_RX_RESTORE
        pdev->rx_ring.rx_reset = 0;
        pdev->rx_ring.htt_rx_restore = 0;
#endif
        pdev->rx_ring.size = htt_rx_ring_size(pdev);
        HTT_ASSERT2(IS_PWR2(pdev->rx_ring.size));
        pdev->rx_ring.size_mask = pdev->rx_ring.size - 1;

        /*
         * Set the initial value for the level to which the rx ring should
         * be filled, based on the max throughput and the worst likely
         * latency for the host to fill the rx ring with new buffers.
         * In theory, this fill level can be dynamically adjusted from
         * the initial value set here, to reflect the actual host latency
         * rather than a conservative assumption about the host latency.
         */
        pdev->rx_ring.fill_level = htt_rx_ring_fill_level(pdev);

        pdev->rx_ring.buf.netbufs_ring = adf_os_mem_alloc(
            pdev->osdev, pdev->rx_ring.size * sizeof(adf_nbuf_t));
        if (!pdev->rx_ring.buf.netbufs_ring) {
            goto fail1;
        }

        pdev->rx_ring.buf.paddrs_ring = adf_os_mem_alloc_consistent(
            pdev->osdev,
            pdev->rx_ring.size * sizeof(u_int32_t),
            &paddr,
            adf_os_get_dma_mem_context((&pdev->rx_ring.buf), memctx));
        if (!pdev->rx_ring.buf.paddrs_ring) {
            goto fail2;
        }
        pdev->rx_ring.base_paddr = paddr;
        pdev->rx_ring.alloc_idx.vaddr = adf_os_mem_alloc_consistent(
            pdev->osdev,
            sizeof(u_int32_t),
            &paddr,
            adf_os_get_dma_mem_context((&pdev->rx_ring.alloc_idx), memctx));
        if (!pdev->rx_ring.alloc_idx.vaddr) {
            goto fail3;
        }
        pdev->rx_ring.alloc_idx.paddr = paddr;
        pdev->rx_ring.sw_rd_idx.msdu_payld = 0;
        pdev->rx_ring.sw_rd_idx.msdu_desc = 0;
        *pdev->rx_ring.alloc_idx.vaddr = 0;

        /*
         * Initialize the Rx refill reference counter to be one so that
         * only one thread is allowed to refill the Rx ring.
         */
        adf_os_atomic_init(&pdev->rx_ring.refill_ref_cnt);
        adf_os_atomic_inc(&pdev->rx_ring.refill_ref_cnt);

        /* Initialize the Rx refill retry timer */
        adf_os_timer_init(pdev->osdev, &pdev->rx_ring.refill_retry_timer,
                          htt_rx_ring_refill_retry, (void *)pdev);

        pdev->rx_ring.fill_cnt = 0;
#ifdef DEBUG_DMA_DONE
        pdev->rx_ring.dbg_ring_idx = 0;
        pdev->rx_ring.dbg_refill_cnt = 0;
        pdev->rx_ring.dbg_sync_success = 0;
#endif
        htt_rx_ring_fill_n(pdev, pdev->rx_ring.fill_level);

        htt_rx_amsdu_pop = htt_rx_amsdu_pop_ll;
        htt_rx_frag_pop = htt_rx_amsdu_pop_ll;
        htt_rx_offload_msdu_pop = htt_rx_offload_msdu_pop_ll;
        htt_rx_mpdu_desc_list_next = htt_rx_mpdu_desc_list_next_ll;
        htt_rx_mpdu_desc_seq_num = htt_rx_mpdu_desc_seq_num_ll;
        htt_rx_mpdu_desc_pn = htt_rx_mpdu_desc_pn_ll;
        htt_rx_msdu_desc_completes_mpdu = htt_rx_msdu_desc_completes_mpdu_ll;
        htt_rx_msdu_first_msdu_flag = htt_rx_msdu_first_msdu_flag_ll;
        htt_rx_msdu_has_wlan_mcast_flag = htt_rx_msdu_has_wlan_mcast_flag_ll;
        htt_rx_msdu_is_wlan_mcast = htt_rx_msdu_is_wlan_mcast_ll;
        htt_rx_msdu_is_frag = htt_rx_msdu_is_frag_ll;
        htt_rx_msdu_desc_retrieve = htt_rx_msdu_desc_retrieve_ll;
        htt_rx_mpdu_is_encrypted = htt_rx_mpdu_is_encrypted_ll;
        htt_rx_msdu_desc_key_id = htt_rx_msdu_desc_key_id_ll;
    } else {
        pdev->rx_ring.size = HTT_RX_RING_SIZE_MIN;
        HTT_ASSERT2(IS_PWR2(pdev->rx_ring.size));
        pdev->rx_ring.size_mask = pdev->rx_ring.size - 1;

        /* host can force ring base address if it wish to do so */
        pdev->rx_ring.base_paddr = 0;
        htt_rx_amsdu_pop = htt_rx_amsdu_pop_hl;
        htt_rx_frag_pop = htt_rx_frag_pop_hl;
        htt_rx_offload_msdu_pop = htt_rx_offload_msdu_pop_hl;
        htt_rx_mpdu_desc_list_next = htt_rx_mpdu_desc_list_next_hl;
        htt_rx_mpdu_desc_seq_num = htt_rx_mpdu_desc_seq_num_hl;
        htt_rx_mpdu_desc_pn = htt_rx_mpdu_desc_pn_hl;
        htt_rx_msdu_desc_completes_mpdu = htt_rx_msdu_desc_completes_mpdu_hl;
        htt_rx_msdu_first_msdu_flag = htt_rx_msdu_first_msdu_flag_hl;
        htt_rx_msdu_has_wlan_mcast_flag = htt_rx_msdu_has_wlan_mcast_flag_hl;
        htt_rx_msdu_is_wlan_mcast = htt_rx_msdu_is_wlan_mcast_hl;
        htt_rx_msdu_is_frag = htt_rx_msdu_is_frag_hl;
        htt_rx_msdu_desc_retrieve = htt_rx_msdu_desc_retrieve_hl;
        htt_rx_mpdu_is_encrypted = htt_rx_mpdu_is_encrypted_hl;
        htt_rx_msdu_desc_key_id = htt_rx_msdu_desc_key_id_hl;

        /*
         * HL case, the rx descriptor can be different sizes for
         * different sub-types of RX_IND messages, e.g. for the
         * initial vs. interior vs. final MSDUs within a PPDU.
         * The size of each RX_IND message's rx desc is read from
         * a field within the RX_IND message itself.
         * In the meantime, until the rx_desc_size_hl variable is
         * set to its real value based on the RX_IND message,
         * initialize it to a reasonable value (zero).
         */
        pdev->rx_desc_size_hl = 0;
    }
    return 0; /* success */

fail3:
    adf_os_mem_free_consistent(
        pdev->osdev,
        pdev->rx_ring.size * sizeof(u_int32_t),
        pdev->rx_ring.buf.paddrs_ring,
        pdev->rx_ring.base_paddr,
        adf_os_get_dma_mem_context((&pdev->rx_ring.buf), memctx));

fail2:
    adf_os_mem_free(pdev->rx_ring.buf.netbufs_ring);

fail1:
    return 1; /* failure */
}
