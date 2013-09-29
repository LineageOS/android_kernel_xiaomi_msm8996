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

#ifndef _HTT_DXE_INTERNAL__H_
#define _HTT_DXE_INTERNAL__H_

#include <athdefs.h>     /* A_STATUS */

#include <adf_nbuf.h>    /* adf_nbuf_t */

#include <hif_dxe.h>     /* E_HIFDXE_CHANNELTYPE */

#include <htt_dxe_types.h>


#define HTT_MAC_ADDR_LEN 6

/*--- utilities ---*/

#ifndef ARRAY_LEN
#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))
#endif


#ifndef HTT_DXE_ASSERT_LEVEL
#define HTT_DXE_ASSERT_LEVEL 3
#endif

#define HTT_DXE_ASSERT_ALWAYS(condition) adf_os_assert_always((condition))

#define HTT_DXE_ASSERT0(condition) adf_os_assert((condition))
#if HTT_DXE_ASSERT_LEVEL > 0
#define HTT_DXE_ASSERT1(condition) adf_os_assert((condition))
#else
#define HTT_DXE_ASSERT1(condition)
#endif

#if HTT_DXE_ASSERT_LEVEL > 1
#define HTT_DXE_ASSERT2(condition) adf_os_assert((condition))
#else
#define HTT_DXE_ASSERT2(condition)
#endif

#if HTT_DXE_ASSERT_LEVEL > 2
#define HTT_DXE_ASSERT3(condition) adf_os_assert((condition))
#else
#define HTT_DXE_ASSERT3(condition)
#endif

/*--- aliases ---*/

#define htt_dxe_tx_desc_alloc   htt_tx_desc_alloc
#define htt_dxe_tx_desc_free    htt_tx_desc_free
#define htt_dxe_tx_desc_display htt_tx_desc_display

/*--- tx ---*/

A_STATUS
htt_dxe_tx_attach(struct htt_dxe_pdev_t *pdev, int desc_pool_elems);

void
htt_dxe_tx_detach(struct htt_pdev_t *pdev);

A_STATUS
htt_dxe_tx_download_done(
    void *context,
    adf_nbuf_t tx_list,
    E_HIFDXE_CHANNELTYPE chan,
    A_STATUS status);

A_STATUS
htt_dxe_tx_low_rsrc(
    void *context,
    E_HIFDXE_CHANNELTYPE chan,
    A_BOOL is_low_resource);

/*--- rx ---*/

A_STATUS
htt_dxe_rx_attach(struct htt_pdev_t *pdev);

void
htt_dxe_rx_detach(struct htt_dxe_pdev_t *pdev);

void
htt_dxe_rx(void *context, adf_nbuf_t rx_msdus, E_HIFDXE_CHANNELTYPE chan);

void
htt_dxe_rx_ctrl(void *context, adf_nbuf_t rx_ctrl_msg);

#if HTT_DXE_RX_LOG
#define HTT_DXE_RX_REORDER_LOG_INIT htt_dxe_rx_reorder_log_init
void htt_dxe_rx_reorder_log_init(struct htt_pdev_t *pdev);
#define HTT_DXE_RX_REORDER_LOG_ADD htt_dxe_rx_reorder_log_add
void
htt_dxe_rx_reorder_log_add(
    struct htt_pdev_t *pdev,
    u_int16_t peer_id,
    u_int8_t tid,
    isoc_rx_bd_t *rx_bd);

#else
#define HTT_DXE_RX_REORDER_LOG_INIT(pdev) /* no-op */
#define HTT_DXE_RX_REORDER_LOG_ADD(pdev, peer_id, tid, rx_bd) /* no-op */
#endif /* HTT_DXE_RX_LOG */

/*--- t2h ---*/

void
htt_dxe_t2h_msg_handler(void *context, adf_nbuf_t htt_t2h_msg);


#endif /* _HTT_DXE_INTERNAL__H_ */
