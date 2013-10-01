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
 * @file htt_dxe_h2t.c
 * @brief Provide dummy functions for host->target HTT messages.
 * @details
 *  For the Riva family of targets supported by this hif_dxe module,
 *  no host->target HTT messages are required.
 *  This file provides dummy versions of the HTT H2T message
 *  construction functions called by txrx, just so the txrx code will
 *  link successfully.
 */

#include <adf_os_util.h>
#include <ol_htt_api.h>

int
htt_h2t_dbg_stats_get(
    struct htt_pdev_t *pdev, 
    u_int32_t stats_type_upload_mask,
    u_int32_t stats_type_reset_mask,
    u_int8_t cfg_stat_type,
    u_int32_t cfg_val,
    u_int64_t cookie)
{
    adf_os_assert(0);
    return 0;
}

A_STATUS
htt_h2t_sync_msg(struct htt_pdev_t *pdev, u_int8_t sync_cnt)
{
    adf_os_assert(0);
    return A_OK;
}

#if defined(TEMP_AGGR_CFG)
int
htt_h2t_aggr_cfg_msg(struct htt_pdev_t *pdev,
                     int max_subfrms_ampdu, 
                     int max_subfrms_amsdu)
{
    adf_os_assert(0);
    return 0;
}
#endif
