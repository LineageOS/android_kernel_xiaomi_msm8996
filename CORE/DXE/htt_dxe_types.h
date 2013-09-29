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

#ifndef _HTT_DXE_TYPES__H_
#define _HTT_DXE_TYPES__H_

#include <osdep.h>        /* u_int16_t, dma_addr_t */
#include <adf_os_types.h> /* adf_os_device_t */
#include <adf_os_lock.h>  /* adf_os_spinlock_t */
//#include <adf_os_timer.h> /* adf_os_timer_t */
//#include <adf_os_atomic.h>/* adf_os_atomic_inc */
#include <adf_nbuf.h>     /* adf_nbuf_t */

#include <isoc_hw_desc.h> /* isoc_tx_bd_t */
#include <htt_isoc.h>     /* HTT_ISOC_T2H_PEER_TYPE_ENUM */

#include <ol_ctrl_api.h>  /* ol_pdev_handle */
#include <ol_txrx_api.h>  /* ol_txrx_pdev_handle */
#include <dmux_dxe_api.h> /* dmux_dxe_handle */
#include <hif_dxe.h>      /* hif_dxe_handle */
#include <isoc_hw_desc.h> /* isoc_rx_bd_t */
#include <ol_htt_api.h>   /* enum htt_op_mode */

#define htt_dxe_pdev_t htt_pdev_t


struct htt_dxe_pdev_t;

struct htt_dxe_tx_desc_t {
    /*
     * N.B. The union portion of this struct can get clobbered when
     * the struct is stored in a freelist.
     * Any elements that need to be maintained during the time that
     * the struct is unallocated in the freelist must be placed
     * after the union.
     */
    union {
        struct {
            u_int8_t ext_tid;
            u_int8_t l2_hdr_size;
            u_int8_t is_mgmt;
        } info;
        struct htt_dxe_tx_desc_t *next; /* used for freelist */
    } u;
    volatile char *tx_bd_buf;
};

enum {
    HTT_DXE_PEER_KEY_UCAST,
    HTT_DXE_PEER_KEY_MCAST,
    HTT_DXE_PEER_KEY_MGMT,

    HTT_DXE_PEER_NUM_KEYS /* keep this last */
};

struct htt_dxe_peer_t {
    HTT_ISOC_T2H_PEER_TYPE_ENUM type;
    u_int32_t rx_aggr_enabled_tids_bitmap;
    struct {
        u_int8_t id;
        u_int8_t signature;
    } security[HTT_DXE_PEER_NUM_KEYS];
    u_int8_t vdev_id; /* which vdev does this peer belong to */
    /*
     * For now, store one flag per byte, to allow for fast access
     * when checking these flags from the per-frame transmit functions.
     * To minimize memory, these flags could be packed together, but
     * that would be less CPU-efficient.
     */
    u_int8_t qos_capable;
    u_int8_t robust_mgmt;
    u_int8_t valid; 
};

struct htt_dxe_vdev_t {
    enum htt_op_mode op_mode;
    u_int16_t self_peer_id;
    u_int16_t bcast_peer_id;
    u_int8_t  valid;
};

struct htt_dxe_msdu_list_t {
    adf_nbuf_t head;
    adf_nbuf_t tail;
};

struct htt_dxe_rx_log_elem_t {
    u_int16_t peer_id;
    int16_t seq_num; /* -1 for n/a */
    u_int8_t  tid;
    u_int8_t  reorder_opcode;
    int8_t  slot_idx; /* -1 for n/a */
    int8_t  fwd_idx; /* -1 for n/a */
};

struct htt_dxe_pdev_t {
    ol_pdev_handle ctrl_pdev;
    ol_txrx_pdev_handle txrx_pdev;
    dmux_dxe_handle dmux_dxe_pdev;
    hif_dxe_handle hif_dxe_pdev;
    adf_os_device_t osdev;

    struct htt_dxe_vdev_t *vdevs;
    struct htt_dxe_peer_t *peers;

    struct {
        struct {
            u_int8_t sw_tx_encap;
            u_int8_t do_frame_translate;
        } flags;
    } cfg;

    struct {
        int size; /* of each HTT tx desc */
        int pool_elems;
        int alloc_cnt;
        struct htt_dxe_tx_desc_t *sw_descs_pool;
        struct {
            char *pool_vaddr;
            u_int32_t pool_paddr;
        } tx_bds;
        struct htt_dxe_tx_desc_t *freelist;
        adf_os_dma_mem_context(memctx);
    } tx_descs;
    isoc_tx_bd_t template_tx_bd;
    u_int32_t tx_bd_sig_serial_num;

    adf_os_spinlock_t tx_mutex;
    u_int8_t tx_mutex_valid;

    struct {
        struct htt_dxe_msdu_list_t pending_amsdus[2/*low+high pri*/];
        struct htt_dxe_msdu_list_t delivery;

        /* cur -
         * temporary context to remember which rx indication
         * is being processed currently
         */
        struct {
           isoc_rx_bd_t *rx_bd;
           u_int8_t peer_id;
           u_int8_t tid;
           u_int8_t rx_aggr_enabled;
        } cur;
    } rx;

    #ifdef HTT_DXE_RX_LOG
    #define HTT_DXE_RX_LOG_LEN_LOG2 7 /* log length = 128 */
    #define HTT_DXE_RX_LOG_LEN (1 << HTT_DXE_RX_LOG_LEN_LOG2)
    #define HTT_DXE_RX_LOG_LEN_MASK (HTT_DXE_RX_LOG_LEN - 1)
    struct {
        struct htt_dxe_rx_log_elem_t data[HTT_DXE_RX_LOG_LEN];
        int idx;
        int enable;
        int wrap;
        int wrapped;
    } reorder_log;
    #endif /* HTT_DXE_RX_LOG */

};



#endif /* _HTT_DXE_TYPES__H_ */
