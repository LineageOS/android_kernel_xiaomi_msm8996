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

#ifndef __WLANDEFS_H__
#define __WLANDEFS_H__

/*
 * This file contains WLAN definitions that may be used across both
 * Host and Target software.  
 */

#define MAX_SPATIAL_STREAM   3


typedef enum {
    MODE_11A        = 0,   /* 11a Mode */
    MODE_11G        = 1,   /* 11b/g Mode */
    MODE_11B        = 2,   /* 11b Mode */
    MODE_11GONLY    = 3,   /* 11g only Mode */
    MODE_11NA_HT20   = 4,  /* 11a HT20 mode */
    MODE_11NG_HT20   = 5,  /* 11g HT20 mode */
    MODE_11NA_HT40   = 6,  /* 11a HT40 mode */
    MODE_11NG_HT40   = 7,  /* 11g HT40 mode */
    MODE_11AC_VHT20 = 8,
    MODE_11AC_VHT40 = 9,
    MODE_11AC_VHT80 = 10,
//    MODE_11AC_VHT160 = 11,
    MODE_11AC_VHT20_2G = 11,
    MODE_11AC_VHT40_2G = 12,
    MODE_11AC_VHT80_2G = 13,
    MODE_UNKNOWN    = 14,
    MODE_MAX        = 14
} WLAN_PHY_MODE;

typedef enum {
    VHT_MODE_NONE = 0,  /* NON VHT Mode, e.g., HT, DSSS, CCK */
    VHT_MODE_20M = 1,
    VHT_MODE_40M = 2,
    VHT_MODE_80M = 3,
    VHT_MODE_160M = 4
} VHT_OPER_MODE;

typedef enum {
    WLAN_11A_CAPABILITY   = 1,
    WLAN_11G_CAPABILITY   = 2,
    WLAN_11AG_CAPABILITY  = 3,
}WLAN_CAPABILITY;


#define A_RATEMASK A_UINT32

#define A_RATEMASK_NUM_OCTET (sizeof (A_RATEMASK))
#define A_RATEMASK_NUM_BITS ((sizeof (A_RATEMASK)) << 3)


#define IS_MODE_VHT(mode) (((mode) == MODE_11AC_VHT20) || \
        ((mode) == MODE_11AC_VHT40) || \
        ((mode) == MODE_11AC_VHT80))

#define IS_MODE_VHT_2G(mode) (((mode) == MODE_11AC_VHT20_2G) || \
        ((mode) == MODE_11AC_VHT40_2G) || \
        ((mode) == MODE_11AC_VHT80_2G))


#define IS_MODE_11A(mode)       (((mode) == MODE_11A) || \
                                 ((mode) == MODE_11NA_HT20) || \
                                 ((mode) == MODE_11NA_HT40) || \
                                 (IS_MODE_VHT(mode)))
                                 
#define IS_MODE_11B(mode)       ((mode) == MODE_11B)
#define IS_MODE_11G(mode)       (((mode) == MODE_11G) || \
                                 ((mode) == MODE_11GONLY) || \
                                 ((mode) == MODE_11NG_HT20) || \
                                 ((mode) == MODE_11NG_HT40) || \
                                 (IS_MODE_VHT_2G(mode)))
#define IS_MODE_11GN(mode)      (((mode) == MODE_11NG_HT20) || \
                                 ((mode) == MODE_11NG_HT40))
#define IS_MODE_11GONLY(mode)   ((mode) == MODE_11GONLY)

enum {
    REGDMN_MODE_11A              = 0x00001,      /* 11a channels */
    REGDMN_MODE_TURBO            = 0x00002,      /* 11a turbo-only channels */
    REGDMN_MODE_11B              = 0x00004,      /* 11b channels */
    REGDMN_MODE_PUREG            = 0x00008,      /* 11g channels (OFDM only) */
    REGDMN_MODE_11G              = 0x00008,      /* XXX historical */
    REGDMN_MODE_108G             = 0x00020,      /* 11g+Turbo channels */
    REGDMN_MODE_108A             = 0x00040,      /* 11a+Turbo channels */
    REGDMN_MODE_XR               = 0x00100,      /* XR channels */
    REGDMN_MODE_11A_HALF_RATE    = 0x00200,      /* 11A half rate channels */
    REGDMN_MODE_11A_QUARTER_RATE = 0x00400,      /* 11A quarter rate channels */
    REGDMN_MODE_11NG_HT20        = 0x00800,      /* 11N-G HT20 channels */
    REGDMN_MODE_11NA_HT20        = 0x01000,      /* 11N-A HT20 channels */
    REGDMN_MODE_11NG_HT40PLUS    = 0x02000,      /* 11N-G HT40 + channels */
    REGDMN_MODE_11NG_HT40MINUS   = 0x04000,      /* 11N-G HT40 - channels */
    REGDMN_MODE_11NA_HT40PLUS    = 0x08000,      /* 11N-A HT40 + channels */
    REGDMN_MODE_11NA_HT40MINUS   = 0x10000,      /* 11N-A HT40 - channels */
    REGDMN_MODE_11AC_VHT20       = 0x20000,      /* 5Ghz, VHT20 */
    REGDMN_MODE_11AC_VHT40PLUS   = 0x40000,      /* 5Ghz, VHT40 + channels */
    REGDMN_MODE_11AC_VHT40MINUS  = 0x80000,      /* 5Ghz  VHT40 - channels */
    REGDMN_MODE_11AC_VHT80       = 0x100000,     /* 5Ghz, VHT80 channels */
    REGDMN_MODE_11AC_VHT20_2G    = 0x200000,     /* 2Ghz, VHT20 */
    REGDMN_MODE_11AC_VHT40_2G    = 0x400000,     /* 2Ghz, VHT40 */
    REGDMN_MODE_11AC_VHT80_2G    = 0x800000,     /* 2Ghz, VHT80 */
};

#define REGDMN_MODE_ALL       (0xFFFFFFFF)       /* REGDMN_MODE_ALL is defined out of the enum
						  * to prevent the ARM compile "warning #66:
						  * enumeration value is out of int range"
						  * Anyway, this is a BIT-OR of all possible values.
						  */

#define REGDMN_CAP1_CHAN_HALF_RATE        0x00000001
#define REGDMN_CAP1_CHAN_QUARTER_RATE     0x00000002
#define REGDMN_CAP1_CHAN_HAL49GHZ         0x00000004


/* regulatory capabilities */
#define REGDMN_EEPROM_EEREGCAP_EN_FCC_MIDBAND   0x0040
#define REGDMN_EEPROM_EEREGCAP_EN_KK_U1_EVEN    0x0080
#define REGDMN_EEPROM_EEREGCAP_EN_KK_U2         0x0100
#define REGDMN_EEPROM_EEREGCAP_EN_KK_MIDBAND    0x0200
#define REGDMN_EEPROM_EEREGCAP_EN_KK_U1_ODD     0x0400
#define REGDMN_EEPROM_EEREGCAP_EN_KK_NEW_11A    0x0800

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMI_TLVTAG_STRUC_HAL_REG_CAPABILITIES */
    A_UINT32 eeprom_rd;      //regdomain value specified in EEPROM
    A_UINT32 eeprom_rd_ext;  //regdomain 
    A_UINT32 regcap1;        // CAP1 capabilities bit map.
    A_UINT32 regcap2;        // REGDMN EEPROM CAP.
    A_UINT32 wireless_modes; // REGDMN MODE 
    A_UINT32 low_2ghz_chan;
    A_UINT32 high_2ghz_chan;
    A_UINT32 low_5ghz_chan;
    A_UINT32 high_5ghz_chan;
} HAL_REG_CAPABILITIES;

/*
 * Used to update rate-control logic with the status of the tx-completion.
 * In host-based implementation of the rate-control feature, this struture is used to 
 * create the payload for HTT message/s from target to host.
 */

typedef struct {
    A_UINT8 rateCode;
    A_UINT8 flags;
}RATE_CODE;

typedef struct {
    RATE_CODE ptx_rc; /* rate code, bw, chain mask sgi */
    A_UINT8 reserved[2];
    A_UINT32 flags;       /* Encodes information such as excessive
                             retransmission, aggregate, some info
                             from .11 frame control,
                             STBC, LDPC, (SGI and Tx Chain Mask
                             are encoded in ptx_rc->flags field),
                             AMPDU truncation (BT/time based etc.),
                             RTS/CTS attempt  */
    A_UINT32 num_enqued;  /* # of MPDUs (for non-AMPDU 1) for this rate */
    A_UINT32 num_retries; /* Total # of transmission attempt for this rate */
    A_UINT32 num_failed;  /* # of failed MPDUs in A-MPDU, 0 otherwise */
    A_UINT32 ack_rssi;    /* ACK RSSI: b'7..b'0 avg RSSI across all chain */
    A_UINT32 time_stamp ; /* ACK timestamp (helps determine age) */
    A_UINT32 is_probe;    /* Valid if probing. Else, 0 */
} RC_TX_DONE_PARAMS;


#define RC_SET_TX_DONE_INFO(_dst, _rc, _f, _nq, _nr, _nf, _rssi, _ts) \
    do {                                                              \
        (_dst).ptx_rc.rateCode = (_rc).rateCode;                      \
        (_dst).ptx_rc.flags    = (_rc).flags;                         \
        (_dst).flags           = (_f);                                \
        (_dst).num_enqued      = (_nq);                               \
        (_dst).num_retries     = (_nr);                               \
        (_dst).num_failed      = (_nf);                               \
        (_dst).ack_rssi        = (_rssi);                             \
        (_dst).time_stamp      = (_ts);                               \
    } while (0)

/* NOTE: NUM_DYN_BW and NUM_SCHED_ENTRIES cannot be changed without breaking WMI Compatibility */
#define NUM_SCHED_ENTRIES           2
#define NUM_DYN_BW_MAX              4
/* Current Product only uses 20/40/80 */
#define NUM_DYN_BW                  3

#define NUM_DYN_BW_MASK             0x3

#define PROD_SCHED_BW_ENTRIES       (NUM_SCHED_ENTRIES * NUM_DYN_BW)
typedef A_UINT8 A_RATE;

#if NUM_DYN_BW  > 3
// Extend rate table module for 80+80/160 MHz first
#error "Extend rate table module for 80+80/160 MHz first"
#endif

typedef struct{
    A_UINT32    psdu_len    [NUM_DYN_BW * NUM_SCHED_ENTRIES];
    A_UINT16    flags       [NUM_DYN_BW * NUM_SCHED_ENTRIES];
    A_RATE      rix         [NUM_DYN_BW * NUM_SCHED_ENTRIES];
    A_UINT8     tpc         [NUM_DYN_BW * NUM_SCHED_ENTRIES];
    A_UINT8     num_mpdus   [NUM_DYN_BW * NUM_SCHED_ENTRIES];
    A_UINT32    antmask     [NUM_SCHED_ENTRIES];
    A_UINT32    txbf_cv_ptr;
    A_UINT16    txbf_cv_len;
    A_UINT8     tries       [NUM_SCHED_ENTRIES];
    A_UINT8     num_valid_rates;
    A_UINT8     paprd_mask;
    A_UINT8     rts_rix;
    A_UINT8     sh_pream;
    A_UINT8     min_spacing_1_4_us;
    A_UINT8     fixed_delims;
    A_UINT8     bw_in_service;
    A_RATE      probe_rix;
} RC_TX_RATE_SCHEDULE;

typedef struct{
    A_UINT16    flags       [NUM_DYN_BW * NUM_SCHED_ENTRIES];
    A_RATE      rix         [NUM_DYN_BW * NUM_SCHED_ENTRIES];
#ifdef DYN_TPC_ENABLE
    A_UINT8     tpc         [NUM_DYN_BW * NUM_SCHED_ENTRIES];
#endif
#ifdef SECTORED_ANTENNA
    A_UINT32    antmask     [NUM_SCHED_ENTRIES];
#endif
    A_UINT8     tries       [NUM_SCHED_ENTRIES];
    A_UINT8     num_valid_rates;
    A_UINT8     rts_rix;
    A_UINT8     sh_pream;
    A_UINT8     bw_in_service;
    A_RATE      probe_rix;
} RC_TX_RATE_INFO;


#define WHAL_RC_INIT_RC_MASKS(_rm) do {                                     \
        _rm[WHAL_RC_MASK_IDX_NON_HT] = A_RATEMASK_OFDM_CCK;                 \
        _rm[WHAL_RC_MASK_IDX_HT_20] = A_RATEMASK_HT_20;                     \
        _rm[WHAL_RC_MASK_IDX_HT_40] = A_RATEMASK_HT_40;                     \
        _rm[WHAL_RC_MASK_IDX_VHT_20] = A_RATEMASK_VHT_20;                   \
        _rm[WHAL_RC_MASK_IDX_VHT_40] = A_RATEMASK_VHT_40;                   \
        _rm[WHAL_RC_MASK_IDX_VHT_80] = A_RATEMASK_VHT_80;                   \
        } while (0)

/**
 * strucutre describing host memory chunk.
 */
typedef struct {
   A_UINT32   tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wlan_host_memory_chunk */
   /** id of the request that is passed up in service ready */
   A_UINT32 req_id; 
   /** the physical address the memory chunk */
   A_UINT32 ptr; 
   /** size of the chunk */
   A_UINT32 size;
} wlan_host_memory_chunk;

#define NUM_UNITS_IS_NUM_VDEVS   0x1
#define NUM_UNITS_IS_NUM_PEERS   0x2

/**
 * structure used by FW for requesting host memory 
 */
typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMI_TLVTAG_STRUC_wlan_host_mem_req */

    /** ID of the request */
    A_UINT32    req_id;
    /** size of the  of each unit */
    A_UINT32    unit_size;
    /**
     * flags to  indicate that
     * the number units is dependent
     * on number of resources(num vdevs num peers .. etc)
     */
    A_UINT32    num_unit_info;
    /*
     * actual number of units to allocate . if flags in the num_unit_info
     * indicate that number of units is tied to number of a particular
     * resource to allocate then  num_units filed is set to 0 and host
     * will derive the number units from number of the resources it is
     * requesting.
     */
    A_UINT32    num_units;
} wlan_host_mem_req;


typedef enum {
    IGNORE_DTIM = 0x01,
    NORMAL_DTIM = 0x02,
    STICK_DTIM  = 0x03,
    AUTO_DTIM   = 0x04,
} BEACON_DTIM_POLICY;

/*
 * NB: it is important to keep all the fields in the structure dword long
 * so that it is easy to handle the statistics in BE host.
 */

struct wlan_dbg_tx_stats {
    /* Num HTT cookies queued to dispatch list */
    A_INT32 comp_queued;
    /* Num HTT cookies dispatched */
    A_INT32 comp_delivered;
    /* Num MSDU queued to WAL */
    A_INT32 msdu_enqued;
    /* Num MPDU queue to WAL */
    A_INT32 mpdu_enqued;
    /* Num MSDUs dropped by WMM limit */
    A_INT32 wmm_drop;
    /* Num Local frames queued */
    A_INT32 local_enqued;
    /* Num Local frames done */
    A_INT32 local_freed;
    /* Num queued to HW */
    A_INT32 hw_queued;
    /* Num PPDU reaped from HW */
    A_INT32 hw_reaped;
    /* Num underruns */
    A_INT32 underrun;
    /* Num PPDUs cleaned up in TX abort */
    A_INT32 tx_abort;
    /* Num MPDUs requed by SW */
    A_INT32 mpdus_requed;
    /* excessive retries */
    A_UINT32 tx_ko;
    /* data hw rate code */
    A_UINT32 data_rc;
    /* Scheduler self triggers */
    A_UINT32 self_triggers;
    /* frames dropped due to excessive sw retries */
    A_UINT32 sw_retry_failure;
    /* illegal rate phy errors  */
    A_UINT32 illgl_rate_phy_err;
    /* wal pdev continous xretry */
    A_UINT32 pdev_cont_xretry;
    /* wal pdev continous xretry */
    A_UINT32 pdev_tx_timeout;
    /* wal pdev resets  */
    A_UINT32 pdev_resets;
    /* frames dropped due to non-availability of stateless TIDs */
    A_UINT32 stateless_tid_alloc_failure;
    A_UINT32 phy_underrun;
    /* MPDU is more than txop limit */
    A_UINT32 txop_ovf;
};

struct wlan_dbg_rx_stats {
    /* Cnts any change in ring routing mid-ppdu */
    A_INT32 mid_ppdu_route_change;
    /* Total number of statuses processed */
    A_INT32 status_rcvd;
    /* Extra frags on rings 0-3 */
    A_INT32 r0_frags;
    A_INT32 r1_frags;
    A_INT32 r2_frags;
    A_INT32 r3_frags;
    /* MSDUs / MPDUs delivered to HTT */
    A_INT32 htt_msdus;
    A_INT32 htt_mpdus;
    /* MSDUs / MPDUs delivered to local stack */
    A_INT32 loc_msdus;
    A_INT32 loc_mpdus;
    /* AMSDUs that have more MSDUs than the status ring size */
    A_INT32 oversize_amsdu;
    /* Number of PHY errors */
    A_INT32 phy_errs;
    /* Number of PHY errors drops */
    A_INT32 phy_err_drop;
    /* Number of mpdu errors - FCS, MIC, ENC etc. */
    A_INT32 mpdu_errs;
};

struct wlan_dbg_peer_stats {

	A_INT32 dummy; /* REMOVE THIS ONCE REAL PEER STAT COUNTERS ARE ADDED */
};

typedef struct {
    A_UINT32 mcs[10];
    A_UINT32 sgi[10];
    A_UINT32 nss[4];
    A_UINT32 nsts;
    A_UINT32 stbc[10];
    A_UINT32 bw[3];
    A_UINT32 pream[6];
    A_UINT32 ldpc;
    A_UINT32 txbf;
    A_UINT32 mgmt_rssi;
    A_UINT32 data_rssi;
    A_UINT32 rssi_chain0;
    A_UINT32 rssi_chain1;
    A_UINT32 rssi_chain2;
} wlan_dbg_rx_rate_info_t ;

typedef struct {
    A_UINT32 mcs[10];
    A_UINT32 sgi[10];
    A_UINT32 nss[3];
    A_UINT32 stbc[10];
    A_UINT32 bw[3];
    A_UINT32 pream[4];
    A_UINT32 ldpc;
    A_UINT32 rts_cnt;
    A_UINT32 ack_rssi;
} wlan_dbg_tx_rate_info_t ;

typedef struct {
    wlan_dbg_rx_rate_info_t rx_phy_info;
    wlan_dbg_tx_rate_info_t tx_rate_info;
} wlan_dbg_rate_info_t;

/* Add functional stats in groups */

struct wlan_dbg_stats {
    struct wlan_dbg_tx_stats tx;
    struct wlan_dbg_rx_stats rx;
    struct wlan_dbg_peer_stats peer;
};

#endif /* __WLANDEFS_H__ */
