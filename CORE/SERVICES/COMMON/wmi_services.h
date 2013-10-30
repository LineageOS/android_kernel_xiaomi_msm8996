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
 * This file defines WMI services bitmap and the set of WMI services .
 * defines macrso to set/clear/get different service bits from the bitmap.
 * the service bitmap is sent up to the host via WMI_READY command.
 *
 */

#ifndef _WMI_SERVICES_H_
#define _WMI_SERVICES_H_


#ifdef __cplusplus
extern "C" {
#endif



typedef  enum  {
    WMI_SERVICE_BEACON_OFFLOAD=0,     /* beacon offload */
    WMI_SERVICE_SCAN_OFFLOAD,         /* scan offload */
    WMI_SERVICE_ROAM_OFFLOAD,         /* roam offload */
    WMI_SERVICE_BCN_MISS_OFFLOAD,     /* beacon miss offload */
    WMI_SERVICE_STA_PWRSAVE,          /* fake sleep + basic power save */
    WMI_SERVICE_STA_ADVANCED_PWRSAVE, /* uapsd, pspoll, force sleep */
    WMI_SERVICE_AP_UAPSD,             /* uapsd on AP */
    WMI_SERVICE_AP_DFS,               /* DFS on AP */
    WMI_SERVICE_11AC,                 /* supports 11ac */
    WMI_SERVICE_BLOCKACK,             /* Supports triggering ADDBA/DELBA from host*/
    WMI_SERVICE_PHYERR,               /* PHY error */
    WMI_SERVICE_BCN_FILTER,           /* Beacon filter support */
    WMI_SERVICE_RTT,                  /* RTT (round trip time) support */
    WMI_SERVICE_WOW,                  /* WOW Support */
    WMI_SERVICE_RATECTRL_CACHE,       /* Rate-control caching */
    WMI_SERVICE_IRAM_TIDS,            /* TIDs in IRAM */
    WMI_SERVICE_ARPNS_OFFLOAD,        /* ARP NS Offload support */
    WMI_SERVICE_NLO,                  /* Network list offload service */
    WMI_SERVICE_GTK_OFFLOAD,          /* GTK offload */
    WMI_SERVICE_SCAN_SCH,             /* Scan Scheduler Service */
    WMI_SERVICE_CSA_OFFLOAD,          /* CSA offload service */
    WMI_SERVICE_CHATTER,              /* Chatter service */
    WMI_SERVICE_COEX_FREQAVOID,       /* FW report freq range to avoid */
    WMI_SERVICE_PACKET_POWER_SAVE,    /* packet power save service */
    WMI_SERVICE_FORCE_FW_HANG,        /* Service to test the firmware recovery mechanism */
    WMI_SERVICE_GPIO,                 /* GPIO service */
    WMI_SERVICE_STA_DTIM_PS_MODULATED_DTIM, /* Modulated DTIM support */
    WMI_STA_UAPSD_BASIC_AUTO_TRIG,          /* Basic version of station UAPSD AC Trigger Generation Method with
                                             * variable tigger periods (service, delay, and suspend intervals) */
    WMI_STA_UAPSD_VAR_AUTO_TRIG,            /* Station UAPSD AC Trigger Generation Method with variable
                                             * trigger periods (service, delay, and suspend intervals) */
    WMI_SERVICE_STA_KEEP_ALIVE,              /* Serivce to support the STA KEEP ALIVE mechanism */
    WMI_SERVICE_TX_ENCAP,             /* Packet type for TX encapsulation */
    WMI_SERVICE_AP_PS_DETECT_OUT_OF_SYNC, /* detect out-of-sync sleeping stations */
    WMI_SERVICE_EARLY_RX,             /* adaptive early-rx feature */
    WMI_SERVICE_STA_SMPS, /* STA MIMO-PS */
    WMI_SERVICE_FWTEST,               /* Firmware test service */
    WMI_SERVICE_STA_WMMAC, /* STA WMMAC */
    WMI_SERVICE_TDLS,                   /* TDLS support */
    WMI_SERVICE_BURST,                /* SIFS spaced burst support */
    WMI_SERVICE_MCC_BCN_INTERVAL_CHANGE,    /* Dynamic beaocn interval change for SAP/P2p GO in MCC scenario */
    WMI_SERVICE_ADAPTIVE_OCS,    /* Service to support adaptive off-channel scheduler */
    WMI_SERVICE_BA_SSN_SUPPORT,    /* target will provide Sequence number for the peer/tid combo */
    WMI_MAX_SERVICE=64                /* max service */
} WMI_SERVICE;

#define WMI_SERVICE_BM_SIZE   ((WMI_MAX_SERVICE + sizeof(A_UINT32)- 1)/sizeof(A_UINT32))


/*
 * turn on the WMI service bit corresponding to  the WMI service.
 */
#define WMI_SERVICE_ENABLE(pwmi_svc_bmap,svc_id) \
    ( (pwmi_svc_bmap)[(svc_id)/(sizeof(A_UINT32))] |= \
         (1 << ((svc_id)%(sizeof(A_UINT32)))) )

#define WMI_SERVICE_DISABLE(pwmi_svc_bmap,svc_id) \
    ( (pwmi_svc_bmap)[(svc_id)/(sizeof(A_UINT32))] &=  \
      ( ~(1 << ((svc_id)%(sizeof(A_UINT32)))) ) )

#define WMI_SERVICE_IS_ENABLED(pwmi_svc_bmap,svc_id) \
    ( ((pwmi_svc_bmap)[(svc_id)/(sizeof(A_UINT32))] &  \
       (1 << ((svc_id)%(sizeof(A_UINT32)))) ) != 0)

#ifdef __cplusplus
}
#endif

#endif /*_WMI_SERVICES_H_*/
