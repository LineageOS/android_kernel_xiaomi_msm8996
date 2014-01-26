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
#ifndef WLAN_QCT_WMA_H
#define WLAN_QCT_WMA_H

/*===========================================================================

               W L A N   DEVICE ADAPTATION   L A Y E R
                       E X T E R N A L  A P I


DESCRIPTION
  This file contains the external API exposed by the wlan adaptation layer for Prima
  and Volans.

  For Volans this layer is actually a thin layer that maps all WMA messages and
  functions to equivalent HAL messages and functions. The reason this layer was introduced
  was to keep the UMAC identical across Prima and Volans. This layer provides the glue
  between SME, PE , TL and HAL.

===========================================================================*/

/*===========================================================================

                      EDIT HISTORY FOR FILE


  This section contains comments describing changes made to the module.
  Notice that changes are listed in reverse chronological order.


  $Header:$ $DateTime: $ $Author: $


when        who          what, where, why
--------    ---         ----------------------------------------------
10/05/2011  haparna     Adding support for Keep Alive Feature
01/27/2011  rnair       Adding WMA support for Volans.
12/08/2010  seokyoun    Move down HAL interfaces from TL to WMA
                        for UMAC convergence btween Volans/Libra and Prima
08/25/2010  adwivedi    WMA Context and exposed API's
=========================================================================== */

#include "aniGlobal.h"
#include "wma_stub.h"

/*
 * Check the version number and find if MCC feature is supported or not
 */
#define IS_MCC_SUPPORTED 0//(WMA_IsWcnssWlanReportedVersionGreaterThanOrEqual( 0, 1, 1, 0))
#define IS_FEATURE_SUPPORTED_BY_FW(featEnumValue) 0//(!!WMA_getFwWlanFeatCaps(featEnumValue))

#ifdef WLAN_ACTIVEMODE_OFFLOAD_FEATURE
#define IS_ACTIVEMODE_OFFLOAD_FEATURE_ENABLE 0//((WMA_getFwWlanFeatCaps(WLANACTIVE_OFFLOAD)) & (WDI_getHostWlanFeatCaps(WLANACTIVE_OFFLOAD)))
#else
#define IS_ACTIVEMODE_OFFLOAD_FEATURE_ENABLE 0
#endif

/* Approximate amount of time to wait for WMA to stop WDI considering 1 pendig req too*/
#define WMA_STOP_TIMEOUT 0
#ifdef WLAN_SOFTAP_VSTA_FEATURE
#define WMA_MAX_STA    (38)
#else
#define WMA_MAX_STA    (16)
#endif
#if defined( FEATURE_WLAN_NON_INTEGRATED_SOC )
#if !defined( wmaGetGlobalSystemRole )
#define wmaGetGlobalSystemRole halGetGlobalSystemRole
#endif
#endif

/* ---------------------------------------------------------------------------
 
   RX Meta info access for Integrated SOC
   RX BD header access for NON Integrated SOC

      These MACRO are for RX frames that are on flat buffers

  ---------------------------------------------------------------------------*/

/* WMA_GET_RX_MAC_HEADER *****************************************************/
#  define WMA_GET_RX_MAC_HEADER(pRxMeta)  0

/* WMA_GET_RX_MPDUHEADER3A ****************************************************/
#  define WMA_GET_RX_MPDUHEADER3A(pRxMeta) 0

/* WMA_GET_RX_MPDU_HEADER_LEN *************************************************/
#  define WMA_GET_RX_MPDU_HEADER_LEN(pRxMeta) 0

/* WMA_GET_RX_MPDU_LEN ********************************************************/
#  define WMA_GET_RX_MPDU_LEN(pRxMeta)  0

/* WMA_GET_RX_PAYLOAD_LEN ****************************************************/
#  define WMA_GET_RX_PAYLOAD_LEN(pRxMeta)  0

/* WMA_GET_RX_MAC_RATE_IDX ***************************************************/
#  define WMA_GET_RX_MAC_RATE_IDX(pRxMeta)  0

/* WMA_GET_RX_MPDU_DATA ******************************************************/
#  define WMA_GET_RX_MPDU_DATA(pRxMeta)  0

/* WMA_GET_RX_MPDU_DATA_OFFSET ***********************************************/
// For Integrated SOC: When UMAC receive the packet. BD is already stripped off.
//                     Data offset is the MPDU header length
#  define WMA_GET_RX_MPDU_DATA_OFFSET(pRxMeta)  WMA_GET_RX_MPDU_HEADER_LEN(pRxMeta)

/* WMA_GET_RX_MPDU_HEADER_OFFSET *********************************************/
// For Integrated SOC: We UMAC receive the frame, 
//                     BD is gone and MAC header at offset 0
#  define WMA_GET_RX_MPDU_HEADER_OFFSET(pRxMeta)   0

/* WMA_GET_RX_UNKNOWN_UCAST **************************************************/
#  define WMA_GET_RX_UNKNOWN_UCAST(pRxMeta)   0

/* WMA_GET_RX_TID ************************************************************/
#  define WMA_GET_RX_TID(pRxMeta) 0//( ((WDI_DS_RxMetaInfoType *)(pRxMeta))->tid )

/* WMA_GET_RX_STAID **********************************************************/
#  define WMA_GET_RX_STAID(pRxMeta) 0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->staId)

/* WMA_GET_RX_ADDR3_IDX ******************************************************/
#  define WMA_GET_RX_ADDR3_IDX(pRxMeta) 0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->addr3Idx)

/* WMA_GET_RX_CH *************************************************************/
#  define WMA_GET_RX_CH(pRxMeta) 0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->rxChannel)

/* WMA_GET_RX_DPUSIG *********************************************************/
#  define WMA_GET_RX_DPUSIG(pRxMeta)  0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->dpuSig)

/* WMA_IS_RX_BCAST ***********************************************************/
#  define WMA_IS_RX_BCAST(pRxMeta)   0
    
/* WMA_GET_RX_FT_DONE ********************************************************/
#  define WMA_GET_RX_FT_DONE(pRxMeta) 0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->ft)

/* WMA_GET_RX_DPU_FEEDBACK **************************************************/
#  define WMA_GET_RX_DPU_FEEDBACK(pRxMeta) 0

/* WMA_GET_RX_ASF ************************************************************/
#  define WMA_GET_RX_ASF(pRxMeta) 0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->amsdu_asf)

/* WMA_GET_RX_AEF ************************************************************/
#  define WMA_GET_RX_AEF(pRxMeta) 0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->amsdu_aef)

/* WMA_GET_RX_ESF ************************************************************/
#  define WMA_GET_RX_ESF(pRxMeta)  0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->amsdu_esf)

/* WMA_GET_RX_BEACON_SENT ****************************************************/
#  define WMA_GET_RX_BEACON_SENT(pRxMeta) 0

/* WMA_GET_RX_TSF_LATER *****************************************************/
#  define WMA_GET_RX_TSF_LATER(pRxMeta) 0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->rtsf)

/* WMA_GET_RX_TYPE ***********************************************************/
#  define WMA_GET_RX_TYPE(pRxMeta) 0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->type)

/* WMA_GET_RX_SUBTYPE ********************************************************/
#  define WMA_GET_RX_SUBTYPE(pRxMeta) 0//(((WDI_DS_RxMetaInfoType*)(pRxMeta))->subtype)

/* WMA_GET_RX_TYPE_SUBTYPE ****************************************************/
#if defined( FEATURE_WLAN_INTEGRATED_SOC )
#  define WMA_GET_RX_TYPE_SUBTYPE(pRxMeta)  \
                 ((WMA_GET_RX_TYPE(pRxMeta)<<4)|WMA_GET_RX_SUBTYPE(pRxMeta))
#endif

/* WMA_GET_RX_REORDER_OPCODE : For MSDU reorder *******************************/
#if defined( FEATURE_WLAN_INTEGRATED_SOC )
#  define WMA_GET_RX_REORDER_OPCODE(pRxMeta) 0
#else
#  define WMA_GET_RX_REORDER_OPCODE(bdHd) WLANHAL_RX_BD_GET_BA_OPCODE(bdHd) 
#endif

/* WMA_GET_RX_REORDER_SLOT_IDX : For MSDU reorder ****************************/
#if defined( FEATURE_WLAN_INTEGRATED_SOC )
#  define WMA_GET_RX_REORDER_SLOT_IDX(pRxMeta) 0
#else
#  define WMA_GET_RX_REORDER_SLOT_IDX(bdHd) WLANHAL_RX_BD_GET_BA_SI(bdHd)
#endif

/* WMA_GET_RX_REORDER_FWD_IDX : For MSDU reorder *****************************/
#  define WMA_GET_RX_REORDER_FWD_IDX(pRxMeta)  0

/* WMA_GET_RX_REORDER_CUR_PKT_SEQ_NO : Fro MSDU reorder **********************/
#  define WMA_GET_RX_REORDER_CUR_PKT_SEQ_NO(pRxMeta)  0

/* WMA_IS_RX_LLC_PRESENT *****************************************************/
#  define WMA_IS_RX_LLC_PRESENT(pRxMeta)    0

#define WLANWMA_HO_IS_AN_AMPDU                    0x4000
#define WLANWMA_HO_LAST_MPDU_OF_AMPDU             0x400

/* WMA_IS_RX_AN_AMPDU ********************************************************/
#  define WMA_IS_RX_AN_AMPDU(pRxMeta)       0

/* WMA_IS_RX_LAST_MPDU *******************************************************/
#  define WMA_IS_RX_LAST_MPDU(pRxMeta)      0 

/* WMA_GET_RX_TIMESTAMP *****************************************************/
#  define WMA_GET_RX_TIMESTAMP(pRxMeta) 0

/* WMA_IS_RX_IN_SCAN *********************************************************/
#  define WMA_IS_RX_IN_SCAN(pRxMeta)  0

/* WMA_GET_RX_RSSI_DB ********************************************************/
// Volans RF
#  define WMA_RSSI_OFFSET             100
#  define WMA_GET_RSSI0_DB(rssi0)     (rssi0 - WMA_RSSI_OFFSET)
#  define WMA_GET_RSSI1_DB(rssi0)     (0 - WMA_RSSI_OFFSET)
#  define WMA_MAX_OF_TWO(val1, val2)  ( ((val1) > (val2)) ? (val1) : (val2))
#  define WMA_GET_RSSI_DB(rssi0)  \
                WMA_MAX_OF_TWO(WMA_GET_RSSI0_DB(rssi0), WMA_GET_RSSI1_DB(rssi0))
#  define WMA_GET_RX_RSSI_DB(pRxMeta) 0

/* WMA_GET_RX_SNR ************************************************************/
#  define WMA_GET_RX_SNR(pRxMeta)  0

/* WMA_IS_RX_FC **************************************************************/
// Flow control frames
/* FIXME WMA should provide the meta info which indicates FC frame 
          In the meantime, use hardcoded FALSE, since we don't support FC yet */
#  define WMA_IS_RX_FC(pRxMeta)    (((WDI_DS_RxMetaInfoType*)(pRxMeta))->fc)

/* WMA_GET_RX_FC_VALID_STA_MASK **********************************************/
#  define WMA_GET_RX_FC_VALID_STA_MASK(pRxMeta) \
                       (((WDI_DS_RxMetaInfoType*)(pRxMeta))->fcSTAValidMask)

/* WMA_GET_RX_FC_PWRSAVE_STA_MASK ********************************************/
#  define WMA_GET_RX_FC_PWRSAVE_STA_MASK(pRxMeta) \
                 (((WDI_DS_RxMetaInfoType*)(pRxMeta))->fcSTAPwrSaveStateMask)

/* WMA_GET_RX_FC_STA_THRD_IND_MASK ********************************************/
#  define WMA_GET_RX_FC_STA_THRD_IND_MASK(pRxMeta) \
                     (((WDI_DS_RxMetaInfoType*)(pRxMeta))->fcSTAThreshIndMask)

/* WMA_GET_RX_FC_FORCED_STA_TX_DISABLED_BITMAP ********************************************/
#  define WMA_GET_RX_FC_STA_TX_DISABLED_BITMAP(pRxMeta) 0

/* WMA_GET_RX_FC_STA_TXQ_LEN *************************************************/
#  define WMA_GET_RX_FC_STA_TXQ_LEN(pRxMeta, staId) \
                  (((WDI_DS_RxMetaInfoType*)(pRxMeta))->fcSTATxQLen[(staId)])

/* WMA_GET_RX_FC_STA_CUR_TXRATE **********************************************/
#  define WMA_GET_RX_FC_STA_CUR_TXRATE(pRxMeta, staId) \
                (((WDI_DS_RxMetaInfoType*)(pRxMeta))->fcSTACurTxRate[(staId)])

/* WMA_GET_RX_REPLAY_COUNT ***************************************************/
#  define WMA_GET_RX_REPLAY_COUNT(pRxMeta) 0

/* WMA_GETRSSI0 ***************************************************************/
#  define WMA_GETRSSI0(pRxMeta) 0

/* WMA_GETRSSI1 ***************************************************************/
#  define WMA_GETRSSI1(pRxMeta) 0



/* --------------------------------------------------------------------*/

uint8 WMA_IsWcnssWlanCompiledVersionGreaterThanOrEqual(uint8 major, uint8 minor, uint8 version, uint8 revision);
uint8 WMA_IsWcnssWlanReportedVersionGreaterThanOrEqual(uint8 major, uint8 minor, uint8 version, uint8 revision);


VOS_STATUS WMA_GetWcnssWlanCompiledVersion(v_PVOID_t pvosGCtx,
                                           tSirVersionType *pVersion);
VOS_STATUS WMA_GetWcnssWlanReportedVersion(v_PVOID_t pvosGCtx,
                                           tSirVersionType *pVersion);
VOS_STATUS WMA_GetWcnssSoftwareVersion(v_PVOID_t pvosGCtx,
                                       tANI_U8 *pVersion,
                                       tANI_U32 versionBufferSize);
VOS_STATUS WMA_GetWcnssHardwareVersion(v_PVOID_t pvosGCtx,
                                       tANI_U8 *pVersion,
                                       tANI_U32 versionBufferSize);

tSirRetStatus uMacPostCtrlMsg(void* pSirGlobal, tSirMbMsg* pMb);


#define WMA_MAX_TXPOWER_INVALID HAL_MAX_TXPOWER_INVALID

#define WMA_APP_SETUP_NTF  SIR_HAL_APP_SETUP_NTF 
#define WMA_NIC_OPER_NTF   SIR_HAL_NIC_OPER_NTF
#define WMA_INIT_START_REQ SIR_HAL_INIT_START_REQ
#define WMA_RESET_REQ      SIR_HAL_RESET_REQ

/*
 * New Taurus related messages
 */
#define WMA_ADD_STA_REQ                SIR_HAL_ADD_STA_REQ
#define WMA_ADD_STA_RSP                SIR_HAL_ADD_STA_RSP
#define WMA_ADD_STA_SELF_RSP           SIR_HAL_ADD_STA_SELF_RSP
#define WMA_DEL_STA_SELF_RSP           SIR_HAL_DEL_STA_SELF_RSP
#define WMA_DELETE_STA_REQ             SIR_HAL_DELETE_STA_REQ 
#define WMA_DELETE_STA_RSP             SIR_HAL_DELETE_STA_RSP
#define WMA_ADD_BSS_REQ                SIR_HAL_ADD_BSS_REQ
#define WMA_ADD_BSS_RSP                SIR_HAL_ADD_BSS_RSP
#define WMA_DELETE_BSS_REQ             SIR_HAL_DELETE_BSS_REQ
#define WMA_DELETE_BSS_RSP             SIR_HAL_DELETE_BSS_RSP
#define WMA_SEND_BEACON_REQ            SIR_HAL_SEND_BEACON_REQ
#define WMA_SEND_BEACON_RSP            SIR_HAL_SEND_BEACON_RSP

#define WMA_INIT_CFG_REQ               SIR_HAL_INIT_CFG_REQ
#define WMA_INIT_CFG_RSP               SIR_HAL_INIT_CFG_RSP

#define WMA_INIT_WM_CFG_REQ            SIR_HAL_INIT_WM_CFG_REQ
#define WMA_INIT_WM_CFG_RSP            SIR_HAL_INIT_WM_CFG_RSP

#define WMA_SET_BSSKEY_REQ             SIR_HAL_SET_BSSKEY_REQ
#define WMA_SET_BSSKEY_RSP             SIR_HAL_SET_BSSKEY_RSP
#define WMA_SET_STAKEY_REQ             SIR_HAL_SET_STAKEY_REQ
#define WMA_SET_STAKEY_RSP             SIR_HAL_SET_STAKEY_RSP
#define WMA_DPU_STATS_REQ              SIR_HAL_DPU_STATS_REQ 
#define WMA_DPU_STATS_RSP              SIR_HAL_DPU_STATS_RSP
#define WMA_GET_DPUINFO_REQ            SIR_HAL_GET_DPUINFO_REQ
#define WMA_GET_DPUINFO_RSP            SIR_HAL_GET_DPUINFO_RSP

#define WMA_UPDATE_EDCA_PROFILE_IND    SIR_HAL_UPDATE_EDCA_PROFILE_IND

#define WMA_UPDATE_STARATEINFO_REQ     SIR_HAL_UPDATE_STARATEINFO_REQ
#define WMA_UPDATE_STARATEINFO_RSP     SIR_HAL_UPDATE_STARATEINFO_RSP

#define WMA_UPDATE_BEACON_IND          SIR_HAL_UPDATE_BEACON_IND
#define WMA_UPDATE_CF_IND              SIR_HAL_UPDATE_CF_IND
#define WMA_CHNL_SWITCH_REQ            SIR_HAL_CHNL_SWITCH_REQ
#define WMA_ADD_TS_REQ                 SIR_HAL_ADD_TS_REQ
#define WMA_DEL_TS_REQ                 SIR_HAL_DEL_TS_REQ
#define WMA_SOFTMAC_TXSTAT_REPORT      SIR_HAL_SOFTMAC_TXSTAT_REPORT

#define WMA_MBOX_SENDMSG_COMPLETE_IND  SIR_HAL_MBOX_SENDMSG_COMPLETE_IND
#define WMA_EXIT_BMPS_REQ              SIR_HAL_EXIT_BMPS_REQ
#define WMA_EXIT_BMPS_RSP              SIR_HAL_EXIT_BMPS_RSP
#define WMA_EXIT_BMPS_IND              SIR_HAL_EXIT_BMPS_IND 
#define WMA_ENTER_BMPS_REQ             SIR_HAL_ENTER_BMPS_REQ
#define WMA_ENTER_BMPS_RSP             SIR_HAL_ENTER_BMPS_RSP
#define WMA_BMPS_STATUS_IND            SIR_HAL_BMPS_STATUS_IND
#define WMA_MISSED_BEACON_IND          SIR_HAL_MISSED_BEACON_IND

#define WMA_CFG_RXP_FILTER_REQ         SIR_HAL_CFG_RXP_FILTER_REQ
#define WMA_CFG_RXP_FILTER_RSP         SIR_HAL_CFG_RXP_FILTER_RSP

#define WMA_SWITCH_CHANNEL_RSP         SIR_HAL_SWITCH_CHANNEL_RSP
#define WMA_P2P_NOA_ATTR_IND           SIR_HAL_P2P_NOA_ATTR_IND
#define WMA_P2P_NOA_START_IND          SIR_HAL_P2P_NOA_START_IND
#define WMA_PWR_SAVE_CFG               SIR_HAL_PWR_SAVE_CFG

#define WMA_REGISTER_PE_CALLBACK       SIR_HAL_REGISTER_PE_CALLBACK
#define WMA_SOFTMAC_MEM_READREQUEST    SIR_HAL_SOFTMAC_MEM_READREQUEST
#define WMA_SOFTMAC_MEM_WRITEREQUEST   SIR_HAL_SOFTMAC_MEM_WRITEREQUEST

#define WMA_SOFTMAC_MEM_READRESPONSE   SIR_HAL_SOFTMAC_MEM_READRESPONSE
#define WMA_SOFTMAC_BULKREGWRITE_CONFIRM      SIR_HAL_SOFTMAC_BULKREGWRITE_CONFIRM
#define WMA_SOFTMAC_BULKREGREAD_RESPONSE      SIR_HAL_SOFTMAC_BULKREGREAD_RESPONSE
#define WMA_SOFTMAC_HOSTMESG_MSGPROCESSRESULT SIR_HAL_SOFTMAC_HOSTMESG_MSGPROCESSRESULT

#define WMA_ADDBA_REQ                  SIR_HAL_ADDBA_REQ 
#define WMA_ADDBA_RSP                  SIR_HAL_ADDBA_RSP
#define WMA_DELBA_IND                  SIR_HAL_DELBA_IND
#define WMA_DEL_BA_IND                 SIR_HAL_DEL_BA_IND
#define WMA_MIC_FAILURE_IND            SIR_HAL_MIC_FAILURE_IND

//message from sme to initiate delete block ack session.
#define WMA_DELBA_REQ                  SIR_HAL_DELBA_REQ
#define WMA_IBSS_STA_ADD               SIR_HAL_IBSS_STA_ADD
#define WMA_TIMER_ADJUST_ADAPTIVE_THRESHOLD_IND   SIR_HAL_TIMER_ADJUST_ADAPTIVE_THRESHOLD_IND
#define WMA_SET_LINK_STATE             SIR_HAL_SET_LINK_STATE
#define WMA_SET_LINK_STATE_RSP         SIR_HAL_SET_LINK_STATE_RSP
#define WMA_ENTER_IMPS_REQ             SIR_HAL_ENTER_IMPS_REQ
#define WMA_ENTER_IMPS_RSP             SIR_HAL_ENTER_IMPS_RSP
#define WMA_EXIT_IMPS_RSP              SIR_HAL_EXIT_IMPS_RSP
#define WMA_EXIT_IMPS_REQ              SIR_HAL_EXIT_IMPS_REQ
#define WMA_SOFTMAC_HOSTMESG_PS_STATUS_IND  SIR_HAL_SOFTMAC_HOSTMESG_PS_STATUS_IND  
#define WMA_POSTPONE_ENTER_IMPS_RSP    SIR_HAL_POSTPONE_ENTER_IMPS_RSP
#define WMA_STA_STAT_REQ               SIR_HAL_STA_STAT_REQ 
#define WMA_GLOBAL_STAT_REQ            SIR_HAL_GLOBAL_STAT_REQ
#define WMA_AGGR_STAT_REQ              SIR_HAL_AGGR_STAT_REQ 
#define WMA_STA_STAT_RSP               SIR_HAL_STA_STAT_RSP
#define WMA_GLOBAL_STAT_RSP            SIR_HAL_GLOBAL_STAT_RSP
#define WMA_AGGR_STAT_RSP              SIR_HAL_AGGR_STAT_RSP
#define WMA_STAT_SUMM_REQ              SIR_HAL_STAT_SUMM_REQ
#define WMA_STAT_SUMM_RSP              SIR_HAL_STAT_SUMM_RSP
#define WMA_REMOVE_BSSKEY_REQ          SIR_HAL_REMOVE_BSSKEY_REQ
#define WMA_REMOVE_BSSKEY_RSP          SIR_HAL_REMOVE_BSSKEY_RSP
#define WMA_REMOVE_STAKEY_REQ          SIR_HAL_REMOVE_STAKEY_REQ
#define WMA_REMOVE_STAKEY_RSP          SIR_HAL_REMOVE_STAKEY_RSP
#define WMA_SET_STA_BCASTKEY_REQ       SIR_HAL_SET_STA_BCASTKEY_REQ 
#define WMA_SET_STA_BCASTKEY_RSP       SIR_HAL_SET_STA_BCASTKEY_RSP
#define WMA_REMOVE_STA_BCASTKEY_REQ    SIR_HAL_REMOVE_STA_BCASTKEY_REQ
#define WMA_REMOVE_STA_BCASTKEY_RSP    SIR_HAL_REMOVE_STA_BCASTKEY_RSP
#define WMA_ADD_TS_RSP                 SIR_HAL_ADD_TS_RSP
#define WMA_DPU_MIC_ERROR              SIR_HAL_DPU_MIC_ERROR
#define WMA_TIMER_BA_ACTIVITY_REQ      SIR_HAL_TIMER_BA_ACTIVITY_REQ
#define WMA_TIMER_CHIP_MONITOR_TIMEOUT SIR_HAL_TIMER_CHIP_MONITOR_TIMEOUT
#define WMA_TIMER_TRAFFIC_ACTIVITY_REQ SIR_HAL_TIMER_TRAFFIC_ACTIVITY_REQ
#define WMA_TIMER_ADC_RSSI_STATS       SIR_HAL_TIMER_ADC_RSSI_STATS
#define WMA_TIMER_TRAFFIC_STATS_IND    SIR_HAL_TRAFFIC_STATS_IND

#ifdef FEATURE_WLAN_CCX
#define WMA_TSM_STATS_REQ              SIR_HAL_TSM_STATS_REQ
#define WMA_TSM_STATS_RSP              SIR_HAL_TSM_STATS_RSP
#endif
#define WMA_UPDATE_PROBE_RSP_IE_BITMAP_IND SIR_HAL_UPDATE_PROBE_RSP_IE_BITMAP_IND
#define WMA_UPDATE_UAPSD_IND           SIR_HAL_UPDATE_UAPSD_IND

#define WMA_SET_MIMOPS_REQ                      SIR_HAL_SET_MIMOPS_REQ 
#define WMA_SET_MIMOPS_RSP                      SIR_HAL_SET_MIMOPS_RSP
#define WMA_SYS_READY_IND                       SIR_HAL_SYS_READY_IND
#define WMA_SET_TX_POWER_REQ                    SIR_HAL_SET_TX_POWER_REQ
#define WMA_SET_TX_POWER_RSP                    SIR_HAL_SET_TX_POWER_RSP
#define WMA_GET_TX_POWER_REQ                    SIR_HAL_GET_TX_POWER_REQ
#define WMA_GET_TX_POWER_RSP                    SIR_HAL_GET_TX_POWER_RSP
#define WMA_GET_NOISE_REQ                       SIR_HAL_GET_NOISE_REQ 
#define WMA_GET_NOISE_RSP                       SIR_HAL_GET_NOISE_RSP
#define WMA_SET_TX_PER_TRACKING_REQ    SIR_HAL_SET_TX_PER_TRACKING_REQ

/* Messages to support transmit_halt and transmit_resume */
#define WMA_TRANSMISSION_CONTROL_IND            SIR_HAL_TRANSMISSION_CONTROL_IND
/* Indication from LIM to HAL to Initialize radar interrupt */
#define WMA_INIT_RADAR_IND                      SIR_HAL_INIT_RADAR_IND
/* Messages to support transmit_halt and transmit_resume */


#define WMA_BEACON_PRE_IND             SIR_HAL_BEACON_PRE_IND
#define WMA_ENTER_UAPSD_REQ            SIR_HAL_ENTER_UAPSD_REQ
#define WMA_ENTER_UAPSD_RSP            SIR_HAL_ENTER_UAPSD_RSP
#define WMA_EXIT_UAPSD_REQ             SIR_HAL_EXIT_UAPSD_REQ 
#define WMA_EXIT_UAPSD_RSP             SIR_HAL_EXIT_UAPSD_RSP
#define WMA_LOW_RSSI_IND               SIR_HAL_LOW_RSSI_IND 
#define WMA_BEACON_FILTER_IND          SIR_HAL_BEACON_FILTER_IND
/// PE <-> HAL WOWL messages
#define WMA_WOWL_ADD_BCAST_PTRN        SIR_HAL_WOWL_ADD_BCAST_PTRN
#define WMA_WOWL_DEL_BCAST_PTRN        SIR_HAL_WOWL_DEL_BCAST_PTRN
#define WMA_WOWL_ENTER_REQ             SIR_HAL_WOWL_ENTER_REQ
#define WMA_WOWL_ENTER_RSP             SIR_HAL_WOWL_ENTER_RSP
#define WMA_WOWL_EXIT_REQ              SIR_HAL_WOWL_EXIT_REQ
#define WMA_WOWL_EXIT_RSP              SIR_HAL_WOWL_EXIT_RSP
#define WMA_TX_COMPLETE_IND            SIR_HAL_TX_COMPLETE_IND
#define WMA_TIMER_RA_COLLECT_AND_ADAPT SIR_HAL_TIMER_RA_COLLECT_AND_ADAPT
/// PE <-> HAL statistics messages
#define WMA_GET_STATISTICS_REQ         SIR_HAL_GET_STATISTICS_REQ
#define WMA_GET_STATISTICS_RSP         SIR_HAL_GET_STATISTICS_RSP
#define WMA_SET_KEY_DONE               SIR_HAL_SET_KEY_DONE

/// PE <-> HAL BTC messages
#define WMA_BTC_SET_CFG                SIR_HAL_BTC_SET_CFG
#define WMA_SIGNAL_BT_EVENT            SIR_HAL_SIGNAL_BT_EVENT
#define WMA_HANDLE_FW_MBOX_RSP         SIR_HAL_HANDLE_FW_MBOX_RSP
#define WMA_UPDATE_PROBE_RSP_TEMPLATE_IND     SIR_HAL_UPDATE_PROBE_RSP_TEMPLATE_IND
#define WMA_SIGNAL_BTAMP_EVENT         SIR_HAL_SIGNAL_BTAMP_EVENT

#ifdef FEATURE_OEM_DATA_SUPPORT
/* PE <-> HAL OEM_DATA RELATED MESSAGES */
#define WMA_START_OEM_DATA_REQ         SIR_HAL_START_OEM_DATA_REQ 
#define WMA_START_OEM_DATA_RSP         SIR_HAL_START_OEM_DATA_RSP
#define WMA_FINISH_OEM_DATA_REQ        SIR_HAL_FINISH_OEM_DATA_REQ
#endif

#define WMA_SET_MAX_TX_POWER_REQ       SIR_HAL_SET_MAX_TX_POWER_REQ
#define WMA_SET_MAX_TX_POWER_RSP       SIR_HAL_SET_MAX_TX_POWER_RSP

#define WMA_SEND_MSG_COMPLETE          SIR_HAL_SEND_MSG_COMPLETE 

/// PE <-> HAL Host Offload message
#define WMA_SET_HOST_OFFLOAD           SIR_HAL_SET_HOST_OFFLOAD

/// PE <-> HAL Keep Alive message
#define WMA_SET_KEEP_ALIVE             SIR_HAL_SET_KEEP_ALIVE

#ifdef WLAN_NS_OFFLOAD
#define WMA_SET_NS_OFFLOAD             SIR_HAL_SET_NS_OFFLOAD
#endif //WLAN_NS_OFFLOAD
#define WMA_ADD_STA_SELF_REQ           SIR_HAL_ADD_STA_SELF_REQ
#define WMA_DEL_STA_SELF_REQ           SIR_HAL_DEL_STA_SELF_REQ

#define WMA_SET_P2P_GO_NOA_REQ         SIR_HAL_SET_P2P_GO_NOA_REQ

#define WMA_TX_COMPLETE_TIMEOUT_IND  (WMA_MSG_TYPES_END - 1)
#define WMA_WLAN_SUSPEND_IND           SIR_HAL_WLAN_SUSPEND_IND
#define WMA_WLAN_RESUME_REQ           SIR_HAL_WLAN_RESUME_REQ
#define WMA_MSG_TYPES_END    SIR_HAL_MSG_TYPES_END

#define WMA_MMH_TXMB_READY_EVT SIR_HAL_MMH_TXMB_READY_EVT     
#define WMA_MMH_RXMB_DONE_EVT  SIR_HAL_MMH_RXMB_DONE_EVT    
#define WMA_MMH_MSGQ_NE_EVT    SIR_HAL_MMH_MSGQ_NE_EVT

#ifdef WLAN_FEATURE_VOWIFI_11R
#define WMA_AGGR_QOS_REQ               SIR_HAL_AGGR_QOS_REQ
#define WMA_AGGR_QOS_RSP               SIR_HAL_AGGR_QOS_RSP
#endif /* WLAN_FEATURE_VOWIFI_11R */

/* FTM CMD MSG */
#define WMA_FTM_CMD_REQ        SIR_PTT_MSG_TYPES_BEGIN
#define WMA_FTM_CMD_RSP        SIR_PTT_MSG_TYPES_END

#ifdef FEATURE_WLAN_SCAN_PNO
/*Requests sent to lower driver*/
#define WMA_SET_PNO_REQ             SIR_HAL_SET_PNO_REQ
#define WMA_SET_RSSI_FILTER_REQ     SIR_HAL_SET_RSSI_FILTER_REQ
#define WMA_UPDATE_SCAN_PARAMS_REQ  SIR_HAL_UPDATE_SCAN_PARAMS

/*Indication comming from lower driver*/
#define WMA_SET_PNO_CHANGED_IND     SIR_HAL_SET_PNO_CHANGED_IND
#endif // FEATURE_WLAN_SCAN_PNO

#if defined(FEATURE_WLAN_CCX) && defined(FEATURE_WLAN_CCX_UPLOAD)
#define WMA_SET_PLM_REQ             SIR_HAL_SET_PLM_REQ
#endif

#ifdef WLAN_WAKEUP_EVENTS
#define WMA_WAKE_REASON_IND    SIR_HAL_WAKE_REASON_IND  
#endif // WLAN_WAKEUP_EVENTS

#ifdef WLAN_FEATURE_PACKET_FILTERING
#define WMA_8023_MULTICAST_LIST_REQ                     SIR_HAL_8023_MULTICAST_LIST_REQ
#define WMA_RECEIVE_FILTER_SET_FILTER_REQ               SIR_HAL_RECEIVE_FILTER_SET_FILTER_REQ
#define WMA_PACKET_COALESCING_FILTER_MATCH_COUNT_REQ    SIR_HAL_PACKET_COALESCING_FILTER_MATCH_COUNT_REQ
#define WMA_PACKET_COALESCING_FILTER_MATCH_COUNT_RSP    SIR_HAL_PACKET_COALESCING_FILTER_MATCH_COUNT_RSP
#define WMA_RECEIVE_FILTER_CLEAR_FILTER_REQ             SIR_HAL_RECEIVE_FILTER_CLEAR_FILTER_REQ   
#endif // WLAN_FEATURE_PACKET_FILTERING

#define WMA_SET_POWER_PARAMS_REQ   SIR_HAL_SET_POWER_PARAMS_REQ

#ifdef WLAN_FEATURE_GTK_OFFLOAD
#define WMA_GTK_OFFLOAD_REQ             SIR_HAL_GTK_OFFLOAD_REQ
#define WMA_GTK_OFFLOAD_GETINFO_REQ     SIR_HAL_GTK_OFFLOAD_GETINFO_REQ
#define WMA_GTK_OFFLOAD_GETINFO_RSP     SIR_HAL_GTK_OFFLOAD_GETINFO_RSP
#endif //WLAN_FEATURE_GTK_OFFLOAD

#define WMA_SET_TM_LEVEL_REQ       SIR_HAL_SET_TM_LEVEL_REQ

#ifdef WLAN_FEATURE_11AC
#define WMA_UPDATE_OP_MODE         SIR_HAL_UPDATE_OP_MODE
#endif

#define WMA_GET_ROAM_RSSI_REQ      SIR_HAL_GET_ROAM_RSSI_REQ
#define WMA_GET_ROAM_RSSI_RSP      SIR_HAL_GET_ROAM_RSSI_RSP

#define WMA_MSG_TYPES_BEGIN		SIR_HAL_MSG_TYPES_BEGIN
#define WMA_MAX_TXPOWER_INVALID		HAL_MAX_TXPOWER_INVALID
#define WMA_RX_SCAN_EVENT               SIR_HAL_RX_SCAN_EVENT

tSirRetStatus wmaPostCtrlMsg(tpAniSirGlobal pMac, tSirMsgQ *pMsg);

#define HAL_USE_BD_RATE2_FOR_MANAGEMENT_FRAME 0x40 // Bit 6 will be used to control BD rate for Management frames

#define halTxFrame(hHal, pFrmBuf, frmLen, frmType, txDir, tid, pCompFunc, pData, txFlag) 0
#define halTxFrameWithTxComplete(hHal, pFrmBuf, frmLen, frmType, txDir, tid, pCompFunc, pData, pCBackFnTxComp, txFlag) 0

/* -----------------------------------------------------------------
  WMA data path API's for TL
 -------------------------------------------------------------------*/

v_BOOL_t WMA_IsHwFrameTxTranslationCapable(v_PVOID_t pVosGCtx, 
                                                      tANI_U8 staIdx);

#  define WMA_EnableUapsdAcParams(vosGCtx, staId, uapsdInfo) \
         WMA_SetUapsdAcParamsReq(vosGCtx, staId, uapsdInfo)

#  define WMA_DisableUapsdAcParams(vosGCtx, staId, ac) \
          WMA_ClearUapsdAcParamsReq(vosGCtx, staId, ac)

#  define WMA_SetRSSIThresholds(pMac, pThresholds) \
         WMA_SetRSSIThresholdsReq(pMac, pThresholds)

#define WMA_UpdateRssiBmps(pvosGCtx,  staId, rssi) \
//        wlan_txrx_update_rssi_bmps(pvosGCtx, staId, rssi)
#endif
