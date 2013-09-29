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

#include <wlan_qct_tl.h>

VOS_STATUS
WLANTL_Open
(
  v_PVOID_t               pvosGCtx,
  WLANTL_ConfigInfoType*  pTLConfig
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_Start
(
  v_PVOID_t  pvosGCtx
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_Stop
(
  v_PVOID_t  pvosGCtx
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_Close
(
  v_PVOID_t  pvosGCtx
)
{
	return VOS_STATUS_SUCCESS;
}


/*----------------------------------------------------------------------------
    INTERACTION WITH HDD
 ---------------------------------------------------------------------------*/
VOS_STATUS
WLANTL_RegisterSTAClient
(
  v_PVOID_t                 pvosGCtx,
  WLANTL_STARxCBType        pfnSTARx,
  WLANTL_TxCompCBType       pfnSTATxComp,
  WLANTL_STAFetchPktCBType  pfnSTAFetchPkt,
  WLAN_STADescType*         wSTADescType ,
  v_S7_t                    rssi
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_ClearSTAClient
(
  v_PVOID_t        pvosGCtx,
  v_U8_t           ucSTAId
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_ChangeSTAState
(
  v_PVOID_t             pvosGCtx,
  v_U8_t                ucSTAId,
  WLANTL_STAStateType   tlSTAState
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_STAPtkInstalled
(
  v_PVOID_t             pvosGCtx,
  v_U8_t                ucSTAId
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_STAPktPending
(
  v_PVOID_t            pvosGCtx,
  v_U8_t               ucSTAId,
  WLANTL_ACEnumType    ucAc
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_SetSTAPriority
(
  v_PVOID_t                pvosGCtx,
  v_U8_t                   ucSTAId,
  WLANTL_STAPriorityType   tlSTAPri
)
{
	return VOS_STATUS_SUCCESS;
}

/*----------------------------------------------------------------------------
    INTERACTION WITH BAP
 ---------------------------------------------------------------------------*/

VOS_STATUS
WLANTL_RegisterBAPClient
(
  v_PVOID_t                   pvosGCtx,
  WLANTL_BAPRxCBType          pfnTlBAPRx,
  WLANTL_FlushOpCompCBType    pfnFlushOpCompleteCb
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_TxBAPFrm
(
  v_PVOID_t               pvosGCtx,
  vos_pkt_t*              vosDataBuff,
  WLANTL_MetaInfoType*    pMetaInfo,
  WLANTL_TxCompCBType     pfnTlBAPTxComp
)
{
	return VOS_STATUS_SUCCESS;
}


/*----------------------------------------------------------------------------
    INTERACTION WITH SME
 ---------------------------------------------------------------------------*/

VOS_STATUS
WLANTL_GetRssi
(
  v_PVOID_t             pvosGCtx,
  v_U8_t                ucSTAId,
  v_S7_t*               puRssi
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_RegisterMgmtFrmClient
(
  v_PVOID_t               pvosGCtx,
  WLANTL_MgmtFrmRxCBType  pfnTlMgmtFrmRx
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_DeRegisterMgmtFrmClient
(
  v_PVOID_t               pvosGCtx
)
{
	return VOS_STATUS_SUCCESS;
}

/*----------------------------------------------------------------------------
    INTERACTION WITH HAL
 ---------------------------------------------------------------------------*/
VOS_STATUS
WLANTL_SuspendDataTx
(
  v_PVOID_t               pvosGCtx,
  v_U8_t*                 ucSTAId,
  WLANTL_SuspendCBType    pfnSuspendTx
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_ResumeDataTx
(
  v_PVOID_t      pvosGCtx,
  v_U8_t*        pucSTAId
)
{
	return VOS_STATUS_SUCCESS;
}

/*==========================================================================
    VOSS SCHEDULER INTERACTION
  ==========================================================================*/

VOS_STATUS
WLANTL_McProcessMsg
(
  v_PVOID_t        pvosGCtx,
  vos_msg_t*       message
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_McFreeMsg
(
  v_PVOID_t        pvosGCtx,
  vos_msg_t*       message
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_TxProcessMsg
(
  v_PVOID_t        pvosGCtx,
  vos_msg_t*       message
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_TxFreeMsg
(
  v_PVOID_t        pvosGCtx,
  vos_msg_t*       message
)
{
	return VOS_STATUS_SUCCESS;
}

#if defined WLAN_FEATURE_NEIGHBOR_ROAMING
VOS_STATUS WLANTL_RegRSSIIndicationCB
(
   v_PVOID_t                       pAdapter,
   v_S7_t                          rssiValue,
   v_U8_t                          triggerEvent,
   WLANTL_RSSICrossThresholdCBType crossCBFunction,
   VOS_MODULE_ID                   moduleID,
   v_PVOID_t                       usrCtxt
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_DeregRSSIIndicationCB
(
   v_PVOID_t                       pAdapter,
   v_S7_t                          rssiValue,
   v_U8_t                          triggerEvent,
   WLANTL_RSSICrossThresholdCBType crossCBFunction,
   VOS_MODULE_ID                   moduleID
)
{
	return VOS_STATUS_SUCCESS;
}
#endif

VOS_STATUS WLANTL_GetStatistics
(
   v_PVOID_t                  pAdapter,
   WLANTL_TRANSFER_STA_TYPE  *statBuffer,
   v_U8_t                     STAid
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_GetACWeights
(
  v_PVOID_t             pvosGCtx,
  v_U8_t*               pACWeights
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS
WLANTL_SetACWeights
(
  v_PVOID_t             pvosGCtx,
  v_U8_t*               pACWeights
)
{
	return VOS_STATUS_SUCCESS;
}

VOS_STATUS WLANTL_GetSoftAPStatistics(v_PVOID_t pAdapter, WLANTL_TRANSFER_STA_TYPE *statsSum, v_BOOL_t bReset)
{
	return VOS_STATUS_SUCCESS;
}

void WLANTL_AssocFailed(v_U8_t staId)
{
}

VOS_STATUS WLANTL_Finish_ULA( void (*callbackRoutine) (void *callbackContext),
                              void *callbackContext)
{
	return VOS_STATUS_SUCCESS;
}

void WLANTL_UpdateRssiBmps(v_PVOID_t pvosGCtx, v_U8_t staId, v_S7_t rssi)
{
}

VOS_STATUS
WLANTL_UpdateSTABssIdforIBSS
(
  v_PVOID_t             pvosGCtx,
  v_U8_t                ucSTAId,
  v_U8_t               *pBssid
)
{
	return VOS_STATUS_SUCCESS;
}

#ifdef WLANTL_DEBUG
void WLANTLPrintPktsRcvdPerRssi(v_PVOID_t pAdapter,
				v_U8_t staId,
				v_BOOL_t flush)
{
}

void WLANTLPrintPktsRcvdPerRateIdx(v_PVOID_t pAdapter,
				   v_U8_t staId,
				   v_BOOL_t flush)
{
}
#endif
