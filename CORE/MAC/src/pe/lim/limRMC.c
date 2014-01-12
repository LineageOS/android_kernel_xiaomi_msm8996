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

/*
 * This file limRMC.c contains the code
 * for processing Leader-based Protocol messages to support Reliable multicast
 *
 */
#include "wniApi.h"
#include "wniCfgSta.h"
#include "cfgApi.h"
#include "sirApi.h"
#include "schApi.h"
#include "utilsApi.h"
#include "limUtils.h"
#include "limTimerUtils.h"
#include "limSendMessages.h"
#include "limSendMessages.h"
#include "limSession.h"
#include "limSessionUtils.h"
#include "wlan_qct_wda.h"
#include "wlan_qct_tli.h"
#include "limRMC.h"

/**
 * DOC: Leader Based Protocol for Reliable Multicast
 *
 * This protocol proposes to achieve reliability in multicast transmissions
 * by having a selected multicast receiver respond with 802.11 ACKs.
 * This is designed for a peer to peer application that uses the underlying
 * IBSS network. The STAs in the IBSS network perform the following different
 * roles to support this protocol -
 *
 * 1) Multicast Transmitter:
 *      A node that delivers MCAST packets to every nodes and performs Reliable
 *      Multicast algorithm as a transmitter.
 * 2) Multicast Receiver:
 *      All nodes that receive MCAST packets
 * 3) Multicast Receiver Leader:
 *      A node that receives MCAST packets and performs a Reliable Multicast
 *      algorithm by sending ACK to transmitter for every multicast frame
 *      received. Multicast Receiver Leader is appointed by the Multicast
 *      Transmitter.
 *
 * The implementation in this file supports the roles of both Multicast
 *  Transmitter and the Multicast Receiver Leader.
 *
 * The firmware performs the Leader Selection algorithm and provides a candidate
 * list. The implementation in this file, sends vendor specific 802.11 Action
 * frame to notify the selected Multicast leader.
 *
 * The leader sets up its data path to send 802.11 ACKs for any received
 * Multicast frames belonging to the specified Multicast Group. It then sends an
 * Action frame to the transmitter to acknowledge that it has accepted the
 * Leader role.
 *
 * On receiving an acknowledgement from the leader, the transmitter sets up its
 * data path to expect 802.11 ACKs for Multicast transmissions.
 *
 * The function limProcessRMCMessages handles messages from HDD to enable or
 * disable this protocol for a Multicast Group.  It handles 802.11 Action frame
 * receive events for this protocol.  It also responds to firmware generated
 * indications and events.
 */

#if defined WLAN_FEATURE_RELIABLE_MCAST

/*
 *  RMC utility routines
 */

/**
 * __rmcGroupHashFunction()
 *
 *FUNCTION:
 * This function is called during scan hash entry operations
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 * NA
 *
 *NOTE:
 * NA
 *
 * @param  transmitter - address of multicast transmitter
 *
 * @return Hash index
 */

static tANI_U8
__rmcGroupHashFunction(tSirMacAddr transmitter)
{
    tANI_U16 hash;

    /*
     * Generate a hash using transmitter address
     */
    hash = transmitter[0] + transmitter[1] + transmitter[2] +
            transmitter[3] + transmitter[4] + transmitter[5];

    return hash & (RMC_MCAST_GROUPS_HASH_SIZE - 1);
}

/**
 *  __rmcGroupLookupHashEntry()
 *
 *FUNCTION:
 * This function is called to lookup RMC group entries
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *  Should be called with lkRmcLock held.
 *
 *NOTE:
 * NA
 *
 * @param  groupAddr - multicast group address
 *         transmitter - address of multicast transmitter
 *         role - transmitter or leader
 *
 * @return pointer to tLimRmcGroupContext
 */

static tLimRmcGroupContext *
__rmcGroupLookupHashEntry(tpAniSirGlobal pMac, tSirMacAddr transmitter)
{
    tANI_U8 index;
    tLimRmcGroupContext *entry;

    index = __rmcGroupHashFunction(transmitter);

    /* Pick the correct hash table based on role */
    entry = pMac->rmcContext.rmcGroupRxHashTable[index];

    PELOG1(limLog(pMac, LOG1, FL("RMC: Hash Lookup:[%d] transmitter "
                         MAC_ADDRESS_STR ), index,
                         MAC_ADDR_ARRAY(transmitter));)
    while (entry)
    {
        if (vos_mem_compare(transmitter, entry->transmitter,
             sizeof(v_MACADDR_t)))
        {
            return entry;
        }

        entry = entry->next;
    }

    return NULL;
}

/**
 *  __rmcGroupInsertHashEntry()
 *
 *FUNCTION:
 * This function is called to insert RMC group entry
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *  Should be called with lkRmcLock held.
 *
 *NOTE:
 * NA
 *
 * @param  transmitter - address of multicast transmitter
 *
 * @return pointer to tLimRmcGroupContext
 */
static tLimRmcGroupContext *
__rmcGroupInsertHashEntry(tpAniSirGlobal pMac, tSirMacAddr transmitter)
{
    tANI_U8 index;
    tLimRmcGroupContext *entry;
    tLimRmcGroupContext **head;

    index = __rmcGroupHashFunction(transmitter);

    PELOG1(limLog(pMac, LOG1, FL("RMC: Hash Insert:[%d] group " MAC_ADDRESS_STR
                             " transmitter " MAC_ADDRESS_STR), index,
                             MAC_ADDR_ARRAY(mcastGroupAddr),
                             MAC_ADDR_ARRAY(transmitter));)

    head = &pMac->rmcContext.rmcGroupRxHashTable[index];

    entry = __rmcGroupLookupHashEntry(pMac, transmitter);

    if (entry)
    {
        /* If the entry exists, return it at the end */
        PELOGE(limLog(pMac, LOGE, FL("RMC: Hash Insert:"
                 MAC_ADDRESS_STR "exists"), MAC_ADDR_ARRAY(transmitter));)
    }
    else
    {
        entry = (tLimRmcGroupContext *)vos_mem_malloc(sizeof(*entry));

        PELOG1(limLog(pMac, LOG1, FL("RMC: Hash Insert:new entry %p"), entry);)

        if (entry)
        {
            vos_mem_copy(entry->transmitter, transmitter, sizeof(tSirMacAddr));
            entry->isLeader = eRMC_IS_NOT_A_LEADER;

            /* chain this entry */
            entry->next = *head;
            *head = entry;
        }
        else
        {
            PELOGE(limLog(pMac, LOGE, FL("RMC: Hash Insert:" MAC_ADDRESS_STR
                             " alloc failed"), MAC_ADDR_ARRAY(transmitter));)
        }
    }

    return entry;
}

/**
 *  __rmcGroupDeleteHashEntry()
 *
 *FUNCTION:
 * This function is called to delete a RMC group entry
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *  Should be called with lkRmcLock held.
 *
 *NOTE:
 * Make sure (for the transmitter role) that the entry is
 * not in the Pending Response queue.
 *
 * @param  transmitter - address of multicast transmitter
 *
 * @return status
 */
static tSirRetStatus
__rmcGroupDeleteHashEntry(tpAniSirGlobal pMac, tSirMacAddr transmitter)
{
    tSirRetStatus status = eSIR_FAILURE;
    tANI_U8 index;
    tLimRmcGroupContext *entry, *prev, **head;

    index = __rmcGroupHashFunction(transmitter);

    head = &pMac->rmcContext.rmcGroupRxHashTable[index];
    entry = *head;
    prev = NULL;

    while (entry)
    {
        if (vos_mem_compare(transmitter, entry->transmitter,
             sizeof(v_MACADDR_t)))
        {
            if (*head == entry)
            {
                *head = entry->next;
            }
            else
            {
                prev->next = entry->next;
            }

            PELOG1(limLog(pMac, LOG1, FL("RMC: Hash Delete: entry %p "
                         " transmitter " MAC_ADDRESS_STR), entry
                             MAC_ADDR_ARRAY(transmitter));)

            /* free the group entry */
            vos_mem_free(entry);

            status = eSIR_SUCCESS;
            break;
        }

        prev = entry;
        entry = entry->next;
    }

    return status;
}

/**
 *  __rmcGroupDeleteAllEntries()
 *
 *FUNCTION:
 * This function is called to delete all RMC group entries
 * for either transmitter or leader, depending on the parameter.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *  Should be called with lkRmcLock held.
 *
 *NOTE:
 *
 * @param  pMac
 *         role - transmitter or leader
 * @return
 */
static void
__rmcGroupDeleteAllEntries(tpAniSirGlobal pMac)
{
    tLimRmcGroupContext *entry, **head;
    int index;

    PELOG1(limLog(pMac, LOG1, FL("RMC: Hash_Delete_All"),);)

    for (index = 0; index < RMC_MCAST_GROUPS_HASH_SIZE; index++)
    {
        head = &pMac->rmcContext.rmcGroupRxHashTable[index];

        entry = *head;

        while (entry)
        {
            *head = entry->next;
            /* free the group entry */
            vos_mem_free(entry);
            entry = *head;
        }
    }
}

/* End RMC utility routines */

/**
 * \brief Send WDA_RMC_LEADER_REQ to HAL, in order
 * to request for a Multicast Leader selection.
 *
 * \sa __limPostMsgLeaderReq
 *
 * \param pMac The global tpAniSirGlobal object
 *
 * \param cmd SUGGEST leader or BECOME leader
 *
 * \param mcastGroup Multicast Group address
 *
 * \param mcastTransmitter Multicast Transmitter address

 * \return none
 *
 */
static void
__limPostMsgLeaderReq ( tpAniSirGlobal pMac,
                        tANI_U8 cmd,
                        tSirMacAddr mcastTransmitter)
{
    tSirMsgQ msg;
    tSirRmcLeaderReq *pLeaderReq;

    pLeaderReq = vos_mem_malloc(sizeof(*pLeaderReq));
    if (NULL == pLeaderReq)
    {
       limLog(pMac, LOGE, FL("AllocateMemory() failed"));
       return;
    }

    pLeaderReq->cmd = cmd;

    vos_mem_copy(pLeaderReq->mcastTransmitter, mcastTransmitter,
                 sizeof(tSirMacAddr));

    /* Initialize black list */
    vos_mem_zero(pLeaderReq->blacklist, sizeof(pLeaderReq->blacklist));

    /*
     * If there are a list of STA receivers that we do not want to be
     * considered for Leader, send it here.
     */
    if (eRMC_SUGGEST_LEADER_CMD == cmd)
    {
        /* TODO - Set the black list. */
    }

    msg.type = WDA_RMC_LEADER_REQ;
    msg.bodyptr = pLeaderReq;
    msg.bodyval = 0;

    MTRACE(macTraceMsgTx(pMac, NO_SESSION, msg.type));
    if (eSIR_SUCCESS != wdaPostCtrlMsg(pMac, &msg))
    {
        vos_mem_free(pLeaderReq);
        limLog(pMac, LOGE, FL("wdaPostCtrlMsg() failed"));
    }

    return;
}

/**
 * \brief Send WDA_RMC_UPDATE_IND to HAL, in order
 * to request for a Multicast Leader selection.
 *
 * \sa __limPostMsgUpdateInd
 *
 * \param pMac The global tpAniSirGlobal object
 *
 * \param indication Accepted or Cancelled
 *
 * \param role Leader or Transmitter
 *
 * \param mcastGroup Multicast Group address
 *
 * \param mcastTransmitter Multicast Transmitter address
 *
 * \param mcastLeader Multicast Leader address
 *
 * \return none
 *
 */
static void
__limPostMsgUpdateInd ( tpAniSirGlobal pMac,
                        tANI_U8 indication,
                        tANI_U8 role,
                        tSirMacAddr mcastTransmitter,
                        tSirMacAddr mcastLeader)
{
    tSirMsgQ msg;
    tSirRmcUpdateInd *pUpdateInd;

    pUpdateInd = vos_mem_malloc(sizeof(*pUpdateInd));
    if ( NULL == pUpdateInd )
    {
       limLog(pMac, LOGE, FL("AllocateMemory() failed"));
       return;
    }

    vos_mem_zero(pUpdateInd, sizeof(*pUpdateInd));

    pUpdateInd->indication = indication;
    pUpdateInd->role = role;

    vos_mem_copy(pUpdateInd->mcastTransmitter,
            mcastTransmitter, sizeof(tSirMacAddr));

    vos_mem_copy(pUpdateInd->mcastLeader,
            mcastLeader, sizeof(tSirMacAddr));

    msg.type = WDA_RMC_UPDATE_IND;
    msg.bodyptr = pUpdateInd;
    msg.bodyval = 0;

    MTRACE(macTraceMsgTx(pMac, NO_SESSION, msg.type));
    if (eSIR_SUCCESS != wdaPostCtrlMsg(pMac, &msg))
    {
        vos_mem_free(pUpdateInd);
        limLog(pMac, LOGE, FL("wdaPostCtrlMsg() failed"));
    }

    return;
}

static char *
__limLeaderMessageToString(eRmcMessageType msgType)
{
    switch (msgType)
    {
        default:
            return "Invalid";
        case eLIM_RMC_ENABLE_REQ:
            return "RMC_ENABLE_REQ";
        case eLIM_RMC_DISABLE_REQ:
            return "RMC_DISABLE_REQ";
        case eLIM_RMC_LEADER_SELECT_RESP:
            return "RMC_LEADER_SELECT_RESP";
        case eLIM_RMC_LEADER_PICK_NEW:
            return "RMC_LEADER_PICK_NEW";
        case eLIM_RMC_OTA_LEADER_INFORM_ACK:
            return "RMC_OTA_LEADER_INFORM_ACK";
        case eLIM_RMC_OTA_LEADER_INFORM_SELECTED:
            return "RMC_OTA_LEADER_INFORM_SELECTED";
        case eLIM_RMC_BECOME_LEADER_RESP:
            return "RMC_BECOME_LEADER_RESP";
        case eLIM_RMC_OTA_LEADER_INFORM_CANCELLED:
            return "RMC_OTA_LEADER_INFORM_CANCELLED";
    }
}

static char *
__limLeaderStateToString(eRmcLeaderState state)
{
    switch (state)
    {
        default:
            return "Invalid";
        case eRMC_IS_NOT_A_LEADER:
            return "Device Not a Leader";
        case eRMC_LEADER_PENDING:
            return "Pending firmware resp";
        case eRMC_IS_A_LEADER:
            return "Device is Leader";
    }
}

static char *
__limMcastTxStateToString(eRmcMcastTxState state)
{
    switch (state)
    {
        default:
            return "Invalid";
        case eRMC_LEADER_NOT_SELECTED:
            return "Not Selected";
        case eRMC_LEADER_ENABLE_REQUESTED:
            return "Enable Requested";
        case eRMC_LEADER_OTA_REQUEST_SENT:
            return "OTA Request Sent";
        case eRMC_LEADER_ACTIVE:
            return "Active";
    }
}

/**
 * __rmcLeaderSelectTimerHandler()
 *
 *FUNCTION:
 * This function is called upon timer expiry.
 *
 *LOGIC:  This function handles unacked LEADER_INFORM messages.
 *        If a leader fails to respond, it tries the next one in
 *        the list.  If all potential leaders are exhausted, the
 *        multicast group is removed.
 *
 *ASSUMPTIONS:
 * NA
 *
 *NOTE:
 * Only one entry is processed for every invocation if this routine.
 * This allows us to use a single timer and makes sure we do not
 * timeout a request too early.
 *
 * @param  param - Message corresponding to the timer that expired
 *
 * @return None
 */

void
__rmcLeaderSelectTimerHandler(void *pMacGlobal, tANI_U32 param)
{
    tpAniSirGlobal pMac = (tpAniSirGlobal)pMacGlobal;
    tSirMacAddr zeroMacAddr = { 0, 0, 0, 0, 0, 0 };
    tSirRetStatus status;
    tSirRMCInfo RMC;
    tpPESession psessionEntry;
    tANI_U32 cfgValue;

    /*
     * This API relies on a single active IBSS session.
     */
    psessionEntry = limIsIBSSSessionActive(pMac);
    if (NULL == psessionEntry)
    {
        PELOGE(limLog(pMac, LOGE,
             FL("RMC:__rmcLeaderSelectTimerHandler:No active IBSS"));)
        return;
    }

    if (wlan_cfgGetInt(pMac, WNI_CFG_RMC_ACTION_PERIOD_FREQUENCY,
                  &cfgValue) != eSIR_SUCCESS)
    {
        /**
         * Could not get Action Period Frequency value
         * from CFG. Log error.
         */
        limLog(pMac, LOGE, FL("could not retrieve ActionPeriodFrequency"));
    }

    cfgValue = SYS_MS_TO_TICKS(cfgValue);

    if (pMac->rmcContext.rmcTimerValInTicks != cfgValue)
    {
        limLog(pMac, LOG1, FL("RMC LeaderSelect timer value changed"));
        if (tx_timer_change(&pMac->rmcContext.gRmcLeaderSelectTimer,
                 cfgValue, 0) != TX_SUCCESS)
        {
            limLog(pMac, LOGE,
                FL("Unable to change LeaderSelect Timer val"));
        }
        pMac->rmcContext.rmcTimerValInTicks = cfgValue;
    }

    /*
     * If we are in the scanning state then we need to return
     * from this function without any further processing
     */
    if (eLIM_HAL_SCANNING_STATE == pMac->lim.gLimHalScanState)
    {
        limLog(pMac, LOG1, FL("In scanning state, can't send action frm"));
        if (tx_timer_activate(&pMac->rmcContext.gRmcLeaderSelectTimer) !=
            TX_SUCCESS)
        {
            limLog(pMac, LOGE, FL("In scanning state, "
                                  "couldn't activate RMC LeaderSelect timer"));
        }
        return;
    }

    /* Acquire RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_acquire(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
             FL("__rmcLeaderSelectTimerHandler lock acquire failed"));
        if (tx_timer_activate(&pMac->rmcContext.gRmcLeaderSelectTimer)!= TX_SUCCESS)
        {
            limLog(pMac, LOGE, FL("could not activate RMC LeaderSelect timer"));
        }
        return;
    }

    vos_mem_copy(&RMC.mcastLeader, &pMac->rmcContext.leader,
                     sizeof(tSirMacAddr));

    if (VOS_FALSE == vos_mem_compare(&zeroMacAddr,
                            &pMac->rmcContext.leader, sizeof(tSirMacAddr)))
    {
        limLog(pMac, LOG1,
               FL("RMC Periodic Leader_Select Leader " MAC_ADDRESS_STR),
                   MAC_ADDR_ARRAY(pMac->rmcContext.leader));
        /*
         * Re-arm timer
         */
        if (tx_timer_activate(&pMac->rmcContext.gRmcLeaderSelectTimer)!=
            TX_SUCCESS)
        {
            limLog(pMac, LOGE, FL("could not activate RMC Response timer"));
        }

        /* Release RMC lock */
        if (!VOS_IS_STATUS_SUCCESS
                (vos_lock_release(&pMac->rmcContext.lkRmcLock)))
        {
            limLog(pMac, LOGE,
                FL("RMC: __rmcLeaderSelectTimerHandler lock release failed"));
        }
    }
    else
    {
        limLog(pMac, LOGE,
               FL("RMC Deactivating timer because no leader was selected"));

        /* Release RMC lock */
        if (!VOS_IS_STATUS_SUCCESS
                (vos_lock_release(&pMac->rmcContext.lkRmcLock)))
        {
            limLog(pMac, LOGE,
                FL("RMC: __rmcLeaderSelectTimerHandler lock release failed"));
        }

        return;
    }

    /*
     * Handle periodic transmission of Leader_Select Action frame.
     */

    RMC.dialogToken = 0;
    RMC.action = SIR_MAC_RMC_LEADER_INFORM_SELECTED;

    status = limSendRMCActionFrame(pMac,
                          SIR_MAC_RMC_MCAST_ADDRESS,
                          &RMC,
                          psessionEntry);

    if (eSIR_FAILURE == status)
    {
        PELOGE(limLog(pMac, LOGE,
         FL("RMC:__rmcLeaderSelectTimerHandler Action frame send failed"));)
    }

    return;
}

/**
 * __limProcessRMCEnableRequest()
 *
 *FUNCTION:
 * This function is called to processes eLIM_RMC_ENABLE_REQ
 * message from SME.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 * @param pMsgBuf    A pointer to the RMC message buffer
 *
 * @return None
 */
static void
__limProcessRMCEnableRequest(tpAniSirGlobal pMac, tANI_U32 *pMsgBuf)
{
    tSirSetRMCReq *setRmcReq = (tSirSetRMCReq *)pMsgBuf;
    tpPESession psessionEntry;

    if (!setRmcReq)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Enable:NULL message") );)
        return;
    }

    /*Enable RMC*/
    pMac->rmcContext.rmcEnabled = TRUE;

    /*
     * This API relies on a single active IBSS session.
     */
    psessionEntry = limIsIBSSSessionActive(pMac);
    if (NULL == psessionEntry)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC:Enable RMC request no active IBSS"));)
        pMac->rmcContext.state = eRMC_LEADER_NOT_SELECTED;
        return;
    }

    /* Send LBP_LEADER_REQ to f/w */
    __limPostMsgLeaderReq(pMac, eRMC_SUGGEST_LEADER_CMD,
                        setRmcReq->mcastTransmitter);

    pMac->rmcContext.state = eRMC_LEADER_ENABLE_REQUESTED;
}

/**
 * __limProcessRMCDisableRequest()
 *
 *FUNCTION:
 * This function is called to processes eLIM_RMC_DISABLE_REQ
 * message from SME.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 * @param pMsgBuf    A pointer to the RMC message buffer
 *
 * @return None
 */
static void
__limProcessRMCDisableRequest(tpAniSirGlobal pMac, tANI_U32 *pMsgBuf)
{
    tpPESession psessionEntry;
    tSirRMCInfo RMC;
    tSirSetRMCReq *setRmcReq = (tSirSetRMCReq *)pMsgBuf;
    tSirRetStatus status;
    v_PVOID_t pvosGCtx;
    VOS_STATUS vos_status;
    v_MACADDR_t vosMcastTransmitter;

    /*Disable RMC*/
    pMac->rmcContext.rmcEnabled = FALSE;

    /*
     * This API relies on a single active IBSS session.
     */
    psessionEntry = limIsIBSSSessionActive(pMac);
    if (NULL == psessionEntry)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Disable:No active IBSS"));)
        return;
    }

    if (!setRmcReq)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Disable:NULL message") );)
        return;
    }

    /* Cancel pending timer */
    tx_timer_deactivate(&pMac->rmcContext.gRmcLeaderSelectTimer);

    vosMcastTransmitter.bytes[0] = psessionEntry->selfMacAddr[0];
    vosMcastTransmitter.bytes[1] = psessionEntry->selfMacAddr[1];
    vosMcastTransmitter.bytes[2] = psessionEntry->selfMacAddr[2];
    vosMcastTransmitter.bytes[3] = psessionEntry->selfMacAddr[3];
    vosMcastTransmitter.bytes[4] = psessionEntry->selfMacAddr[4];
    vosMcastTransmitter.bytes[5] = psessionEntry->selfMacAddr[5];

    /* Disable RMC in TL */
    pvosGCtx = vos_get_global_context(VOS_MODULE_ID_PE, (v_VOID_t *) pMac);
    vos_status = WLANTL_DisableReliableMcast(pvosGCtx, &vosMcastTransmitter);

    if (VOS_STATUS_SUCCESS != vos_status)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC:Disable: TL disable failed"));)
    }

    if (pMac->rmcContext.state == eRMC_LEADER_ACTIVE)
    {
        /*
         * Send Leader_Inform_Cancelled Action frame to the Leader.
         */
        RMC.dialogToken = 0;
        RMC.action = SIR_MAC_RMC_LEADER_INFORM_CANCELLED;
        vos_mem_copy(&RMC.mcastLeader, &pMac->rmcContext.leader, sizeof(tSirMacAddr));

        status = limSendRMCActionFrame(pMac, pMac->rmcContext.leader,
                             &RMC, psessionEntry);
        if (eSIR_FAILURE == status)
        {
            PELOGE(limLog(pMac, LOGE, FL("RMC:Disable: Action frame send failed"));)
        }

        pMac->rmcContext.state = eRMC_LEADER_NOT_SELECTED;
    }

    /* send LBP_UPDATE_IND */
    __limPostMsgUpdateInd(pMac, eRMC_LEADER_CANCELLED, eRMC_TRANSMITTER_ROLE,
                         setRmcReq->mcastTransmitter, pMac->rmcContext.leader);

    vos_mem_zero(pMac->rmcContext.leader, sizeof(tSirMacAddr));

}

/**
 * __limProcessRMCLeaderSelectResponse()
 *
 *FUNCTION:
 * This function is called to processes eLIM_RMC_LEADER_SELECT_RESP
 * message from the firmware.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 * @param pMsgBuf    A pointer to the RMC message buffer
 *
 * @return None
 */
static void
__limProcessRMCLeaderSelectResponse(tpAniSirGlobal pMac, tANI_U32 *pMsgBuf)
{
    tSirRmcLeaderSelectInd *pRmcLeaderSelectInd;
    tpPESession psessionEntry;
    tSirRetStatus status;
    v_PVOID_t pvosGCtx;
    VOS_STATUS vos_status;
    v_MACADDR_t vosMcastTransmitter;
    tSirRMCInfo RMC;

    if (NULL == pMsgBuf)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Leader_Select_Resp:NULL message"));)
        return;
    }

    /*
     * This API relies on a single active IBSS session.
     */
    psessionEntry = limIsIBSSSessionActive(pMac);
    if (NULL == psessionEntry)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC:Leader_Select_Resp:No active IBSS"));)
        pMac->rmcContext.state = eRMC_LEADER_NOT_SELECTED;
        return;
    }

    pRmcLeaderSelectInd = (tSirRmcLeaderSelectInd *)pMsgBuf;

    if (pMac->rmcContext.state != eRMC_LEADER_ENABLE_REQUESTED)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Leader_Select_Resp:Bad state %s"),
                        __limMcastTxStateToString(pMac->rmcContext.state) );)
        return;
    }

    if (pRmcLeaderSelectInd->status)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC:Leader_Select_Resp:FW Status %d"),
                        pRmcLeaderSelectInd->status);)
        pMac->rmcContext.state = eRMC_LEADER_NOT_SELECTED;
        return;
    }

    /* Acquire RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_acquire(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE, FL("RMC:Leader_Select_Resp:lock acquire failed"));
        pMac->rmcContext.state = eRMC_LEADER_NOT_SELECTED;
        return;
    }

    /* Cache the current leader */
    vos_mem_copy(&pMac->rmcContext.leader, &pRmcLeaderSelectInd->leader[0],
                 sizeof(tSirMacAddr));

    /* Release RMC lock */
    if (!VOS_IS_STATUS_SUCCESS
            (vos_lock_release(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE, FL("RMC: Leader_Select_Resp: lock release failed"));
    }

    RMC.dialogToken = 0;
    RMC.action = SIR_MAC_RMC_LEADER_INFORM_SELECTED;
    vos_mem_copy(&RMC.mcastLeader, &pRmcLeaderSelectInd->leader[0],
                 sizeof(tSirMacAddr));

    PELOG1(limLog(pMac, LOG1, FL("RMC: Leader_Select :leader " MAC_ADDRESS_STR),
             MAC_ADDR_ARRAY(pRmcLeaderSelectInd->leader[0]));)

    /*
     * Send Leader_Inform Action frame to the candidate leader.
     * Candidate leader is at leader_index.
     */
    status = limSendRMCActionFrame(pMac,
                          SIR_MAC_RMC_MCAST_ADDRESS,
                          &RMC,
                          psessionEntry);

    if (eSIR_FAILURE == status)
    {
        PELOGE(limLog(pMac, LOGE,
         FL("RMC: Leader_Select_Resp: Action send failed"));)
    }

    /* send LBP_UPDATE_IND */
    __limPostMsgUpdateInd(pMac, eRMC_LEADER_ACCEPTED, eRMC_TRANSMITTER_ROLE,
                 psessionEntry->selfMacAddr, pMac->rmcContext.leader);

    vosMcastTransmitter.bytes[0] = psessionEntry->selfMacAddr[0];
    vosMcastTransmitter.bytes[1] = psessionEntry->selfMacAddr[1];
    vosMcastTransmitter.bytes[2] = psessionEntry->selfMacAddr[2];
    vosMcastTransmitter.bytes[3] = psessionEntry->selfMacAddr[3];
    vosMcastTransmitter.bytes[4] = psessionEntry->selfMacAddr[4];
    vosMcastTransmitter.bytes[5] = psessionEntry->selfMacAddr[5];

    /* Enable TL */
    pvosGCtx = vos_get_global_context(VOS_MODULE_ID_PE, (v_VOID_t *) pMac);
    vos_status = WLANTL_EnableReliableMcast(pvosGCtx, &vosMcastTransmitter);

    /* Set leader state to Active. */
    pMac->rmcContext.state = eRMC_LEADER_ACTIVE;

    /* Start timer to send periodic Leader_Select */
    if (tx_timer_activate(&pMac->rmcContext.gRmcLeaderSelectTimer)!= TX_SUCCESS)
    {
        limLog(pMac, LOGE,
         FL("Leader_Select_Resp:Activate RMC Response timer failed"));
    }
}

/**
 * __limProcessRMCLeaderPickNew()
 *
 *FUNCTION:
 * This function is called to processes eLIM_RMC_LEADER_PICK_NEW
 * message from the firmware.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 * @param pMsgBuf    A pointer to the RMC message buffer
 *
 * @return None
 */
static void
__limProcessRMCLeaderPickNew(tpAniSirGlobal pMac, tANI_U32 *pMsgBuf)
{
    tSirRmcUpdateInd *pRmcUpdateInd;
    tpPESession psessionEntry;
    tSirRetStatus status;
    tSirRMCInfo RMC;
    v_PVOID_t pvosGCtx;
    VOS_STATUS vos_status;
    v_MACADDR_t vosMcastTransmitter;
    tSirMacAddr zeroMacAddr = { 0, 0, 0, 0, 0, 0 };

    if (NULL == pMsgBuf)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Leader_Pick_New:NULL message"));)
        return;
    }

    /*
     * This API relies on a single active IBSS session.
     */
    psessionEntry = limIsIBSSSessionActive(pMac);
    if (NULL == psessionEntry)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Leader_Pick_New:No active IBSS"));)
        return;
    }

    pvosGCtx = vos_get_global_context(VOS_MODULE_ID_PE, (v_VOID_t *) pMac);

    pRmcUpdateInd = (tSirRmcUpdateInd *)pMsgBuf;

    /* Acquire RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_acquire(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE, FL("RMC:Leader_Pick_New:lock acquire failed"));
        return;
    }


    /* Fill out Action frame parameters */
    RMC.dialogToken = 0;

    /*
     * Check the multicast Leader address sent by firmware.
     * Prepare to send Leader_Inform_Cancel only if this address
     * is valid.
     */
    if (VOS_FALSE == vos_mem_compare(&zeroMacAddr,
                        &pRmcUpdateInd->mcastLeader,
                        sizeof(tSirMacAddr)))
    {

        vos_mem_copy(&RMC.mcastLeader, &pRmcUpdateInd->mcastLeader,
                     sizeof(tSirMacAddr));

        /*
         * Send Leader_Inform_Cancelled Action frame to the current leader.
         */
        RMC.action = SIR_MAC_RMC_LEADER_INFORM_CANCELLED;
        status = limSendRMCActionFrame(pMac,
                         pRmcUpdateInd->mcastLeader,
                         &RMC, psessionEntry);
        if (eSIR_FAILURE == status)
        {
            PELOGE(limLog(pMac, LOGE,
                FL("RMC:Leader_Pick_New: Inform_Cancel Action send failed"));)
            goto done;
        }

        vosMcastTransmitter.bytes[0] = psessionEntry->selfMacAddr[0];
        vosMcastTransmitter.bytes[1] = psessionEntry->selfMacAddr[1];
        vosMcastTransmitter.bytes[2] = psessionEntry->selfMacAddr[2];
        vosMcastTransmitter.bytes[3] = psessionEntry->selfMacAddr[3];
        vosMcastTransmitter.bytes[4] = psessionEntry->selfMacAddr[4];
        vosMcastTransmitter.bytes[5] = psessionEntry->selfMacAddr[5];

        /* Disable RMC in TL */
        vos_status = WLANTL_DisableReliableMcast(pvosGCtx, &vosMcastTransmitter);

        if (VOS_STATUS_SUCCESS != vos_status)
        {
            PELOGE(limLog(pMac, LOGE,
                 FL("RMC:Leader_Pick_New: TL disable failed"));)
        }
    }

    /*
     * Cache the leader list for this multicast group
     * If no leader list was given, this will essentially zero out
     * the list.
     */
    vos_mem_copy(pMac->rmcContext.leader, pRmcUpdateInd->leader[0],
                 sizeof(tSirMacAddr));

    pMac->rmcContext.state = eRMC_LEADER_NOT_SELECTED;

    /*
     * Verify that the Pick_New indication has any candidate leaders.
     */
    if (VOS_TRUE == vos_mem_compare(&zeroMacAddr,
                        pMac->rmcContext.leader,
                        sizeof(tSirMacAddr)))
    {
        PELOGE(limLog(pMac, LOGE,
           FL("RMC:Leader_Pick_New: No candidate leaders available"));)
        goto done;
    }

    /*
     * Send Leader_Inform Action frame to the new candidate leader.
     */

    RMC.action = SIR_MAC_RMC_LEADER_INFORM_SELECTED;
    vos_mem_copy(&RMC.mcastLeader, &pMac->rmcContext.leader,
                     sizeof(tSirMacAddr));
    status = limSendRMCActionFrame(pMac, SIR_MAC_RMC_MCAST_ADDRESS,
                         &RMC, psessionEntry);
    if (eSIR_FAILURE == status)
    {
        PELOGE(limLog(pMac, LOGE,
           FL("RMC:Leader_Pick_New: Inform_Selected Action send failed"));)
        goto done;
    }

    /* send LBP_UPDATE_IND */
    __limPostMsgUpdateInd(pMac, eRMC_LEADER_ACCEPTED, eRMC_TRANSMITTER_ROLE,
                         psessionEntry->selfMacAddr, pMac->rmcContext.leader);

    vosMcastTransmitter.bytes[0] = psessionEntry->selfMacAddr[0];
    vosMcastTransmitter.bytes[1] = psessionEntry->selfMacAddr[1];
    vosMcastTransmitter.bytes[2] = psessionEntry->selfMacAddr[2];
    vosMcastTransmitter.bytes[3] = psessionEntry->selfMacAddr[3];
    vosMcastTransmitter.bytes[4] = psessionEntry->selfMacAddr[4];
    vosMcastTransmitter.bytes[5] = psessionEntry->selfMacAddr[5];

    /* Enable TL */
    vos_status = WLANTL_EnableReliableMcast(pvosGCtx, &vosMcastTransmitter);

    if (VOS_STATUS_SUCCESS != vos_status)
    {
        PELOGE(limLog(pMac, LOGE,
            FL("RMC:Leader_Pick_New: TL enable failed"));)
        goto done;
    }

    /* Set leader state to Active. */
    pMac->rmcContext.state = eRMC_LEADER_ACTIVE;

    /* Start timer to send periodic Leader_Select */
    if (tx_timer_activate(&pMac->rmcContext.gRmcLeaderSelectTimer)!= TX_SUCCESS)
    {
        limLog(pMac, LOGE,
         FL("Leader_Pick_New:Activate RMC Response timer failed"));
    }

done:
    /* Release RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_release(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
            FL("RMC: Leader_Pick_New: lock release failed"));
    }
}

/**
 * __limProcessRMCLeaderInformSelected()
 *
 *FUNCTION:
 * This function is called to processes eLIM_RMC_OTA_LEADER_INFORM_SELECTED
 * message from the "Leader Inform" Action frame from the
 * multicast transmitter.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 * @param pMsgBuf    A pointer to the RMC message buffer
 *
 * @return None
 */
static void
__limProcessRMCLeaderInformSelected(tpAniSirGlobal pMac, tANI_U32 *pMsgBuf)
{
    tpSirMacMgmtHdr pHdr;
    tANI_U8 *pFrameData;
    tANI_U32 frameLen;
    tLimRmcGroupContext *entry;
    tpPESession psessionEntry;
    tSirRetStatus status;

    if (!pMsgBuf)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Leader_Inform:NULL msg"));)
        return;
    }

    /*
     * This API relies on a single active IBSS session.
     */
    psessionEntry = limIsIBSSSessionActive(pMac);
    if (NULL == psessionEntry)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC:Become_Leader_Resp:No active IBSS"));)
        return;
    }

    /*
     * Get the frame header
     */
    pHdr = WDA_GET_RX_MAC_HEADER((tANI_U8 *)pMsgBuf);

    frameLen = WDA_GET_RX_PAYLOAD_LEN((tANI_U8 *)pMsgBuf);
    if (frameLen < sizeof(tSirMacOxygenNetworkFrameHdr))
    {
        PELOGE(limLog(pMac, LOGE,
             FL("RMC: Leader_Inform:Bad length %d "), frameLen);)
        return;
    }

    pFrameData = WDA_GET_RX_MPDU_DATA((tANI_U8 *)pMsgBuf) +
                    sizeof(tSirMacOxygenNetworkFrameHdr);

    if (!pFrameData)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Leader_Inform:NULL data"));)
        return;
    }

    /* Acquire RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_acquire(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE, FL("RMC:Become_Leader_Resp:lock acquire failed"));
        return;
    }

    /*
     * Check if this transmitter exists in our database.
     */
    entry = __rmcGroupLookupHashEntry(pMac, pHdr->sa);

    /*
     * Check if we are being advertised as the leader.
     * The leader address is from the Action frame payload.
     */
    if (VOS_FALSE == vos_mem_compare(pFrameData, psessionEntry->selfMacAddr,
                                     sizeof(tSirMacAddr)))
    {
        /*
         * If we were the leader for this transmitter, tell the firmware
         * that we are not any more.  This is a implicit Leader_Cancel.
         */
        if (entry)
        {
            PELOG1(limLog(pMac, LOG1,
                 FL("RMC: Leader_Inform: Leader Cancelled"));)
            /* send LBP_UPDATE_IND */
            __limPostMsgUpdateInd(pMac, eRMC_LEADER_CANCELLED,
                      eRMC_LEADER_ROLE, pHdr->sa, psessionEntry->selfMacAddr);

            /*
             * Delete hash entry for this Group address.
             */
            status = __rmcGroupDeleteHashEntry(pMac, pHdr->sa);
            if (eSIR_FAILURE == status)
            {
                PELOGE(limLog(pMac, LOGE,
                      FL("RMC: Leader_Inform:hash delete failed"));)
            }
        }
    }
    else
    {
        /*
         * If we have been selected as the new leader for this transmitter,
         * add it to your database.  If we are already in the database, there
         * is nothing to do.
         */
        if (NULL == entry)
        {
            /* Add the transmitter address to the hash */
            entry = __rmcGroupInsertHashEntry(pMac, pHdr->sa);
            if (entry)
            {
                if (entry->isLeader != eRMC_LEADER_PENDING)
                {
                    /* Send LBP_LEADER_REQ to f/w */
                    __limPostMsgLeaderReq(pMac, eRMC_BECOME_LEADER_CMD,
                                         pHdr->sa);
                    entry->isLeader = eRMC_LEADER_PENDING;
                }
            }
            else
            {
                PELOGE(limLog(pMac, LOGE,
                         FL("RMC: Leader_Inform:Hash insert failed"));)
            }

        }
    }

    /* Release RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_release(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
            FL("RMC: Leader_Inform: lock release failed"));
    }

}

/**
 * __limProcessRMCBecomeLeaderResp()
 *
 *FUNCTION:
 * This function is called to processes eLIM_RMC_BECOME_LEADER_RESP
 * message from the firmware.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 * @param pMsgBuf    A pointer to the RMC message buffer
 *
 * @return None
 */
static void
__limProcessRMCBecomeLeaderResp(tpAniSirGlobal pMac, tANI_U32 *pMsgBuf)
{
    tSirRmcBecomeLeaderInd *pRmcBecomeLeaderInd;
    tLimRmcGroupContext *entry;
    tSirRetStatus status = eSIR_SUCCESS;

    if (NULL == pMsgBuf)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Become_Leader_Resp:NULL message"));)
        return;
    }

    pRmcBecomeLeaderInd = (tSirRmcBecomeLeaderInd *)pMsgBuf;

    /* Acquire RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_acquire(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE, FL("RMC:Become_Leader_Resp:lock acquire failed"));
        return;
    }

    /*
     * Find the entry for this Group Address.
     */
    entry = __rmcGroupLookupHashEntry(pMac,
                  pRmcBecomeLeaderInd->mcastTransmitter);
    if (NULL == entry)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Become_Leader_Resp: No entry"));)
        goto done;
    }

    if (pRmcBecomeLeaderInd->status)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC:Become_Leader_Resp:FW Status %d"),
                        pRmcBecomeLeaderInd->status);)
        status = eSIR_FAILURE;
        goto done;
    }

    if (entry->isLeader != eRMC_LEADER_PENDING)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Become_Leader_Resp:Bad state: %s"),
                        __limLeaderStateToString(entry->isLeader) );)
        status = eSIR_FAILURE;
        goto done;
    }

    entry->isLeader = eRMC_IS_A_LEADER;

done:
    if (eSIR_FAILURE == status)
    {
        status = __rmcGroupDeleteHashEntry(pMac,
                       pRmcBecomeLeaderInd->mcastTransmitter);
        if (eSIR_FAILURE == status)
        {
            PELOGE(limLog(pMac, LOGE,
                      FL("RMC: Become_Leader_Resp:hash delete failed"));)
        }
    }

    /* Release RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_release(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
            FL("RMC: Become_Leader_Resp: lock release failed"));
    }

    return;
}

/**
 * __limProcessRMCLeaderInformCancelled()
 *
 *FUNCTION:
 * This function is called to processes eLIM_RMC_OTA_LEADER_INFORM_CANCELLED
 * message from the "Leader Inform Cancelled" Action frame from the
 * multicast transmitter.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 * @param pMsgBuf    A pointer to the RMC message buffer
 *
 * @return None
 */
static void
__limProcessRMCLeaderInformCancelled(tpAniSirGlobal pMac, tANI_U32 *pMsgBuf)
{
    tpSirMacMgmtHdr pHdr;
    tANI_U8 *pFrameData;
    tANI_U32 frameLen;
    tSirRetStatus status;
    tLimRmcGroupContext *entry;
    tpPESession psessionEntry;

    if (!pMsgBuf)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Leader_Inform_Cancel:NULL msg"));)
        return;
    }

    /*
     * This API relies on a single active IBSS session.
     */
    psessionEntry = limIsIBSSSessionActive(pMac);
    if (NULL == psessionEntry)
    {
        PELOGE(limLog(pMac, LOGE,
             FL("RMC:Leader_Inform_Cancel:No active IBSS"));)
        return;
    }

    pHdr = WDA_GET_RX_MAC_HEADER((tANI_U8 *)pMsgBuf);

    frameLen = WDA_GET_RX_PAYLOAD_LEN((tANI_U8 *)pMsgBuf);
    if (frameLen < sizeof(tSirMacOxygenNetworkFrameHdr))
    {
        PELOGE(limLog(pMac, LOGE,
             FL("RMC: Leader_Inform:Bad length %d "), frameLen);)
        return;
    }

    pFrameData = WDA_GET_RX_MPDU_DATA((tANI_U8 *)pMsgBuf) +
                    sizeof(tSirMacOxygenNetworkFrameHdr);

    if (!pFrameData)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Leader_Inform_Cancel:NULL data"));)
        return;
    }

    /* Acquire RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_acquire(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE, FL("RMC:Leader_Inform_Cancel lock acquire failed"));
        return;
    }

    /*
     * Find the entry for this Group Address.
     */
    entry = __rmcGroupLookupHashEntry(pMac, pHdr->sa);
    if (NULL == entry)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Leader_Inform_Cancel: No entry"));)
        goto done;
    }

    /* send LBP_UPDATE_END */
    __limPostMsgUpdateInd(pMac, eRMC_LEADER_CANCELLED,
                     eRMC_LEADER_ROLE, pHdr->sa, psessionEntry->selfMacAddr);

    /*
     * Delete hash entry for this Group address.
     */
    status = __rmcGroupDeleteHashEntry(pMac, pHdr->sa);
    if (eSIR_FAILURE == status)
    {
        PELOGE(limLog(pMac, LOGE,
                  FL("RMC: Leader_Inform_Cancel:hash delete failed"));)
    }

done:
    /* Release RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_release(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
            FL("RMC: Leader_Inform_Cancel: lock release failed"));
    }
    return;
}

/**
 * limProcessRMCMessages()
 *
 *FUNCTION:
 * This function is called to processes various RMC messages.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 * @param  msgType   Indicates the RMC message type
 * @param  *pMsgBuf  A pointer to the RMC message buffer
 *
 * @return None
 */
void
limProcessRMCMessages(tpAniSirGlobal pMac, eRmcMessageType msgType,
                      tANI_U32 *pMsgBuf)
{

    if (pMsgBuf == NULL)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: Buffer is Pointing to NULL"));)
        return;
    }

    limLog(pMac, LOG1, FL("RMC: limProcessRMCMessages: %s"),
                        __limLeaderMessageToString(msgType));

    switch (msgType)
    {
        /*
         * Begin - messages processed by RMC multicast transmitter.
         */
        case eLIM_RMC_ENABLE_REQ:
            __limProcessRMCEnableRequest(pMac, pMsgBuf);
            break;

        case eLIM_RMC_DISABLE_REQ:
            __limProcessRMCDisableRequest(pMac, pMsgBuf);
            break;

        case eLIM_RMC_LEADER_SELECT_RESP:
            __limProcessRMCLeaderSelectResponse(pMac, pMsgBuf);
            break;

        case eLIM_RMC_LEADER_PICK_NEW:
            __limProcessRMCLeaderPickNew(pMac, pMsgBuf);
            break;

        /*
         * End - messages processed by RMC multicast transmitter.
         */

        /*
         * Begin - messages processed by RMC Leader (receiver).
         */
        case eLIM_RMC_OTA_LEADER_INFORM_SELECTED:
            __limProcessRMCLeaderInformSelected(pMac, pMsgBuf);
            break;

        case eLIM_RMC_BECOME_LEADER_RESP:
            __limProcessRMCBecomeLeaderResp(pMac, pMsgBuf);
            break;

        case eLIM_RMC_OTA_LEADER_INFORM_CANCELLED:
            __limProcessRMCLeaderInformCancelled(pMac, pMsgBuf);
            break;

        /*
         * End - messages processed by RMC Leader (receiver).
         */

        default:
            break;
    } // switch (msgType)
    return;
} /*** end limProcessRMCMessages() ***/

/**
 * limRmcInit()
 *
 *FUNCTION:
 * This function is called to initialize RMC module.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 *
 * @return None
 */
void
limRmcInit(tpAniSirGlobal pMac)
{
    tANI_U32 cfgValue;

    if (wlan_cfgGetInt(pMac, WNI_CFG_RMC_ACTION_PERIOD_FREQUENCY,
                  &cfgValue) != eSIR_SUCCESS)
    {
        /**
         * Could not get Action Period Frequency value
         * from CFG. Log error.
         */
        limLog(pMac, LOGP, FL("could not retrieve ActionPeriodFrequency"));
    }

    cfgValue = SYS_MS_TO_TICKS(cfgValue);

    vos_mem_zero(&pMac->rmcContext, sizeof(pMac->rmcContext));

    if (!VOS_IS_STATUS_SUCCESS(vos_lock_init(&pMac->rmcContext.lkRmcLock)))
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC lock init failed!"));)
    }

    if (tx_timer_create(&pMac->rmcContext.gRmcLeaderSelectTimer,
                            "RMC RSP TIMEOUT",
                            __rmcLeaderSelectTimerHandler,
                            0 /* param */,
                            cfgValue, 0,
                            TX_NO_ACTIVATE) != TX_SUCCESS)
    {
        /*  Could not create RMC response timer. */
        limLog(pMac, LOGE, FL("could not create RMC response timer"));
    }

    pMac->rmcContext.rmcTimerValInTicks = cfgValue;
}

/**
 * limRmcCleanup()
 *
 *FUNCTION:
 * This function is called to clean up RMC module.
 *
 *LOGIC:
 *
 *ASSUMPTIONS: limRmcIbssDelete should have been called before this.
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 *
 * @return None
 */
void
limRmcCleanup(tpAniSirGlobal pMac)
{
    /* Delete all entries from Leader database. */
    limRmcIbssDelete(pMac);

    if (!VOS_IS_STATUS_SUCCESS(vos_lock_destroy(&pMac->rmcContext.lkRmcLock)))
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC lock destroy failed!"));)
    }

    tx_timer_delete(&pMac->rmcContext.gRmcLeaderSelectTimer);
}

/**
 * limRmcTransmitterDelete()
 *
 *FUNCTION:
 * This function is called on a Leader to handle deletion of the transmitter.
 * It is called when the IBSS module wants to delete a peer. If the peer
 * exists in our database, we delete the entries associated with this peer.
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 *        transmitter Address of the transmitter
 * @return None
 */
void
limRmcTransmitterDelete(tpAniSirGlobal pMac, tSirMacAddr transmitter)
{
    /* Acquire RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_acquire(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
             FL("RMC: limRMCTransmitterDelete lock acquire failed"));
        return;
    }

    /* Delete this transmitter from Leader database. */
    __rmcGroupDeleteHashEntry(pMac, transmitter);

    /* Release RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_release(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
            FL("RMC: limRMCTransmitterDelete lock release failed"));
    }

    limLog(pMac, LOG1, FL("RMC: limRmcTransmitterDelete complete"));
}

/**
 * limRmcIbssDelete()
 *
 *FUNCTION:
 * This function is called when the IBSS is being deleted for either
 * transmitter or leader STA.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 *
 * @return None
 */
void
limRmcIbssDelete(tpAniSirGlobal pMac)
{
    tpPESession psessionEntry;
    tSirMacAddr zeroMacAddr = { 0, 0, 0, 0, 0, 0 };

    /*
     * This API relies on a single active IBSS session.
     */
    psessionEntry = limIsIBSSSessionActive(pMac);
    if (NULL == psessionEntry)
    {
        PELOGE(limLog(pMac, LOGE, FL("RMC: limRmcIbssDelete:No active IBSS"));)
        return;
    }

    if (VOS_FALSE == vos_mem_compare(&zeroMacAddr,
                            &pMac->rmcContext.leader, sizeof(tSirMacAddr)))
    {
        /* send LBP_UPDATE_IND */
        __limPostMsgUpdateInd(pMac, eRMC_LEADER_CANCELLED,
                         eRMC_TRANSMITTER_ROLE, psessionEntry->selfMacAddr,
                         pMac->rmcContext.leader);
    }

    /* Acquire RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_acquire(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
             FL("RMC: limRmcIbssDelete lock acquire failed"));
        return;
    }

    /* Cancel pending timer */
    tx_timer_deactivate(&pMac->rmcContext.gRmcLeaderSelectTimer);

    /* Delete all entries from Leader database. */
    __rmcGroupDeleteAllEntries(pMac);

    /* Release RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_release(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
            FL("RMC: limRmcIbssDelete lock release failed"));
    }

    limLog(pMac, LOG1, FL("RMC: limRmcIbssDelete complete"));
}

/**
 * limRmcDumpStatus()
 *
 *FUNCTION:
 * This function is called to display RMC status for transmitter and leader.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac       Pointer to Global MAC structure
 *
 * @return char *   Pointer to buffer with RMC information.
 */
void
limRmcDumpStatus(tpAniSirGlobal pMac)
{
    tLimRmcGroupContext *entry;
    int index, count;

    /* Acquire RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_acquire(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
             FL("RMC: limRmcDumpStatus lock acquire failed"));
        return;
    }


    limLog(pMac, LOGE, FL(" ----- RMC Transmitter Information ----- \n"));
    limLog(pMac, LOGE,
         FL("   Leader Address   |  RMC State \n"));

    if (pMac->rmcContext.state != eRMC_LEADER_NOT_SELECTED)
    {
        limLog(pMac,LOGE, FL( MAC_ADDRESS_STR " | %s\n"),
                         MAC_ADDR_ARRAY(pMac->rmcContext.leader),
                        __limMcastTxStateToString(pMac->rmcContext.state));
    }

    limLog( pMac,LOGE, FL(" ----- RMC Leader Information ----- \n"));
    limLog( pMac,LOGE, FL("  Transmitter Address\n"));

    count = 0;
    for (index = 0; index < RMC_MCAST_GROUPS_HASH_SIZE; index++)
    {
        entry = pMac->rmcContext.rmcGroupRxHashTable[index];

        while (entry)
        {
            count++;
            limLog( pMac,LOGE, FL("%d. " MAC_ADDRESS_STR " \n"),
                    count, MAC_ADDR_ARRAY(entry->transmitter));
            entry = entry->next;
        }
    }

    /* Release RMC lock */
    if (!VOS_IS_STATUS_SUCCESS(vos_lock_release(&pMac->rmcContext.lkRmcLock)))
    {
        limLog(pMac, LOGE,
            FL("RMC: limRmcDumpStatus lock release failed"));
    }

    return;

}

/**
 * limRmcTriggerLeaderSelection()
 *
 *FUNCTION:
 * This function is called to RMC leader selection in FW
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param pMac      Pointer to Global MAC structure
 *
 * @param macAddr   Input mac address
 *
 * @return : VOS_STATUS_SUCCESS if RMC state machine allows leader selection and
                leader selection is triggered in FW
             VOS_STATUS_E_FAILURE if RMC state machine does not allow leader
                selection in its current state
 */
VOS_STATUS
limRmcTriggerLeaderSelection(tpAniSirGlobal pMac, tSirMacAddr macAddr)
{
    /*Trigger LBP leader selection in FW*/
    if ((TRUE == pMac->rmcContext.rmcEnabled) &&
        (eRMC_LEADER_NOT_SELECTED == pMac->rmcContext.state))
    {
        limLog(pMac, LOG1,
          FL("Leader selection trigerred in FW"));

        __limPostMsgLeaderReq(pMac, eRMC_SUGGEST_LEADER_CMD, macAddr);

        pMac->rmcContext.state = eRMC_LEADER_ENABLE_REQUESTED;

        return VOS_STATUS_SUCCESS;
    }
    else
    {
        limLog(pMac, LOG1,
          FL("Could not trigger leader selection: RMC state %d rmcEnabled %d"),
          pMac->rmcContext.state, pMac->rmcContext.rmcEnabled);

        return VOS_STATUS_E_FAILURE;
    }
}

#endif /* WLAN_FEATURE_RELIABLE_MCAST */
