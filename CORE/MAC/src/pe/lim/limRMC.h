/*
 *
 * Copyright (c) 2012, The Linux Foundation. All rights reserved.
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
 * Date:          08/15/13
 * History:-
 * Date           Modified by    Modification Information
 * --------------------------------------------------------------------
 */
#ifndef __LIM_RMC_H
#define __LIM_RMC_H

#if defined WLAN_FEATURE_RELIABLE_MCAST

typedef enum {
    eLIM_RMC_ENABLE_REQ = 0,
    eLIM_RMC_DISABLE_REQ = 1,
    eLIM_RMC_BECOME_LEADER_RESP = 2,
    eLIM_RMC_LEADER_SELECT_RESP = 3,
    eLIM_RMC_LEADER_PICK_NEW = 4,
    eLIM_RMC_OTA_LEADER_INFORM_CANCELLED = 5,
    eLIM_RMC_OTA_LEADER_INFORM_ACK = 6,
    eLIM_RMC_OTA_LEADER_INFORM_SELECTED = 7,
} eRmcMessageType;

typedef enum {
    eRMC_LEADER_NOT_SELECTED     = 0,
    eRMC_LEADER_ENABLE_REQUESTED = 1,
    eRMC_LEADER_OTA_REQUEST_SENT = 2,
    eRMC_LEADER_ACTIVE           = 3,
} eRmcMcastTxState;

typedef enum {
    eRMC_IS_NOT_A_LEADER = 0,
    eRMC_LEADER_PENDING = 1,
    eRMC_IS_A_LEADER = 2,
} eRmcLeaderState;

enum {
    eRMC_SUGGEST_LEADER_CMD = 0,
    eRMC_BECOME_LEADER_CMD  = 1,
};

/* tLbpUpdateIndType */
enum {
    eRMC_LEADER_ACCEPTED  = 0,     //Host-->FW
    eRMC_LEADER_CANCELLED = 1,     //Host-->FW
    eRMC_LEADER_PICK_NEW  = 2,     //FW-->Host
};

/* tLbpRoleType; */
typedef enum
{
    eRMC_LEADER_ROLE,
    eRMC_TRANSMITTER_ROLE,
} eRmcRole;

#define RMC_MCAST_GROUPS_HASH_SIZE 32

typedef struct sLimRmcGroupContext
{
    tSirMacAddr          transmitter;
    eRmcLeaderState      isLeader;
    struct sLimRmcGroupContext *next;
} tLimRmcGroupContext, *tpLimRmcGroupContext;

typedef struct sLimRmcContext
{
    tANI_BOOLEAN         rmcEnabled;
    tSirMacAddr          leader;
    eRmcMcastTxState     state;
    TX_TIMER             gRmcLeaderSelectTimer;
    tANI_U32             rmcTimerValInTicks;
    vos_lock_t           lkRmcLock;
    tLimRmcGroupContext *rmcGroupRxHashTable[RMC_MCAST_GROUPS_HASH_SIZE];
} tLimRmcContext, *tpLimRmcContext;


void limRmcInit(tpAniSirGlobal pMac);
void limRmcCleanup(tpAniSirGlobal pMac);
void limRmcTransmitterDelete(tpAniSirGlobal pMac, tSirMacAddr transmitter);
void limRmcIbssDelete(tpAniSirGlobal pMac);
void limRmcDumpStatus(tpAniSirGlobal pMac);

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
 * @param pMac       Pointer to Global MAC structure
 *
 * @param macAddr    Input MAC addres
 *
 * @return : VOS_STATUS_SUCCESS if RMC state machine allows leader selection and
                leader selection is triggered in FW
             VOS_STATUS_E_FAILURE if RMC state machine does not allow leader
                selection in its current state
 */
VOS_STATUS
limRmcTriggerLeaderSelection(tpAniSirGlobal pMac, tSirMacAddr macAddr);


#endif /* WLAN_FEATURE_RELIABLE_MCAST */

#endif /*  __LIM_RMC_H */
