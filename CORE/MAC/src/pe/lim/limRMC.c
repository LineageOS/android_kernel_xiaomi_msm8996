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

