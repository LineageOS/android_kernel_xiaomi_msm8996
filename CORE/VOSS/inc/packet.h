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

/**========================================================================

  \file     packet.h
  \brief   

  ========================================================================*/
/**=========================================================================
  EDIT HISTORY FOR FILE


  This section contains comments describing changes made to the module.
  Notice that changes are listed in reverse chronological order.

  $Header:$   $DateTime: $ $Author: $


  when              who           what, where, why
  --------          ---           -----------------------------------------
  26/03/2013        Ganesh        Created module for Packet Handling
                    Babu
  ==========================================================================*/
#ifndef _PACKET_H_
#define _PACKET_H_
#include "adf_os_types.h"

/*
 * Rx Packet Struct
 */
typedef struct 
{
	u_int8_t channel;
	u_int8_t snr;
	u_int32_t rssi;
	u_int32_t timestamp;
	u_int8_t *mpdu_hdr_ptr;
	u_int8_t *mpdu_data_ptr;
	u_int32_t mpdu_len;
	u_int32_t mpdu_hdr_len;
	u_int32_t mpdu_data_len;
}t_rxpacketmeta, *tp_rxpacketmeta;

typedef struct 
{
	/* Rx Packet Meta Information */
	t_rxpacketmeta rxpktmeta;

	/* Pointer to Rx Packet */
	void *rx_nbuf;
	
}t_rxpacket, *tp_rxpacket;

/**
 * voss_rx_packet_free  Free the Rx Packet
 * @ Rx Packet
 */
void voss_rx_packet_free(void* rxpacket);

#endif //_PACKET_H_

