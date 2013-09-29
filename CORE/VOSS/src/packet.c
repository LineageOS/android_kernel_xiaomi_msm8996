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

  \file     packet.c
  \brief    Implementation of packet module

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
#include "packet.h"
#include "adf_nbuf.h"
#include "vos_memory.h"

/**
 * voss_rx_packet_free  Free the Rx Packet
 * @ Rx Packet
 */
void voss_rx_packet_free(void* rxpacket)
{
	tp_rxpacket rx_packet = (tp_rxpacket)rxpacket;

	/* Free up the Adf nbuf */
	adf_nbuf_free(rx_packet->rx_nbuf);

	/* Free up the Rx packet */
	vos_mem_free(rx_packet);
}


