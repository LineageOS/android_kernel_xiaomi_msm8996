/*
 * Copyright (c) 2013-2016 The Linux Foundation. All rights reserved.
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

#if !defined( WLAN_HDD_TX_RX_H )
#define WLAN_HDD_TX_RX_H

/**===========================================================================

  \file  wlan_hdd_tx_rx.h

  \brief Linux HDD Tx/RX APIs

  ==========================================================================*/

/*---------------------------------------------------------------------------
  Include files
  -------------------------------------------------------------------------*/
#include <wlan_hdd_includes.h>
#include <vos_api.h>
#include <linux/skbuff.h>
#include <wlan_qct_tl.h>
#include "tl_shim.h"

/*---------------------------------------------------------------------------
  Preprocessor definitions and constants
  -------------------------------------------------------------------------*/
#define HDD_ETHERTYPE_802_1_X              ( 0x888E )
#define HDD_ETHERTYPE_802_1_X_FRAME_OFFSET ( 12 )
#define HDD_ETHERTYPE_802_1_X_SIZE         ( 2 )
#ifdef FEATURE_WLAN_WAPI
#define HDD_ETHERTYPE_WAI                  ( 0x88b4 )
#endif

#define HDD_80211_HEADER_LEN      24
#define HDD_80211_HEADER_QOS_CTL  2
#define HDD_LLC_HDR_LEN           6
#define HDD_FRAME_TYPE_MASK       0x0c
#define HDD_FRAME_SUBTYPE_MASK    0xf0
#define HDD_FRAME_TYPE_DATA       0x08
#define HDD_FRAME_TYPE_MGMT       0x00
#define HDD_FRAME_SUBTYPE_QOSDATA 0x80
#define HDD_FRAME_SUBTYPE_DEAUTH  0xC0
#define HDD_FRAME_SUBTYPE_DISASSOC 0xA0
#define HDD_DEST_ADDR_OFFSET      6

#define HDD_MAC_HDR_SIZE          6

#define HDD_PSB_CFG_INVALID                   0xFF
#define HDD_PSB_CHANGED                       0xFF
#define SME_QOS_UAPSD_CFG_BK_CHANGED_MASK     0xF1
#define SME_QOS_UAPSD_CFG_BE_CHANGED_MASK     0xF2
#define SME_QOS_UAPSD_CFG_VI_CHANGED_MASK     0xF4
#define SME_QOS_UAPSD_CFG_VO_CHANGED_MASK     0xF8

#define HDD_ETH_HEADER_LEN      14

#define HDD_BUG_REPORT_MIN_COUNT  3
#define HDD_BUG_REPORT_MIN_TIME   300000     /* 5 minutes */

#define TX_PATH 1
#define RX_PATH 0
#define STA  1
#define AP 0

/*---------------------------------------------------------------------------
  Type declarations
  -------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  Function declarations and documentation
  -------------------------------------------------------------------------*/

/**============================================================================
  @brief hdd_hard_start_xmit() - Function registered with the Linux OS for
  transmitting packets

  @param skb      : [in]  pointer to OS packet (sk_buff)
  @param dev      : [in] pointer to Libra network device

  @return         : NET_XMIT_DROP if packets are dropped
                  : NET_XMIT_SUCCESS if packet is enqueued successfully
  ===========================================================================*/
extern int hdd_hard_start_xmit(struct sk_buff *skb, struct net_device *dev);

extern void hdd_drop_skb(hdd_adapter_t *adapter, struct sk_buff *skb);

extern void hdd_drop_skb_list(hdd_adapter_t *adapter, struct sk_buff *skb,
                                                      bool is_update_ac_stats);

/**============================================================================
  @brief hdd_tx_timeout() - Function called by OS if there is any
  timeout during transmission. Since HDD simply enqueues packet
  and returns control to OS right away, this would never be invoked

  @param dev : [in] pointer to Libra network device
  @return    : None
  ===========================================================================*/
extern void hdd_tx_timeout(struct net_device *dev);

/**============================================================================
  @brief hdd_stats() - Function registered with the Linux OS for
  device TX/RX statistics

  @param dev      : [in] pointer to Libra network device

  @return         : pointer to net_device_stats structure
  ===========================================================================*/
extern struct net_device_stats* hdd_stats(struct net_device *dev);

/**============================================================================
  @brief hdd_init_tx_rx() - Init function to initialize Tx/RX
  modules in HDD

  @param pAdapter : [in] pointer to adapter context
  @return         : VOS_STATUS_E_FAILURE if any errors encountered
                  : VOS_STATUS_SUCCESS otherwise
  ===========================================================================*/
extern VOS_STATUS hdd_init_tx_rx( hdd_adapter_t *pAdapter );

/**============================================================================
  @brief hdd_deinit_tx_rx() - Deinit function to clean up Tx/RX
  modules in HDD

  @param pAdapter : [in] pointer to adapter context
  @return         : VOS_STATUS_E_FAILURE if any errors encountered
                  : VOS_STATUS_SUCCESS otherwise
  ===========================================================================*/
extern VOS_STATUS hdd_deinit_tx_rx( hdd_adapter_t *pAdapter );

/**============================================================================
  @brief hdd_disconnect_tx_rx() - Disconnect function to clean up Tx/RX
  modules in HDD

  @param pAdapter : [in] pointer to adapter context
  @return         : VOS_STATUS_E_FAILURE if any errors encountered
                  : VOS_STATUS_SUCCESS otherwise
  ===========================================================================*/
extern VOS_STATUS hdd_disconnect_tx_rx( hdd_adapter_t *pAdapter );

/**============================================================================
  @brief hdd_rx_packet_cbk() - Receive callback registered with TL.
  TL will call this to notify the HDD when a packet was received
  for a registered STA.

  @param vosContext   : [in] pointer to VOS context
  @param rxBufChain   : [in] pointer to adf_nbuf rx chain
  @param staId        : [in] Station Id

  @return             : VOS_STATUS_E_FAILURE if any errors encountered,
                      : VOS_STATUS_SUCCESS otherwise
  ===========================================================================*/
extern VOS_STATUS hdd_rx_packet_cbk(v_VOID_t *vosContext, adf_nbuf_t rxBufChain,
                                    v_U8_t staId);

/**============================================================================
  @brief hdd_IsEAPOLPacket() - Checks the packet is EAPOL or not.

  @param pVosPacket : [in] pointer to vos packet
  @return         : VOS_TRUE if the packet is EAPOL
                  : VOS_FALSE otherwise
  ===========================================================================*/
extern v_BOOL_t hdd_IsEAPOLPacket( vos_pkt_t *pVosPacket );

 /**
 * hdd_get_peer_sta_id() - Get the StationID using the Peer Mac address
 * @sta_ctx: pointer to HDD Station Context
 * @peer_mac_addr: pointer to Peer Mac address
 * @sta_id: pointer to Station Index
 *
 * Returns: VOS_STATUS_SUCCESS on success, VOS_STATUS_E_FAILURE on error
 */
VOS_STATUS hdd_get_peer_sta_id(hdd_station_ctx_t *sta_ctx,
                               v_MACADDR_t *peer_mac_addr, uint8_t *sta_id);

int hdd_get_peer_idx(hdd_station_ctx_t *sta_ctx, v_MACADDR_t *addr);

/**============================================================================
  @brief hdd_flush_ibss_tx_queues() -
                    Flush tx queues in IBSS mode
  @param pAdapter: Hdd adapter
  @param STAId:    Sta index
  @return    : VOS_STATUS_SUCCESS/VOS_STATUS_E_FAILURE
  ===========================================================================*/
void hdd_flush_ibss_tx_queues( hdd_adapter_t *pAdapter, v_U8_t STAId);

/**=========================================================================
  @brief hdd_wmm_acquire_access_required()-
                   Determine whether wmm ac acquire access is required
  @param pAdapter  : pointer to Adapter context
  @param acType    : AC
  @return          : void
   ========================================================================*/
void hdd_wmm_acquire_access_required(hdd_adapter_t *pAdapter,
                                     WLANTL_ACEnumType acType);

#ifdef QCA_LL_TX_FLOW_CT
/**============================================================================
  @brief hdd_tx_resume_cb() - Resume OS TX Q.
      Q was stopped due to WLAN TX path low resource condition

  @param adapter_context : [in] pointer to vdev adapter
  @param tx_resume       : [in] TX Q resume trigger

  @return         : NONE
  ===========================================================================*/
void hdd_tx_resume_cb(void *adapter_context,
                        v_BOOL_t tx_resume);

/**============================================================================
  @brief hdd_tx_resume_timer_expired_handler() - Resume OS TX Q timer expired
      handler.
      If Blocked OS Q is not resumed during timeout period, to prevent
      permanent stall, resume OS Q forcefully.

  @param adapter_context : [in] pointer to vdev adapter

  @return         : NONE
  ===========================================================================*/
void hdd_tx_resume_timer_expired_handler(void *adapter_context);
#endif /* QCA_LL_TX_FLOW_CT */

/**
 * hdd_rst_tcp_delack() - Reset tcp delack value to original level.
 * @hdd_context_t : HDD context
 *
 * HDD will call this API on unloading path to clear delack value.
 *
 * Return: None
 */
void hdd_rst_tcp_delack(hdd_context_t *hdd_ctx);

/**
 * hdd_mon_rx_packet_cbk() - Receive callback registered with TL.
 * @vosContext: [in] pointer to VOS context
 * @staId:      [in] Station Id
 * @rxBuf:      [in] pointer to rx adf_nbuf
 *
 * TL will call this to notify the HDD when one or more packets were
 * received for a registered STA.
 *
 * Return: VOS_STATUS_E_FAILURE if any errors encountered, VOS_STATUS_SUCCESS
 * otherwise
 */
VOS_STATUS hdd_mon_rx_packet_cbk(v_VOID_t *vos_ctx, adf_nbuf_t rx_buf,
				 uint8_t sta_id);

void wlan_display_tx_timeout_stats(hdd_adapter_t *adapter);

const char *hdd_reason_type_to_string(enum netif_reason_type reason);
const char *hdd_action_type_to_string(enum netif_action_type action);
void wlan_hdd_netif_queue_control(hdd_adapter_t *adapter,
		enum netif_action_type action, enum netif_reason_type reason);

#ifdef QCA_PKT_PROTO_TRACE
void hdd_dhcp_pkt_trace_buf_update(struct sk_buff *skb, int is_transmission,
				   int is_sta);
#else
static inline void hdd_dhcp_pkt_trace_buf_update(struct sk_buff *skb,
					    int is_transmission, int is_sta)
{
	return;
}
#endif
#endif    // end #if !defined( WLAN_HDD_TX_RX_H )
