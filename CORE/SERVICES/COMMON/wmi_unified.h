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
 * @addtogroup WMIAPI
 *@{
 */

/** @file
 * This file specifies the WMI interface for the  Software Architecture.
 *
 * It includes definitions of all the commands and events. Commands are messages
 * from the host to the target. Events and Replies are messages from the target
 * to the host.
 *
 * Ownership of correctness in regards to WMI commands
 * belongs to the host driver and the target is not required to validate
 * parameters for value, proper range, or any other checking.
 *
 * Guidelines for extending this interface are below.
 *
 * 1. Add new WMI commands ONLY within the specified range - 0x9000 - 0x9fff
 * 2. Use ONLY A_UINT32 type for defining member variables within WMI command/event
 *    structures. Do not use A_UINT8, A_UINT16, A_BOOL or enum types within these structures.
 * 3. DO NOT define bit fields within structures. Implement bit fields using masks
 *    if necessary. Do not use the programming language's bit field definition.
 * 4. Define macros for encode/decode of A_UINT8, A_UINT16 fields within the A_UINT32
 *    variables. Use these macros for set/get of these fields. Try to use this to
 *    optimize the structure without bloating it with A_UINT32 variables for every lower
 *    sized field.
 * 5. Do not use PACK/UNPACK attributes for the structures as each member variable is
 *    already 4-byte aligned by virtue of being a A_UINT32 type.
 * 6. Comment each parameter part of the WMI command/event structure by using the
 *    2 stars at the begining of C comment instead of one star to enable HTML document
 *    generation using Doxygen.
 *
 */

#ifndef _WMI_UNIFIED_H_
#define _WMI_UNIFIED_H_


#ifdef __cplusplus
extern "C" {
#endif

#include <wlan_defs.h>
#include <wmi_services.h>
#include <dbglog.h>

#define ATH_MAC_LEN             6               /**< length of MAC in bytes */
#define WMI_EVENT_STATUS_SUCCESS 0 /* Success return status to host */
#define WMI_EVENT_STATUS_FAILURE 1 /* Failure return status to host */

#define MAX_TX_RATE_VALUES      10 /*Max Tx Rates*/
#define MAX_RSSI_VALUES         10 /*Max Rssi values*/

//The maximum value of access category
#define WLAN_MAX_AC  4

/*
 * These don't necessarily belong here; but as the MS/SM macros require
 * ar6000_internal.h to be included, it may not be defined as yet.
 */
#define WMI_F_MS(_v, _f)                                            \
            ( ((_v) & (_f)) >> (_f##_S) )

/*
 * This breaks the "good macro practice" of only referencing each
 * macro field once (to avoid things like field++ from causing issues.)
 */
#define WMI_F_RMW(_var, _v, _f)                                     \
            do {                                                    \
                (_var) &= ~(_f);                                    \
                (_var) |= ( ((_v) << (_f##_S)) & (_f));             \
            } while (0)

/** 2 word representation of MAC addr */
typedef struct {
    /** upper 4 bytes of  MAC address */
    A_UINT32 mac_addr31to0;
    /** lower 2 bytes of  MAC address */
    A_UINT32 mac_addr47to32;
} wmi_mac_addr;

/** macro to convert MAC address from WMI word format to char array */
#define WMI_MAC_ADDR_TO_CHAR_ARRAY(pwmi_mac_addr,c_macaddr) do {               \
     (c_macaddr)[0] =    ((pwmi_mac_addr)->mac_addr31to0) & 0xff;     \
     (c_macaddr)[1] =  ( ((pwmi_mac_addr)->mac_addr31to0) >> 8) & 0xff; \
     (c_macaddr)[2] =  ( ((pwmi_mac_addr)->mac_addr31to0) >> 16) & 0xff; \
     (c_macaddr)[3] =  ( ((pwmi_mac_addr)->mac_addr31to0) >> 24) & 0xff;  \
     (c_macaddr)[4] =    ((pwmi_mac_addr)->mac_addr47to32) & 0xff;        \
     (c_macaddr)[5] =  ( ((pwmi_mac_addr)->mac_addr47to32) >> 8) & 0xff; \
   } while(0)

/** macro to convert MAC address from char array to WMI word format */
#define WMI_CHAR_ARRAY_TO_MAC_ADDR(c_macaddr,pwmi_mac_addr)  do { \
    (pwmi_mac_addr)->mac_addr31to0  =                                   \
        ( (c_macaddr)[0] | ((c_macaddr)[1] << 8)                           \
               | ((c_macaddr)[2] << 16) | ((c_macaddr)[3] << 24) );         \
    (pwmi_mac_addr)->mac_addr47to32  =                                  \
                  ( (c_macaddr)[4] | ((c_macaddr)[5] << 8));             \
   } while(0)


/*
 * wmi command groups.
 */
typedef enum {
    /* 0 to 2 are reserved */
    WMI_GRP_START=0x3,
    WMI_GRP_SCAN=WMI_GRP_START,
    WMI_GRP_PDEV,
    WMI_GRP_VDEV,
    WMI_GRP_PEER,
    WMI_GRP_MGMT,
    WMI_GRP_BA_NEG,
    WMI_GRP_STA_PS,
    WMI_GRP_DFS,
    WMI_GRP_ROAM,
    WMI_GRP_OFL_SCAN,
    WMI_GRP_P2P,
    WMI_GRP_AP_PS,
    WMI_GRP_RATE_CTRL,
    WMI_GRP_PROFILE,
    WMI_GRP_SUSPEND,
    WMI_GRP_BCN_FILTER,
    WMI_GRP_WOW,
    WMI_GRP_RTT,
    WMI_GRP_SPECTRAL,
    WMI_GRP_STATS,
    WMI_GRP_ARP_NS_OFL,
    WMI_GRP_NLO_OFL,
    WMI_GRP_GTK_OFL,
    WMI_GRP_CSA_OFL,
    WMI_GRP_CHATTER,
    WMI_GRP_TID_ADDBA,
    WMI_GRP_MISC,
    WMI_GRP_GPIO,
    WMI_GRP_FWTEST,
    WMI_GRP_TDLS,
    WMI_GRP_RESMGR,
    WMI_GRP_STA_SMPS,
} WMI_GRP_ID;

#define WMI_CMD_GRP_START_ID(grp_id) (((grp_id) << 12) | 0x1)
#define WMI_EVT_GRP_START_ID(grp_id) (((grp_id) << 12) | 0x1)

/**
 * Command IDs and commange events.
 */
typedef enum {
    /** initialize the wlan sub system */
    WMI_INIT_CMDID=0x1,

    /* Scan specific commands */

    /** start scan request to FW  */
    WMI_START_SCAN_CMDID = WMI_CMD_GRP_START_ID(WMI_GRP_SCAN) ,
    /** stop scan request to FW  */
    WMI_STOP_SCAN_CMDID,
    /** full list of channels as defined by the regulatory that will be used by scanner   */
    WMI_SCAN_CHAN_LIST_CMDID,
    /** overwrite default priority table in scan scheduler   */
    WMI_SCAN_SCH_PRIO_TBL_CMDID,
    /** This command to adjust the priority and min.max_rest_time
     * of an on ongoing scan request.
     */
    WMI_SCAN_UPDATE_REQUEST_CMDID,

    /* PDEV(physical device) specific commands */
    /** set regulatorty ctl id used by FW to determine the exact ctl power limits */
    WMI_PDEV_SET_REGDOMAIN_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_PDEV),
    /** set channel. mainly used for supporting monitor mode */
    WMI_PDEV_SET_CHANNEL_CMDID,
    /** set pdev specific parameters */
    WMI_PDEV_SET_PARAM_CMDID,
    /** enable packet log */
    WMI_PDEV_PKTLOG_ENABLE_CMDID,
    /** disable packet log*/
    WMI_PDEV_PKTLOG_DISABLE_CMDID,
    /** set wmm parameters */
    WMI_PDEV_SET_WMM_PARAMS_CMDID,
    /** set HT cap ie that needs to be carried probe requests HT/VHT channels */
    WMI_PDEV_SET_HT_CAP_IE_CMDID,
    /** set VHT cap ie that needs to be carried on probe requests on VHT channels */
    WMI_PDEV_SET_VHT_CAP_IE_CMDID,

    /** Command to send the DSCP-to-TID map to the target */
    WMI_PDEV_SET_DSCP_TID_MAP_CMDID,
    /** set quiet ie parameters. primarily used in AP mode */
    WMI_PDEV_SET_QUIET_MODE_CMDID,
    /** Enable/Disable Green AP Power Save  */
    WMI_PDEV_GREEN_AP_PS_ENABLE_CMDID,
    /** get TPC config for the current operating channel */
    WMI_PDEV_GET_TPC_CONFIG_CMDID,

    /** set the base MAC address for the physical device before a VDEV is created.
     *  For firmware that doesn’t support this feature and this command, the pdev
     *  MAC address will not be changed. */
    WMI_PDEV_SET_BASE_MACADDR_CMDID,

    /* eeprom content dump , the same to bdboard data */
    WMI_PDEV_DUMP_CMDID,

    /* VDEV(virtual device) specific commands */
    /** vdev create */
    WMI_VDEV_CREATE_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_VDEV),
    /** vdev delete */
    WMI_VDEV_DELETE_CMDID,
    /** vdev start request */
    WMI_VDEV_START_REQUEST_CMDID,
    /** vdev restart request (RX only, NO TX, used for CAC period)*/
    WMI_VDEV_RESTART_REQUEST_CMDID,
    /** vdev up request */
    WMI_VDEV_UP_CMDID,
    /** vdev stop request */
    WMI_VDEV_STOP_CMDID,
    /** vdev down request */
    WMI_VDEV_DOWN_CMDID,
    /* set a vdev param */
    WMI_VDEV_SET_PARAM_CMDID,
    /* set a key (used for setting per peer unicast and per vdev multicast) */
    WMI_VDEV_INSTALL_KEY_CMDID,

    /* wnm sleep mode command */
    WMI_VDEV_WNM_SLEEPMODE_CMDID,
    WMI_VDEV_WMM_ADDTS_CMDID,
    WMI_VDEV_WMM_DELTS_CMDID,
    WMI_VDEV_SET_WMM_PARAMS_CMDID,

    /* peer specific commands */

    /** create a peer */
    WMI_PEER_CREATE_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_PEER),
    /** delete a peer */
    WMI_PEER_DELETE_CMDID,
    /** flush specific  tid queues of a peer */
    WMI_PEER_FLUSH_TIDS_CMDID,
    /** set a parameter of a peer */
    WMI_PEER_SET_PARAM_CMDID,
    /** set peer to associated state. will cary all parameters determined during assocication time */
    WMI_PEER_ASSOC_CMDID,
    /**add a wds  (4 address ) entry. used only for testing WDS feature on AP products */
    WMI_PEER_ADD_WDS_ENTRY_CMDID,
    /**remove wds  (4 address ) entry. used only for testing WDS feature on AP products */
    WMI_PEER_REMOVE_WDS_ENTRY_CMDID,
    /** set up mcast group infor for multicast to unicast conversion */
    WMI_PEER_MCAST_GROUP_CMDID,

    /* beacon/management specific commands */

    /** transmit beacon by reference . used for transmitting beacon on low latency interface like pcie */
    WMI_BCN_TX_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_MGMT),
    /** transmit beacon by value */
    WMI_PDEV_SEND_BCN_CMDID,
    /** set the beacon template. used in beacon offload mode to setup the
     *  the common beacon template with the FW to be used by FW to generate beacons */
    WMI_BCN_TMPL_CMDID,
    /** set beacon filter with FW */
    WMI_BCN_FILTER_RX_CMDID,
    /* enable/disable filtering of probe requests in the firmware */
    WMI_PRB_REQ_FILTER_RX_CMDID,
    /** transmit management frame by value. will be deprecated */
    WMI_MGMT_TX_CMDID,
    /** set the probe response template. used in beacon offload mode to setup the
     *  the common probe response template with the FW to be used by FW to generate
     *  probe responses */
    WMI_PRB_TMPL_CMDID,

    /** commands to directly control ba negotiation directly from host. only used in test mode */

    /** turn off FW Auto addba mode and let host control addba */
    WMI_ADDBA_CLEAR_RESP_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_BA_NEG),
    /** send add ba request */
    WMI_ADDBA_SEND_CMDID,
    WMI_ADDBA_STATUS_CMDID,
    /** send del ba */
    WMI_DELBA_SEND_CMDID,
    /** set add ba response will be used by FW to generate addba response*/
    WMI_ADDBA_SET_RESP_CMDID,
    /** send single VHT MPDU with AMSDU */
    WMI_SEND_SINGLEAMSDU_CMDID,

    /** Station power save specific config */
    /** enable/disable station powersave */
    WMI_STA_POWERSAVE_MODE_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_STA_PS),
    /** set station power save specific parameter */
    WMI_STA_POWERSAVE_PARAM_CMDID,
    /** set station mimo powersave mode */
    WMI_STA_MIMO_PS_MODE_CMDID,


    /** DFS-specific commands */
    /** enable DFS (radar detection)*/
    WMI_PDEV_DFS_ENABLE_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_DFS),
    /** disable DFS (radar detection)*/
    WMI_PDEV_DFS_DISABLE_CMDID,


    /* Roaming specific  commands */
    /** set roam scan mode */
    WMI_ROAM_SCAN_MODE=WMI_CMD_GRP_START_ID(WMI_GRP_ROAM),
    /** set roam scan rssi threshold below which roam scan is enabled  */
    WMI_ROAM_SCAN_RSSI_THRESHOLD,
    /** set roam scan period for periodic roam scan mode  */
    WMI_ROAM_SCAN_PERIOD,
    /** set roam scan trigger rssi change threshold   */
    WMI_ROAM_SCAN_RSSI_CHANGE_THRESHOLD,
    /** set roam AP profile   */
    WMI_ROAM_AP_PROFILE,
    /** set channel list for roam scans */
    WMI_ROAM_CHAN_LIST,

    /** offload scan specific commands */
    /** set offload scan AP profile   */
    WMI_OFL_SCAN_ADD_AP_PROFILE=WMI_CMD_GRP_START_ID(WMI_GRP_OFL_SCAN),
    /** remove offload scan AP profile   */
    WMI_OFL_SCAN_REMOVE_AP_PROFILE,
    /** set offload scan period   */
    WMI_OFL_SCAN_PERIOD,

    /* P2P specific commands */
    /**set P2P device info. FW will used by FW to create P2P IE to be carried in probe response
     * generated during p2p listen and for p2p discoverability  */
    WMI_P2P_DEV_SET_DEVICE_INFO=WMI_CMD_GRP_START_ID(WMI_GRP_P2P),
    /** enable/disable p2p discoverability on STA/AP VDEVs  */
    WMI_P2P_DEV_SET_DISCOVERABILITY,
    /** set p2p ie to be carried in beacons generated by FW for GO  */
    WMI_P2P_GO_SET_BEACON_IE,
    /** set p2p ie to be carried in probe response frames generated by FW for GO  */
    WMI_P2P_GO_SET_PROBE_RESP_IE,
    /** set the vendor specific p2p ie data. FW will use this to parse the P2P NoA
     *  attribute in the beacons/probe responses received.
     */
    WMI_P2P_SET_VENDOR_IE_DATA_CMDID,
    /** set the configure of p2p find offload */
    WMI_P2P_DISC_OFFLOAD_CONFIG_CMDID,
    /** set the vendor specific p2p ie data for p2p find offload using */
    WMI_P2P_DISC_OFFLOAD_APPIE_CMDID,
    /** set the BSSID/device name pattern of p2p find offload */
    WMI_P2P_DISC_OFFLOAD_PATTERN_CMDID,
	/** set OppPS related parameters **/
	WMI_P2P_SET_OPPPS_PARAM_CMDID,

    /** AP power save specific config */
    /** set AP power save specific param */
    WMI_AP_PS_PEER_PARAM_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_AP_PS),
    /** set AP UAPSD coex pecific param */
    WMI_AP_PS_PEER_UAPSD_COEX_CMDID,


    /** Rate-control specific commands */
    WMI_PEER_RATE_RETRY_SCHED_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_RATE_CTRL),

    /** WLAN Profiling commands. */
    WMI_WLAN_PROFILE_TRIGGER_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_PROFILE),
    WMI_WLAN_PROFILE_SET_HIST_INTVL_CMDID,
    WMI_WLAN_PROFILE_GET_PROFILE_DATA_CMDID,
    WMI_WLAN_PROFILE_ENABLE_PROFILE_ID_CMDID,
    WMI_WLAN_PROFILE_LIST_PROFILE_ID_CMDID,

    /** Suspend resume command Ids */
    WMI_PDEV_SUSPEND_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_SUSPEND),
    WMI_PDEV_RESUME_CMDID,

    /* Beacon filter commands */
    /** add a beacon filter */
    WMI_ADD_BCN_FILTER_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_BCN_FILTER),
    /** remove a  beacon filter */
    WMI_RMV_BCN_FILTER_CMDID,

    /* WOW Specific WMI commands*/
    /** add pattern for awake */
    WMI_WOW_ADD_WAKE_PATTERN_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_WOW),
    /** deleta a wake pattern */
    WMI_WOW_DEL_WAKE_PATTERN_CMDID,
    /** enable/deisable wake event  */
    WMI_WOW_ENABLE_DISABLE_WAKE_EVENT_CMDID,
    /** enable WOW  */
    WMI_WOW_ENABLE_CMDID,
    /** host woke up from sleep event to FW. Generated in response to WOW Hardware event */
    WMI_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID,

    /* RTT measurement related cmd */
    /** reques to make an RTT measurement */
    WMI_RTT_MEASREQ_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_RTT),
    /** reques to report a tsf measurement */
    WMI_RTT_TSF_CMDID,

    /** spectral scan command */
    /** configure spectral scan */
    WMI_VDEV_SPECTRAL_SCAN_CONFIGURE_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_SPECTRAL),
    /** enable/disable spectral scan and trigger */
    WMI_VDEV_SPECTRAL_SCAN_ENABLE_CMDID,

    /* F/W stats */
    /** one time request for stats */
    WMI_REQUEST_STATS_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_STATS),

    /** ARP OFFLOAD REQUEST*/
    WMI_SET_ARP_NS_OFFLOAD_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_ARP_NS_OFL),

    /** NS offload confid*/
    WMI_NETWORK_LIST_OFFLOAD_CONFIG_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_NLO_OFL),

	/* GTK offload Specific WMI commands*/
	WMI_GTK_OFFLOAD_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_GTK_OFL),

	/* CSA offload Specific WMI commands*/
    /** csa offload enable */
    WMI_CSA_OFFLOAD_ENABLE_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_CSA_OFL),
    /** chan switch command */
    WMI_CSA_OFFLOAD_CHANSWITCH_CMDID,

    /* Chatter commands*/
    /* Change chatter mode of operation */
    WMI_CHATTER_SET_MODE_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_CHATTER),
    /** chatter add coalescing filter command */
    WMI_CHATTER_ADD_COALESCING_FILTER_CMDID,
    /** chatter delete coalescing filter command */
    WMI_CHATTER_DELETE_COALESCING_FILTER_CMDID,
    /** chatter coalecing query command */
    WMI_CHATTER_COALESCING_QUERY_CMDID,

    /**addba specific commands */
    /** start the aggregation on this TID */
    WMI_PEER_TID_ADDBA_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_TID_ADDBA),
    /** stop the aggregation on this TID */
    WMI_PEER_TID_DELBA_CMDID,

    /** set station mimo powersave method */
    WMI_STA_DTIM_PS_METHOD_CMDID,
    /** Configure the Station UAPSD AC Auto Trigger Parameters */
    WMI_STA_UAPSD_AUTO_TRIG_CMDID,
    /** Configure the Keep Alive Parameters */
    WMI_STA_KEEPALIVE_CMDID,

    /* Request ssn from target for a sta/tid pair */
    WMI_BA_REQ_SSN_CMDID,
    /* misc command group */
    /** echo command mainly used for testing */
    WMI_ECHO_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_MISC),

	/* !!IMPORTANT!!
	  * If you need to add a new WMI command to the WMI_GRP_MISC sub-group,
	  * please make sure you add it BEHIND WMI_PDEV_UTF_CMDID,
	  * as we MUST have a fixed value here to maintain compatibility between
	  * UTF and the ART2 driver
	*/
	/** UTF WMI commands */
	WMI_PDEV_UTF_CMDID,

    /** set debug log config */
    WMI_DBGLOG_CFG_CMDID,
    /* QVIT specific command id */
    WMI_PDEV_QVIT_CMDID,
    /* Factory Testing Mode request command
     * used for integrated chipsets */
    WMI_PDEV_FTM_INTG_CMDID,
    /* set and get keepalive parameters command */
    WMI_VDEV_SET_KEEPALIVE_CMDID,
    WMI_VDEV_GET_KEEPALIVE_CMDID,
    /* For fw recovery test command */
    WMI_FORCE_FW_HANG_CMDID,
    /* Set Mcast/Bdcast filter */
    WMI_SET_MCASTBCAST_FILTER_CMDID,

    /* GPIO Configuration */
    WMI_GPIO_CONFIG_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_GPIO),
    WMI_GPIO_OUTPUT_CMDID,

    /* Txbf configuration command */
    WMI_TXBF_CMDID,

    /* FWTEST Commands */
    WMI_FWTEST_VDEV_MCC_SET_TBTT_MODE_CMDID=WMI_CMD_GRP_START_ID(WMI_GRP_FWTEST),
	/** set NoA descs **/
	WMI_FWTEST_P2P_SET_NOA_PARAM_CMDID,

    /** TDLS Configuration */
    /** enable/disable TDLS */
    WMI_TDLS_SET_STATE_CMDID = WMI_CMD_GRP_START_ID(WMI_GRP_TDLS),
    /** set tdls peer state */
    WMI_TDLS_PEER_UPDATE_CMDID,

    /** Resmgr Configuration */
    /** Adaptive OCS is enabled by default in the FW. This command is used to
     * disable FW based adaptive OCS.
     */
    WMI_RESMGR_ADAPTIVE_OCS_DISABLE_CMDID = WMI_CMD_GRP_START_ID(WMI_GRP_RESMGR),
    /** set the requested channel time quota for the home channels */
    WMI_RESMGR_SET_CHAN_TIME_QUOTA_CMDID,
    /** set the requested latency for the home channels */
    WMI_RESMGR_SET_CHAN_LATENCY_CMDID,

    /** STA SMPS Configuration */
    /** force SMPS mode */
    WMI_STA_SMPS_FORCE_MODE_CMDID = WMI_CMD_GRP_START_ID(WMI_GRP_STA_SMPS),
} WMI_CMD_ID;

typedef enum {
    /** WMI service is ready; after this event WMI messages can be sent/received  */
    WMI_SERVICE_READY_EVENTID=0x1,
    /** WMI is ready; after this event the wlan subsystem is initialized and can process commands. */
    WMI_READY_EVENTID,

    /** Scan specific events */
    WMI_SCAN_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_SCAN) ,

    /* PDEV specific events */
    /** TPC config for the current operating channel */
    WMI_PDEV_TPC_CONFIG_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_PDEV) ,
    /** Channel stats event    */
    WMI_CHAN_INFO_EVENTID,

    /** PHY Error specific WMI event */
    WMI_PHYERR_EVENTID,

    /** eeprom dump event  */
    WMI_PDEV_DUMP_EVENTID,

    /* VDEV specific events */
    /** VDEV started event in response to VDEV_START request */
    WMI_VDEV_START_RESP_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_VDEV),
    /** vdev stopped event , generated in response to VDEV_STOP request */
    WMI_VDEV_STOPPED_EVENTID,
    /* Indicate the set key (used for setting per
     * peer unicast and per vdev multicast)
     * operation has completed */
    WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID,
    /* NOTE: WMI_VDEV_MCC_BCN_INTERVAL_CHANGE_REQ_EVENTID would be deprecated. Please
     don't use this for any new implementations */
    /* Firmware requests dynamic change to a specific beacon interval for a specific vdev ID in MCC scenario.
     This request is valid only for vdevs operating in soft AP or P2P GO mode */
    WMI_VDEV_MCC_BCN_INTERVAL_CHANGE_REQ_EVENTID,

    /* peer  specific events */
    /** FW reauet to kick out the station for reasons like inactivity,lack of response ..etc */
    WMI_PEER_STA_KICKOUT_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_PEER),

    /* beacon/mgmt specific events */
    /** RX management frame. the entire frame is carried along with the event.  */
    WMI_MGMT_RX_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_MGMT),
    /** software beacon alert event to Host requesting host to Queue a beacon for transmission
        use only in host beacon mode */
    WMI_HOST_SWBA_EVENTID,
    /** beacon tbtt offset event indicating the tsf offset of the tbtt from the theritical value.
        tbtt offset is normally 0 and will be non zero if there are multiple VDEVs operating in
        staggered beacon transmission mode */
    WMI_TBTTOFFSET_UPDATE_EVENTID,

    /*ADDBA Related WMI Events*/
    /** Indication the completion of the prior
       WMI_PEER_TID_DELBA_CMDID(initiator) */
    WMI_TX_DELBA_COMPLETE_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_BA_NEG),
    /** Indication the completion of the prior
       *WMI_PEER_TID_ADDBA_CMDID(initiator) */
    WMI_TX_ADDBA_COMPLETE_EVENTID,

    /* Seq num returned from hw for a sta/tid pair */
    WMI_BA_RSP_SSN_EVENTID,
    /** Roam event to trigger roaming on host */
    WMI_ROAM_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_ROAM),

    /** matching AP found from list of profiles */
    WMI_PROFILE_MATCH,

    /** P2P disc found */
    WMI_P2P_DISC_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_P2P),

    /** WOW wake up host event.generated in response to WMI_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID.
        will cary wake reason */
    WMI_WOW_WAKEUP_HOST_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_WOW),

    /*RTT related event ID*/
    /** RTT measurement report */
    WMI_RTT_MEASUREMENT_REPORT_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_RTT),
    /** TSF measurement report */
    WMI_TSF_MEASUREMENT_REPORT_EVENTID,
    /** RTT error report */
    WMI_RTT_ERROR_REPORT_EVENTID,

    /*NLO specific events*/
    /** NLO match event after the first match */
    WMI_NLO_MATCH_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_NLO_OFL),

    /** NLO scan complete event */
    WMI_NLO_SCAN_COMPLETE_EVENTID,


    /** GTK offload stautus event requested by host */
    WMI_GTK_OFFLOAD_STATUS_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_GTK_OFL),

	/** GTK offload failed to rekey event */
	WMI_GTK_REKEY_FAIL_EVENTID,
    /* CSA IE received event */
    WMI_CSA_HANDLING_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_CSA_OFL),

    /*chatter query reply event*/
    WMI_CHATTER_PC_QUERY_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_CHATTER),

    /** echo event in response to echo command */
    WMI_ECHO_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_MISC),

	/* !!IMPORTANT!!
	  * If you need to add a new WMI event ID to the WMI_GRP_MISC sub-group,
	  * please make sure you add it BEHIND WMI_PDEV_UTF_EVENTID,
	  * as we MUST have a fixed value here to maintain compatibility between
	  * UTF and the ART2 driver
	*/
	/** UTF specific WMI event */
	WMI_PDEV_UTF_EVENTID,

    /** event carries buffered debug messages  */
    WMI_DEBUG_MESG_EVENTID,
    /** FW stats(periodic or on shot)  */
    WMI_UPDATE_STATS_EVENTID,
    /** debug print message used for tracing FW code while debugging  */
    WMI_DEBUG_PRINT_EVENTID,
    /** DCS wlan or non-wlan interference event
     */
    WMI_DCS_INTERFERENCE_EVENTID,
    /** VI spoecific event  */
    WMI_PDEV_QVIT_EVENTID,
    /** FW code profile data in response to profile request  */
    WMI_WLAN_PROFILE_DATA_EVENTID,
    /* Factory Testing Mode request event
     * used for integrated chipsets */
    WMI_PDEV_FTM_INTG_EVENTID,
    /* avoid list of frequencies .
     */
    WMI_WLAN_FREQ_AVOID_EVENTID,
    /* Indicate the keepalive parameters */
    WMI_VDEV_GET_KEEPALIVE_EVENTID,

    /* GPIO Event */
    WMI_GPIO_INPUT_EVENTID=WMI_EVT_GRP_START_ID(WMI_GRP_GPIO),

    /** upload H_CV info WMI event
     * to indicate uploaded H_CV info to host
     */
    WMI_UPLOADH_EVENTID,

    /** capture H info WMI event
     * to indicate captured H info to host
     */
    WMI_CAPTUREH_EVENTID,
    /* TDLS Event */
    WMI_TDLS_PEER_EVENTID = WMI_EVT_GRP_START_ID(WMI_GRP_TDLS),
} WMI_EVT_ID;


#define WMI_CHAN_LIST_TAG 0x1
#define WMI_SSID_LIST_TAG 0x2
#define WMI_BSSID_LIST_TAG 0x3
#define WMI_IE_TAG 0x4

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_channel */
    /** primary 20 MHz channel frequency in mhz */
    A_UINT32 mhz;
    /** Center frequency 1 in MHz*/
    A_UINT32 band_center_freq1;
    /** Center frequency 2 in MHz - valid only for 11acvht 80plus80 mode*/
    A_UINT32 band_center_freq2;
    /** channel info described below */
    A_UINT32 info;
    /** contains min power, max power, reg power and reg class id.  */
    A_UINT32 reg_info_1;
    /** contains antennamax */
    A_UINT32 reg_info_2;
} wmi_channel;

typedef enum{
WMI_CHANNEL_CHANGE_CAUSE_NONE = 0,
WMI_CHANNEL_CHANGE_CAUSE_CSA,
}wmi_channel_change_cause;

/** channel info consists of 6 bits of channel mode */

#define WMI_SET_CHANNEL_MODE(pwmi_channel,val) do { \
     (pwmi_channel)->info &= 0xffffffc0;            \
     (pwmi_channel)->info |= (val);                 \
     } while(0)

#define WMI_GET_CHANNEL_MODE(pwmi_channel) ((pwmi_channel)->info & 0x0000003f )

#define WMI_CHAN_FLAG_HT40_PLUS   6
#define WMI_CHAN_FLAG_PASSIVE     7
#define WMI_CHAN_ADHOC_ALLOWED    8
#define WMI_CHAN_AP_DISABLED      9
#define WMI_CHAN_FLAG_DFS         10
#define WMI_CHAN_FLAG_ALLOW_HT    11  /* HT is allowed on this channel */
#define WMI_CHAN_FLAG_ALLOW_VHT   12  /* VHT is allowed on this channel */
#define WMI_CHANNEL_CHANGE_CAUSE_CSA 13 /*Indicate reason for channel switch */

#define WMI_SET_CHANNEL_FLAG(pwmi_channel,flag) do { \
        (pwmi_channel)->info |=  (1 << flag);      \
     } while(0)

#define WMI_GET_CHANNEL_FLAG(pwmi_channel,flag)   \
        (((pwmi_channel)->info & (1 << flag)) >> flag)

#define WMI_SET_CHANNEL_MIN_POWER(pwmi_channel,val) do { \
     (pwmi_channel)->reg_info_1 &= 0xffffff00;           \
     (pwmi_channel)->reg_info_1 |= (val&0xff);           \
     } while(0)
#define WMI_GET_CHANNEL_MIN_POWER(pwmi_channel) ((pwmi_channel)->reg_info_1 & 0xff )

#define WMI_SET_CHANNEL_MAX_POWER(pwmi_channel,val) do { \
     (pwmi_channel)->reg_info_1 &= 0xffff00ff;           \
     (pwmi_channel)->reg_info_1 |= ((val&0xff) << 8);    \
     } while(0)
#define WMI_GET_CHANNEL_MAX_POWER(pwmi_channel) ( (((pwmi_channel)->reg_info_1) >> 8) & 0xff )

#define WMI_SET_CHANNEL_REG_POWER(pwmi_channel,val) do { \
     (pwmi_channel)->reg_info_1 &= 0xff00ffff;           \
     (pwmi_channel)->reg_info_1 |= ((val&0xff) << 16);   \
     } while(0)
#define WMI_GET_CHANNEL_REG_POWER(pwmi_channel) ( (((pwmi_channel)->reg_info_1) >> 16) & 0xff )
#define WMI_SET_CHANNEL_REG_CLASSID(pwmi_channel,val) do { \
     (pwmi_channel)->reg_info_1 &= 0x00ffffff;             \
     (pwmi_channel)->reg_info_1 |= ((val&0xff) << 24);     \
     } while(0)
#define WMI_GET_CHANNEL_REG_CLASSID(pwmi_channel) ( (((pwmi_channel)->reg_info_1) >> 24) & 0xff )

#define WMI_SET_CHANNEL_ANTENNA_MAX(pwmi_channel,val) do { \
     (pwmi_channel)->reg_info_2 &= 0xffffff00;             \
     (pwmi_channel)->reg_info_2 |= (val&0xff);             \
     } while(0)
#define WMI_GET_CHANNEL_ANTENNA_MAX(pwmi_channel) ((pwmi_channel)->reg_info_2 & 0xff )

#define WMI_SET_CHANNEL_MAX_TX_POWER(pwmi_channel,val) do { \
     (pwmi_channel)->reg_info_2 &= 0xffff00ff;              \
     (pwmi_channel)->reg_info_2 |= ((val&0xff)<<8);         \
     } while(0)
#define WMI_GET_CHANNEL_MAX_TX_POWER(pwmi_channel) ( (((pwmi_channel)->reg_info_2)>>8) & 0xff )


/** HT Capabilities*/
#define WMI_HT_CAP_ENABLED                0x0001   /* HT Enabled/ disabled */
#define WMI_HT_CAP_HT20_SGI               0x0002   /* Short Guard Interval with HT20 */
#define WMI_HT_CAP_DYNAMIC_SMPS           0x0004   /* Dynamic MIMO powersave */
#define WMI_HT_CAP_TX_STBC                0x0008   /* B3 TX STBC */
#define WMI_HT_CAP_TX_STBC_MASK_SHIFT     3
#define WMI_HT_CAP_RX_STBC                0x0030   /* B4-B5 RX STBC */
#define WMI_HT_CAP_RX_STBC_MASK_SHIFT     4
#define WMI_HT_CAP_LDPC                   0x0040   /* LDPC supported */
#define WMI_HT_CAP_L_SIG_TXOP_PROT        0x0080   /* L-SIG TXOP Protection */
#define WMI_HT_CAP_MPDU_DENSITY           0x0700   /* MPDU Density */
#define WMI_HT_CAP_MPDU_DENSITY_MASK_SHIFT 8
#define WMI_HT_CAP_HT40_SGI               0x0800

/* These macros should be used when we wish to advertise STBC support for
 * only 1SS or 2SS or 3SS. */
#define WMI_HT_CAP_RX_STBC_1SS            0x0010   /* B4-B5 RX STBC */
#define WMI_HT_CAP_RX_STBC_2SS            0x0020   /* B4-B5 RX STBC */
#define WMI_HT_CAP_RX_STBC_3SS            0x0030   /* B4-B5 RX STBC */


#define WMI_HT_CAP_DEFAULT_ALL (WMI_HT_CAP_ENABLED       | \
                                WMI_HT_CAP_HT20_SGI      | \
                                WMI_HT_CAP_HT40_SGI      | \
                                WMI_HT_CAP_TX_STBC       | \
                                WMI_HT_CAP_RX_STBC       | \
                                WMI_HT_CAP_LDPC)

/* WMI_VHT_CAP_* these maps to ieee 802.11ac vht capability information
   field. The fields not defined here are not supported, or reserved.
   Do not change these masks and if you have to add new one follow the
   bitmask as specified by 802.11ac draft.
*/

#define WMI_VHT_CAP_MAX_MPDU_LEN_MASK            0x00000003
#define WMI_VHT_CAP_RX_LDPC                      0x00000010
#define WMI_VHT_CAP_SGI_80MHZ                    0x00000020
#define WMI_VHT_CAP_TX_STBC                      0x00000080
#define WMI_VHT_CAP_RX_STBC_MASK                 0x00000300
#define WMI_VHT_CAP_RX_STBC_MASK_SHIFT           8
#define WMI_VHT_CAP_MAX_AMPDU_LEN_EXP            0x03800000
#define WMI_VHT_CAP_MAX_AMPDU_LEN_EXP_SHIT       23
#define WMI_VHT_CAP_RX_FIXED_ANT                 0x10000000
#define WMI_VHT_CAP_TX_FIXED_ANT                 0x20000000

#define WMI_VHT_CAP_MAX_MPDU_LEN_11454           0x00000002

/* These macros should be used when we wish to advertise STBC support for
 * only 1SS or 2SS or 3SS. */
#define WMI_VHT_CAP_RX_STBC_1SS            0x00000100
#define WMI_VHT_CAP_RX_STBC_2SS            0x00000200
#define WMI_vHT_CAP_RX_STBC_3SS            0x00000300

#define WMI_VHT_CAP_DEFAULT_ALL (WMI_VHT_CAP_MAX_MPDU_LEN_11454  |      \
                                 WMI_VHT_CAP_SGI_80MHZ           |      \
                                 WMI_VHT_CAP_TX_STBC             |      \
                                 WMI_VHT_CAP_RX_STBC_MASK        |      \
                                 WMI_VHT_CAP_RX_LDPC             |      \
                                 WMI_VHT_CAP_MAX_AMPDU_LEN_EXP   |      \
                                 WMI_VHT_CAP_RX_FIXED_ANT        |      \
                                 WMI_VHT_CAP_TX_FIXED_ANT)

/* Interested readers refer to Rx/Tx MCS Map definition as defined in
   802.11ac
*/
#define WMI_VHT_MAX_MCS_4_SS_MASK(r,ss)      ((3 & (r)) << (((ss) - 1) << 1))
#define WMI_VHT_MAX_SUPP_RATE_MASK           0x1fff0000
#define WMI_VHT_MAX_SUPP_RATE_MASK_SHIFT     16

/* WMI_SYS_CAPS_* refer to the capabilities that system support
*/
#define WMI_SYS_CAP_ENABLE                       0x00000001
#define WMI_SYS_CAP_TXPOWER                      0x00000002

/** NOTE: This structure cannot be extended in the future without breaking WMI compatibility */
typedef struct _wmi_abi_version {
    A_UINT32    abi_version_0;   /** WMI Major and Minor versions */
    A_UINT32    abi_version_1;   /** WMI change revision */
    A_UINT32    abi_version_ns_0;  /** ABI version namespace first four dwords */
    A_UINT32    abi_version_ns_1;  /** ABI version namespace second four dwords */
    A_UINT32    abi_version_ns_2;  /** ABI version namespace third four dwords */
    A_UINT32    abi_version_ns_3;  /** ABI version namespace fourth four dwords */
} wmi_abi_version;

/*
* maximum number of memroy requests allowed from FW.
*/
#define WMI_MAX_MEM_REQS 16
/**
 * The following struct holds optional payload for
 * wmi_service_ready_event_fixed_param,e.g., 11ac pass some of the
 * device capability to the host.
*/
typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_SERVICE_READY_EVENT */
    A_UINT32    fw_build_vers; /* firmware build number */
    wmi_abi_version fw_abi_vers;
    A_UINT32    phy_capability;  /* WMI_PHY_CAPABILITY */
	A_UINT32    max_frag_entry;  /* Maximum number of frag table entries that SW will populate less 1 */
    A_UINT32    num_rf_chains;
    /* The following field is only valid for service type WMI_SERVICE_11AC */
    A_UINT32    ht_cap_info; /* WMI HT Capability */
    A_UINT32    vht_cap_info; /* VHT capability info field of 802.11ac */
    A_UINT32    vht_supp_mcs; /* VHT Supported MCS Set field Rx/Tx same */
    A_UINT32    hw_min_tx_power;
    A_UINT32    hw_max_tx_power;
    A_UINT32    sys_cap_info;
    A_UINT32    min_pkt_size_enable; /* Enterprise mode short pkt enable */
    /** Max beacon and Probe Response IE offload size (includes
     *  optional P2P IEs) */
    A_UINT32    max_bcn_ie_size;
    /*
     * request to host to allocate a chuck of memory and pss it down to FW via WM_INIT.
     * FW uses this as FW extesnsion memory for saving its data structures. Only valid
     * for low latency interfaces like PCIE where FW can access this memory directly (or)
     * by DMA.
     */
    A_UINT32    num_mem_reqs;
    /* The TLVs for hal_reg_capabilities, wmi_service_bitmap and mem_reqs[] will follow this TLV.
         *     HAL_REG_CAPABILITIES   hal_reg_capabilities;
         *     A_UINT32 wmi_service_bitmap[WMI_SERVICE_BM_SIZE];
         *     wlan_host_mem_req mem_reqs[];
         */
} wmi_service_ready_event_fixed_param;

/** status consists of  upper 16 bits fo A_STATUS status and lower 16 bits of module ID that retuned status */
#define WLAN_INIT_STATUS_SUCCESS   0x0
#define WLAN_INIT_STATUS_GEN_FAILED   0x1
#define WLAN_GET_INIT_STATUS_REASON(status)    ((status) & 0xffff)
#define WLAN_GET_INIT_STATUS_MODULE_ID(status) (((status) >> 16) & 0xffff)

typedef A_UINT32 WLAN_INIT_STATUS;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_ready_event_fixed_param */
    wmi_abi_version fw_abi_vers;
    wmi_mac_addr mac_addr;
    A_UINT32    status;
} wmi_ready_event_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_resource_config */
/**
 * @brief num_vdev - number of virtual devices (VAPs) to support
 */
    A_UINT32 num_vdevs;
/**
 * @brief num_peers - number of peer nodes to support
 */
    A_UINT32 num_peers;
/*
 * @brief In offload mode target supports features like WOW, chatter and other
 * protocol offloads. In order to support them some functionalities like
 * reorder buffering, PN checking need to be done in target. This determines
 * maximum number of peers suported by target in offload mode
 */
    A_UINT32 num_offload_peers;
/* @brief Number of reorder buffers available for doing target based reorder
 * Rx reorder buffering
 */
    A_UINT32 num_offload_reorder_buffs;
/**
 * @brief num_peer_keys - number of keys per peer
 */
    A_UINT32 num_peer_keys;
/**
 * @brief num_peer_tids - number of TIDs to provide storage for per peer.
 */
    A_UINT32 num_tids;
/**
 * @brief ast_skid_limit - max skid for resolving hash collisions
 * @details
 *     The address search table is sparse, so that if two MAC addresses
 *     result in the same hash value, the second of these conflicting
 *     entries can slide to the next index in the address search table,
 *     and use it, if it is unoccupied.  This ast_skid_limit parameter
 *     specifies the upper bound on how many subsequent indices to search
 *     over to find an unoccupied space.
 */
    A_UINT32 ast_skid_limit;
/**
 * @brief tx_chain_mask - the nominal chain mask for transmit
 * @details
 *     The chain mask may be modified dynamically, e.g. to operate AP tx with
 *     a reduced number of chains if no clients are associated.
 *     This configuration parameter specifies the nominal chain-mask that
 *     should be used when not operating with a reduced set of tx chains.
 */
    A_UINT32 tx_chain_mask;
/**
 * @brief rx_chain_mask - the nominal chain mask for receive
 * @details
 *     The chain mask may be modified dynamically, e.g. for a client to use
 *     a reduced number of chains for receive if the traffic to the client
 *     is low enough that it doesn't require downlink MIMO or antenna
 *     diversity.
 *     This configuration parameter specifies the nominal chain-mask that
 *     should be used when not operating with a reduced set of rx chains.
 */
    A_UINT32 rx_chain_mask;
/**
 * @brief rx_timeout_pri - what rx reorder timeout (ms) to use for the AC
 * @details
 *     Each WMM access class (voice, video, best-effort, background) will
 *     have its own timeout value to dictate how long to wait for missing
 *     rx MPDUs to arrive before flushing subsequent MPDUs that have already
 *     been received.
 *     This parameter specifies the timeout in milliseconds for each class .
 *     NOTE: the number of class (defined as 4) cannot be
 *     changed in the future without breaking WMI compatibility.
 */
    A_UINT32 rx_timeout_pri[4];
/**
 * @brief rx_decap mode - what mode the rx should decap packets to
 * @details
 *     MAC can decap to RAW (no decap), native wifi or Ethernet types
 *     THis setting also determines the default TX behavior, however TX
 *     behavior can be modified on a per VAP basis during VAP init
 */
    A_UINT32 rx_decap_mode;
 /**
  * @brief  scan_max_pending_req - what is the maximum scan requests than can be queued
  */
    A_UINT32 scan_max_pending_req;

    /**
     * @brief maximum VDEV that could use BMISS offload
     */
    A_UINT32 bmiss_offload_max_vdev;

    /**
     * @brief maximum VDEV that could use offload roaming
     */
    A_UINT32 roam_offload_max_vdev;

    /**
     * @brief maximum AP profiles that would push to offload roaming
     */
    A_UINT32 roam_offload_max_ap_profiles;

/**
 * @brief num_mcast_groups - how many groups to use for mcast->ucast conversion
 * @details
 *     The target's WAL maintains a table to hold information regarding which
 *     peers belong to a given multicast group, so that if multicast->unicast
 *     conversion is enabled, the target can convert multicast tx frames to a
 *     series of unicast tx frames, to each peer within the multicast group.
 *     This num_mcast_groups configuration parameter tells the target how
 *     many multicast groups to provide storage for within its multicast
 *     group membership table.
 */
    A_UINT32 num_mcast_groups;

/**
 * @brief num_mcast_table_elems - size to alloc for the mcast membership table
 * @details
 *     This num_mcast_table_elems configuration parameter tells the target
 *     how many peer elements it needs to provide storage for in its
 *     multicast group membership table.
 *     These multicast group membership table elements are shared by the
 *     multicast groups stored within the table.
 */
    A_UINT32 num_mcast_table_elems;

/**
 * @brief mcast2ucast_mode - whether/how to do multicast->unicast conversion
 * @details
 *     This configuration parameter specifies whether the target should
 *     perform multicast --> unicast conversion on transmit, and if so,
 *     what to do if it finds no entries in its multicast group membership
 *     table for the multicast IP address in the tx frame.
 *     Configuration value:
 *     0 -> Do not perform multicast to unicast conversion.
 *     1 -> Convert multicast frames to unicast, if the IP multicast address
 *          from the tx frame is found in the multicast group membership
 *          table.  If the IP multicast address is not found, drop the frame.
 *     2 -> Convert multicast frames to unicast, if the IP multicast address
 *          from the tx frame is found in the multicast group membership
 *          table.  If the IP multicast address is not found, transmit the
 *          frame as multicast.
 */
    A_UINT32 mcast2ucast_mode;


 /**
  * @brief tx_dbg_log_size - how much memory to allocate for a tx PPDU dbg log
  * @details
  *     This parameter controls how much memory the target will allocate to
  *     store a log of tx PPDU meta-information (how large the PPDU was,
  *     when it was sent, whether it was successful, etc.)
  */
    A_UINT32 tx_dbg_log_size;

 /**
  * @brief num_wds_entries - how many AST entries to be allocated for WDS
  */
    A_UINT32 num_wds_entries;

 /**
  * @brief dma_burst_size - MAC DMA burst size, e.g., on Peregrine on PCI
  * this limit can be 0 -default, 1 256B
  */
    A_UINT32 dma_burst_size;

  /**
   * @brief mac_aggr_delim - Fixed delimiters to be inserted after every MPDU
   * to account for interface latency to avoid underrun.
   */
    A_UINT32 mac_aggr_delim;
    /**
     * @brief rx_skip_defrag_timeout_dup_detection_check
     * @details
     *  determine whether target is responsible for detecting duplicate
     *  non-aggregate MPDU and timing out stale fragments.
     *
     *  A-MPDU reordering is always performed on the target.
     *
     *  0: target responsible for frag timeout and dup checking
     *  1: host responsible for frag timeout and dup checking
     */
    A_UINT32 rx_skip_defrag_timeout_dup_detection_check;

    /**
     * @brief vow_config - Configuration for VoW : No of Video Nodes to be supported
     * and Max no of descriptors for each Video link (node).
     */
    A_UINT32 vow_config;

    /**
     * @brief maximum VDEV that could use GTK offload
     */
	A_UINT32 gtk_offload_max_vdev;

    /**
     * @brief num_msdu_desc - Number of msdu descriptors target should use
     */
    A_UINT32 num_msdu_desc; /* Number of msdu desc */
 /**
  * @brief max_frag_entry - Max. number of Tx fragments per MSDU
  * @details
  *     This parameter controls the max number of Tx fragments per MSDU.
  *     This is sent by the target as part of the WMI_SERVICE_READY event
  *     and is overriden by the OS shim as required.
  */
    A_UINT32 max_frag_entries;

    /**
     * @brief num_tdls_vdevs - Max. number of vdevs that can support TDLS
     * @brief num_msdu_desc - Number of vdev that can support beacon offload
     */

    A_UINT32 num_tdls_vdevs; /* number of vdevs allowed to do tdls */

    /**
     * @brief num_tdls_conn_table_entries - Number of peers tracked by tdls vdev
     * @details
     *      Each TDLS enabled vdev can track outgoing transmits/rssi/rates to/of
     *      peers in a connection tracking table for possible TDLS link creation
     *      or deletion. This controls the number of tracked peers per vdev.
     */
    A_UINT32  num_tdls_conn_table_entries; /* number of peers to track per TDLS vdev */
     A_UINT32 beacon_tx_offload_max_vdev;
     A_UINT32 num_multicast_filter_entries;
} wmi_resource_config;


typedef struct {
    A_UINT32   tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_init_cmd_fixed_param */

    /** The following indicate the WMI versions to be supported by
     *  the host driver. Note that the host driver decide to
     *  "downgrade" its WMI version support and this may not be the
     *  native version of the host driver. */
    wmi_abi_version  host_abi_vers;

    A_UINT32   num_host_mem_chunks; /** size of array host_mem_chunks[] */
    /* The TLVs for resource_config and host_mem_chunks[] will follow.
     *     wmi_resource_config   resource_config;
     *     wlan_host_memory_chunk host_mem_chunks[];
     */

} wmi_init_cmd_fixed_param;

/**
 * TLV for channel list
 */
typedef struct {
    /** WMI_CHAN_LIST_TAG */
    A_UINT32     tag;
    /** # if channels to scan */
    A_UINT32 num_chan;
    /** channels in Mhz */
    A_UINT32 channel_list[1];
} wmi_chan_list;


/**
 * TLV for bssid list
 */
typedef struct {
    /** WMI_BSSID_LIST_TAG */
    A_UINT32     tag;
    /** number of bssids   */
    A_UINT32 num_bssid;
    /** bssid list         */
    wmi_mac_addr bssid_list[1];
} wmi_bssid_list;

/**
 * TLV for  ie data.
 */
typedef struct {
    /** WMI_IE_TAG */
    A_UINT32     tag;
    /** number of bytes in ie data   */
    A_UINT32 ie_len;
    /** ie data array  (ie_len adjusted to  number of words  (ie_len + 4)/4 )  */
    A_UINT32 ie_data[1];
} wmi_ie_data;


typedef struct {
    /** Len of the SSID */
    A_UINT32     ssid_len;
    /** SSID */
    A_UINT32     ssid[8];
} wmi_ssid;

typedef struct {
    /** WMI_SSID_LIST_TAG */
    A_UINT32     tag;
    A_UINT32     num_ssids;
    wmi_ssid ssids[1];
} wmi_ssid_list;

/* prefix used by scan requestor ids on the host */
#define WMI_HOST_SCAN_REQUESTOR_ID_PREFIX 0xA000
/* prefix used by scan request ids generated on the host */
/* host cycles through the lower 12 bits to generate ids */
#define WMI_HOST_SCAN_REQ_ID_PREFIX 0xA000

#define WLAN_SCAN_PARAMS_MAX_SSID    16
#define WLAN_SCAN_PARAMS_MAX_BSSID   4
#define WLAN_SCAN_PARAMS_MAX_IE_LEN  256

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_start_scan_cmd_fixed_param */
    /** Scan ID */
    A_UINT32 scan_id;
    /** Scan requestor ID */
    A_UINT32 scan_req_id;
    /** VDEV id(interface) that is requesting scan */
    A_UINT32 vdev_id;
    /** Scan Priority, input to scan scheduler */
    A_UINT32 scan_priority;
    /** Scan events subscription */
    A_UINT32 notify_scan_events;
    /** dwell time in msec on active channels */
    A_UINT32 dwell_time_active;
    /** dwell time in msec on passive channels */
    A_UINT32 dwell_time_passive;
    /** min time in msec on the BSS channel,only valid if atleast one VDEV is active*/
    A_UINT32 min_rest_time;
    /** max rest time in msec on the BSS channel,only valid if at least one VDEV is active*/
    /** the scanner will rest on the bss channel at least min_rest_time. after min_rest_time the scanner
     *  will start checking for tx/rx activity on all VDEVs. if there is no activity the scanner will
     *  switch to off channel. if there is activity the scanner will let the radio on the bss channel
     *  until max_rest_time expires.at max_rest_time scanner will switch to off channel
     *  irrespective of activity. activity is determined by the idle_time parameter.
     */
    A_UINT32  max_rest_time;
    /** time before sending next set of probe requests.
     *   The scanner keeps repeating probe requests transmission with period specified by repeat_probe_time.
     *   The number of probe requests specified depends on the ssid_list and bssid_list
     */
    A_UINT32  repeat_probe_time;
    /** time in msec between 2 consequetive probe requests with in a set. */
    A_UINT32  probe_spacing_time;
    /** data inactivity time in msec on bss channel that will be used by scanner for measuring the inactivity  */
    A_UINT32 idle_time;
    /** maximum time in msec allowed for scan  */
    A_UINT32  max_scan_time;
    /** delay in msec before sending first probe request after switching to a channel */
    A_UINT32  probe_delay;
    /** Scan control flags */
    A_UINT32 scan_ctrl_flags;
    /** Burst duration time in msec*/
    A_UINT32 burst_duration;

    /** # if channels to scan. In the TLV channel_list[] */
    A_UINT32 num_chan;
    /** number of bssids. In the TLV bssid_list[] */
    A_UINT32 num_bssid;
    /** number of ssid. In the TLV ssid_list[] */
    A_UINT32     num_ssids;
    /** number of bytes in ie data. In the TLV ie_data[] */
    A_UINT32 ie_len;

    /**
         * TLV (tag length value ) parameters follow the scan_cmd
         * structure. The TLV's are:
         *     A_UINT32 channel_list[];
         *     wmi_ssid ssid_list[];
         *     wmi_mac_addr bssid_list[];
         *     A_UINT8 ie_data[];
         */
} wmi_start_scan_cmd_fixed_param;

/**
 * scan control flags.
 */

/** passively scan all channels including active channels */
#define WMI_SCAN_FLAG_PASSIVE        0x1
/** add wild card ssid probe request even though ssid_list is specified. */
#define WMI_SCAN_ADD_BCAST_PROBE_REQ 0x2
/** add cck rates to rates/xrate ie for the generated probe request */
#define WMI_SCAN_ADD_CCK_RATES 0x4
/** add ofdm rates to rates/xrate ie for the generated probe request */
#define WMI_SCAN_ADD_OFDM_RATES 0x8
/** To enable indication of Chan load and Noise floor to host */
#define WMI_SCAN_CHAN_STAT_EVENT 0x10
/** Filter Probe request frames  */
#define WMI_SCAN_FILTER_PROBE_REQ 0x20
/**When set, not to scan DFS channels*/
#define WMI_SCAN_BYPASS_DFS_CHN 0x40
/**When set, certain errors are ignored and scan continues.
* Different FW scan engine may use its own logic to decide what errors to ignore*/
#define WMI_SCAN_CONTINUE_ON_ERROR 0x80

/** WMI_SCAN_CLASS_MASK must be the same value as IEEE80211_SCAN_CLASS_MASK */
#define WMI_SCAN_CLASS_MASK 0xFF000000

/*
* Masks identifying types/ID of scans
* Scan_Stop macros should be the same value as below defined in UMAC
* #define IEEE80211_SPECIFIC_SCAN       0x00000000
* #define IEEE80211_VAP_SCAN            0x01000000
* #define IEEE80211_ALL_SCANS           0x04000000
*/
#define WMI_SCAN_STOP_ONE       0x00000000
#define WMI_SCN_STOP_VAP_ALL    0x01000000
#define WMI_SCAN_STOP_ALL       0x04000000

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_stop_scan_cmd_fixed_param */
    /** requestor requesting cancel  */
    A_UINT32 requestor;
    /** Scan ID */
    A_UINT32 scan_id;
    /**
    * Req Type
    * req_type should be WMI_SCAN_STOP_ONE, WMI_SCN_STOP_VAP_ALL or WMI_SCAN_STOP_ALL
    * WMI_SCAN_STOP_ONE indicates to stop a specific scan with scan_id
    * WMI_SCN_STOP_VAP_ALL indicates to stop all scan requests on a specific vDev with vdev_id
    * WMI_SCAN_STOP_ALL indicates to stop all scan requests in both Scheduler's queue and Scan Engine
    */
    A_UINT32 req_type;
    /**
    * vDev ID
    * used when req_type equals to WMI_SCN_STOP_VAP_ALL, it indexed the vDev on which to stop the scan
    */
    A_UINT32 vdev_id;
} wmi_stop_scan_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_scan_chan_list_cmd_fixed_param */
    A_UINT32 num_scan_chans;  /** no of elements in chan_info[] */
    /** Followed by the variable length TLV chan_info:
     *  wmi_channel chan_info[] */
} wmi_scan_chan_list_cmd_fixed_param;

/*
 * Priority numbers must be sequential, starting with 0.
 */
 /* NOTE: WLAN SCAN_PRIORITY_COUNT can't be changed without breaking the compatibility */
typedef enum {
    WMI_SCAN_PRIORITY_VERY_LOW    = 0,
    WMI_SCAN_PRIORITY_LOW,
    WMI_SCAN_PRIORITY_MEDIUM,
    WMI_SCAN_PRIORITY_HIGH,
    WMI_SCAN_PRIORITY_VERY_HIGH,

    WMI_SCAN_PRIORITY_COUNT   /* number of priorities supported */
} wmi_scan_priority;

/* Five Levels for Requested Priority */
/* VERY_LOW LOW  MEDIUM   HIGH  VERY_HIGH */
typedef A_UINT32 WLAN_PRIORITY_MAPPING[WMI_SCAN_PRIORITY_COUNT];

/**
* to keep align with UMAC implementation, we pass only vdev_type but not vdev_subtype when we overwrite an entry for a specific vdev_subtype
* ex. if we need overwrite P2P Client prority entry, we will overwrite the whole table for WLAN_M_STA
* we will generate the new WLAN_M_STA table with modified P2P Client Entry but keep STA entry intact
*/
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_scan_sch_priority_table_cmd_fixed_param */
    /**
    * used as an index to find the proper table for a specific vdev type in default_scan_priority_mapping_table
    * vdev_type should be one of enum in WLAN_OPMODE which inculdes WLAN_M_IBSS, WLAN_M_STA, WLAN_M_AP and WLAN_M_MONITOR currently
    */
    A_UINT32      vdev_type;
    /**
    * number of rows in mapping_table for a specific vdev
    * for WLAN_M_STA type, there are 3 entries in the table (refer to default_scan_priority_mapping_table definition)
    */
    A_UINT32                    number_rows;
    /**  mapping_table for a specific vdev follows this TLV
      *   WLAN_PRIORITY_MAPPING mapping_table[]; */
}wmi_scan_sch_priority_table_cmd_fixed_param;

/** update flags */
#define WMI_SCAN_UPDATE_SCAN_PRIORITY           0x1
#define WMI_SCAN_UPDATE_SCAN_MIN_REST_TIME      0x2
#define WMI_SCAN_UPDATE_SCAN_MAX_REST_TIME      0x4

typedef struct {
    A_UINT32 tlv_header;
    /** requestor requesting update scan request  */
    A_UINT32 requestor;
    /** Scan ID of the scan request that need to be update */
    A_UINT32 scan_id;
    /** update flags, indicating which of the following fields are valid and need to be updated*/
    A_UINT32 scan_update_flags;
    /** scan priority. Only valid if WMI_SCAN_UPDATE_SCAN_PRIORITY flag is set in scan_update_flag */
    A_UINT32 scan_priority;
    /** min rest time. Only valid if WMI_SCAN_UPDATE_MIN_REST_TIME flag is set in scan_update_flag */
    A_UINT32 min_rest_time;
    /** min rest time. Only valid if WMI_SCAN_UPDATE_MAX_REST_TIME flag is set in scan_update_flag */
    A_UINT32 max_rest_time;
} wmi_scan_update_request_cmd_fixed_param;

enum wmi_scan_event_type {
    WMI_SCAN_EVENT_STARTED=0x1,
    WMI_SCAN_EVENT_COMPLETED=0x2,
    WMI_SCAN_EVENT_BSS_CHANNEL=0x4,
    WMI_SCAN_EVENT_FOREIGN_CHANNEL = 0x8,
    WMI_SCAN_EVENT_DEQUEUED=0x10,       /* scan request got dequeued */
    WMI_SCAN_EVENT_PREEMPTED=0x20,		/* preempted by other high priority scan */
    WMI_SCAN_EVENT_START_FAILED=0x40,   /* scan start failed */
    WMI_SCAN_EVENT_RESTARTED=0x80,      /*scan restarted*/
    WMI_SCAN_EVENT_MAX=0x8000
};

enum wmi_scan_completion_reason {
    /** scan related events */
    WMI_SCAN_REASON_NONE                = 0xFF,
    WMI_SCAN_REASON_COMPLETED           = 0,
    WMI_SCAN_REASON_CANCELLED           = 1,
    WMI_SCAN_REASON_PREEMPTED           = 2,
    WMI_SCAN_REASON_TIMEDOUT            = 3,
    WMI_SCAN_REASON_INTERNAL_FAILURE    = 4, /* This reason indication failures when performaing scan */
    WMI_SCAN_REASON_MAX,
};

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_scan_event_fixed_param */
    /** scan event (wmi_scan_event_type) */
    A_UINT32 event;
    /** status of the scan completion event */
    A_UINT32 reason;
    /** channel freq , only valid for FOREIGN channel event*/
    A_UINT32 channel_freq;
    /**id of the requestor whose scan is in progress */
    A_UINT32 requestor;
    /**id of the scan that is in progress */
    A_UINT32 scan_id;
    /**id of VDEV that requested the scan */
    A_UINT32 vdev_id;
} wmi_scan_event_fixed_param;

/*
 * This defines how much headroom is kept in the
 * receive frame between the descriptor and the
 * payload, in order for the WMI PHY error and
 * management handler to insert header contents.
 *
 * This is in bytes.
 */
#define WMI_MGMT_RX_HDR_HEADROOM    sizeof(wmi_comb_phyerr_rx_hdr) + WMI_TLV_HDR_SIZE + sizeof(wmi_single_phyerr_rx_hdr)

/** This event will be used for sending scan results
 * as well as rx mgmt frames to the host. The rx buffer
 * will be sent as part of this WMI event. It would be a
 * good idea to pass all the fields in the RX status
 * descriptor up to the host.
 */
 /* ATH_MAX_ANTENNA value (4) can't be changed without breaking the compatibility */
#define ATH_MAX_ANTENNA 4 /* To support 4 chains */
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_mgmt_rx_hdr */
    /** channel on which this frame is received. */
    A_UINT32 channel;
    /** snr information used to cal rssi */
    A_UINT32 snr;
    /** Rate kbps */
    A_UINT32 rate;
    /** rx phy mode WLAN_PHY_MODE */
    A_UINT32 phy_mode;
    /** length of the frame */
    A_UINT32 buf_len;
    /** rx status */
    A_UINT32 status;
    /** RSSI of PRI 20MHz for each chain. */
    A_UINT32 rssi_ctl[ATH_MAX_ANTENNA];
    /* This TLV is followed by array of bytes:
         * // management frame buffer
         *   A_UINT8 bufp[];
         */
} wmi_mgmt_rx_hdr;

/* WMI PHY Error RX */

typedef struct {
    /** TSF timestamp */
    A_UINT32 tsf_timestamp;

    /**
     * Current freq1, freq2
     *
     * [7:0]:    freq1[lo]
     * [15:8] :   freq1[hi]
     * [23:16]:   freq2[lo]
     * [31:24]:   freq2[hi]
     */
    A_UINT32 freq_info_1;

    /**
     * Combined RSSI over all chains and channel width for this PHY error
     *
     * [7:0]: RSSI combined
     * [15:8]: Channel width (MHz)
     * [23:16]: PHY error code
     * [24:16]: reserved (future use)
     */
    A_UINT32 freq_info_2;

    /**
     * RSSI on chain 0 through 3
     *
     * This is formatted the same as the PPDU_START RX descriptor
     * field:
     *
     * [7:0]:   pri20
     * [15:8]:  sec20
     * [23:16]: sec40
     * [31:24]: sec80
     */
    A_UINT32 rssi_chain0;
    A_UINT32 rssi_chain1;
    A_UINT32 rssi_chain2;
    A_UINT32 rssi_chain3;

   /**
     * Last calibrated NF value for chain 0 through 3
     *
     * nf_list_1:
     *
     * + [15:0] - chain 0
     * + [31:16] - chain 1
     *
     * nf_list_2:
     *
     * + [15:0] - chain 2
     * + [31:16] - chain 3
     */
    A_UINT32 nf_list_1;
    A_UINT32 nf_list_2;

    /** Length of the frame */
    A_UINT32 buf_len;
} wmi_single_phyerr_rx_hdr;

#define WMI_UNIFIED_FREQINFO_1_LO   0x000000ff
#define WMI_UNIFIED_FREQINFO_1_LO_S 0
#define WMI_UNIFIED_FREQINFO_1_HI   0x0000ff00
#define WMI_UNIFIED_FREQINFO_1_HI_S 8
#define WMI_UNIFIED_FREQINFO_2_LO   0x00ff0000
#define WMI_UNIFIED_FREQINFO_2_LO_S 16
#define WMI_UNIFIED_FREQINFO_2_HI   0xff000000
#define WMI_UNIFIED_FREQINFO_2_HI_S 24

/*
 * Please keep in mind that these _SET macros break macro side effect
 * assumptions; don't be clever with them.
 */
#define WMI_UNIFIED_FREQ_INFO_GET(hdr, f)                                   \
            ( WMI_F_MS( (hdr)->freq_info_1,                                 \
              WMI_UNIFIED_FREQINFO_##f##_LO )                               \
              | (WMI_F_MS( (hdr)->freq_info_1,                              \
                 WMI_UNIFIED_FREQINFO_##f##_HI ) << 8) )

#define WMI_UNIFIED_FREQ_INFO_SET(hdr, f, v)                                \
        do {                                                                \
            WMI_F_RMW((hdr)->freq_info_1, (v) & 0xff,                       \
              WMI_UNIFIED_FREQINFO_##f##_LO);                               \
            WMI_F_RMW((hdr)->freq_info_1, ((v) >> 8) & 0xff,                \
                WMI_UNIFIED_FREQINFO_##f##_HI);                             \
        } while (0)

#define WMI_UNIFIED_FREQINFO_2_RSSI_COMB    0x000000ff
#define WMI_UNIFIED_FREQINFO_2_RSSI_COMB_S  0
#define WMI_UNIFIED_FREQINFO_2_CHWIDTH      0x0000ff00
#define WMI_UNIFIED_FREQINFO_2_CHWIDTH_S    8
#define WMI_UNIFIED_FREQINFO_2_PHYERRCODE   0x00ff0000
#define WMI_UNIFIED_FREQINFO_2_PHYERRCODE_S 16

#define WMI_UNIFIED_RSSI_COMB_GET(hdr)                                      \
            ( (int8_t) (WMI_F_MS((hdr)->freq_info_2,                        \
                WMI_UNIFIED_FREQINFO_2_RSSI_COMB)))

#define WMI_UNIFIED_RSSI_COMB_SET(hdr, v)                                   \
            WMI_F_RMW((hdr)->freq_info_2, (v) & 0xff,                       \
              WMI_UNIFIED_FREQINFO_2_RSSI_COMB);

#define WMI_UNIFIED_CHWIDTH_GET(hdr)                                        \
            WMI_F_MS((hdr)->freq_info_2, WMI_UNIFIED_FREQINFO_2_CHWIDTH)

#define WMI_UNIFIED_CHWIDTH_SET(hdr, v)                                     \
            WMI_F_RMW((hdr)->freq_info_2, (v) & 0xff,                       \
              WMI_UNIFIED_FREQINFO_2_CHWIDTH);

#define WMI_UNIFIED_PHYERRCODE_GET(hdr)                                     \
            WMI_F_MS((hdr)->freq_info_2, WMI_UNIFIED_FREQINFO_2_PHYERRCODE)

#define WMI_UNIFIED_PHYERRCODE_SET(hdr, v)                                  \
            WMI_F_RMW((hdr)->freq_info_2, (v) & 0xff,                       \
              WMI_UNIFIED_FREQINFO_2_PHYERRCODE);

#define WMI_UNIFIED_CHAIN_0     0x0000ffff
#define WMI_UNIFIED_CHAIN_0_S   0
#define WMI_UNIFIED_CHAIN_1     0xffff0000
#define WMI_UNIFIED_CHAIN_1_S   16
#define WMI_UNIFIED_CHAIN_2     0x0000ffff
#define WMI_UNIFIED_CHAIN_2_S   0
#define WMI_UNIFIED_CHAIN_3     0xffff0000
#define WMI_UNIFIED_CHAIN_3_S   16

#define WMI_UNIFIED_CHAIN_0_FIELD   nf_list_1
#define WMI_UNIFIED_CHAIN_1_FIELD   nf_list_1
#define WMI_UNIFIED_CHAIN_2_FIELD   nf_list_2
#define WMI_UNIFIED_CHAIN_3_FIELD   nf_list_2

#define WMI_UNIFIED_NF_CHAIN_GET(hdr, c)                                    \
            ((int16_t) (WMI_F_MS((hdr)->WMI_UNIFIED_CHAIN_##c##_FIELD,      \
              WMI_UNIFIED_CHAIN_##c)))

#define WMI_UNIFIED_NF_CHAIN_SET(hdr, c, nf)                                \
            WMI_F_RMW((hdr)->WMI_UNIFIED_CHAIN_##c##_FIELD, (nf) & 0xffff,  \
              WMI_UNIFIED_CHAIN_##c);

/*
 * For now, this matches what the underlying hardware is doing.
 * Update ar6000ProcRxDesc() to use these macros when populating
 * the rx descriptor and then we can just copy the field over
 * to the WMI PHY notification without worrying about breaking
 * things.
 */
#define WMI_UNIFIED_RSSI_CHAN_PRI20     0x000000ff
#define WMI_UNIFIED_RSSI_CHAN_PRI20_S   0
#define WMI_UNIFIED_RSSI_CHAN_SEC20     0x0000ff00
#define WMI_UNIFIED_RSSI_CHAN_SEC20_S   8
#define WMI_UNIFIED_RSSI_CHAN_SEC40     0x00ff0000
#define WMI_UNIFIED_RSSI_CHAN_SEC40_S   16
#define WMI_UNIFIED_RSSI_CHAN_SEC80     0xff000000
#define WMI_UNIFIED_RSSI_CHAN_SEC80_S   24

#define WMI_UNIFIED_RSSI_CHAN_SET(hdr, c, ch, rssi)                         \
            WMI_F_RMW((hdr)->rssi_chain##c, (rssi) & 0xff,                  \
              WMI_UNIFIED_RSSI_CHAN_##ch);

#define WMI_UNIFIED_RSSI_CHAN_GET(hdr, c, ch)                               \
            ((int8_t) (WMI_F_MS((hdr)->rssi_chain##c,                       \
              WMI_UNIFIED_RSSI_CHAN_##ch)))

typedef struct {
    /** Phy error event header */
    wmi_single_phyerr_rx_hdr hdr;
    /** frame buffer */
    A_UINT8 bufp[1];
}wmi_single_phyerr_rx_event;

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_comb_phyerr_rx_hdr */
    /** Phy error phy error count */
    A_UINT32 num_phyerr_events;
    A_UINT32 tsf_l32;
    A_UINT32 tsf_u32;
    A_UINT32 buf_len;
    /* This TLV is followed by array of bytes:
         * // frame buffer - contains multiple payloads in the order:
         * // header - payload, header - payload...
         *  (The header is of type: wmi_single_phyerr_rx_hdr)
         *   A_UINT8 bufp[];
         */
} wmi_comb_phyerr_rx_hdr;

/* WMI MGMT TX  */
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_mgmt_tx_hdr */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** xmit rate */
    A_UINT32 tx_rate;
    /** xmit power */
    A_UINT32 tx_power;
    /** Buffer length in bytes */
    A_UINT32 buf_len;
    /* This TLV is followed by array of bytes:
         * // management frame buffer
         *   A_UINT8 bufp[];
         */
} wmi_mgmt_tx_hdr;

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_echo_event_fixed_param */
    A_UINT32 value;
} wmi_echo_event_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_echo_cmd_fixed_param */
    A_UINT32 value;
}wmi_echo_cmd_fixed_param;


typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_set_regdomain_cmd_fixed_param */

    A_UINT32 reserved0;      /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    /** reg domain code */
    A_UINT32 reg_domain;
    A_UINT32 reg_domain_2G;
    A_UINT32 reg_domain_5G;
    A_UINT32 conformance_test_limit_2G;
    A_UINT32 conformance_test_limit_5G;
} wmi_pdev_set_regdomain_cmd_fixed_param;

typedef struct {
    /** TRUE for scan start and flase for scan end */
    A_UINT32 scan_start;
} wmi_pdev_scan_cmd;

//currently, only RTT measurement has been implemented

/*
 * Mesage format for WMI_RTT_TSF_CMDID
 * This CMD trigger FW to report TSF Measurement result to host
 */
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_rtt_tsf_cmd_fixed_param */
    A_UINT32 req_id;               //unique request ID for this TSF measure req
    wmi_mac_addr dest_mac;        //destination mac address for measurement
    wmi_mac_addr spoof_bssid;     //spoof BSSID for measurement with unassociated STA
    A_UINT32 vdev_id;              // vdev used for TSF
    A_UINT32 time_out;             //timeout for this TSF mesurement (ms)
    /* This TLV is followed by below TLVs:
     *     wmi_channel channel;          //channel information for this Requirement
     */
}wmi_rtt_tsf_cmd_fixed_param;

/*
 * Mesage format for WMI_RTT_MEASREQ_CMDID
 * This CMD trigger FW to start measurement with a peer
 * Need be careful about 32 alignment if any change made in future
 */
typedef struct { //any new change need take care of 32 alignment
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_rtt_measreq_body */
    A_UINT32 control_flag;       // some control information here
  /*********************************************************************************
   *Bits 1:0:   Reserved
   *Bits 4:2:   802.11 Frame Type to measure RTT
   *            000: NULL, 001: Qos NULL, 010: TMR-TM
   *Bits 8:5:   Tx chain mask used for transmission 0000 - 1111
   *Bits 12:9:  Receive chainmask to use for reception 0000 - 1111
   *Bits 13:13  peer is qca chip or not
   *Bits 15:14: BW 0- 20MHz 1- 40MHz 2- 80MHz 3 - 160 MHz
   *Bits 17:16: Preamble 0- Legacy 2- HT 3-VHT
   *Bits 21:18: Retry times
   *Bits 29:22  MCS
   *Bits 31:30  Reserved
   *********************************************************************************/
    A_UINT32 measure_info;
    /*******************************************************************************
     *Bit 0-7 vdev_id vdev used for RTT
     *Bit 15-8 num_meas #of measurements of each peer
     *Bit 23:16 timeout for this rtt mesurement (ms)
     *Bit 31-24 report_type
     *******************************************************************************/
    wmi_mac_addr dest_mac;      //destination mac address for measurement
    wmi_mac_addr spoof_bssid;   //spoof BSSID for measurement with unassociated STA
}wmi_rtt_measreq_body;

typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_rtt_measreq_head */
    A_UINT32 req_id;                //unique request ID for this RTT measure req
    /******************************************************************************
     *bit 15:0       Request ID
     *bit 16:        sps enable  0- unenable  1--enable
     *bit 31:17      reserved
	 ******************************************************************************/
    A_UINT32 sta_num;               // how many number of STA in this RTT requirement
    /******************************************************************************
     *bit 7:0        # of measurement peers
     *bit 23:8       if  sps, time delay for SPS (ms)
     *bit 31:24      reserved
	 ******************************************************************************/
    /* This TLV is followed by below TLVs
     *    wmi_channel channel;            // common channel information for this Requirement
     *    wmi_rtt_measreq_body body[];
     */
} wmi_rtt_measreq_head;

//Bit map macro define for RTT measurement command
#define RTT_MEAS_FRAME_NULL 0
#define RTT_MEAS_FRAME_QOSNULL 1
#define RTT_MEAS_FRAME_TMR 2

#define WMI_RTT_BW_20 0
#define WMI_RTT_BW_40 1
#define WMI_RTT_BW_80 2
#define WMI_RTT_BW_160 3

#define WMI_RTT_PREAM_LEGACY 0
#define WMI_RTT_PREAM_HT 2
#define WMI_RTT_PREAM_VHT 3

#define WMI_RTT_REQ_ID_S 0
#define WMI_RTT_REQ_ID (0xffff << WMI_RTT_REQ_ID_S)
#define WMI_RTT_REQ_ID_GET(x) WMI_F_MS(x,WMI_RTT_REQ_ID)
#define WMI_RTT_REQ_ID_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REQ_ID)

//SPS here is synchronized power save
#define WMI_RTT_SPS_S 16
#define WMI_RTT_SPS (0x1 << WMI_RTT_SPS_S)
#define WMI_RTT_SPS_GET(x) WMI_F_MS(x,WMI_RTT_SPS)
#define WMI_RTT_SPS_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_SPS)

#define WMI_RTT_NUM_STA_S 0
#define WMI_RTT_NUM_STA (0xff << WMI_RTT_NUM_STA_S)
#define WMI_RTT_NUM_STA_GET(x) WMI_F_MS(x,WMI_RTT_NUM_STA)
#define WMI_RTT_NUM_STA_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_NUM_STA)

#define WMI_RTT_SPS_DELAY_S 8
#define WMI_RTT_SPS_DELAY (0xffff << WMI_RTT_SPS_DELAY_S)
#define WMI_RTT_SPS_DELAY_GET(x) WMI_F_MS(x,WMI_RTT_SPS_DELAY)
#define WMI_RTT_SPS_DELAY_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_SPS_DELAY)

//req body Macro
#define WMI_RTT_FRAME_TYPE_S 2
#define WMI_RTT_FRAME_TYPE (7 << WMI_RTT_FRAME_TYPE_S)
#define WMI_RTT_FRAME_TYPE_GET(x) WMI_F_MS(x,WMI_RTT_FRAME_TYPE)
#define WMI_RTT_FRAME_TYPE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_FRAME_TYPE)

#define WMI_RTT_TX_CHAIN_S 5
#define WMI_RTT_TX_CHAIN (0xf << WMI_RTT_TX_CHAIN_S)
#define WMI_RTT_TX_CHAIN_GET(x) WMI_F_MS(x,WMI_RTT_TX_CHAIN)
#define WMI_RTT_TX_CHAIN_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_TX_CHAIN)

#define WMI_RTT_RX_CHAIN_S 9
#define WMI_RTT_RX_CHAIN (0xf << WMI_RTT_RX_CHAIN_S)
#define WMI_RTT_RX_CHAIN_GET(x) WMI_F_MS(x,WMI_RTT_RX_CHAIN)
#define WMI_RTT_RX_CHAIN_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RX_CHAIN)

#define WMI_RTT_QCA_PEER_S 13
#define WMI_RTT_QCA_PEER (0x1 << WMI_RTT_QCA_PEER_S)
#define WMI_RTT_QCA_PEER_GET(x) WMI_F_MS(x,WMI_RTT_QCA_PEER)
#define WMI_RTT_QCA_PEER_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_QCA_PEER)

#define WMI_RTT_BW_S 14
#define WMI_RTT_BW (0x3 <<WMI_RTT_BW_S)
#define WMI_RTT_BW_GET(x) WMI_F_MS(x,WMI_RTT_BW)
#define WMI_RTT_BW_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_BW)

#define WMI_RTT_PREAMBLE_S 16
#define WMI_RTT_PREAMBLE (0x3 <<WMI_RTT_PREAMBLE_S)
#define WMI_RTT_PREAMBLE_GET(x) WMI_F_MS(x,WMI_RTT_PREAMBLE)
#define WMI_RTT_PREAMBLE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_PREAMBLE)

#define WMI_RTT_RETRIES_S 18
#define WMI_RTT_RETRIES (0xf << WMI_RTT_RETRIES_S)
#define WMI_RTT_RETRIES_GET(x) WMI_F_MS(x,WMI_RTT_RETRIES)
#define WMI_RTT_RETRIES_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RETRIES)

#define WMI_RTT_MCS_S 22
#define WMI_RTT_MCS (0xff << WMI_RTT_MCS_S)
#define WMI_RTT_MCS_GET(x) WMI_F_MS(x,WMI_RTT_MCS)
#define WMI_RTT_MCS_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_MCS)

#define WMI_RTT_VDEV_ID_S 0
#define WMI_RTT_VDEV_ID (0xff << WMI_RTT_VDEV_ID_S)
#define WMI_RTT_VDEV_ID_GET(x) WMI_F_MS(x,WMI_RTT_VDEV_ID)
#define WMI_RTT_VDEV_ID_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_VDEV_ID)

#define WMI_RTT_MEAS_NUM_S 8
#define WMI_RTT_MEAS_NUM (0xff << WMI_RTT_MEAS_NUM_S)
#define WMI_RTT_MEAS_NUM_GET(x) WMI_F_MS(x,WMI_RTT_MEAS_NUM)
#define WMI_RTT_MEAS_NUM_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_MEAS_NUM)

#define WMI_RTT_TIMEOUT_S 16
#define WMI_RTT_TIMEOUT (0xff << WMI_RTT_TIMEOUT_S)
#define WMI_RTT_TIMEOUT_GET(x) WMI_F_MS(x,WMI_RTT_TIMEOUT)
#define WMI_RTT_TIMEOUT_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_TIMEOUT)

#define WMI_RTT_REPORT_TYPE_S 24
#define WMI_RTT_REPORT_TYPE (0x3 <<WMI_RTT_REPORT_TYPE_S)
#define WMI_RTT_REPORT_TYPE_GET(x) WMI_F_MS(x,WMI_RTT_REPORT_TYPE)
#define WMI_RTT_REPORT_TYPE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REPORT_TYPE)

/*---end of RTT COMMAND---*/

/*Command to set/unset chip in quiet mode*/
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_set_quiet_cmd_fixed_param */
    A_UINT32 reserved0;      /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
	A_UINT32 period;		/*period in TUs*/	
	A_UINT32 duration;		/*duration in TUs*/
	A_UINT32 next_start;	/*offset in TUs*/
        A_UINT32 enabled; 		/*enable/disable*/
} wmi_pdev_set_quiet_cmd_fixed_param;

/*
 * Command to enable/disable Green AP Power Save.
 * This helps conserve power during AP operation. When the AP has no
 * stations associated with it, the host can enable Green AP Power Save
 * to request the firmware to shut down all but one transmit and receive
 * chains.
 */
typedef struct {
    A_UINT32 tlv_header;         /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_green_ap_ps_enable_cmd_fixed_param */
    A_UINT32 reserved0;          /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    A_UINT32 enable;              /*1:enable, 0:disable*/
} wmi_pdev_green_ap_ps_enable_cmd_fixed_param;


#define MAX_HT_IE_LEN 32
typedef struct {
    A_UINT32 tlv_header;   /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_set_ht_ie_cmd_fixed_param */
    A_UINT32 reserved0;    /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    A_UINT32 ie_len;       /*length of the ht ie in the TLV ie_data[] */
    /** The TLV for the HT IE follows:
     *       A_UINT32 ie_data[];
     */
} wmi_pdev_set_ht_ie_cmd_fixed_param;

#define MAX_VHT_IE_LEN 32
typedef struct {
    A_UINT32 tlv_header;   /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_set_vht_ie_cmd_fixed_param */
    A_UINT32 reserved0;    /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    A_UINT32 ie_len;          /*length of the vht ie in the TLV ie_data[] */
    /** The TLV for the VHT IE follows:
     *       A_UINT32 ie_data[];
     */
} wmi_pdev_set_vht_ie_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;   /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_set_base_macaddr_cmd_fixed_param */
    A_UINT32 reserved0;    /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    wmi_mac_addr base_macaddr;
} wmi_pdev_set_base_macaddr_cmd_fixed_param;

/*
 * For now, the spectral configuration is global rather than
 * per-vdev.  The vdev is a placeholder and will be ignored
 * by the firmware.
 */
typedef struct {
        A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_spectral_configure_cmd_fixed_param */
        A_UINT32    vdev_id;
        A_UINT32    spectral_scan_count;
        A_UINT32    spectral_scan_period;
        A_UINT32    spectral_scan_priority;
        A_UINT32    spectral_scan_fft_size;
        A_UINT32    spectral_scan_gc_ena;
        A_UINT32    spectral_scan_restart_ena;
        A_UINT32    spectral_scan_noise_floor_ref;
        A_UINT32    spectral_scan_init_delay;
        A_UINT32    spectral_scan_nb_tone_thr;
        A_UINT32    spectral_scan_str_bin_thr;
        A_UINT32    spectral_scan_wb_rpt_mode;
        A_UINT32    spectral_scan_rssi_rpt_mode;
        A_UINT32    spectral_scan_rssi_thr;
        A_UINT32    spectral_scan_pwr_format;
        A_UINT32    spectral_scan_rpt_mode;
        A_UINT32    spectral_scan_bin_scale;
        A_UINT32    spectral_scan_dBm_adj;
        A_UINT32    spectral_scan_chn_mask;
} wmi_vdev_spectral_configure_cmd_fixed_param;

/*
 * Enabling, disabling and triggering the spectral scan
 * is a per-vdev operation.  That is, it will set channel
 * flags per vdev rather than globally; so concurrent scan/run
 * and multiple STA (eg p2p, tdls, multi-band STA) is possible.
 */
typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_spectral_enable_cmd_fixed_param */
    A_UINT32    vdev_id;
    /* 0 - ignore; 1 - trigger, 2 - clear trigger */
    A_UINT32    trigger_cmd;
    /* 0 - ignore; 1 - enable, 2 - disable */
    A_UINT32    enable_cmd;
} wmi_vdev_spectral_enable_cmd_fixed_param;

typedef enum {
WMI_CSA_IE_PRESENT = 0x00000001,
WMI_XCSA_IE_PRESENT = 0x00000002,
WMI_WBW_IE_PRESENT = 0x00000004,
WMI_CSWARP_IE_PRESENT = 0x00000008,
}WMI_CSA_EVENT_IES_PRESENT_FLAG;

/* wmi CSA receive event from beacon frame */
typedef struct{
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_csa_event_fixed_param */
    A_UINT32 i_fc_dur;
//  Bit 0-15: FC
//  Bit 16-31: DUR
    wmi_mac_addr i_addr1;
    wmi_mac_addr i_addr2;
    /* NOTE: size of array of csa_ie[], xcsa_ie[], and wb_ie[] cannot be
         * changed in the future without breaking WMI compatibility */
    A_UINT32 csa_ie[2];
    A_UINT32 xcsa_ie[2];
    A_UINT32 wb_ie[2];
    A_UINT32 cswarp_ie;
    A_UINT32 ies_present_flag; //WMI_CSA_EVENT_IES_PRESENT_FLAG
}wmi_csa_event_fixed_param;

typedef enum {
    /** TX chian mask */
    WMI_PDEV_PARAM_TX_CHAIN_MASK = 0x1,
    /** RX chian mask */
    WMI_PDEV_PARAM_RX_CHAIN_MASK,
    /** TX power limit for 2G Radio */
    WMI_PDEV_PARAM_TXPOWER_LIMIT2G,
    /** TX power limit for 5G Radio */
    WMI_PDEV_PARAM_TXPOWER_LIMIT5G,
    /** TX power scale */
    WMI_PDEV_PARAM_TXPOWER_SCALE,
    /** Beacon generation mode . 0: host, 1: target   */
    WMI_PDEV_PARAM_BEACON_GEN_MODE,
    /** Beacon generation mode . 0: staggered 1: bursted   */
    WMI_PDEV_PARAM_BEACON_TX_MODE,
    /** Resource manager off chan mode .
     * 0: turn off off chan mode. 1: turn on offchan mode
     */
    WMI_PDEV_PARAM_RESMGR_OFFCHAN_MODE,
    /** Protection mode  0: no protection 1:use CTS-to-self 2: use RTS/CTS */
    WMI_PDEV_PARAM_PROTECTION_MODE,
    /** Dynamic bandwidth 0: disable 1: enable */
    WMI_PDEV_PARAM_DYNAMIC_BW,
    /** Non aggregrate/ 11g sw retry threshold.0-disable */
    WMI_PDEV_PARAM_NON_AGG_SW_RETRY_TH,
    /** aggregrate sw retry threshold. 0-disable*/
    WMI_PDEV_PARAM_AGG_SW_RETRY_TH,
    /** Station kickout threshold (non of consecutive failures).0-disable */
    WMI_PDEV_PARAM_STA_KICKOUT_TH,
    /** Aggerate size scaling configuration per AC */
    WMI_PDEV_PARAM_AC_AGGRSIZE_SCALING,
    /** LTR enable */
    WMI_PDEV_PARAM_LTR_ENABLE,
    /** LTR latency for BE, in us */
    WMI_PDEV_PARAM_LTR_AC_LATENCY_BE,
    /** LTR latency for BK, in us */
    WMI_PDEV_PARAM_LTR_AC_LATENCY_BK,
    /** LTR latency for VI, in us */
    WMI_PDEV_PARAM_LTR_AC_LATENCY_VI,
    /** LTR latency for VO, in us  */
    WMI_PDEV_PARAM_LTR_AC_LATENCY_VO,
    /** LTR AC latency timeout, in ms */
    WMI_PDEV_PARAM_LTR_AC_LATENCY_TIMEOUT,
    /** LTR platform latency override, in us */
    WMI_PDEV_PARAM_LTR_SLEEP_OVERRIDE,
    /** LTR-M override, in us */
    WMI_PDEV_PARAM_LTR_RX_OVERRIDE,
    /** Tx activity timeout for LTR, in us */
    WMI_PDEV_PARAM_LTR_TX_ACTIVITY_TIMEOUT,
    /** L1SS state machine enable */
    WMI_PDEV_PARAM_L1SS_ENABLE,
    /** Deep sleep state machine enable */
    WMI_PDEV_PARAM_DSLEEP_ENABLE,
    /** RX buffering flush enable */
    WMI_PDEV_PARAM_PCIELP_TXBUF_FLUSH,
    /** RX buffering matermark */
    WMI_PDEV_PARAM_PCIELP_TXBUF_WATERMARK,
    /** RX buffering timeout enable */
    WMI_PDEV_PARAM_PCIELP_TXBUF_TMO_EN,
    /** RX buffering timeout value */
    WMI_PDEV_PARAM_PCIELP_TXBUF_TMO_VALUE,
    /** pdev level stats update period in ms */
    WMI_PDEV_PARAM_PDEV_STATS_UPDATE_PERIOD,
    /** vdev level stats update period in ms */
    WMI_PDEV_PARAM_VDEV_STATS_UPDATE_PERIOD,
    /** peer level stats update period in ms */
    WMI_PDEV_PARAM_PEER_STATS_UPDATE_PERIOD,
    /** beacon filter status update period */
    WMI_PDEV_PARAM_BCNFLT_STATS_UPDATE_PERIOD,
    /** QOS Mgmt frame protection MFP/PMF 0: disable, 1: enable */
    WMI_PDEV_PARAM_PMF_QOS,
    /** Access category on which ARP frames are sent */
    WMI_PDEV_PARAM_ARP_AC_OVERRIDE,
    /** DCS configuration */
    WMI_PDEV_PARAM_DCS,
    /** Enable/Disable ANI on target */
    WMI_PDEV_PARAM_ANI_ENABLE,
    /** configure the ANI polling period */
    WMI_PDEV_PARAM_ANI_POLL_PERIOD,
    /** configure the ANI listening period */
    WMI_PDEV_PARAM_ANI_LISTEN_PERIOD,
    /** configure OFDM immunity level */
    WMI_PDEV_PARAM_ANI_OFDM_LEVEL,
    /** configure CCK immunity level */
    WMI_PDEV_PARAM_ANI_CCK_LEVEL,
    /** Enable/Disable CDD for 1x1 STAs in rate control module */
    WMI_PDEV_PARAM_DYNTXCHAIN,
    /** Enable/Disable proxy STA */
    WMI_PDEV_PARAM_PROXY_STA,
    /** Enable/Disable low power state when all VDEVs are inactive/idle. */
    WMI_PDEV_PARAM_IDLE_PS_CONFIG,
    /** Enable/Disable power gating sleep */
    WMI_PDEV_PARAM_POWER_GATING_SLEEP,
    /** Enable/Disable Rfkill */
    WMI_PDEV_PARAM_RFKILL_ENABLE,
    /** Set Bursting DUR */
    WMI_PDEV_PARAM_BURST_DUR,
    /** Set Bursting ENABLE */
    WMI_PDEV_PARAM_BURST_ENABLE,
} WMI_PDEV_PARAM;

typedef enum {
    /** Set the loglevel */
    WMI_DBGLOG_LOG_LEVEL = 0x1,
    /** Enable VAP level debug */
    WMI_DBGLOG_VAP_ENABLE,
    /** Disable VAP level debug */
    WMI_DBGLOG_VAP_DISABLE,
    /** Enable MODULE level debug */
    WMI_DBGLOG_MODULE_ENABLE,
    /** Disable MODULE level debug */
    WMI_DBGLOG_MODULE_DISABLE,
    /** Enable MODULE level debug */
    WMI_DBGLOG_MOD_LOG_LEVEL,
    /** set type of the debug output */
    WMI_DBGLOG_TYPE,
    /** Enable Disable debug */
    WMI_DBGLOG_REPORT_ENABLE
} WMI_DBG_PARAM;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_set_param_cmd_fixed_param */
    A_UINT32 reserved0;      /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    /** parameter id   */
    A_UINT32 param_id;
    /** parametr value */
    A_UINT32 param_value;
} wmi_pdev_set_param_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_get_tpc_config_cmd_fixed_param */
    A_UINT32 reserved0;      /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    /** parameter   */
    A_UINT32 param;
} wmi_pdev_get_tpc_config_cmd_fixed_param;


typedef struct {
    /** parameter   */
    A_UINT32 param;
} wmi_pdev_dump_cmd;


#define WMI_TPC_RATE_MAX            160
/* WMI_TPC_TX_NUM_CHAIN macro can't be changed without breaking the WMI compatibility */
#define WMI_TPC_TX_NUM_CHAIN        4

typedef enum {
    WMI_TPC_CONFIG_EVENT_FLAG_TABLE_CDD     = 0x1,
    WMI_TPC_CONFIG_EVENT_FLAG_TABLE_STBC    = 0x2,
    WMI_TPC_CONFIG_EVENT_FLAG_TABLE_TXBF    = 0x4,
} WMI_TPC_CONFIG_EVENT_FLAG;

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_tpc_config_event_fixed_param  */
    A_UINT32 regDomain;
    A_UINT32 chanFreq;
    A_UINT32 phyMode;
    A_UINT32 twiceAntennaReduction;
    A_UINT32 twiceMaxRDPower;
    A_INT32  twiceAntennaGain;
    A_UINT32 powerLimit;
    A_UINT32 rateMax;
    A_UINT32 numTxChain;
    A_UINT32 ctl;
    A_UINT32 flags;
    /* WMI_TPC_TX_NUM_CHAIN macro can't be changed without breaking the WMI compatibility */
    A_INT8  maxRegAllowedPower[WMI_TPC_TX_NUM_CHAIN];
    A_INT8  maxRegAllowedPowerAGCDD[WMI_TPC_TX_NUM_CHAIN][WMI_TPC_TX_NUM_CHAIN];
    A_INT8  maxRegAllowedPowerAGSTBC[WMI_TPC_TX_NUM_CHAIN][WMI_TPC_TX_NUM_CHAIN];
    A_INT8  maxRegAllowedPowerAGTXBF[WMI_TPC_TX_NUM_CHAIN][WMI_TPC_TX_NUM_CHAIN];
    /* This TLV is followed by a byte array:
         *      A_UINT8 ratesArray[];
         */
} wmi_pdev_tpc_config_event_fixed_param;


typedef struct {
    A_UINT32 len;
    A_UINT32 msgref;
    A_UINT32 segmentInfo;
} wmi_pdev_seg_hdr_info;


/*
 * Transmit power scale factor.
 *
 */
typedef enum {
    WMI_TP_SCALE_MAX    = 0,        /* no scaling (default) */
    WMI_TP_SCALE_50     = 1,        /* 50% of max (-3 dBm) */
    WMI_TP_SCALE_25     = 2,        /* 25% of max (-6 dBm) */
    WMI_TP_SCALE_12     = 3,        /* 12% of max (-9 dBm) */
    WMI_TP_SCALE_MIN    = 4,        /* min, but still on   */
    WMI_TP_SCALE_SIZE   = 5,        /* max num of enum     */
} WMI_TP_SCALE;

#define WMI_MAX_DEBUG_MESG (sizeof(A_UINT32) * 32)

typedef struct {
   /** message buffer, NULL terminated */
   char bufp[WMI_MAX_DEBUG_MESG];
} wmi_debug_mesg_event;

enum {
    /** IBSS station */
    VDEV_TYPE_IBSS  = 0,
    /** infra STA */
    VDEV_TYPE_STA   = 1,
    /** infra AP */
    VDEV_TYPE_AP    = 2,
    /** Monitor */
    VDEV_TYPE_MONITOR =3,
};

enum {
    /** P2P device */
    VDEV_SUBTYPE_P2PDEV=0,
    /** P2P client */
    VDEV_SUBTYPE_P2PCLI,
    /** P2P GO */
    VDEV_SUBTYPE_P2PGO,
    /** BT3.0 HS */
    VDEV_SUBTYPE_BT,
};

typedef struct {
    /** idnore power , only use flags , mode and freq */
   wmi_channel  chan;
}    wmi_pdev_set_channel_cmd;

typedef enum {
    WMI_PKTLOG_EVENT_RX  = 0x1,
    WMI_PKTLOG_EVENT_TX  = 0x2,
    WMI_PKTLOG_EVENT_RCF = 0x4, /* Rate Control Find */
    WMI_PKTLOG_EVENT_RCU = 0x8, /* Rate Control Update */
} WMI_PKTLOG_EVENT;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_pktlog_enable_cmd_fixed_param */
    A_UINT32 reserved0;      /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    WMI_PKTLOG_EVENT evlist;
} wmi_pdev_pktlog_enable_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_pktlog_disable_cmd_fixed_param */
    A_UINT32 reserved0;
} wmi_pdev_pktlog_disable_cmd_fixed_param;

/** Customize the DSCP (bit) to TID (0-7) mapping for QOS.
 *  NOTE: This constant cannot be changed without breaking
 *  WMI Compatibility. */

#define WMI_DSCP_MAP_MAX    (64)
    /*
     * @brief dscp_tid_map_cmdid - command to send the dscp to tid map to the target
     * @details
     * Create an API for sending the custom DSCP-to-TID map to the target
     * If this is a request from the user space or from above the UMAC
     * then the best place to implement this is in the umac_if_offload of the OL path.
     * Provide a place holder for this API in the ieee80211com (ic).
     *
     * This API will be a function pointer in the ieee80211com (ic). Any user space calls for manually setting the DSCP-to-TID mapping
     * in the target should be directed to the function pointer in the ic.
     *
     * Implementation details of the API to send the map to the target are as described-
     *
     * 1. The function will have 2 arguments- struct ieee80211com, DSCP-to-TID map.
     *    DSCP-to-TID map is a one dimensional u_int32_t array of length 64 to accomodate
     *    64 TID values for 2^6 (64) DSCP ids.
     *    Example:
     *      A_UINT32 dscp_tid_map[WMI_DSCP_MAP_MAX] = {
	 *									0, 0, 0, 0, 0, 0, 0, 0,
	 *									1, 1, 1, 1, 1, 1, 1, 1,
	 *									2, 2, 2, 2, 2, 2, 2, 2,
	 *									3, 3, 3, 3, 3, 3, 3, 3,
	 *									4, 4, 4, 4, 4, 4, 4, 4,
	 *									5, 5, 5, 5, 5, 5, 5, 5,
	 *									6, 6, 6, 6, 6, 6, 6, 6,
	 *									7, 7, 7, 7, 7, 7, 7, 7,
	 *								  };
     *
     * 2. Request for the WMI buffer of size equal to the size of the DSCP-to-TID map.
     *
     * 3. Copy the DSCP-to-TID map into the WMI buffer.
     *
     * 4. Invoke the wmi_unified_cmd_send to send the cmd buffer to the target with the
     *    WMI_PDEV_SET_DSCP_TID_MAP_CMDID. Arguments to the wmi send cmd API
     *    (wmi_unified_send_cmd) are wmi handle, cmd buffer, length of the cmd buffer and
     *    the WMI_PDEV_SET_DSCP_TID_MAP_CMDID id.
     *
     */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_set_dscp_tid_map_cmd_fixed_param */
    A_UINT32 reserved0;      /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
 /* map indicating DSCP to TID conversion */
    A_UINT32 dscp_to_tid_map[WMI_DSCP_MAP_MAX];
} wmi_pdev_set_dscp_tid_map_cmd_fixed_param;

/** Fixed rate (rate-code) for broadcast/ multicast data frames */
/* @brief bcast_mcast_data_rate - set the rates for the bcast/ mcast frames
 * @details
 * Create an API for setting the custom rate for the MCAST and BCAST frames
 * in the target. If this is a request from the user space or from above the UMAC
 * then the best place to implement this is in the umac_if_offload of the OL path.
 * Provide a place holder for this API in the ieee80211com (ic).
 *
 * Implementation details of the API to set custom rates for MCAST and BCAST in
 * the target are as described-
 *
 * 1. The function will have 3 arguments-
 *    vap structure,
 *    MCAST/ BCAST identifier code,
 *    8 bit rate code
 *
 * The rate-code is a 1-byte field in which:for given rate, nss and preamble
 * b'7-b-6 indicate the preamble (0 OFDM, 1 CCK, 2, HT, 3 VHT)
 * b'5-b'4 indicate the NSS (0 - 1x1, 1 - 2x2, 2 - 3x3)
 * b'3-b'0 indicate the rate, which is indicated as follows:
 *          OFDM :     0: OFDM 48 Mbps
 *                     1: OFDM 24 Mbps
 *                     2: OFDM 12 Mbps
 *                     3: OFDM 6 Mbps
 *                     4: OFDM 54 Mbps
 *                     5: OFDM 36 Mbps
 *                     6: OFDM 18 Mbps
 *                     7: OFDM 9 Mbps
 *         CCK (pream == 1)
 *                     0: CCK 11 Mbps Long
 *                     1: CCK 5.5 Mbps Long
 *                     2: CCK 2 Mbps Long
 *                     3: CCK 1 Mbps Long
 *                     4: CCK 11 Mbps Short
 *                     5: CCK 5.5 Mbps Short
 *                     6: CCK 2 Mbps Short
 *         HT/VHT (pream == 2/3)
 *                     0..7: MCS0..MCS7 (HT)
 *                     0..9: MCS0..MCS9 (VHT)
 *
 * 2. Invoke the wmi_unified_vdev_set_param_send to send the rate value
 *    to the target.
 *    Arguments to the API are-
 *    wmi handle,
 *    VAP interface id (av_if_id) defined in ol_ath_vap_net80211,
 *    WMI_VDEV_PARAM_BCAST_DATA_RATE/ WMI_VDEV_PARAM_MCAST_DATA_RATE,
 *    rate value.
 */
typedef enum {
    WMI_SET_MCAST_RATE,
    WMI_SET_BCAST_RATE
} MCAST_BCAST_RATE_ID;

typedef struct {
    MCAST_BCAST_RATE_ID rate_id;
    A_UINT32 rate;
} mcast_bcast_rate;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_wmm_params */
    A_UINT32 cwmin;
    A_UINT32 cwmax;
    A_UINT32 aifs;
    A_UINT32 txoplimit;
    A_UINT32 acm;
    A_UINT32 no_ack;
} wmi_wmm_params;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_set_wmm_params_cmd_fixed_param */
    A_UINT32 reserved0;      /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    A_UINT32 dg_type;

    /* The TLVs for the 4 AC follows:
     *     wmi_wmm_params wmm_params_ac_be;
     *     wmi_wmm_params wmm_params_ac_bk;
     *     wmi_wmm_params wmm_params_ac_vi;
     *     wmi_wmm_params wmm_params_ac_vo;
     */
} wmi_pdev_set_wmm_params_cmd_fixed_param;

typedef enum {
    WMI_REQUEST_PEER_STAT  = 0x01,
    WMI_REQUEST_AP_STAT    = 0x02
} wmi_stats_id;

typedef struct {
    A_UINT32   tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_request_stats_cmd_fixed_param */
    wmi_stats_id stats_id;
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
} wmi_request_stats_cmd_fixed_param;

/** Suspend option */
enum {
    WMI_PDEV_SUSPEND, /* suspend */
    WMI_PDEV_SUSPEND_AND_DISABLE_INTR, /* suspend and disable all interrupts */
};

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_suspend_cmd_fixed_param  */
    /* suspend option sent to target */
    A_UINT32    reserved0;                           /** placeholder for pdev_id of future multiple MAC products. Init. to 0. */
    A_UINT32 suspend_opt;
} wmi_pdev_suspend_cmd_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_resume_cmd_fixed_param  */
    /** Reserved for future use */
    A_UINT32    reserved0;
} wmi_pdev_resume_cmd_fixed_param;

typedef struct {
    A_UINT32   tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_stats_event_fixed_param */
    wmi_stats_id stats_id;
    /** number of pdev stats event structures (wmi_pdev_stats) 0 or 1 */
    A_UINT32 num_pdev_stats;
    /** number of vdev stats event structures  (wmi_vdev_stats) 0 or max vdevs */
    A_UINT32 num_vdev_stats;
    /** number of peer stats event structures  (wmi_peer_stats) 0 or max peers */
    A_UINT32 num_peer_stats;
    A_UINT32 num_bcnflt_stats;
    /** number of chan stats event structures  (wmi_chan_stats) 0 to MAX MCC CHANS */
    A_UINT32 num_chan_stats;
    /* This TLV is followed by another TLV of array of bytes
         *   A_UINT8 data[];
         *  This data array contains
         *   num_pdev_stats * size of(struct wmi_pdev_stats)
         *   num_vdev_stats * size of(struct wmi_vdev_stats)
         *   num_peer_stats * size of(struct wmi_peer_stats)
         *   num_bcnflt_stats * size_of()
 *   num_chan_stats * size of(struct wmi_chan_stats)
         *
         */
} wmi_stats_event_fixed_param;

/**
 *  PDEV statistics
 *  @todo
 *  add all PDEV stats here
 */
typedef struct {
    /** Channel noise floor */
    A_INT32 chan_nf;
    /** TX frame count */
    A_UINT32 tx_frame_count;
    /** RX frame count */
    A_UINT32 rx_frame_count;
    /** rx clear count */
    A_UINT32 rx_clear_count;
    /** cycle count */
    A_UINT32 cycle_count;
    /** Phy error count */
    A_UINT32 phy_err_count;
    /** Channel Tx Power */
    A_UINT32 chan_tx_pwr;
    /** WAL dbg stats */
    struct wlan_dbg_stats pdev_stats;

} wmi_pdev_stats;

/**
 *  VDEV statistics
 *  @todo
 *  add all VDEV stats here
 */

typedef struct {
    A_INT32 bcn_snr;
    A_INT32 dat_snr;
} wmi_snr_info;

typedef struct {
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32         vdev_id;
    wmi_snr_info     vdev_snr;
    A_UINT32         tx_frm_cnt[WLAN_MAX_AC];/* Total number of packets(per AC) that were successfully transmitted(with and without retries, including multi-cast, broadcast) */
    A_UINT32         rx_frm_cnt;/* Total number of packets that were successfully received (after appropriate filter rules including multi-cast, broadcast)*/
    A_UINT32         multiple_retry_cnt[WLAN_MAX_AC];/*The number of MSDU packets and MMPDU frames per AC
                                                       that the 802.11 station successfully transmitted after more than one retransmission attempt*/
    A_UINT32         fail_cnt[WLAN_MAX_AC]; /*Total number packets(per AC) failed to transmit */
    A_UINT32         rts_fail_cnt;/*Total number of RTS/CTS sequence failures for transmission of a packet*/
    A_UINT32         rts_succ_cnt;/*Total number of RTS/CTS sequence success for transmission of a packet*/
    A_UINT32         rx_err_cnt;/*The receive error count. HAL will provide the RxP FCS error global */
    A_UINT32         rx_discard_cnt;/* The sum of the receive error count and dropped-receive-buffer error count. (FCS error)*/
    A_UINT32         ack_fail_cnt;/*Total number packets failed transmit because of no ACK from the remote entity*/
   A_UINT32          tx_rate_history[MAX_TX_RATE_VALUES];/*History of last ten transmit rate, in units of 500 kbit/sec*/
    A_UINT32         bcn_rssi_history[MAX_RSSI_VALUES];/*History of last ten Beacon rssi of the connected Bss*/
} wmi_vdev_stats;

/**
 *  peer statistics.
 *
 * @todo
 * add more stats
 *
 */
typedef struct {
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** rssi */
    A_UINT32  peer_rssi;
    /** last tx data rate used for peer */
    A_UINT32  peer_tx_rate;
    /** last rx data rate used for peer */
    A_UINT32  peer_rx_rate;
} wmi_peer_stats;

typedef struct {
    /** Primary channel freq of the channel for which stats are sent */
    A_UINT32 chan_mhz;
    /** Time spent on the channel */
    A_UINT32 sampling_period_us;
    /** Aggregate duration over a sampling period for which channel activity was observed */
    A_UINT32 rx_clear_count;
    /** Accumalation of the TX PPDU duration over a sampling period */
    A_UINT32 tx_duration_us;
    /** Accumalation of the RX PPDU duration over a sampling period */
    A_UINT32 rx_duration_us;
} wmi_chan_stats;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_create_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** VDEV type (AP,STA,IBSS,MONITOR) */
    A_UINT32 vdev_type;
    /** VDEV subtype (P2PDEV, P2PCLI, P2PGO, BT3.0)*/
    A_UINT32 vdev_subtype;
    /** VDEV MAC address */
    wmi_mac_addr vdev_macaddr;
} wmi_vdev_create_cmd_fixed_param;

/* wmi_p2p_noa_descriptor structure can't be modified without breaking the compatibility for WMI_HOST_SWBA_EVENTID */
typedef struct {
    A_UINT32   tlv_header; /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_p2p_noa_descriptor */
    A_UINT32   type_count; /** 255: continuous schedule, 0: reserved */
    A_UINT32   duration ;  /** Absent period duration in micro seconds */
    A_UINT32   interval;   /** Absent period interval in micro seconds */
    A_UINT32   start_time; /** 32 bit tsf time when in starts */
} wmi_p2p_noa_descriptor;

/** values for vdev_type */
#define WMI_VDEV_TYPE_AP         0x1
#define WMI_VDEV_TYPE_STA        0x2
#define WMI_VDEV_TYPE_IBSS       0x3
#define WMI_VDEV_TYPE_MONITOR    0x4

/** values for vdev_subtype */
#define WMI_UNIFIED_VDEV_SUBTYPE_P2P_DEVICE 0x1
#define WMI_UNIFIED_VDEV_SUBTYPE_P2P_CLIENT 0x2
#define WMI_UNIFIED_VDEV_SUBTYPE_P2P_GO     0x3

/** values for vdev_start_request flags */
/** Indicates that AP VDEV uses hidden ssid. only valid for
 *  AP/GO */
#define WMI_UNIFIED_VDEV_START_HIDDEN_SSID  (1<<0)
/** Indicates if robust management frame/management frame
 *  protection is enabled. For GO/AP vdevs, it indicates that
 *  it may support station/client associations with RMF enabled.
 *  For STA/client vdevs, it indicates that sta will
 *  associate with AP with RMF enabled. */
#define WMI_UNIFIED_VDEV_START_PMF_ENABLED  (1<<1)

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_start_request_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** requestor id identifying the caller module */
    A_UINT32 requestor_id;
    /** beacon interval from received beacon */
    A_UINT32 beacon_interval;
    /** DTIM Period from the received beacon */
    A_UINT32 dtim_period;
    /** Flags */
    A_UINT32 flags;
    /** ssid field. Only valid for AP/GO/IBSS/BTAmp VDEV type. */
    wmi_ssid ssid;
    /** beacon/probe reponse xmit rate. Applicable for SoftAP. */
    A_UINT32 bcn_tx_rate;
    /** beacon/probe reponse xmit power. Applicable for SoftAP. */
    A_UINT32 bcn_txPower;
    /** number of p2p NOA descriptor(s) from scan entry */
    A_UINT32  num_noa_descriptors;
    /** Disable H/W ack. This used by WMI_VDEV_RESTART_REQUEST_CMDID.
          During CAC, Our HW shouldn't ack ditected frames */
    A_UINT32  disable_hw_ack;
    /* The TLVs follows this structure:
         *     wmi_channel chan;   //WMI channel
         *     wmi_p2p_noa_descriptor  noa_descriptors[]; //actual p2p NOA descriptor from scan entry
         */
} wmi_vdev_start_request_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_delete_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
} wmi_vdev_delete_cmd_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_up_cmdid_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** aid (assoc id) received in association response for STA VDEV  */
    A_UINT32 vdev_assoc_id;
    /** bssid of the BSS the VDEV is joining  */
    wmi_mac_addr vdev_bssid;
} wmi_vdev_up_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_stop_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
} wmi_vdev_stop_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_down_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
} wmi_vdev_down_cmd_fixed_param;

typedef struct {
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
} wmi_vdev_standby_response_cmd;

typedef struct {
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
} wmi_vdev_resume_response_cmd;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_set_param_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** parameter id   */
    A_UINT32 param_id;
    /** parameter value */
    A_UINT32 param_value;
} wmi_vdev_set_param_cmd_fixed_param;

typedef struct {
    A_UINT32 key_seq_counter_l;
    A_UINT32 key_seq_counter_h;
} wmi_key_seq_counter;

#define  WMI_CIPHER_NONE     0x0  /* clear key */
#define  WMI_CIPHER_WEP      0x1
#define  WMI_CIPHER_TKIP     0x2
#define  WMI_CIPHER_AES_OCB  0x3
#define  WMI_CIPHER_AES_CCM  0x4
#define  WMI_CIPHER_WAPI     0x5
#define  WMI_CIPHER_CKIP     0x6
#define  WMI_CIPHER_AES_CMAC 0x7

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_install_key_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** MAC address used for installing   */
    wmi_mac_addr peer_macaddr;
    /** key index */
    A_UINT32 key_ix;
    /** key flags */
    A_UINT32 key_flags;
    /** key cipher, defined above */
    A_UINT32 key_cipher;
    /** key rsc counter */
    wmi_key_seq_counter key_rsc_counter;
    /** global key rsc counter */
    wmi_key_seq_counter key_global_rsc_counter;
    /** global key tsc counter */
    wmi_key_seq_counter key_tsc_counter;
    /** WAPI key rsc counter */
    A_UINT8 wpi_key_rsc_counter[16];
    /** WAPI key tsc counter */
    A_UINT8 wpi_key_tsc_counter[16];
    /** key length */
    A_UINT32 key_len;
    /** key tx mic length */
    A_UINT32 key_txmic_len;
    /** key rx mic length */
    A_UINT32 key_rxmic_len;
        /*
         * Following this struct are this TLV.
         *     // actual key data
         *     A_UINT8  key_data[]; // contains key followed by tx mic followed by rx mic
         */
} wmi_vdev_install_key_cmd_fixed_param;

/** Preamble types to be used with VDEV fixed rate configuration */
typedef enum {
    WMI_RATE_PREAMBLE_OFDM,
    WMI_RATE_PREAMBLE_CCK,
    WMI_RATE_PREAMBLE_HT,
    WMI_RATE_PREAMBLE_VHT,
} WMI_RATE_PREAMBLE;

/** Value to disable fixed rate setting */
#define WMI_FIXED_RATE_NONE    (0xff)

/** the definition of different VDEV parameters */
typedef enum {
    /** RTS Threshold */
    WMI_VDEV_PARAM_RTS_THRESHOLD = 0x1,
    /** Fragmentation threshold */
    WMI_VDEV_PARAM_FRAGMENTATION_THRESHOLD,
    /** beacon interval in TUs */
    WMI_VDEV_PARAM_BEACON_INTERVAL,
    /** Listen interval in TUs */
    WMI_VDEV_PARAM_LISTEN_INTERVAL,
    /** muticast rate in Mbps */
    WMI_VDEV_PARAM_MULTICAST_RATE,
    /** management frame rate in Mbps */
    WMI_VDEV_PARAM_MGMT_TX_RATE,
    /** slot time (long vs short) */
    WMI_VDEV_PARAM_SLOT_TIME,
    /** preamble (long vs short) */
    WMI_VDEV_PARAM_PREAMBLE,
    /** SWBA time (time before tbtt in msec) */
    WMI_VDEV_PARAM_SWBA_TIME,
    /** time period for updating VDEV stats */
    WMI_VDEV_STATS_UPDATE_PERIOD,
    /** age out time in msec for frames queued for station in power save*/
    WMI_VDEV_PWRSAVE_AGEOUT_TIME,
    /** Host SWBA interval (time in msec before tbtt for SWBA event generation) */
    WMI_VDEV_HOST_SWBA_INTERVAL,
    /** DTIM period (specified in units of num beacon intervals) */
    WMI_VDEV_PARAM_DTIM_PERIOD,
    /** scheduler air time limit for this VDEV. used by off chan scheduler  */
    WMI_VDEV_OC_SCHEDULER_AIR_TIME_LIMIT,
    /** enable/dsiable WDS for this VDEV  */
    WMI_VDEV_PARAM_WDS,
    /** ATIM Window */
    WMI_VDEV_PARAM_ATIM_WINDOW,
    /** BMISS max */
    WMI_VDEV_PARAM_BMISS_COUNT_MAX,
    /** BMISS first time */
    WMI_VDEV_PARAM_BMISS_FIRST_BCNT,
    /** BMISS final time */
    WMI_VDEV_PARAM_BMISS_FINAL_BCNT,
    /** WMM enables/disabled */
    WMI_VDEV_PARAM_FEATURE_WMM,
    /** Channel width */
    WMI_VDEV_PARAM_CHWIDTH,
    /** Channel Offset */
    WMI_VDEV_PARAM_CHEXTOFFSET,
    /** Disable HT Protection */
    WMI_VDEV_PARAM_DISABLE_HTPROTECTION,
    /** Quick STA Kickout */
    WMI_VDEV_PARAM_STA_QUICKKICKOUT,
    /** Rate to be used with Management frames */
    WMI_VDEV_PARAM_MGMT_RATE,
    /** Protection Mode */
    WMI_VDEV_PARAM_PROTECTION_MODE,
    /** Fixed rate setting */
    WMI_VDEV_PARAM_FIXED_RATE,
    /** Short GI Enable/Disable */
    WMI_VDEV_PARAM_SGI,
    /** Enable LDPC */
    WMI_VDEV_PARAM_LDPC,
    /** Enable Tx STBC */
    WMI_VDEV_PARAM_TX_STBC,
    /** Enable Rx STBC */
    WMI_VDEV_PARAM_RX_STBC,
    /** Intra BSS forwarding  */
    WMI_VDEV_PARAM_INTRA_BSS_FWD,
    /** Setting Default xmit key for Vdev */
    WMI_VDEV_PARAM_DEF_KEYID,
    /** NSS width */
    WMI_VDEV_PARAM_NSS,
    /** Set the custom rate for the broadcast data frames */
    WMI_VDEV_PARAM_BCAST_DATA_RATE,
    /** Set the custom rate (rate-code) for multicast data frames */
    WMI_VDEV_PARAM_MCAST_DATA_RATE,
    /** Tx multicast packet indicate Enable/Disable */
    WMI_VDEV_PARAM_MCAST_INDICATE,
    /** Tx DHCP packet indicate Enable/Disable */
    WMI_VDEV_PARAM_DHCP_INDICATE,
    /** Enable host inspection of Tx unicast packet to unknown destination */
    WMI_VDEV_PARAM_UNKNOWN_DEST_INDICATE,

    /* The minimum amount of time AP begins to consider STA inactive */
    WMI_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS,

    /* An associated STA is considered inactive when there is no recent TX/RX
     * activity and no downlink frames are buffered for it. Once a STA exceeds
     * the maximum idle inactive time, the AP will send an 802.11 data-null as
     * a keep alive to verify the STA is still associated. If the STA does ACK
     * the data-null, or if the data-null is buffered and the STA does not
     * retrieve it, the STA will be considered unresponsive (see
     * WMI_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS). */
    WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS,

    /* An associated STA is considered unresponsive if there is no recent
     * TX/RX activity and downlink frames are buffered for it. Once a STA
     * exceeds the maximum unresponsive time, the AP will send a
     * WMI_STA_KICKOUT event to the host so the STA can be deleted. */
    WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS,

    /* Enable NAWDS : MCAST INSPECT Enable, NAWDS Flag set */
    WMI_VDEV_PARAM_AP_ENABLE_NAWDS,
    /** Enable/Disable RTS-CTS */
    WMI_VDEV_PARAM_ENABLE_RTSCTS,
    /* Enable TXBFee/er */
    WMI_VDEV_PARAM_TXBF,

    /**Set packet power save */
    WMI_VDEV_PARAM_PACKET_POWERSAVE,

    /**Drops un-encrypted packets if any received in an encryted connection
     * otherwise forwards to host
     */
    WMI_VDEV_PARAM_DROP_UNENCRY,

    /*
     * Set TX encap type.
     *
     * enum wmi_pkt_type is to be used as the parameter
     * specifying the encap type.
     */
    WMI_VDEV_PARAM_TX_ENCAP_TYPE,

    /*
     * Try to detect stations that woke-up and exited power save but did not
     * successfully transmit data-null with PM=0 to AP. When this happens,
     * STA and AP power save state are out-of-sync. Use buffered but
     * undelivered MSDU to the STA as a hint that the STA is really awake
     * and expecting normal ASAP delivery, rather than retrieving BU with
     * PS-Poll, U-APSD trigger, etc.
     *
     * 0 disables out-of-sync detection. Maximum time is 255 seconds.
     */
    WMI_VDEV_PARAM_AP_DETECT_OUT_OF_SYNC_SLEEPING_STA_TIME_SECS,

    /* Enable/Disable early rx dynamic adjust feature.
      * Early-rx dynamic adjust is a advance power save feature.
      * Early-rx is a wakeup duration before exact TBTT,which is deemed necessary to provide a cushion for various
      * timing discrepancies in the system.
      * In current code branch, the duration is set to a very conservative fix value to make sure the drift impact is minimum.
      * The fix early-tx will result in the unnessary power consume, so a dynamic early-rx adjust algorithm can be designed
      * properly to minimum the power consume.*/
    WMI_VDEV_PARAM_EARLY_RX_ADJUST_ENABLE,

    /* set target bmiss number per sample cycle if bmiss adjust was chosen.
     * In this adjust policy,early-rx is adjusted by comparing the current bmiss rate to target bmiss rate
     * which can be set by user through WMI command.
     */
    WMI_VDEV_PARAM_EARLY_RX_TGT_BMISS_NUM,

    /* set sample cycle(in the unit of beacon interval) if bmiss adjust was chosen */
    WMI_VDEV_PARAM_EARLY_RX_BMISS_SAMPLE_CYCLE,

    /* set slop_step */
    WMI_VDEV_PARAM_EARLY_RX_SLOP_STEP,

    /* set init slop */
    WMI_VDEV_PARAM_EARLY_RX_INIT_SLOP,

    /* pause adjust enable/disable */
    WMI_VDEV_PARAM_EARLY_RX_ADJUST_PAUSE,


    /* Set channel pwr limit value of the vdev the minimal value of all
     * vdevs operating on this channel will be set as channel tx power
     * limit, which is used to configure ratearray
     */
    WMI_VDEV_PARAM_TX_PWRLIMIT,

    /* set the count of snr value for calculation in snr monitor */
    WMI_VDEV_PARAM_SNR_NUM_FOR_CAL,

    /** Roaming offload */
    WMI_VDEV_PARAM_ROAM_FW_OFFLOAD,
} WMI_VDEV_PARAM;

enum wmi_pkt_type {
    WMI_PKT_TYPE_RAW = 0,
    WMI_PKT_TYPE_NATIVE_WIFI = 1,
    WMI_PKT_TYPE_ETHERNET = 2,
};

typedef struct {
    A_UINT8     sutxbfee : 1,
                mutxbfee : 1,
                sutxbfer : 1,
                mutxbfer : 1,
                reserved : 4;
} wmi_vdev_txbf_en;

        /** slot time long */
        #define WMI_VDEV_SLOT_TIME_LONG                                  0x1
        /** slot time short */
        #define WMI_VDEV_SLOT_TIME_SHORT                                 0x2
        /** preablbe long */
        #define WMI_VDEV_PREAMBLE_LONG                                   0x1
        /** preablbe short */
        #define WMI_VDEV_PREAMBLE_SHORT                                  0x2

/** the definition of different START/RESTART Event response  */
    typedef enum {
        /* Event respose of START CMD */
        WMI_VDEV_START_RESP_EVENT = 0,
        /* Event respose of RESTART CMD */
        WMI_VDEV_RESTART_RESP_EVENT,
    } WMI_START_EVENT_PARAM;

        typedef struct {
            A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_start_response_event_fixed_param  */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** requestor id that requested the VDEV start request */
            A_UINT32 requestor_id;
            /* Respose of Event type START/RESTART */
            WMI_START_EVENT_PARAM resp_type;
            /** status of the response */
            A_UINT32 status;
        } wmi_vdev_start_response_event_fixed_param;

        typedef struct {
            A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_stopped_event_fixed_param  */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
        } wmi_vdev_stopped_event_fixed_param;

        /** common structure used for simple events (stopped, resume_req, standby response) */
        typedef struct {
            A_UINT32    tlv_header;     /* TLV tag and len; tag would be equivalent to actual event  */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
        } wmi_vdev_simple_event_fixed_param;


        /** VDEV start response status codes */
        #define WMI_VDEV_START_RESPONSE_STATUS_SUCCESS 0x0  /** VDEV succesfully started */
        #define WMI_VDEV_START_RESPONSE_INVALID_VDEVID  0x1  /** requested VDEV not found */
        #define WMI_VDEV_START_RESPONSE_NOT_SUPPORTED  0x2  /** unsupported VDEV combination */

        /** Beacon processing related command and event structures */
        typedef struct {
            A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_bcn_tx_hdr */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** xmit rate */
            A_UINT32 tx_rate;
            /** xmit power */
            A_UINT32 txPower;
            /** beacon buffer length in bytes */
            A_UINT32 buf_len;
            /* This TLV is followed by array of bytes:
                       * // beacon frame buffer
                       *   A_UINT8 bufp[];
                       */
        } wmi_bcn_tx_hdr;

        /* Beacon filter */
        #define WMI_BCN_FILTER_ALL   0 /* Filter all beacons */
        #define WMI_BCN_FILTER_NONE  1 /* Pass all beacons */
        #define WMI_BCN_FILTER_RSSI  2 /* Pass Beacons RSSI >= RSSI threshold */
        #define WMI_BCN_FILTER_BSSID 3 /* Pass Beacons with matching BSSID */
        #define WMI_BCN_FILTER_SSID  4 /* Pass Beacons with matching SSID */

        typedef struct {
            /** Filter ID */
            A_UINT32 bcn_filter_id;
            /** Filter type - wmi_bcn_filter */
            A_UINT32 bcn_filter;
            /** Buffer len */
            A_UINT32 bcn_filter_len;
            /** Filter info (threshold, BSSID, RSSI) */
            A_UINT8 *bcn_filter_buf;
        } wmi_bcn_filter_rx_cmd;

        /** Capabilities and IEs to be passed to firmware */
        typedef struct {
            A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_bcn_prb_info */
            /** Capabilities */
            A_UINT32 caps;
            /** ERP info */
            A_UINT32 erp;
            /** Advanced capabilities */
            /** HT capabilities */
            /** HT Info */
            /** ibss_dfs */
            /** wpa Info */
            /** rsn Info */
            /** rrm info */
            /** ath_ext */
            /** app IE */
        } wmi_bcn_prb_info;

         typedef struct {
             A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_bcn_tmpl_cmd_fixed_param */
             /** unique id identifying the VDEV, generated by the caller */
             A_UINT32 vdev_id;
             /** TIM IE offset from the beginning of the template. */
             A_UINT32 tim_ie_offset;
             /** beacon buffer length. data is in TLV data[] */
             A_UINT32 buf_len;
             /*
                         * The TLVs follows:
                         *    wmi_bcn_prb_info bcn_prb_info; //beacon probe capabilities and IEs
                         *    A_UINT8  data[]; //Variable length data
                         */
        } wmi_bcn_tmpl_cmd_fixed_param;


         typedef struct {
             A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_prb_tmpl_cmd_fixed_param */
             /** unique id identifying the VDEV, generated by the caller */
             A_UINT32 vdev_id;
             /** beacon buffer length. data is in TLV data[] */
             A_UINT32 buf_len;
             /*
                         * The TLVs follows:
                         *    wmi_bcn_prb_info bcn_prb_info; //beacon probe capabilities and IEs
                         *    A_UINT8  data[]; //Variable length data
                         */
         } wmi_prb_tmpl_cmd_fixed_param;


        enum wmi_sta_ps_mode {
            /** enable power save for the given STA VDEV */
            WMI_STA_PS_MODE_DISABLED = 0,
            /** disable power save  for a given STA VDEV */
            WMI_STA_PS_MODE_ENABLED = 1,
        };

        typedef struct {
            A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_sta_powersave_mode_cmd_fixed_param */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;

            /** Power save mode
             *
             * (see enum wmi_sta_ps_mode)
             */
            A_UINT32 sta_ps_mode;
        } wmi_sta_powersave_mode_cmd_fixed_param;

       enum wmi_csa_offload_en{
           WMI_CSA_OFFLOAD_DISABLE = 0,
           WMI_CSA_OFFLOAD_ENABLE = 1,
       };

       typedef struct{
          A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_csa_offload_enable_cmd_fixed_param  */
          A_UINT32 vdev_id;
          A_UINT32 csa_offload_enable;
       } wmi_csa_offload_enable_cmd_fixed_param;

       typedef struct{
          A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_csa_offload_chanswitch_cmd_fixed_param  */
          A_UINT32 vdev_id;
          /*
           * The TLVs follows:
           *    wmi_channel chan;
           */
       } wmi_csa_offload_chanswitch_cmd_fixed_param;
        /**
         * This parameter controls the policy for retrieving frames from AP while the
         * STA is in sleep state.
         *
         * Only takes affect if the sta_ps_mode is enabled
         */
        enum wmi_sta_ps_param_rx_wake_policy {
            /* Wake up when ever there is an  RX activity on the VDEV. In this mode
             * the Power save SM(state machine) will come out of sleep by either
             * sending null frame (or) a data frame (with PS==0) in response to TIM
             * bit set in the received beacon frame from AP.
             */
            WMI_STA_PS_RX_WAKE_POLICY_WAKE = 0,

            /* Here the power save state machine will not wakeup in response to TIM
             * bit, instead it will send a PSPOLL (or) UASPD trigger based on UAPSD
             * configuration setup by WMISET_PS_SET_UAPSD  WMI command.  When all
             * access categories are delivery-enabled, the station will send a UAPSD
             * trigger frame, otherwise it will send a PS-Poll.
             */
            WMI_STA_PS_RX_WAKE_POLICY_POLL_UAPSD = 1,
        };

        /** Number of tx frames/beacon  that cause the power save SM to wake up.
         *
         * Value 1 causes the SM to wake up for every TX. Value 0 has a special
         * meaning, It will cause the SM to never wake up. This is useful if you want
         * to keep the system to sleep all the time for some kind of test mode . host
         * can change this parameter any time.  It will affect at the next tx frame.
         */
        enum wmi_sta_ps_param_tx_wake_threshold {
            WMI_STA_PS_TX_WAKE_THRESHOLD_NEVER = 0,
            WMI_STA_PS_TX_WAKE_THRESHOLD_ALWAYS = 1,

            /* Values greater than one indicate that many TX attempts per beacon
             * interval before the STA will wake up
             */
        };

        /**
         * The maximum number of PS-Poll frames the FW will send in response to
         * traffic advertised in TIM before waking up (by sending a null frame with PS
         * = 0). Value 0 has a special meaning: there is no maximum count and the FW
         * will send as many PS-Poll as are necessary to retrieve buffered BU. This
         * parameter is used when the RX wake policy is
         * WMI_STA_PS_RX_WAKE_POLICY_POLL_UAPSD and ignored when the RX wake
         * policy is WMI_STA_PS_RX_WAKE_POLICY_WAKE.
         */
        enum wmi_sta_ps_param_pspoll_count {
            WMI_STA_PS_PSPOLL_COUNT_NO_MAX = 0,
            /* Values greater than 0 indicate the maximum numer of PS-Poll frames FW
             * will send before waking up.
             */
        };

        /*
         * This will include the delivery and trigger enabled state for every AC.
         * This is the negotiated state with AP. The host MLME needs to set this based
         * on AP capability and the state Set in the association request by the
         * station MLME.Lower 8 bits of the value specify the UAPSD configuration.
         */
        #define WMI_UAPSD_AC_TYPE_DELI 0
        #define WMI_UAPSD_AC_TYPE_TRIG 1

        #define WMI_UAPSD_AC_BIT_MASK(ac,type) (type ==  WMI_UAPSD_AC_TYPE_DELI)?(1<<(ac<<1)):(1<<((ac<<1)+1))

        enum wmi_sta_ps_param_uapsd {
            WMI_STA_PS_UAPSD_AC0_DELIVERY_EN = (1 << 0),
            WMI_STA_PS_UAPSD_AC0_TRIGGER_EN  = (1 << 1),
            WMI_STA_PS_UAPSD_AC1_DELIVERY_EN = (1 << 2),
            WMI_STA_PS_UAPSD_AC1_TRIGGER_EN  = (1 << 3),
            WMI_STA_PS_UAPSD_AC2_DELIVERY_EN = (1 << 4),
            WMI_STA_PS_UAPSD_AC2_TRIGGER_EN  = (1 << 5),
            WMI_STA_PS_UAPSD_AC3_DELIVERY_EN = (1 << 6),
            WMI_STA_PS_UAPSD_AC3_TRIGGER_EN  = (1 << 7),
        };

        enum wmi_sta_powersave_param {
            /**
             * Controls how frames are retrievd from AP while STA is sleeping
             *
             * (see enum wmi_sta_ps_param_rx_wake_policy)
             */
            WMI_STA_PS_PARAM_RX_WAKE_POLICY = 0,

            /**
             * The STA will go active after this many TX
             *
             * (see enum wmi_sta_ps_param_tx_wake_threshold)
             */
            WMI_STA_PS_PARAM_TX_WAKE_THRESHOLD = 1,

            /**
             * Number of PS-Poll to send before STA wakes up
             *
             * (see enum wmi_sta_ps_param_pspoll_count)
             *
             */
            WMI_STA_PS_PARAM_PSPOLL_COUNT = 2,

            /**
             * TX/RX inactivity time in msec before going to sleep.
             *
             * The power save SM will monitor tx/rx activity on the VDEV, if no
             * activity for the specified msec of the parameter the Power save SM will
             * go to sleep.
             */
            WMI_STA_PS_PARAM_INACTIVITY_TIME = 3,

            /**
             * Set uapsd configuration.
             *
             * (see enum wmi_sta_ps_param_uapsd)
             */
            WMI_STA_PS_PARAM_UAPSD = 4,
    /**
     * Number of PS-Poll to send before STA wakes up in QPower Mode
     */
    WMI_STA_PS_PARAM_QPOWER_PSPOLL_COUNT = 5,

    /**
     * Enable QPower
     */
    WMI_STA_PS_ENABLE_QPOWER = 6,

    /**
     * Disable QPower
     */
    WMI_STA_PS_DISABLE_QPOWER = 7,
        };

        typedef struct {
            A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_sta_powersave_param_cmd_fixed_param */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** station power save parameter (see enum wmi_sta_powersave_param) */
            A_UINT32 param;
            A_UINT32 value;
        } wmi_sta_powersave_param_cmd_fixed_param;

         /** No MIMO power save */
        #define WMI_STA_MIMO_PS_MODE_DISABLE
         /** mimo powersave mode static*/
        #define WMI_STA_MIMO_PS_MODE_STATIC
         /** mimo powersave mode dynamic */
        #define WMI_STA_MIMO_PS_MODE_DYNAMI

        typedef struct {
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** mimo powersave mode as defined above */
            A_UINT32 mimo_pwrsave_mode;
        } wmi_sta_mimo_ps_mode_cmd;


        /** U-APSD configuration of peer station from (re)assoc request and TSPECs */
        enum wmi_ap_ps_param_uapsd {
            WMI_AP_PS_UAPSD_AC0_DELIVERY_EN = (1 << 0),
            WMI_AP_PS_UAPSD_AC0_TRIGGER_EN  = (1 << 1),
            WMI_AP_PS_UAPSD_AC1_DELIVERY_EN = (1 << 2),
            WMI_AP_PS_UAPSD_AC1_TRIGGER_EN  = (1 << 3),
            WMI_AP_PS_UAPSD_AC2_DELIVERY_EN = (1 << 4),
            WMI_AP_PS_UAPSD_AC2_TRIGGER_EN  = (1 << 5),
            WMI_AP_PS_UAPSD_AC3_DELIVERY_EN = (1 << 6),
            WMI_AP_PS_UAPSD_AC3_TRIGGER_EN  = (1 << 7),
        };

        /** U-APSD maximum service period of peer station */
        enum wmi_ap_ps_peer_param_max_sp {
            WMI_AP_PS_PEER_PARAM_MAX_SP_UNLIMITED = 0,
            WMI_AP_PS_PEER_PARAM_MAX_SP_2 = 1,
            WMI_AP_PS_PEER_PARAM_MAX_SP_4 = 2,
            WMI_AP_PS_PEER_PARAM_MAX_SP_6 = 3,

            /* keep last! */
            MAX_WMI_AP_PS_PEER_PARAM_MAX_SP,
        };

        /**
         * AP power save parameter
         * Set a power save specific parameter for a peer station
         */
        enum wmi_ap_ps_peer_param {
            /** Set uapsd configuration for a given peer.
             *
             * This will include the delivery and trigger enabled state for every AC.
             * The host  MLME needs to set this based on AP capability and stations
             * request Set in the association request  received from the station.
             *
             * Lower 8 bits of the value specify the UAPSD configuration.
             *
             * (see enum wmi_ap_ps_param_uapsd)
             * The default value is 0.
             */
            WMI_AP_PS_PEER_PARAM_UAPSD = 0,

            /**
             * Set the service period for a UAPSD capable station
             *
             * The service period from wme ie in the (re)assoc request frame.
             *
             * (see enum wmi_ap_ps_peer_param_max_sp)
             */
            WMI_AP_PS_PEER_PARAM_MAX_SP = 1,

            /** Time in seconds for aging out buffered frames for STA in power save */
            WMI_AP_PS_PEER_PARAM_AGEOUT_TIME = 2,
        };

        typedef struct {
            A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_ap_ps_peer_cmd_fixed_param */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** peer MAC address */
            wmi_mac_addr peer_macaddr;
            /** AP powersave param (see enum wmi_ap_ps_peer_param) */
            A_UINT32 param;
            /** AP powersave param value */
            A_UINT32 value;
        } wmi_ap_ps_peer_cmd_fixed_param;

        /** Configure peer station 11v U-APSD coexistance
         *
         * Two parameters from uaspd coexistence ie info (as specified in 11v) are
         * sent down to FW along with this command.
         *
         * The semantics of these fields are described in the following text extracted
         * from 802.11v.
         *
         * ---  If the non-AP STA specified a non-zero TSF 0 Offset value in the
         *      U-APSD Coexistence element, the AP should not transmit frames to the
         *      non-AP STA outside of the U-APSD Coexistence Service Period, which
         *      begins when the AP receives the U-APSD trigger frame and ends after
         *      the transmission period specified by the result of the following
         *      calculation:
         *
         *          End of transmission period = T + (Interval . ((T . TSF 0 Offset) mod Interval))
         *
         *      Where T is the time the U-APSD trigger frame was received at the AP
         *      Interval is the UAPSD Coexistence element Duration/Interval field
         *      value (see 7.3.2.91) or upon the successful transmission of a frame
         *      with EOSP bit set to 1, whichever is earlier.
         *
         *
         * ---  If the non-AP STA specified a zero TSF 0 Offset value in the U-APSD
         *      Coexistence element, the AP should not transmit frames to the non-AP
         *      STA outside of the U-APSD Coexistence Service Period, which begins
         *      when the AP receives a U-APSD trigger frame and ends after the
         *      transmission period specified by the result of the following
         *      calculation: End of transmission period = T + Duration
         */
        typedef struct {
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** peer MAC address */
            wmi_mac_addr peer_macaddr;
            /** Enable U-APSD coexistence support for this peer
             *
             * 0 -> disabled (default)
             * 1 -> enabled
             */
            A_UINT32 enabled;
            /** Duration/Interval as defined by 11v U-ASPD coexistance */
            A_UINT32 duration_interval;
            /** Upper 32 bits of 64-bit TSF offset */
            A_UINT32 tsf_offset_high;
            /** Lower 32 bits of 64-bit TSF offset */
            A_UINT32 tsf_offset_low;
        } wmi_ap_powersave_peer_uapsd_coex_cmd;

        /* 128 clients = 4 words */
        /* WMI_TIM_BITMAP_ARRAY_SIZE can't be modified without breaking the compatibility */
        #define WMI_TIM_BITMAP_ARRAY_SIZE 4

        typedef struct {
            A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_tim_info  */
            /** TIM bitmap len (in bytes)*/
            A_UINT32 tim_len;
            /** TIM Partial Virtual Bitmap */
            A_UINT32 tim_mcast;
            A_UINT32 tim_bitmap[WMI_TIM_BITMAP_ARRAY_SIZE];
            A_UINT32 tim_changed;
            A_UINT32 tim_num_ps_pending;
        } wmi_tim_info;

        typedef struct {
            /** Flag to enable quiet period IE support */
            A_UINT32   is_enabled;
            /** Quiet start */
            A_UINT32   tbttcount;
            /** Beacon intervals between quiets*/
            A_UINT32   period;
            /** TUs of each quiet*/
            A_UINT32   duration;
            /** TUs of from TBTT of quiet start*/
            A_UINT32   offset;
        } wmi_quiet_info;

/* WMI_P2P_MAX_NOA_DESCRIPTORS can't be modified without breaking the compatibility */
#define WMI_P2P_MAX_NOA_DESCRIPTORS 4	/* Maximum number of NOA Descriptors supported */

        typedef struct {
        A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_p2p_noa_info  */
        /** Bit  0:        Flag to indicate an update in NOA schedule
         *  Bits 7-1:    Reserved
         *  Bits 15-8:    Index (identifies the instance of NOA sub element)
         *  Bit  16:     Opp PS state of the AP
         *     Bits 23-17:    Ctwindow in TUs
         *     Bits 31-24:    Number of NOA descriptors
         */
        A_UINT32    noa_attributes;
        wmi_p2p_noa_descriptor    noa_descriptors[WMI_P2P_MAX_NOA_DESCRIPTORS];
        }wmi_p2p_noa_info;

#define	WMI_UNIFIED_NOA_ATTR_MODIFIED		0x1
#define	WMI_UNIFIED_NOA_ATTR_MODIFIED_S		0

#define WMI_UNIFIED_NOA_ATTR_IS_MODIFIED(hdr)                       \
			WMI_F_MS((hdr)->noa_attributes, WMI_UNIFIED_NOA_ATTR_MODIFIED)

#define WMI_UNIFIED_NOA_ATTR_MODIFIED_SET(hdr)                      \
            WMI_F_RMW((hdr)->noa_attributes, 0x1,                    \
              WMI_UNIFIED_NOA_ATTR_MODIFIED);

#define	WMI_UNIFIED_NOA_ATTR_INDEX			0xff00
#define	WMI_UNIFIED_NOA_ATTR_INDEX_S		8

#define WMI_UNIFIED_NOA_ATTR_INDEX_GET(hdr)                            \
            WMI_F_MS((hdr)->noa_attributes, WMI_UNIFIED_NOA_ATTR_INDEX)

#define WMI_UNIFIED_NOA_ATTR_INDEX_SET(hdr, v)                      \
            WMI_F_RMW((hdr)->noa_attributes, (v) & 0xff,            \
        WMI_UNIFIED_NOA_ATTR_INDEX);

#define	WMI_UNIFIED_NOA_ATTR_OPP_PS			0x10000
#define	WMI_UNIFIED_NOA_ATTR_OPP_PS_S		16

#define WMI_UNIFIED_NOA_ATTR_OPP_PS_GET(hdr)                         \
            WMI_F_MS((hdr)->noa_attributes, WMI_UNIFIED_NOA_ATTR_OPP_PS)

#define WMI_UNIFIED_NOA_ATTR_OPP_PS_SET(hdr)                         \
            WMI_F_RMW((hdr)->noa_attributes, 0x1,                    \
        WMI_UNIFIED_NOA_ATTR_OPP_PS);

#define	WMI_UNIFIED_NOA_ATTR_CTWIN			0xfe0000
#define	WMI_UNIFIED_NOA_ATTR_CTWIN_S		17

#define WMI_UNIFIED_NOA_ATTR_CTWIN_GET(hdr)                          \
            WMI_F_MS((hdr)->noa_attributes, WMI_UNIFIED_NOA_ATTR_CTWIN)

#define WMI_UNIFIED_NOA_ATTR_CTWIN_SET(hdr, v)                       \
            WMI_F_RMW((hdr)->noa_attributes, (v) & 0x7f,             \
        WMI_UNIFIED_NOA_ATTR_CTWIN);

#define	WMI_UNIFIED_NOA_ATTR_NUM_DESC		0xff000000
#define	WMI_UNIFIED_NOA_ATTR_NUM_DESC_S		24

#define WMI_UNIFIED_NOA_ATTR_NUM_DESC_GET(hdr)                       \
            WMI_F_MS((hdr)->noa_attributes, WMI_UNIFIED_NOA_ATTR_NUM_DESC)

#define WMI_UNIFIED_NOA_ATTR_NUM_DESC_SET(hdr, v)                    \
            WMI_F_RMW((hdr)->noa_attributes, (v) & 0xff,             \
        WMI_UNIFIED_NOA_ATTR_NUM_DESC);

        typedef struct {
            /** TIM info */
            wmi_tim_info tim_info;
            /** P2P NOA info */
            wmi_p2p_noa_info p2p_noa_info;
            /* TBD: More info elements to be added later */
        } wmi_bcn_info;

        typedef struct {
            A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_host_swba_event_fixed_param  */
            /** bitmap identifying the VDEVs, generated by the caller */
            A_UINT32 vdev_map;
            /* This TLV is followed by tim_info and p2p_noa_info for each vdev in vdevmap :
                       *     wmi_tim_info tim_info[];
                       *     wmi_p2p_noa_info p2p_noa_info[];
                       *
                       */
        } wmi_host_swba_event_fixed_param;

        #define WMI_MAX_AP_VDEV 16


        typedef struct {
            A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_tbtt_offset_event_fixed_param  */
            /** bimtap of VDEVs that has tbtt offset updated */
            A_UINT32 vdev_map;
            /* The TLVs for tbttoffset_list will follow this TLV.
                      *     tbtt offset list in the order of the LSB to MSB in the vdev_map bitmap
                      *     A_UINT32 tbttoffset_list[WMI_MAX_AP_VDEV];
                      */
        } wmi_tbtt_offset_event_fixed_param;


        /* Peer Specific commands and events */
        typedef struct {
            A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_create_cmd_fixed_param */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** peer MAC address */
            wmi_mac_addr peer_macaddr;
        } wmi_peer_create_cmd_fixed_param;

        typedef struct {
            A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_delete_cmd_fixed_param */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** peer MAC address */
            wmi_mac_addr peer_macaddr;
        } wmi_peer_delete_cmd_fixed_param;

        typedef struct {
            A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_flush_tids_cmd_fixed_param */
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** peer MAC address */
            wmi_mac_addr peer_macaddr;
            /** tid bitmap identifying the tids to flush */
            A_UINT32 peer_tid_bitmap;
        } wmi_peer_flush_tids_cmd_fixed_param;

        typedef struct {
            /** rate mode . 0: disable fixed rate (auto rate)
             *   1: legacy (non 11n) rate  specified as ieee rate 2*Mbps
             *   2: ht20 11n rate  specified as mcs index
             *   3: ht40 11n rate  specified as mcs index
             */
            A_UINT32  rate_mode;
             /** 4 rate values for 4 rate series. series 0 is stored in byte 0 (LSB)
              *  and series 3 is stored at byte 3 (MSB) */
            A_UINT32  rate_series;
             /** 4 retry counts for 4 rate series. retry count for rate 0 is stored in byte 0 (LSB)
              *  and retry count for rate 3 is stored at byte 3 (MSB) */
            A_UINT32  rate_retries;
        } wmi_fixed_rate;

        typedef struct {
            /** unique id identifying the VDEV, generated by the caller */
            A_UINT32 vdev_id;
            /** peer MAC address */
            wmi_mac_addr peer_macaddr;
            /** fixed rate */
            wmi_fixed_rate peer_fixed_rate;
        } wmi_peer_fixed_rate_cmd;

        #define WMI_MGMT_TID    17

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_addba_clear_resp_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
} wmi_addba_clear_resp_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_addba_send_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** Tid number */
    A_UINT32 tid;
    /** Buffer/Window size*/
    A_UINT32 buffersize;
} wmi_addba_send_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_delba_send_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** Tid number */
    A_UINT32 tid;
    /** Is Initiator */
    A_UINT32 initiator;
    /** Reason code */
    A_UINT32 reasoncode;
} wmi_delba_send_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_addba_setresponse_cmd_fixed_param */
    /** unique id identifying the vdev, generated by the caller */
    A_UINT32 vdev_id;
    /** peer mac address */
    wmi_mac_addr peer_macaddr;
    /** Tid number */
    A_UINT32 tid;
    /** status code */
    A_UINT32 statuscode;
} wmi_addba_setresponse_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_send_singleamsdu_cmd_fixed_param */
    /** unique id identifying the vdev, generated by the caller */
    A_UINT32 vdev_id;
    /** peer mac address */
    wmi_mac_addr peer_macaddr;
    /** Tid number */
    A_UINT32 tid;
} wmi_send_singleamsdu_cmd_fixed_param;

/* Type of Station DTIM Power Save method */
enum {
    /* For NORMAL DTIM, the parameter is the number of beacon intervals and
     * also the same value as the listen interval. For this method, the
     * station will wake up based on the listen interval. If this
     * listen interval is not equal to DTIM, then the station may
     * miss certain DTIM beacons. If this value is 1, then the
     * station will wake up for every beacon.
     */
    WMI_STA_DTIM_PS_NORMAL_DTIM = 0x01,
    /* For MODULATED_DTIM, parameter is a multiple of DTIM beacons to skip.
     * When this value is 1, then the station will wake at every DTIM beacon.
     * If this value is >1, then the station will skip certain DTIM beacons.
     * This value is the multiple of DTIM intervals that the station will
     * wake up to receive the DTIM beacons.
     */
    WMI_STA_DTIM_PS_MODULATED_DTIM = 0x02,
};

/* Parameter structure for the WMI_STA_DTIM_PS_METHOD_CMDID */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_sta_dtim_ps_method_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** Station DTIM Power Save method as defined above */
    A_UINT32 dtim_pwrsave_method;
    /** DTIM PS value. Contents depends on the method */
    A_UINT32 value;
} wmi_sta_dtim_ps_method_cmd_fixed_param;

    /*
    * For Station UAPSD Auto Trigger feature, the Firmware monitors the
    * uAPSD uplink and downlink traffic for each uAPSD enabled WMM ACs.
    * If there is no uplink/download for the specified service interval (field service_interval),
    * firmware will auto generate a QOS-NULL trigger for that WMM-AP with the TID value
    * specified in the UP (field user_priority).
    * Firmware also monitors the responses for these QOS-NULL triggers.
    * If the peer does not have any delivery frames, it will respond with
    * QOS-NULL (EOSP=1). This feature of only using service interval is assumed to be mandatory for all
    * firmware implementation. For this basic implementation, the suspend_interval and delay_interval
    * are unused and should be set to 0.
    * When service_interval is 0, then the firmware will not send any trigger frames. This is for
    * certain host-based implementations that don't want this firmware offload.
    * Note that the per-AC intervals are required for some usage scenarios. This is why the intervals
    * are given in the array of ac_param[]. For example, Voice service interval may defaults to 20 ms
    * and rest of the AC default to 300 ms.
    *
    * The service bit, WMI_STA_UAPSD_VAR_AUTO_TRIG, will indicate that the more advanced feature
    * of variable auto trigger is supported. The suspend_interval and delay_interval is used in
    * the more advanced monitoring method.
    * If the PEER does not have any delivery enabled data frames (non QOS-NULL) for the
    * suspend interval (field suspend_interval), firmware will change its auto trigger interval
    * to delay interval (field delay_interval). This way, when there is no traffic, the station
    * will save more power by waking up less and sending less trigger frames.
    * The (service_interval < suspend_interval) and (service_interval < delay_interval).
    * If this variable auto trigger is not required, then the suspend_interval and delay_interval
    * should be 0.
    */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_sta_uapsd_auto_trig_param */
    /** WMM Access category from 0 to 3 */
    A_UINT32 wmm_ac;
    /** User priority to use in trigger frames. It is the TID
     *  value. This field needs to be specified and may not be
     *  equivalent to AC since some implementation may use the TSPEC
     *  to enable UAPSD and negotiate a particular user priority. */
    A_UINT32 user_priority;
    /** service interval in ms */
    A_UINT32 service_interval;
    /** Suspend interval in ms */
    A_UINT32 suspend_interval;
    /** delay interval in ms */
    A_UINT32 delay_interval;
} wmi_sta_uapsd_auto_trig_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_sta_uapsd_auto_trig_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer mac address */
    wmi_mac_addr peer_macaddr;
    /** Number of AC to specify */
    A_UINT32 num_ac;
    /*
         * Following this struc is the TLV:
         *     wmi_sta_uapsd_auto_trig_param ac_param[]; //Variable number of AC parameters (defined by field num_ac)
         */

} wmi_sta_uapsd_auto_trig_cmd_fixed_param;

/** mimo powersave state */
#define WMI_PEER_MIMO_PS_STATE                          0x1
/** enable/disable AMPDU . initial value (enabled) */
#define WMI_PEER_AMPDU                                  0x2
/** authorize/unauthorize peer. initial value is unauthorized (0)  */
#define WMI_PEER_AUTHORIZE                              0x3
/** peer channel bandwidth */
#define WMI_PEER_CHWIDTH                                0x4
/** peer NSS */
#define WMI_PEER_NSS                                    0x5
/** USE 4 ADDR */
#define WMI_PEER_USE_4ADDR                              0x6
/* set group membership status */
#define WMI_PEER_MEMBERSHIP                0x7
#define WMI_PEER_USERPOS                0x8
/*
 * A critical high-level protocol is being used with this peer. Target
 * should take appropriate measures (if possible) to ensure more
 * reliable link with minimal latency. This *may* include modifying the
 * station power save policy, enabling more RX chains, increased
 * priority of channel scheduling, etc.
 *
 * NOTE: This parameter should only be considered a hint as specific
 * behavior will depend on many factors including current network load
 * and vdev/peer configuration.
 *
 * For STA VDEV this peer corresponds to the AP's BSS peer.
 * For AP VDEV this peer corresponds to the remote peer STA.
 */
#define WMI_PEER_CRIT_PROTO_HINT_ENABLED     0x9

/** mimo ps values for the parameter WMI_PEER_MIMO_PS_STATE  */
#define WMI_PEER_MIMO_PS_NONE                          0x0
#define WMI_PEER_MIMO_PS_STATIC                        0x1
#define WMI_PEER_MIMO_PS_DYNAMIC                       0x2

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_set_param_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** parameter id   */
    A_UINT32 param_id;
    /** parametr value */
    A_UINT32 param_value;
} wmi_peer_set_param_cmd_fixed_param;

#define MAX_SUPPORTED_RATES 128

typedef struct {
    /** total number of rates */
    A_UINT32 num_rates;
    /**
     * rates (each 8bit value) packed into a 32 bit word.
     * the rates are filled from least significant byte to most
     * significant byte.
     */
    A_UINT32 rates[(MAX_SUPPORTED_RATES/4)+1];
} wmi_rate_set;

/* NOTE: It would bea good idea to represent the Tx MCS
 * info in one word and Rx in another word. This is split
 * into multiple words for convenience
 */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vht_rate_set */
    A_UINT32 rx_max_rate; /* Max Rx data rate */
    A_UINT32 rx_mcs_set;  /* Negotiated RX VHT rates */
    A_UINT32 tx_max_rate; /* Max Tx data rate */
    A_UINT32 tx_mcs_set;  /* Negotiated TX VHT rates */
}wmi_vht_rate_set;

/*
 * IMPORTANT: Make sure the bit definitions here are consistent
 * with the ni_flags definitions in wlan_peer.h
 */
#define WMI_PEER_AUTH           0x00000001  /* Authorized for data */
#define WMI_PEER_QOS            0x00000002  /* QoS enabled */
#define WMI_PEER_NEED_PTK_4_WAY 0x00000004  /* Needs PTK 4 way handshake for authorization */
#define WMI_PEER_NEED_GTK_2_WAY 0x00000010  /* Needs GTK 2 way handshake after 4-way handshake */
#define WMI_PEER_APSD           0x00000800  /* U-APSD power save enabled */
#define WMI_PEER_HT             0x00001000  /* HT enabled */
#define WMI_PEER_40MHZ          0x00002000  /* 40MHz enabld */
#define WMI_PEER_STBC           0x00008000  /* STBC Enabled */
#define WMI_PEER_LDPC           0x00010000  /* LDPC ENabled */
#define WMI_PEER_DYN_MIMOPS     0x00020000  /* Dynamic MIMO PS Enabled */
#define WMI_PEER_STATIC_MIMOPS  0x00040000  /* Static MIMO PS enabled */
#define WMI_PEER_SPATIAL_MUX    0x00200000  /* SM Enabled */
#define WMI_PEER_VHT            0x02000000  /* VHT Enabled */
#define WMI_PEER_80MHZ          0x04000000  /* 80MHz enabld */
#define WMI_PEER_PMF            0x08000000  /* Robust Management Frame Protection enabled */
/** TODO: Place holder for WLAN_PEER_F_PS_PRESEND_REQUIRED = 0x10000000. Need to be clean up */

/**
 * Peer rate capabilities.
 *
 * This is of interest to the ratecontrol
 * module which resides in the firmware. The bit definitions are
 * consistent with that defined in if_athrate.c.
 *
 * @todo
 * Move this to a common header file later so there is no need to
 * duplicate the definitions or maintain consistency.
 */
#define WMI_RC_DS_FLAG          0x01    /* Dual stream flag */
#define WMI_RC_CW40_FLAG        0x02    /* CW 40 */
#define WMI_RC_SGI_FLAG         0x04    /* Short Guard Interval */
#define WMI_RC_HT_FLAG          0x08    /* HT */
#define WMI_RC_RTSCTS_FLAG      0x10    /* RTS-CTS */
#define WMI_RC_TX_STBC_FLAG     0x20    /* TX STBC */
#define WMI_RC_RX_STBC_FLAG     0xC0    /* RX STBC ,2 bits */
#define WMI_RC_RX_STBC_FLAG_S   6       /* RX STBC ,2 bits */
#define WMI_RC_WEP_TKIP_FLAG    0x100   /* WEP/TKIP encryption */
#define WMI_RC_TS_FLAG          0x200   /* Three stream flag */
#define WMI_RC_UAPSD_FLAG       0x400   /* UAPSD Rate Control */

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_assoc_complete_cmd_fixed_param */
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** VDEV id */
    A_UINT32 vdev_id;
    /** assoc = 1 reassoc = 0 */
    A_UINT32 peer_new_assoc;
    /** peer associd (16 bits) */
    A_UINT32 peer_associd;
    /** peer station flags: see definition above */
    A_UINT32 peer_flags;
    /** negotiated capabilities (lower 16 bits)*/
    A_UINT32 peer_caps;
    /** Listen interval */
    A_UINT32 peer_listen_intval;
    /** HT capabilties of the peer */
    A_UINT32 peer_ht_caps;
    /** maximum rx A-MPDU length */
    A_UINT32 peer_max_mpdu;
    /** mpdu density of the peer in usec(0 to 16) */
    A_UINT32 peer_mpdu_density;
    /** peer rate capabilties see flags above */
    A_UINT32 peer_rate_caps;
    /** num spatial streams */
    A_UINT32 peer_nss;
    /** VHT capabilties of the peer */
    A_UINT32 peer_vht_caps;
    /** phy mode */
    A_UINT32 peer_phymode;
    /** HT Operation Element of the peer. Five bytes packed in 2
         *  INT32 array and filled from lsb to msb.
         *  Note that the size of array peer_ht_info[] cannotbe changed
         *  without breaking WMI Compatibility. */
    A_UINT32 peer_ht_info[2];
    /** total number of negotiated legacy rate set. Also the sizeof
     *  peer_legacy_rates[] */
    A_UINT32 num_peer_legacy_rates;
    /** total number of negotiated ht rate set. Also the sizeof
     *  peer_ht_rates[] */
    A_UINT32 num_peer_ht_rates;
    /* Following this struc are the TLV's:
         *     A_UINT8 peer_legacy_rates[];
         *     A_UINT8 peer_ht_rates[];
         *     wmi_vht_rate_set peer_vht_rates; //VHT capabilties of the peer
         */
} wmi_peer_assoc_complete_cmd_fixed_param;

typedef struct {
    A_UINT32     tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_add_wds_entry_cmd_fixed_param */
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** wds MAC addr */
    wmi_mac_addr wds_macaddr;
} wmi_peer_add_wds_entry_cmd_fixed_param;

typedef struct {
    A_UINT32     tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_remove_wds_entry_cmd_fixed_param */
    /** wds MAC addr */
    wmi_mac_addr wds_macaddr;
} wmi_peer_remove_wds_entry_cmd_fixed_param;


typedef struct {
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
} wmi_peer_q_empty_callback_event;



/**
 * Channel info WMI event
 */
typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_chan_info_event_fixed_param */
     /** Error code */
    A_UINT32 err_code;
   /** Channel freq */
    A_UINT32 freq;
    /** Read flags */
    A_UINT32 cmd_flags;
    /** Noise Floor value */
    A_UINT32 noise_floor;
    /** rx clear count */
    A_UINT32   rx_clear_count;
    /** cycle count */
    A_UINT32   cycle_count;
} wmi_chan_info_event_fixed_param;

/**
 * Non wlan interference event
 */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_ath_dcs_cw_int */
    A_UINT32 channel; /* either number or freq in mhz*/
} ath_dcs_cw_int;

/**
 *  wlan_dcs_im_tgt_stats
 *
 */
typedef struct _wlan_dcs_im_tgt_stats {
    /** current running TSF from the TSF-1 */
    A_UINT32                  reg_tsf32;

    /** Known last frame rssi, in case of multiple stations, if
     *  and at different ranges, this would not gaurantee that
     *  this is the least rssi.
     */
    A_UINT32                  last_ack_rssi;

    /**  Sum of all the failed durations in the last one second interval.
     */
    A_UINT32                  tx_waste_time;
    /** count how many times the hal_rxerr_phy is marked, in this
     *  time period
     */
    A_UINT32                rx_time;
    A_UINT32                 phyerr_cnt;

    /**
         *  WLAN IM stats from target to host
         *
         *  Below statistics are sent from target to host periodically.
         *  These are collected at target as long as target is running
         *  and target chip is not in sleep.
         *
         */
    /** listen time from ANI */
    A_INT32   listen_time;

    /** tx frame count, MAC_PCU_TX_FRAME_CNT_ADDRESS */
    A_UINT32   reg_tx_frame_cnt;

    /** rx frame count, MAC_PCU_RX_FRAME_CNT_ADDRESS */
    A_UINT32   reg_rx_frame_cnt;

    /** rx clear count, MAC_PCU_RX_CLEAR_CNT_ADDRESS */
    A_UINT32   reg_rxclr_cnt;

    /** total cycle counts MAC_PCU_CYCLE_CNT_ADDRESS */
    A_UINT32   reg_cycle_cnt;            /* delta cycle count */

    /** extenstion channel rx clear count  */
    A_UINT32   reg_rxclr_ext_cnt;

    /** OFDM phy error counts, MAC_PCU_PHY_ERR_CNT_1_ADDRESS */
    A_UINT32   reg_ofdm_phyerr_cnt;

    /** CCK phy error count, MAC_PCU_PHY_ERR_CNT_2_ADDRESS */
    A_UINT32   reg_cck_phyerr_cnt;        /* CCK err count since last reset, read from register */

} wlan_dcs_im_tgt_stats_t;

/**
 *  wmi_dcs_interference_event_t
 *
 *  Right now this is event and stats together. Partly this is
 *  because cw interference is handled in target now. This
 *  can be done at host itself, if we can carry the NF alone
 *  as a stats event. In future this would be done and this
 *  event would carry only stats.
 */
typedef struct {
    A_UINT32    tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_dcs_interference_event_fixed_param */
    /**
     * Type of the event present, either the cw interference event, or the wlan_im stats
     */
    A_UINT32    interference_type;      /* type of interference, wlan or cw */
    /*
     * Following this struct are these TLVs. Note that they are both array of structures
     * but can have at most one element. Which TLV is empty or has one element depends
     * on the field interference_type. This is to emulate an union with cw_int and wlan_stat
     * elements (not arrays).     union { ath_dcs_cw_int cw_int; wlan_dcs_im_tgt_stats_t   wlan_stat; } int_event;
     *
     *        //cw_interference event
     *       ath_dcs_cw_int            cw_int[];  this element
     *       // wlan im interfernce stats
     *       wlan_dcs_im_tgt_stats_t   wlan_stat[];
     */
} wmi_dcs_interference_event_fixed_param;

enum wmi_peer_mcast_group_action {
    wmi_peer_mcast_group_action_add = 0,
    wmi_peer_mcast_group_action_del = 1
};
#define WMI_PEER_MCAST_GROUP_FLAG_ACTION_M   0x1
#define WMI_PEER_MCAST_GROUP_FLAG_ACTION_S   0
#define WMI_PEER_MCAST_GROUP_FLAG_WILDCARD_M 0x2
#define WMI_PEER_MCAST_GROUP_FLAG_WILDCARD_S 1
/* multicast group membership commands */
/* TODO: Converting this will be tricky since it uses an union.
   Also, the mac_addr is not aligned. We will convert to the wmi_mac_addr */
typedef struct{
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_mcast_group_cmd_fixed_param */
    A_UINT32 flags;
    wmi_mac_addr ucast_mac_addr;
    A_UINT8 mcast_ip_addr[16]; /* in network byte order */
} wmi_peer_mcast_group_cmd_fixed_param;


/** Offload Scan and Roaming related  commands */
/** The FW performs 2 different kinds of offload scans independent
 *  of host. One is Roam scan which is primarily performed  on a
 *  station VDEV after association to look for a better AP that
 *  the station VDEV can roam to. The second scan is connect scan
 *  which is mainly performed when the station is not associated
 *  and to look for a matching AP profile from a list of
 *  configured profiles. */

/**
 * WMI_ROAM_SCAN_MODE: Set Roam Scan mode
 *   the roam scan mode is one of the periodic, rssi change, both, none.
 *   None        : Disable Roam scan. No Roam scan at all.
 *   Periodic    : Scan periodically with a configurable period.
 *   Rssi change : Scan when ever rssi to current AP changes by the threshold value
 *                 set by WMI_ROAM_SCAN_RSSI_CHANGE_THRESHOLD command.
 *   Both        : Both of the above (scan when either period expires or rss to current AP changes by X amount)
 *
 */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_roam_scan_mode_fixed_param */
	A_UINT32 roam_scan_mode;
    A_UINT32 vdev_id;
} wmi_roam_scan_mode_fixed_param;

#define WMI_ROAM_SCAN_MODE_NONE        0x0
#define WMI_ROAM_SCAN_MODE_PERIODIC    0x1
#define WMI_ROAM_SCAN_MODE_RSSI_CHANGE 0x2
#define WMI_ROAM_SCAN_MODE_BOTH        0x3

/**
 * WMI_ROAM_SCAN_RSSI_THRESHOLD : set scan rssi thresold
 *  scan rssi threshold is the rssi threshold below which the FW will start running Roam scans.
 * Applicable when WMI_ROAM_SCAN_MODE is not set to none.
 */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_roam_scan_rssi_threshold_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** roam scan rssi threshold */
    A_UINT32 roam_scan_rssi_thresh;
    /** When using Hw generated beacon RSSI interrupts */
    A_UINT32 roam_rssi_thresh_diff;
} wmi_roam_scan_rssi_threshold_fixed_param;

/**
 * WMI_ROAM_SCAN_PERIOD: period for roam scan.
 *  Applicable when the scan mode is Periodic or both.
 */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_roam_scan_period_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** roam scan period value */
    A_UINT32 roam_scan_period;
    /** Aging for Roam scans */
    A_UINT32 roam_scan_age;
} wmi_roam_scan_period_fixed_param;

/**
 * WMI_ROAM_SCAN_RSSI_CHANGE_THRESHOLD : rssi delta to trigger the roam scan.
 *   Rssi change threshold used when mode is Rssi change (or) Both.
 *   The FW will run the roam scan when ever the rssi changes (up or down) by the value set by this parameter.
 *   Note scan is triggered based on the rssi threshold condition set by WMI_ROAM_SCAN_RSSI_THRESHOLD
 */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_roam_scan_rssi_change_threshold_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** roam scan rssi change threshold value */
    A_UINT32 roam_scan_rssi_change_thresh;
    /** When using Hw generated beacon RSSI interrupts */
    A_UINT32 bcn_rssi_weight;
} wmi_roam_scan_rssi_change_threshold_fixed_param;

#define WMI_ROAM_SCAN_CHAN_LIST_TYPE_NONE 0x1
#define WMI_ROAM_SCAN_CHAN_LIST_TYPE_STATIC 0x2
#define WMI_ROAM_SCAN_CHAN_LIST_TYPE_DYNAMIC 0x3
/**
 * TLV for roaming channel list
 */
typedef struct {
    A_UINT32 tlv_header; /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_roam_chan_list_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** WMI_CHAN_LIST_TAG */
    A_UINT32 chan_list_type;
    /** # if channels to scan */
    A_UINT32 num_chan;
/**
 * TLV (tag length value ) parameters follow the wmi_roam_chan_list
 * structure. The TLV's are:
 *     A_UINT32 channel_list[];
 **/
} wmi_roam_chan_list_fixed_param;

/** Authentication modes */
enum {
    WMI_AUTH_NONE   , /* no upper level auth */
    WMI_AUTH_OPEN   , /* open */
    WMI_AUTH_SHARED , /* shared-key */
    WMI_AUTH_8021X  , /* 802.1x */
    WMI_AUTH_AUTO   , /* Auto */
    WMI_AUTH_WPA    , /* WPA */
    WMI_AUTH_RSNA   , /* WPA2/RSNA */
    WMI_AUTH_CCKM   , /* CCK */
    WMI_AUTH_WAPI   ,/* WAPI */
};

typedef struct {
    /** authentication mode (defined above)  */
    A_UINT32               rsn_authmode;
    /** unicast cipher set */
    A_UINT32               rsn_ucastcipherset;
    /** mcast/group cipher set */
    A_UINT32               rsn_mcastcipherset;
    /** mcast/group management frames cipher set */
    A_UINT32               rsn_mcastmgmtcipherset;
} wmi_rsn_params;

/** looking for a wps enabled AP */
#define WMI_AP_PROFILE_FLAG_WPS    0x1
/** looking for a secure AP  */
#define WMI_AP_PROFILE_FLAG_CRYPTO 0x2

/** To match an open AP, the rs_authmode should be set to WMI_AUTH_NONE
 *  and WMI_AP_PROFILE_FLAG_CRYPTO should be clear.
 *  To match a WEP enabled AP, the rs_authmode should be set to WMI_AUTH_NONE
 *  and WMI_AP_PROFILE_FLAG_CRYPTO should be set .
 */

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_ap_profile */
    /** flags as defined above */
    A_UINT32  flags;
	/**
     * rssi thresold value: the value of the the candidate AP should
	 * higher by this threshold than the rssi of the currrently associated AP.
	 */
	A_UINT32 rssi_threshold;
	/**
	 * ssid vlaue to be matched.
	 */
    wmi_ssid ssid;

    /**
	 * security params to be matched.
	 */
    /** authentication mode (defined above)  */
    A_UINT32               rsn_authmode;
    /** unicast cipher set */
    A_UINT32               rsn_ucastcipherset;
    /** mcast/group cipher set */
    A_UINT32               rsn_mcastcipherset;
    /** mcast/group management frames cipher set */
    A_UINT32               rsn_mcastmgmtcipherset;
} wmi_ap_profile;

/** Beacon filter wmi command info */

#define BCN_FLT_MAX_SUPPORTED_IES    256
#define BCN_FLT_MAX_ELEMS_IE_LIST    BCN_FLT_MAX_SUPPORTED_IES/32

typedef struct bss_bcn_stats {
    A_UINT32    vdev_id;
    A_UINT32    bss_bcnsdropped;
    A_UINT32    bss_bcnsdelivered;
}wmi_bss_bcn_stats_t;

typedef struct bcn_filter_stats {
    A_UINT32    bcns_dropped;
    A_UINT32    bcns_delivered;
    A_UINT32    activefilters;
    wmi_bss_bcn_stats_t bss_stats;
}wmi_bcnfilter_stats_t;

typedef struct wmi_add_bcn_filter_cmd {
    A_UINT32    tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_add_bcn_filter_cmd_fixed_param */
    A_UINT32    vdev_id;
    /*
     * Following this structure is the TLV:
     *    A_UINT32   ie_map[BCN_FLT_MAX_ELEMS_IE_LIST];
    */
} wmi_add_bcn_filter_cmd_fixed_param;

typedef struct wmi_rmv_bcn_filter_cmd {
    A_UINT32    tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_rmv_bcn_filter_cmd_fixed_param */
    A_UINT32    vdev_id;
}wmi_rmv_bcn_filter_cmd_fixed_param;

#define WMI_BCN_SEND_DTIM_ZERO         1
#define WMI_BCN_SEND_DTIM_BITCTL_SET   2
typedef struct wmi_bcn_send_from_host {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_bcn_send_from_host_cmd_fixed_param  */
    A_UINT32 vdev_id;
    A_UINT32 data_len;
    A_UINT32 frag_ptr; /* Physical address of the frame */
    A_UINT32 frame_ctrl; /* farme ctrl to setup PPDU desc */
    A_UINT32 dtim_flag;   /* to control CABQ traffic */
}wmi_bcn_send_from_host_cmd_fixed_param;

/* cmd to support bcn snd for all vaps at once */
typedef struct wmi_pdev_send_bcn {
    A_UINT32                       num_vdevs;
    wmi_bcn_send_from_host_cmd_fixed_param   bcn_cmd[1];
} wmi_pdev_send_bcn_cmd_t;

 /*
  * WMI_ROAM_AP_PROFILE:  AP profile of connected AP for roaming.
  */
typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_roam_ap_profile_fixed_param */
    /** id of AP criteria */
	A_UINT32 id;

    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;

    /*
         * Following this structure is the TLV:
         *     wmi_ap_profile ap_profile; //AP profile info
        */
} wmi_roam_ap_profile_fixed_param;;

/**
 * WMI_OFL_SCAN_ADD_AP_PROFILE: add an AP profile.
 */
typedef struct {
    /** id of AP criteria */
	A_UINT32 id;

    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;

    /** AP profile info */
    wmi_ap_profile ap_profile;

} wmi_ofl_scan_add_ap_profile;

/**
 * WMI_OFL_SCAN_REMOVE_AP_CRITERIA: remove an ap profile.
 */
typedef struct {
    /** id of AP criteria */
	A_UINT32 id;
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
} wmi_ofl_scan_remove_ap_profile;

/**
 * WMI_OFL_SCAN_PERIOD: period in msec for offload scan.
 *  0 will disable ofload scan and a very low value will perform a continous
 *  scan.
 */
typedef struct {
	/** offload scan period value, used for scans used when not connected */
	A_UINT32 ofl_scan_period;
} wmi_ofl_scan_period;



/** WMI_ROAM_EVENT: roam event triggering the host roam logic.
 * generated when ever a better AP is found in the recent roam scan (or)
 * when beacon miss is detected (or) when a DEAUTH/DISASSOC is received
 * from the current AP.
 */
typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_roam_event_fixed_param  */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** reason for roam event */
    A_UINT32 reason;
    /** associated AP's rssi calculated by FW when reason code is WMI_ROAM_REASON_LOW_RSSI*/
    A_UINT32 rssi;

} wmi_roam_event_fixed_param;

#define WMI_ROAM_REASON_BETTER_AP 0x1 /** found a better AP */
#define WMI_ROAM_REASON_BMISS     0x2 /** beacon miss detected */
#define WMI_ROAM_REASON_DEAUTH    0x2 /** deauth/disassoc received */
#define WMI_ROAM_REASON_LOW_RSSI  0x3 /** connected AP's low rssi condition detected */

/** WMI_PROFILE_MATCH_EVENT: offload scan
 * generated when ever atleast one of the matching profiles is found
 * in recent NLO scan. no data is carried with the event.
 */

/** P2P specific commands */

/**
 * WMI_P2P_DEV_SET_DEVICE_INFO : p2p device info, which will be used by
 * FW to generate P2P IE tobe carried in probe response frames.
 * FW will respond to probe requests while in listen state.
 */
typedef struct {
    /* number of secondary device types,supported */
    A_UINT32 num_secondary_dev_types;
    /**
     * followed by 8 bytes of primary device id and
     * num_secondary_dev_types * 8 bytes of secondary device
     * id.
     */
} wmi_p2p_dev_set_device_info;

/** WMI_P2P_DEV_SET_DISCOVERABILITY: enable/disable discoverability
 *  state. if enabled, an active STA/AP will respond to P2P probe requests on
 *  the operating channel of the VDEV.
 */

typedef struct {
    /* 1:enable disoverability, 0:disable discoverability */
    A_UINT32 enable_discoverability;
}  wmi_p2p_set_discoverability;

/** WMI_P2P_GO_SET_BEACON_IE: P2P IE to be added to
 *  beacons generated by FW. used in FW beacon mode.
 *  the FW will add this IE to beacon in addition to the beacon
 *  template set by WMI_BCN_TMPL_CMDID command.
 */
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_p2p_go_set_beacon_ie_fixed_param  */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /* ie length */
    A_UINT32 ie_buf_len;
   /* Following this structure is the TLV byte stream of ie data of length ie_buf_len:
       *     A_UINT8 ie_data[];    // length in byte given by field num_data.
       */

}  wmi_p2p_go_set_beacon_ie_fixed_param;

/** WMI_P2P_GO_PROBE_RESP_IE: P2P IE to be added to
 *  probe response generated by FW. used in FW beacon mode.
 *  the FW will add this IE to probe response in addition to the probe response
 *  template set by WMI_PRB_TMPL_CMDID command.
 */
typedef struct {
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /* ie length */
    A_UINT32 ie_buf_len;
    /*followed by  byte stream of ie data of length ie_buf_len */
}  wmi_p2p_go_set_probe_resp_ie;

/** WMI_P2P_SET_VENDOR_IE_DATA_CMDID: Vendor specific P2P IE data, which will
 *  be used by the FW to parse the P2P NoA attribute in beacons, probe resposes
 *  and action frames received by the P2P Client.
 */
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_p2p_set_vendor_ie_data_cmd_fixed_param */
    /** OS specific P2P IE OUI (3 bytes) + OUI type (1 byte)  */
    A_UINT32 p2p_ie_oui_type;
    /** OS specific NoA Attribute ID */
    A_UINT32 p2p_noa_attribute;
}  wmi_p2p_set_vendor_ie_data_cmd_fixed_param;

/*----P2P disc offload definition  ----*/

typedef struct {
    A_UINT32        pattern_type;
    /**
     * TLV (tag length value )  paramerters follow the pattern structure.
     * TLV can contain bssid list, ssid list and
     * ie. the TLV tags are defined above;
     */
}wmi_p2p_disc_offload_pattern_cmd;

typedef struct {
    /* unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
	/* mgmt type of the ie*/
	A_UINT32 mgmt_type;
    /* ie length */
    A_UINT32 ie_buf_len;
    /*followed by  byte stream of ie data of length ie_buf_len */
}wmi_p2p_disc_offload_appie_cmd;

typedef struct {
    /* enable/disable p2p find offload*/
    A_UINT32      enable;
	/* unique id identifying the VDEV, generated by the caller */
	A_UINT32      vdev_id;
	/* p2p find type */
	A_UINT32      disc_type;
	/* p2p find perodic */
	A_UINT32      perodic;
	/* p2p find listen channel */
	A_UINT32      listen_channel;
	/* p2p find full channel number */
    A_UINT32      num_scan_chans;
	/**
     * TLV (tag length value )  paramerters follow the pattern structure.
     * TLV  contain channel list
     */
}wmi_p2p_disc_offload_config_cmd;

/*----P2P OppPS definition  ----*/
typedef struct {
	/* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_p2p_set_oppps_cmd_fixed_param  */
    A_UINT32 tlv_header;
    /* unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /* OppPS attributes */
	/** Bit  0: Indicate enable/disable of OppPS
	 *	Bits 7-1:	Ctwindow in TUs
	 *	Bits 31-8:  Reserved
	 */
	A_UINT32	oppps_attr;
} wmi_p2p_set_oppps_cmd_fixed_param;

#define	WMI_UNIFIED_OPPPS_ATTR_ENALBED		0x1
#define	WMI_UNIFIED_OPPPS_ATTR_ENALBED_S	0

#define WMI_UNIFIED_OPPPS_ATTR_IS_ENABLED(hdr)                   \
			WMI_F_MS((hdr)->oppps_attr, WMI_UNIFIED_OPPPS_ATTR_ENALBED)

#define WMI_UNIFIED_OPPPS_ATTR_ENABLED_SET(hdr)                 \
            WMI_F_RMW((hdr)->oppps_attr, 0x1,                \
            WMI_UNIFIED_OPPPS_ATTR_ENALBED);

#define	WMI_UNIFIED_OPPPS_ATTR_CTWIN		0xfe
#define	WMI_UNIFIED_OPPPS_ATTR_CTWIN_S		1

#define WMI_UNIFIED_OPPPS_ATTR_CTWIN_GET(hdr)                        \
            WMI_F_MS((hdr)->oppps_attr, WMI_UNIFIED_OPPPS_ATTR_CTWIN)

#define WMI_UNIFIED_OPPPS_ATTR_CTWIN_SET(hdr, v)                \
            WMI_F_RMW((hdr)->oppps_attr, (v) & 0x7f,            \
            WMI_UNIFIED_OPPPS_ATTR_CTWIN);
/*----RTT Report event definition  ----*/
typedef enum {
    RTT_COMMAND_HEADER_ERROR = 0,      //rtt cmd header parsing error  --terminate
    RTT_COMMAND_ERROR,                 //rtt body parsing error -- skip current STA REQ
    RTT_MODULE_BUSY,                   //rtt no resource        -- terminate
    RTT_TOO_MANY_STA,                  //STA exceed the support limit -- only server the first n STA
    RTT_NO_RESOURCE,                   //any allocate failure
    RTT_VDEV_ERROR,                    //can not find vdev with vdev ID -- skip current STA REQ
    RTT_TRANSIMISSION_ERROR,           //Tx failure   -- continiue and measure number--
    RTT_TM_TIMER_EXPIRE,               //wait for first TM timer expire   -- terminate current STA measurement
    RTT_FRAME_TYPE_NOSUPPORT,          //we do not support RTT measurement with this type of frame
    RTT_TIMER_EXPIRE,                  //whole RTT measurement timer expire  -- terminate current STA measurement
    RTT_CHAN_SWITCH_ERROR,             //channel swicth failed
    RTT_TMR_TRANS_ERROR,               //TMR trans error, this dest peer will be skipped
    RTT_NO_REPORT_BAD_CFR_TOKEN,       //V3 only. If both CFR and Token mismatch, do not report
    RTT_NO_REPORT_FIRST_TM_BAD_CFR,    //For First TM, if CFR is bad, then do not report
    RTT_REPORT_TYPE2_MIX,              //do not allow report type2 mix with type 0, 1
    WMI_RTT_REJECT_MAX,
} WMI_RTT_ERROR_INDICATOR;

typedef struct {
    A_UINT32 time32;     //upper 32 bits of time stamp
    A_UINT32 time0;      //lower 32 bits of time stamp
} A_TIME64;

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_rtt_event_header  */
    A_UINT32 req_id;                   //identify the command and info
    /*result is a bit mask
     *bit 0:15 req_id from measurement request command
     *bit 16: Success 1 / Fail 0
     *bit 17: Measurement Finished 1 / Measurement not Finished 0
     *bit 20:18 RTT measurement Type 000 - NULL 001-QoS_NULL 002 -TMR
     *bit 23:21 report type (0,1,2)
     *bit 25:24 V3 report status (v2 ignore) (report type 2 ignore)
     *    00-Good 01 - Bad CFR 10 -- bad token
     *bit 26:   V3 accomplishment (v2 ignore) (report type 2 ignore)
     *    0 - sending side is not finishing
     *    1 - sending side finish
	 *bit 27: V3 start of a TM sequence (v2 ignore) (report type 2 ignore)
     *    0 - not a start frame  1 -- start frame
     *bit 31:28: #of AP inside this report (only for report type 2, 0,1 ignore)
      */
    wmi_mac_addr  dest_mac;
    //In report type 1 and 2, MAC of the AP
    //in report type 2, bit 31:0 is the channel info
}wmi_rtt_event_hdr;

typedef struct {
    /* RTT header would be added to the buffer as a TLV preceding this structure*/
    A_UINT32 rx_chain;                // Rx chain info
    /************************************************************
     * Bit:0-3:chain mask                                       *
     * Bit 4-5: band width info                                 *
     * 00 --Legacy 20, 01 --HT/VHT20                            *
     * 10 --HT/VHT40, 11 -- VHT80                               *
     ************************************************************/
    A_TIME64 tod;                     // resolution of 0.1ns
    A_TIME64 toa;                     // resolution of 0.1ns
    //If Measurement type is TMR, should be T3, T4 here A_TIME64
    //chain report body will be expand here
    //includes rssi + channel dump for each chain
}wmi_rtt_meas_event;

typedef struct {
    wmi_mac_addr  dest_mac;
    A_UINT32 control;
    //bit 0:7 #of measurement reports in this AP
    //bit 10:8 RTT measurement type
    //bit 31:11 reserved
}wmi_rtt_per_peer_event_hdr;

typedef struct {
    A_UINT32 rx_bw;
    A_UINT32 rssi;
    A_TIME64 tod;
    A_TIME64 toa;
} wmi_rtt_per_frame_ie_v2;

typedef struct {
    A_UINT32 rx_bw;
    A_UINT32 rssi;
    A_TIME64 t1;
    A_TIME64 t2;
    A_UINT32 t3_del;
    A_UINT32 t4_del;
} wmi_rtt_per_frame_ie_v3;


typedef struct {
    /* RTT Event header TLV precedes this TLV
         * wmi_rtt_event_hdr header;
         */
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_rtt_error_report_event_fixed_param  */
    WMI_RTT_ERROR_INDICATOR reject_reason;
}wmi_rtt_error_report_event_fixed_param;

typedef struct {
    A_UINT32 req_id;                   //identify the command
    A_UINT32 result;                   //Successfully or not 0-fail, 1-success
    A_UINT64 peer_tsf;                 //TSF of peer
    A_UINT64 self_tsf;                 //Self's TSF
    A_UINT32 beacon_delta;             //time delta between peer and self's beacon
}wmi_rtt_tsf_meas_event;

#define RTT_V3_GOOD 0x0
#define RTT_V3_BAD_CFR 0x1
#define RTT_V3_BAD_TOKEN 0x2

#define RTT_REPORT_PER_FRAME_WITH_CFR 0
#define RTT_REPORT_PER_FRAME_NO_CFR   1
#define RTT_AGGREAGET_REPORT_NON_CFR  2

//define RTT report macro
#define WMI_RTT_REPORT_REQ_ID_S 0
#define WMI_RTT_REPORT_REQ_ID (0xffff << WMI_RTT_REPORT_REQ_ID_S)
#define WMI_RTT_REPORT_REQ_ID_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_REQ_ID)
#define WMI_RTT_REPORT_REQ_ID_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_REQ_ID)

#define WMI_RTT_REPORT_CHAN_INFO_S 0
#define WMI_RTT_REPORT_CHAN_INFO (0xffffffff << WMI_RTT_REPORT_CHAN_INFO_S)
#define WMI_RTT_REPORT_CHAN_INFO_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_CHAN_INFO)
#define WMI_RTT_REPORT_CHAN_INFO_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_CHAN_INFO)


#define WMI_RTT_REPORT_STATUS_S 16
#define WMI_RTT_REPORT_STATUS (0x1 << WMI_RTT_REPORT_STATUS_S)
#define WMI_RTT_REPORT_STATUS_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_STATUS)
#define WMI_RTT_REPORT_STATUS_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_STATUS)

#define WMI_RTT_REPORT_FINISH_S 17
#define WMI_RTT_REPORT_FINISH (0x1 << WMI_RTT_REPORT_FINISH_S)
#define WMI_RTT_REPORT_FINISH_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_FINISH)
#define WMI_RTT_REPORT_FINISH_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_FINISH)

#define WMI_RTT_REPORT_MEAS_TYPE_S 18
#define WMI_RTT_REPORT_MEAS_TYPE (0x7 << WMI_RTT_REPORT_MEAS_TYPE_S)
#define WMI_RTT_REPORT_MEAS_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_MEAS_TYPE)
#define WMI_RTT_REPORT_MEAS_TYPE_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_MEAS_TYPE)

#define WMI_RTT_REPORT_REPORT_TYPE_S 21
#define WMI_RTT_REPORT_REPORT_TYPE (0x7 << WMI_RTT_REPORT_REPORT_TYPE_S)
#define WMI_RTT_REPORT_REPORT_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_REPORT_TYPE)
#define WMI_RTT_REPORT_REPORT_TYPE_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_REPORT_TYPE)

#define WMI_RTT_REPORT_V3_STATUS_S 24
#define WMI_RTT_REPORT_V3_STATUS (0x3 << WMI_RTT_REPORT_V3_STATUS_S)
#define WMI_RTT_REPORT_V3_STATUS_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_V3_STATUS)
#define WMI_RTT_REPORT_V3_STATUS_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_V3_STATUS)

#define WMI_RTT_REPORT_V3_FINISH_S 26
#define WMI_RTT_REPORT_V3_FINISH (0x1 << WMI_RTT_REPORT_V3_FINISH_S)
#define WMI_RTT_REPORT_V3_FINISH_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_V3_FINISH)
#define WMI_RTT_REPORT_V3_FINISH_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_V3_FINISH)

#define WMI_RTT_REPORT_V3_TM_START_S 27
#define WMI_RTT_REPORT_V3_TM_START (0x1 << WMI_RTT_REPORT_V3_TM_START_S)
#define WMI_RTT_REPORT_V3_TM_START_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_V3_TM_START)
#define WMI_RTT_REPORT_V3_TM_START_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_V3_TM_START)

#define WMI_RTT_REPORT_NUM_AP_S 28     //used for only Report Type 2
#define WMI_RTT_REPORT_NUM_AP (0xf << WMI_RTT_REPORT_NUM_AP_S)
#define WMI_RTT_REPORT_NUM_AP_GET(x) WMI_F_MS(x,WMI_RTT_REPORT_NUM_AP)
#define WMI_RTT_REPORT_NUM_AP_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REPORT_NUM_AP)

//body start here
#define WMI_RTT_REPORT_RX_CHAIN_S 0
#define WMI_RTT_REPORT_RX_CHAIN (0xf << WMI_RTT_REPORT_RX_CHAIN_S)
#define WMI_RTT_REPORT_RX_CHAIN_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_RX_CHAIN)
#define WMI_RTT_REPORT_RX_CHAIN_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_RX_CHAIN)

#define WMI_RTT_REPORT_RX_BW_S 4
#define WMI_RTT_REPORT_RX_BW (0x3 << WMI_RTT_REPORT_RX_BW_S)
#define WMI_RTT_REPORT_RX_BW_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_RX_BW)
#define WMI_RTT_REPORT_RX_BW_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_RX_BW)

#define WMI_RTT_REPORT_TYPE2_NUM_MEAS_S 0
#define WMI_RTT_REPORT_TYPE2_NUM_MEAS (0xff << WMI_RTT_REPORT_TYPE2_NUM_MEAS_S)
#define WMI_RTT_REPORT_TYPE2_NUM_MEAS_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_NUM_MEAS)
#define WMI_RTT_REPORT_TYPE2_NUM_MEAS_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_NUM_MEAS)

#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE_S 8
#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE (0x7 << WMI_RTT_REPORT_TYPE2_MEAS_TYPE_S)
#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_MEAS_TYPE)
#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_MEAS_TYPE)

/*---- end of RTT report event definition ----*/

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_sta_kickout_event_fixed_param  */
    /** peer mac address */
    wmi_mac_addr peer_macaddr;
} wmi_peer_sta_kickout_event_fixed_param;

#define WMI_WLAN_PROFILE_MAX_HIST     3
#define WMI_WLAN_PROFILE_MAX_BIN_CNT 32

typedef struct _wmi_wlan_profile_t {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_wlan_profile_t */
    A_UINT32 id;
    A_UINT32 cnt;
    A_UINT32 tot;
    A_UINT32 min;
    A_UINT32 max;
    A_UINT32 hist_intvl;
    A_UINT32 hist[WMI_WLAN_PROFILE_MAX_HIST];
} wmi_wlan_profile_t;

typedef struct _wmi_wlan_profile_ctx_t {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_wlan_profile_ctx_t */
    A_UINT32 tot; /* time in us */
    A_UINT32 tx_msdu_cnt;
    A_UINT32 tx_mpdu_cnt;
    A_UINT32 tx_ppdu_cnt;
    A_UINT32 rx_msdu_cnt;
    A_UINT32 rx_mpdu_cnt;
    A_UINT32 bin_count;
} wmi_wlan_profile_ctx_t;


typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_wlan_profile_trigger_cmd_fixed_param */
    A_UINT32 enable;
} wmi_wlan_profile_trigger_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_wlan_profile_get_prof_data_cmd_fixed_param */
    A_UINT32 value;
} wmi_wlan_profile_get_prof_data_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_wlan_profile_set_hist_intvl_cmd_fixed_param */
    A_UINT32 profile_id;
    A_UINT32 value;
} wmi_wlan_profile_set_hist_intvl_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_wlan_profile_enable_profile_id_cmd_fixed_param */
    A_UINT32 profile_id;
    A_UINT32 enable;
} wmi_wlan_profile_enable_profile_id_cmd_fixed_param;

/*Wifi header is upto 26, LLC is 8, with 14 byte duplicate in 802.3 header, that's 26+8-14=20.
146-128=18. So this means it is converted to non-QoS header. Riva FW take care of the QOS/non-QOS
when comparing wifi header.*/
/* NOTE: WOW_DEFAULT_BITMAP_PATTERN_SIZE(_DWORD) and WOW_DEFAULT_BITMASK_SIZE(_DWORD) can't be changed without breaking the compatibility */
#define WOW_DEFAULT_BITMAP_PATTERN_SIZE      146
#define WOW_DEFAULT_BITMAP_PATTERN_SIZE_DWORD 37 //Convert WOW_DEFAULT_EVT_BUF_SIZE into Int32 size
#define WOW_DEFAULT_BITMASK_SIZE             146
#define WOW_DEFAULT_BITMASK_SIZE_DWORD        37
#define WOW_MAX_BITMAP_FILTERS               22
#define WOW_DEFAULT_MAGIG_PATTERN_MATCH_CNT  16
#define WOW_DEFAULT_EVT_BUF_SIZE             148  /* Maximum 148 bytes of the data is copied starting from header incase if the match is found.
                                                                                    The 148 comes from (128 - 14 )  payload size  + 8bytes LLC + 26bytes MAC header*/
typedef enum pattern_type_e {
    WOW_PATTERN_MIN = 0,
    WOW_BITMAP_PATTERN = WOW_PATTERN_MIN,
    WOW_IPV4_SYNC_PATTERN,
    WOW_IPV6_SYNC_PATTERN,
    WOW_WILD_CARD_PATTERN,
    WOW_TIMER_PATTERN,
    WOW_MAGIC_PATTERN,
    WOW_PATTERN_MAX
}WOW_PATTERN_TYPE;

typedef enum event_type_e {
    WOW_BMISS_EVENT = 0,
    WOW_BETTER_AP_EVENT,
    WOW_DEAUTH_RECVD_EVENT,
    WOW_MAGIC_PKT_RECVD_EVENT,
    WOW_GTK_ERR_EVENT,
    WOW_FOURWAY_HSHAKE_EVENT,
    WOW_EAPOL_RECVD_EVENT,
    WOW_NLO_DETECTED_EVENT,
    WOW_DISASSOC_RECVD_EVENT,
    WOW_PATTERN_MATCH_EVENT,
}WOW_WAKE_EVENT_TYPE;

typedef enum wake_reason_e {
    WOW_REASON_UNSPECIFIED =-1,
    WOW_REASON_NLOD = 0,
    WOW_REASON_AP_ASSOC_LOST,
    WOW_REASON_LOW_RSSI,
    WOW_REASON_DEAUTH_RECVD,
    WOW_REASON_DISASSOC_RECVD,
    WOW_REASON_GTK_HS_ERR,
    WOW_REASON_EAP_REQ,
    WOW_REASON_FOURWAY_HS_RECV,
    WOW_REASON_TIMER_INTR_RECV,
    WOW_REASON_PATTERN_MATCH_FOUND,
    WOW_REASON_RECV_MAGIC_PATTERN,
    WOW_REASON_P2P_DISC,
    WOW_REASON_DEBUG_TEST = 0xFF,
}WOW_WAKE_REASON_TYPE;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_wow_enable_cmd_fixed_param  */
    A_UINT32    enable;
} wmi_wow_enable_cmd_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_wow_hostwakeup_from_sleep_cmd_fixed_param  */
    /** Reserved for future use */
    A_UINT32    reserved0;
} wmi_wow_hostwakeup_from_sleep_cmd_fixed_param;

typedef struct bitmap_pattern_s {
    A_UINT32     tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WOW_BITMAP_PATTERN_T */
    A_UINT32     patternbuf[WOW_DEFAULT_BITMAP_PATTERN_SIZE_DWORD];
    A_UINT32     bitmaskbuf[WOW_DEFAULT_BITMASK_SIZE_DWORD];
    A_UINT32     pattern_offset;
    A_UINT32     pattern_len;
    A_UINT32     bitmask_len;
    A_UINT32     pattern_id;  /* must be less than max_bitmap_filters */
}WOW_BITMAP_PATTERN_T;

typedef struct ipv4_sync_s {
    A_UINT32     tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WOW_IPV4_SYNC_PATTERN_T */
    A_UINT32     ipv4_src_addr;
    A_UINT32     ipv4_dst_addr;
    A_UINT32     tcp_src_prt;
    A_UINT32     tcp_dst_prt;
}WOW_IPV4_SYNC_PATTERN_T;

typedef struct ipv6_sync_s {
    A_UINT32     tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WOW_IPV6_SYNC_PATTERN_T */
    A_UINT32     ipv6_src_addr[4];
    A_UINT32     ipv6_dst_addr[4];
    A_UINT32     tcp_src_prt;
    A_UINT32     tcp_dst_prt;
}WOW_IPV6_SYNC_PATTERN_T;

typedef struct WOW_MAGIC_PATTERN_CMD
{
    A_UINT32     tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WOW_MAGIC_PATTERN_CMD */
	wmi_mac_addr macaddr;
}WOW_MAGIC_PATTERN_CMD;

typedef struct {
    A_UINT32        tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_WOW_ADD_PATTERN_CMD_fixed_param */
    A_UINT32        vdev_id;
    A_UINT32        pattern_id;
    A_UINT32        pattern_type;
    /*
     * Following this struct are these TLVs. Note that they are all array of structures
     * but can have at most one element. Which TLV is empty or has one element depends
     * on the field pattern_type. This is to emulate an union.
     *     WOW_BITMAP_PATTERN_T       pattern_info_bitmap[];
     *     WOW_IPV4_SYNC_PATTERN_T    pattern_info_ipv4[];
     *     WOW_IPV6_SYNC_PATTERN_T    pattern_info_ipv6[];
     *     WOW_MAGIC_PATTERN_CMD      pattern_info_magic_pattern[];
     *     A_UINT32                   pattern_info_timeout[];
     */
}WMI_WOW_ADD_PATTERN_CMD_fixed_param;

typedef struct {
    A_UINT32        tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_WOW_DEL_PATTERN_CMD_fixed_param */
    A_UINT32        vdev_id;
    A_UINT32        pattern_id;
    A_UINT32        pattern_type;
}WMI_WOW_DEL_PATTERN_CMD_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_WOW_ADD_DEL_EVT_CMD_fixed_param  */
    A_UINT32    vdev_id;
    A_UINT32    is_add;
    A_UINT32    event_bitmap;
}WMI_WOW_ADD_DEL_EVT_CMD_fixed_param;

typedef struct  wow_event_info_s {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_WOW_EVENT_INFO_fixed_param  */
    A_UINT32    vdev_id;
    A_UINT32    flag;                              /*This is current reserved.*/
    A_INT32     wake_reason;
    A_UINT32    data_len;
}WOW_EVENT_INFO_fixed_param;

typedef enum {
    WOW_EVENT_INFO_TYPE_PACKET = 0x0001,
    WOW_EVENT_INFO_TYPE_BITMAP,
    WOW_EVENT_INFO_TYPE_GTKIGTK,
}WOW_EVENT_INFO_TYPE;

typedef struct  wow_event_info_section_s {
    A_UINT32    data_type;
    A_UINT32    data_len;
}WOW_EVENT_INFO_SECTION;

typedef struct  wow_event_info_section_packet_s {
    A_UINT8     packet[WOW_DEFAULT_EVT_BUF_SIZE];
}WOW_EVENT_INFO_SECTION_PACKET;

typedef struct  wow_event_info_section_bitmap_s {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_WOW_EVENT_INFO_SECTION_BITMAP  */
    A_UINT32    flag;                              /*This is current reserved.*/
    A_UINT32    value;                         /*This could be the pattern id for bitmap pattern.*/
    A_UINT32    org_len;                      /*The length of the orginal packet.*/
}WOW_EVENT_INFO_SECTION_BITMAP;

#define WMI_RXERR_CRC               0x01    /* CRC error on frame */
#define WMI_RXERR_DECRYPT           0x08    /* non-Michael decrypt error */
#define WMI_RXERR_MIC               0x10    /* Michael MIC decrypt error */
#define WMI_RXERR_KEY_CACHE_MISS    0x20    /* No/incorrect key matter in h/w */

typedef enum {
    PKT_PWR_SAVE_PAID_MATCH =         0x0001,
    PKT_PWR_SAVE_GID_MATCH =          0x0002,
    PKT_PWR_SAVE_EARLY_TIM_CLEAR =    0x0004,
    PKT_PWR_SAVE_EARLY_DTIM_CLEAR =   0x0008,
    PKT_PWR_SAVE_EOF_PAD_DELIM =      0x0010,
    PKT_PWR_SAVE_MACADDR_MISMATCH =   0x0020,
    PKT_PWR_SAVE_DELIM_CRC_FAIL =     0x0040,
    PKT_PWR_SAVE_GID_NSTS_ZERO =      0x0080,
    PKT_PWR_SAVE_RSSI_CHECK =         0x0100,
    WMI_PKT_PWR_SAVE_MAX =            0x0200,
} WMI_PKT_PWR_SAVE_TYPE;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_ftm_intg_cmd_fixed_param */
    A_UINT32 num_data;       /** length in byte of data[]. */
    /* This structure is used to send Factory Test Mode [FTM] command
     * from host to firmware for integrated chips which are binary blobs.
     * Following this structure is the TLV:
     *     A_UINT8 data[];    // length in byte given by field num_data.
     */
}wmi_ftm_intg_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_ftm_intg_event_fixed_param */
    A_UINT32 num_data;       /** length in byte of data[]. */
    /* This structure is used to receive Factory Test Mode [FTM] event
     * from firmware to host for integrated chips which are binary blobs.
     * Following this structure is the TLV:
     *     A_UINT8 data[];    // length in byte given by field num_data.
     */
}wmi_ftm_intg_event_fixed_param;

#define WMI_MAX_NS_OFFLOADS           2
#define WMI_MAX_ARP_OFFLOADS          2

#define WMI_ARPOFF_FLAGS_VALID              (1 << 0)    /* the tuple entry is valid */
#define WMI_ARPOFF_FLAGS_MAC_VALID          (1 << 1)    /* the target mac address is valid */
#define WMI_ARPOFF_FLAGS_REMOTE_IP_VALID    (1 << 2)    /* remote IP field is valid */

typedef struct _WMI_IPV6_ADDR {
    A_UINT8    address[16];    /* IPV6 in Network Byte Order */
} WMI_IPV6_ADDR;


typedef struct {
    A_UINT32          tlv_header;              /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_ARP_OFFLOAD_TUPLE */
    A_UINT32           flags;                  /* flags */
    A_UINT8           target_ipaddr[4];        /* IPV4 addresses of the local node*/
    A_UINT8           remote_ipaddr[4];        /* source address of the remote node requesting the ARP (qualifier) */
    wmi_mac_addr      target_mac;              /* mac address for this tuple, if not valid, the local MAC is used */
} WMI_ARP_OFFLOAD_TUPLE;

#define WMI_NSOFF_FLAGS_VALID           (1 << 0)    /* the tuple entry is valid */
#define WMI_NSOFF_FLAGS_MAC_VALID       (1 << 1)    /* the target mac address is valid */
#define WMI_NSOFF_FLAGS_REMOTE_IP_VALID (1 << 2)    /* remote IP field is valid */

#define WMI_NSOFF_MAX_TARGET_IPS    2

typedef struct {
    A_UINT32          tlv_header;                /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_NS_OFFLOAD_TUPLE */
    A_UINT32           flags;                     /* flags */
    /* NOTE: This size of array target_ipaddr[] cannot be changed without breaking WMI compatibility. */
    WMI_IPV6_ADDR     target_ipaddr[WMI_NSOFF_MAX_TARGET_IPS]; /* IPV6 target addresses of the local node  */
    WMI_IPV6_ADDR     solicitation_ipaddr;       /* multi-cast source IP addresses for receiving solicitations */
    WMI_IPV6_ADDR     remote_ipaddr;             /* address of remote node requesting the solicitation (qualifier) */
    wmi_mac_addr      target_mac;                /* mac address for this tuple, if not valid, the local MAC is used */
} WMI_NS_OFFLOAD_TUPLE;

typedef struct {
    A_UINT32                tlv_header;      /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_SET_ARP_NS_OFFLOAD_CMD_fixed_param */
    A_UINT32                flags;
    A_UINT32                vdev_id;
    /* Following this structure are the TLVs:
         *     WMI_NS_OFFLOAD_TUPLE    ns_tuples[WMI_MAX_NS_OFFLOADS];
         *     WMI_ARP_OFFLOAD_TUPLE   arp_tuples[WMI_MAX_ARP_OFFLOADS];
         */
} WMI_SET_ARP_NS_OFFLOAD_CMD_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_tid_addba_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** Tid number */
    A_UINT32 tid;
    /** Initiator (1) or Responder (0) for this aggregation */
    A_UINT32 initiator;
    /** size of the negotiated window */
    A_UINT32 window_size;
    /** starting sequence number (only valid for initiator) */
    A_UINT32 ssn;
    /** timeout field represents the time to wait for Block Ack in
    *   initiator case and the time to wait for BAR in responder
    *   case. 0 represents no timeout. */
    A_UINT32 timeout;
    /* BA policy: immediate ACK (0) or delayed ACK (1) */
    A_UINT32 policy;
} wmi_peer_tid_addba_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_peer_tid_delba_cmd */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** Tid number */
    A_UINT32 tid;
    /** Initiator (1) or Responder (0) for this aggregation */
    A_UINT32 initiator;
} wmi_peer_tid_delba_cmd_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_tx_addba_complete_event_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** Tid number */
    A_UINT32 tid;
    /** Event status */
    A_UINT32 status;
} wmi_tx_addba_complete_event_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_tx_delba_complete_event_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** peer MAC address */
    wmi_mac_addr peer_macaddr;
    /** Tid number */
    A_UINT32 tid;
    /** Event status */
    A_UINT32 status;
} wmi_tx_delba_complete_event_fixed_param;
/*
 * Structure to request sequence numbers for a given
 * peer station on different TIDs. The TIDs are
 * indicated in the tidBitMap, tid 0 would
 * be represented by LSB bit 0. tid 1 would be
 * represented by LSB bit 1 etc.
 * The target will retrieve the current sequence
 * numbers for the peer on all the TIDs requested
 * and send back a response in a WMI event.
 */
typedef struct
{
    A_UINT32    tlv_header;  /* TLV tag and len; tag equals
                                WMITLV_TAG_STRUC_wmi_ba_req_ssn_cmd_sub_struct_param */
    wmi_mac_addr peer_macaddr;
    A_UINT32 tidBitmap;
} wmi_ba_req_ssn;

typedef struct {
    A_UINT32 tlv_header; /* TLV tag and len; tag equals
     WMITLV_TAG_STRUC_wmi_ba_req_ssn_cmd_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** Number of requested SSN In the TLV wmi_ba_req_ssn[] */
    A_UINT32 num_ba_req_ssn;
/* Following this struc are the TLV's:
 *     wmi_ba_req_ssn ba_req_ssn_list; All peer and tidBitMap for which the ssn is requested
 */
} wmi_ba_req_ssn_cmd_fixed_param;

/*
 * Max transmit categories
 *
 * Note: In future if we need to increase WMI_MAX_TC definition
 * It would break the compatibility for WMI_BA_RSP_SSN_EVENTID.
 */
#define WMI_MAX_TC  8

/*
 * Structure to send response sequence numbers
 * for a give peer and tidmap.
 */
typedef struct
{
    A_UINT32    tlv_header;  /* TLV tag and len; tag equals
                                WMITLV_TAG_STRUC_wmi_ba_req_ssn_event_sub_struct_param */
    wmi_mac_addr peer_macaddr;
    /* A boolean to indicate if ssn is present */
    A_UINT32 ssn_present_for_tid[WMI_MAX_TC];
    /* The ssn from target, valid only if
     * ssn_present_for_tid[tidn] equals 1
     */
    A_UINT32 ssn_for_tid[WMI_MAX_TC];
} wmi_ba_event_ssn;

typedef struct {
    A_UINT32 tlv_header; /* TLV tag and len; tag equals
     WMITLV_TAG_STRUC_wmi_ba_rsp_ssn_event_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** Event status, success or failure of the overall operation */
    A_UINT32 status;
    /** Number of requested SSN In the TLV wmi_ba_req_ssn[] */
    A_UINT32 num_ba_event_ssn;
/* Following this struc are the TLV's:
 *     wmi_ba_event_ssn ba_event_ssn_list; All peer and tidBitMap for which the ssn is requested
 */
} wmi_ba_rsp_ssn_event_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_install_key_complete_event_fixed_param */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /** MAC address used for installing   */
    wmi_mac_addr peer_macaddr;
    /** key index */
    A_UINT32 key_ix;
    /** key flags */
    A_UINT32 key_flags;
    /** Event status */
    A_UINT32 status;
} wmi_vdev_install_key_complete_event_fixed_param;

typedef enum _WMI_NLO_AUTH_ALGORITHM {
    WMI_NLO_AUTH_ALGO_80211_OPEN        = 1,
    WMI_NLO_AUTH_ALGO_80211_SHARED_KEY  = 2,
    WMI_NLO_AUTH_ALGO_WPA               = 3,
    WMI_NLO_AUTH_ALGO_WPA_PSK           = 4,
    WMI_NLO_AUTH_ALGO_WPA_NONE          = 5,
    WMI_NLO_AUTH_ALGO_RSNA              = 6,
    WMI_NLO_AUTH_ALGO_RSNA_PSK          = 7,
} WMI_NLO_AUTH_ALGORITHM;

typedef enum _WMI_NLO_CIPHER_ALGORITHM {
    WMI_NLO_CIPHER_ALGO_NONE           = 0x00,
    WMI_NLO_CIPHER_ALGO_WEP40          = 0x01,
    WMI_NLO_CIPHER_ALGO_TKIP           = 0x02,
    WMI_NLO_CIPHER_ALGO_CCMP           = 0x04,
    WMI_NLO_CIPHER_ALGO_WEP104         = 0x05,
    WMI_NLO_CIPHER_ALGO_BIP            = 0x06,
    WMI_NLO_CIPHER_ALGO_WPA_USE_GROUP  = 0x100,
    WMI_NLO_CIPHER_ALGO_RSN_USE_GROUP  = 0x100,
    WMI_NLO_CIPHER_ALGO_WEP            = 0x101,
} WMI_NLO_CIPHER_ALGORITHM;

#define WMI_NLO_MAX_SSIDS    16
#define WMI_NLO_MAX_CHAN     48

#define WMI_NLO_CONFIG_STOP      (0x1 << 0)
#define WMI_NLO_CONFIG_START     (0x1 << 1)
#define WMI_NLO_CONFIG_RESET     (0x1 << 2)
#define WMI_NLO_CONFIG_SLOW_SCAN (0x1 << 4)
#define WMI_NLO_CONFIG_FAST_SCAN (0x1 << 5)

/* NOTE: wmi_nlo_ssid_param structure can't be changed without breaking the compatibility */
typedef struct wmi_nlo_ssid_param
{
	A_UINT32 valid;
    wmi_ssid ssid;
} wmi_nlo_ssid_param;

/* NOTE: wmi_nlo_enc_param structure can't be changed without breaking the compatibility */
typedef struct wmi_nlo_enc_param
{
	A_UINT32 valid;
    A_UINT32 enc_type;
} wmi_nlo_enc_param;

/* NOTE: wmi_nlo_auth_param structure can't be changed without breaking the compatibility */
typedef struct wmi_nlo_auth_param
{
	A_UINT32 valid;
    A_UINT32 auth_type;
} wmi_nlo_auth_param;
/* NOTE: wmi_nlo_rssi_param structure can't be changed without breaking the compatibility */
typedef struct wmi_nlo_rssi_param
{
    A_UINT32 valid;
    A_INT32 rssi;
} wmi_nlo_rssi_param;

typedef struct nlo_configured_parameters {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_nlo_configured_parameters */
    wmi_nlo_ssid_param ssid;
    wmi_nlo_enc_param enc_type;
    wmi_nlo_auth_param auth_type;
    wmi_nlo_rssi_param rssi_cond;
} nlo_configured_parameters;

typedef struct wmi_nlo_config {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_nlo_config_cmd_fixed_param */
    A_UINT32    flags;
    A_UINT32    vdev_id;
    A_UINT32    fast_scan_max_cycles;
    A_UINT32    active_dwell_time;
    A_UINT32    passive_dwell_time; /* PDT in msecs */
    A_UINT32    probe_bundle_size;
    A_UINT32    rest_time;  /* ART = IRT */
    A_UINT32    max_rest_time; /* Max value that can be reached after SBM */
    A_UINT32    scan_backoff_multiplier;  /* SBM */
    A_UINT32    fast_scan_period; /* SCBM */
    A_UINT32    slow_scan_period; /* specific to windows */
    A_UINT32    no_of_ssids;
    A_UINT32    num_of_channels;
    /* The TLVs will follow.
        * nlo_configured_parameters nlo_list[];
        * A_UINT32 channel_list[];
        */

} wmi_nlo_config_cmd_fixed_param;

typedef struct wmi_nlo_event
{
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_nlo_event */
    A_UINT32    vdev_id;
}wmi_nlo_event;

#define GTK_OFFLOAD_OPCODE_MASK				0xFF000000
/** Enable GTK offload, and provided parameters KEK,KCK and replay counter values */
#define GTK_OFFLOAD_ENABLE_OPCODE			0x01000000
/** Disable GTK offload */
#define GTK_OFFLOAD_DISABLE_OPCODE			0x02000000
/** Read GTK offload parameters, generates WMI_GTK_OFFLOAD_STATUS_EVENT */
#define GTK_OFFLOAD_REQUEST_STATUS_OPCODE	0x04000000
enum wmi_chatter_mode {
    /* Chatter enter/exit happens
     * automatically based on preset
     * params
     */
    WMI_CHATTER_MODE_AUTO,
    /* Chatter enter is triggered
     * manually by the user
     */
    WMI_CHATTER_MODE_MANUAL_ENTER,
    /* Chatter exit is triggered
     * manually by the user
     */
    WMI_CHATTER_MODE_MANUAL_EXIT,
    /* Placeholder max value, always last*/
    WMI_CHATTER_MODE_MAX
};

enum wmi_chatter_query_type {
    /*query coalescing filter match counter*/
    WMI_CHATTER_QUERY_FILTER_MATCH_CNT,
    WMI_CHATTER_QUERY_MAX
};

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_chatter_set_mode_cmd_fixed_param  */
    A_UINT32 chatter_mode;
} wmi_chatter_set_mode_cmd_fixed_param;

/** maximum number of filter supported*/
#define CHATTER_MAX_COALESCING_RULES     11
/** maximum number of field tests per filter*/
#define CHATTER_MAX_FIELD_TEST           5
/** maximum field length in number of DWORDS*/
#define CHATTER_MAX_TEST_FIELD_LEN32     2

/** field test kinds*/
#define CHATTER_COALESCING_TEST_EQUAL            1
#define CHATTER_COALESCING_TEST_MASKED_EQUAL     2
#define CHATTER_COALESCING_TEST_NOT_EQUAL        3

/** packet type*/
#define CHATTER_COALESCING_PKT_TYPE_UNICAST      (1 << 0)
#define CHATTER_COALESCING_PKT_TYPE_MULTICAST    (1 << 1)
#define CHATTER_COALESCING_PKT_TYPE_BROADCAST    (1 << 2)

/** coalescing field test*/
typedef struct _chatter_pkt_coalescing_hdr_test {
    /** offset from start of mac header, for windows native wifi host driver
     * should assume standard 802.11 frame format without QoS info and address4
     * FW would account for any non-stand fields for final offset value.
     */
    A_UINT32    offset;
    A_UINT32    length;	    /* length of test field*/
    A_UINT32    test;       /*equal, not equal or masked equal*/
    A_UINT32    mask[CHATTER_MAX_TEST_FIELD_LEN32];    /*mask byte stream*/
    A_UINT32    value[CHATTER_MAX_TEST_FIELD_LEN32];   /*value byte stream*/
} chatter_pkt_coalescing_hdr_test;

/** packet coalescing filter*/
typedef struct _chatter_pkt_coalescing_filter {
    A_UINT32    tlv_header; /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_chatter_pkt_coalescing_filter */
    A_UINT32    filter_id;  /*unique id assigned by OS*/
    A_UINT32    max_coalescing_delay; /*max miliseconds 1st pkt can be hold*/
    A_UINT32    pkt_type; /*unicast/multicast/broadcast*/
    A_UINT32    num_of_test_field;    /*number of field test in table*/
    chatter_pkt_coalescing_hdr_test   test_fields[CHATTER_MAX_FIELD_TEST]; /*field test tbl*/
} chatter_pkt_coalescing_filter;

/** packet coalescing filter add command*/
typedef struct {
    A_UINT32    tlv_header; /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_chatter_coalescing_add_filter_cmd_fixed_param */
    A_UINT32    num_of_filters;
    /* Following this tlv, there comes an array of structure of type chatter_pkt_coalescing_filter
     chatter_pkt_coalescing_filter rx_filter[1];*/
} wmi_chatter_coalescing_add_filter_cmd_fixed_param;
/** packet coalescing filter delete command*/
typedef struct {
    A_UINT32    tlv_header;  /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_chatter_coalescing_delete_filter_cmd_fixed_param */
    A_UINT32    filter_id; /*filter id which will be deleted*/
} wmi_chatter_coalescing_delete_filter_cmd_fixed_param;
/** packet coalescing query command*/
typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_chatter_coalescing_query_cmd_fixed_param */
    A_UINT32    type;    /*type of query*/
} wmi_chatter_coalescing_query_cmd_fixed_param;
/** chatter query reply event*/
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_chatter_query_reply_event_fixed_param  */
    A_UINT32    type;    /*query type*/
    A_UINT32    filter_match_cnt; /*coalescing filter match counter*/
} wmi_chatter_query_reply_event_fixed_param;

/* NOTE: This constants GTK_OFFLOAD_KEK_BYTES, GTK_OFFLOAD_KCK_BYTES, and GTK_REPLAY_COUNTER_BYTES
 * cannot be changed without breaking WMI compatibility. */
#define GTK_OFFLOAD_KEK_BYTES       16
#define GTK_OFFLOAD_KCK_BYTES       16
/* NOTE: GTK_REPLAY_COUNTER_BYTES, WMI_MAX_KEY_LEN, IGTK_PN_SIZE cannot be changed in the future without breaking WMI compatibility */
#define GTK_REPLAY_COUNTER_BYTES    8
#define WMI_MAX_KEY_LEN             32
#define IGTK_PN_SIZE                6

typedef struct {
    A_UINT32    tlv_header;  /* TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_GTK_OFFLOAD_STATUS_EVENT_fixed_param */
    A_UINT32    vdev_id;     /** unique id identifying the VDEV */
    A_UINT32    flags;       /* status flags */
    A_UINT32    refresh_cnt; /* number of successful GTK refresh exchanges since last SET operation */
    A_UINT8     replay_counter[GTK_REPLAY_COUNTER_BYTES]; /* current replay counter */
    A_UINT8     igtk_keyIndex; /* Use if IGTK_OFFLOAD is defined */
    A_UINT8     igtk_keyLength; /* Use if IGTK_OFFLOAD is defined */
    A_UINT8     igtk_keyRSC[IGTK_PN_SIZE];  /* key replay sequence counter */ /* Use if IGTK_OFFLOAD is defined */
    A_UINT8     igtk_key[WMI_MAX_KEY_LEN]; /* Use if IGTK_OFFLOAD is defined */
} WMI_GTK_OFFLOAD_STATUS_EVENT_fixed_param;

typedef struct {
    A_UINT32    tlv_header;                     /** TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_GTK_OFFLOAD_CMD_fixed_param */
    A_UINT32 	vdev_id;    					/** unique id identifying the VDEV */
    A_UINT32    flags;                          /* control flags, GTK offload command use high byte  */
    /* The size of following 3 arrays cannot be changed without breaking WMI compatibility. */
    A_UINT8     KEK[GTK_OFFLOAD_KEK_BYTES];     /* key encryption key */
    A_UINT8     KCK[GTK_OFFLOAD_KCK_BYTES];     /* key confirmation key */
    A_UINT8     replay_counter[GTK_REPLAY_COUNTER_BYTES];  /* replay counter for re-key */
}WMI_GTK_OFFLOAD_CMD_fixed_param;

typedef struct  {
    A_UINT8    address[4];    /* IPV4 address in Network Byte Order */
} WMI_IPV4_ADDR;

typedef enum {
    WMI_STA_KEEPALIVE_METHOD_NULL_FRAME = 1,                   /* 802.11 NULL frame */
    WMI_STA_KEEPALIVE_METHOD_UNSOLICITED_ARP_RESPONSE = 2,     /* ARP response */
    WMI_STA_KEEPALIVE_METHOD_ETHERNET_LOOPBACK = 3, /*ETHERNET LOOPBACK*/
} WMI_STA_KEEPALIVE_METHOD;

typedef struct {
    A_UINT32                 tlv_header;               /* TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_STA_KEEPALVE_ARP_RESPONSE */
    WMI_IPV4_ADDR            sender_prot_addr;         /* Sender protocol address */
    WMI_IPV4_ADDR            target_prot_addr;         /* Target protocol address */
    wmi_mac_addr             dest_mac_addr;            /* destination MAC address */
} WMI_STA_KEEPALVE_ARP_RESPONSE;

typedef struct  {
    A_UINT32 tlv_header;                    /* TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_STA_KEEPALIVE_CMD_fixed_param */
    A_UINT32 vdev_id;
    A_UINT32 enable;                        /* 1 - Enable, 0 - disable */
    A_UINT32 method;                        /* keep alive method */
    A_UINT32 interval;                      /* time interval in seconds  */
    /*
        * NOTE: following this structure is the TLV for ARP Resonse:
        *     WMI_STA_KEEPALVE_ARP_RESPONSE arp_resp; // ARP response
        */
} WMI_STA_KEEPALIVE_CMD_fixed_param;

typedef struct  {
    A_UINT32 tlv_header;
    A_UINT32 vdev_id;
    A_UINT32 action;
} WMI_VDEV_WNM_SLEEPMODE_CMD_fixed_param;
typedef WMI_VDEV_WNM_SLEEPMODE_CMD_fixed_param WMI_STA_WNMSLEEP_CMD;

typedef struct {
    A_UINT32 tlv_header;           /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_set_keepalive_cmd_fixed_param */
    A_UINT32 vdev_id;
    A_UINT32 keepaliveInterval;   /* seconds */
    A_UINT32 keepaliveMethod;
} wmi_vdev_set_keepalive_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;           /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_get_keepalive_cmd_fixed_param */
    A_UINT32    vdev_id;
} wmi_vdev_get_keepalive_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_get_keepalive_event_fixed_param */
    A_UINT32 vdev_id;
    A_UINT32 keepaliveInterval;   /* seconds */
    A_UINT32 keepaliveMethod;   /* seconds */
} wmi_vdev_get_keepalive_event_fixed_param;

typedef struct {
    A_UINT32 tlv_header;
    A_UINT32 vdev_id;
    A_UINT32 mcc_tbttmode;
    wmi_mac_addr mcc_bssid;
} wmi_vdev_mcc_set_tbtt_mode_cmd_fixed_param;

typedef struct {
	/* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_p2p_set_noa_cmd_fixed_param  */
    A_UINT32 tlv_header;
    /* unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /* enable/disable NoA */
	A_UINT32 enable;
	/** number of NoA desc. In the TLV noa_descriptor[] */
	A_UINT32 num_noa;
	/**
     * TLV (tag length value )  paramerters follow the pattern structure.
     * TLV  contain NoA desc with num of num_noa
     */
} wmi_p2p_set_noa_cmd_fixed_param;

typedef enum {
    RECOVERY_SIM_ASSERT          = 0x01,
    RECOVERY_SIM_NO_DETECT       = 0x02,
    RECOVERY_SIM_CTR_EP_FULL     = 0x03,
    RECOVERY_SIM_EMPTY_POINT     = 0x04,
    RECOVERY_SIM_STACK_OV        = 0x05,
    RECOVERY_SIM_INFINITE_LOOP   = 0x06,
} RECOVERY_SIM_TYPE;

/* WMI_FORCE_FW_HANG_CMDID */
typedef struct {
    A_UINT32 tlv_header;           /* TLV tag and len; tag equals WMITLV_TAG_STRUC_WMI_FORCE_FW_HANG_CMD_fixed_param */
    A_UINT32 type;     /*0:unused 1: ASSERT, 2: not respond detect command,3:  simulate ep-full(),4:...*/
    A_UINT32 delay_time_ms;   /*0xffffffff means the simulate will delay for random time (0 ~0xffffffff ms)*/
}WMI_FORCE_FW_HANG_CMD_fixed_param;
#define WMI_MCAST_FILTER_SET 1
#define WMI_MCAST_FILTER_DELETE 2
typedef struct {
    A_UINT32 tlv_header;
    A_UINT32 vdev_id;
    A_UINT32 index;
    A_UINT32 action;
    wmi_mac_addr mcastbdcastaddr;
} WMI_SET_MCASTBCAST_FILTER_CMD_fixed_param;

/* GPIO Command and Event data structures */

/* WMI_GPIO_CONFIG_CMDID */
enum {
    WMI_GPIO_PULL_NONE,
    WMI_GPIO_PULL_UP,
    WMI_GPIO_PULL_DOWN,
};

enum {
    WMI_GPIO_INTTYPE_DISABLE,
    WMI_GPIO_INTTYPE_RISING_EDGE,
    WMI_GPIO_INTTYPE_FALLING_EDGE,
    WMI_GPIO_INTTYPE_BOTH_EDGE,
    WMI_GPIO_INTTYPE_LEVEL_LOW,
    WMI_GPIO_INTTYPE_LEVEL_HIGH
};

typedef struct {
    A_UINT32 tlv_header;           /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_gpio_config_cmd_fixed_param */
    A_UINT32 gpio_num;             /* GPIO number to be setup */
    A_UINT32 input;                /* 0 - Output/ 1 - Input */
    A_UINT32 pull_type;            /* Pull type defined above */
    A_UINT32 intr_mode;            /* Interrupt mode defined above (Input) */
} wmi_gpio_config_cmd_fixed_param;

/* WMI_GPIO_OUTPUT_CMDID */
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_gpio_output_cmd_fixed_param */
    A_UINT32 gpio_num;    /* GPIO number to be setup */
    A_UINT32 set;         /* Set the GPIO pin*/
} wmi_gpio_output_cmd_fixed_param;

/* WMI_GPIO_INPUT_EVENTID */
typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_gpio_input_event_fixed_param */
    A_UINT32 gpio_num;    /* GPIO number which changed state */
} wmi_gpio_input_event_fixed_param;

/* WMI_P2P_DISC_EVENTID */
enum {
    P2P_DISC_SEARCH_PROB_REQ_HIT = 0,   /* prob req hit the p2p find pattern */
    P2P_DISC_SEARCH_PROB_RESP_HIT,      /* prob resp hit the p2p find pattern */
};

enum {
    P2P_DISC_MODE_SEARCH = 0, /* do search when p2p find offload*/
    P2P_DISC_MODE_LISTEN,     /* do listen when p2p find offload*/
	P2P_DISC_MODE_AUTO,       /* do listen and search when p2p find offload*/
};

enum {
    P2P_DISC_PATTERN_TYPE_BSSID = 0,  /* BSSID pattern */
    P2P_DISC_PATTERN_TYPE_DEV_NAME,   /* device name pattern */
};

typedef struct {
    A_UINT32    vdev_id;
    A_UINT32    reason;    /* P2P DISC wake up reason*/
} wmi_p2p_disc_event;

typedef WMI_GTK_OFFLOAD_STATUS_EVENT_fixed_param WOW_EVENT_INFO_SECTION_GTKIGTK;

typedef enum {
    WMI_FAKE_TXBFER_SEND_NDPA,
    WMI_FAKE_TXBFER_SEND_MU,
    WMI_FAKE_TXBFER_NDPA_FBTYPE,
    WMI_FAKE_TXBFER_NDPA_NCIDX,
    WMI_FAKE_TXBFER_NDPA_POLL,
    WMI_FAKE_TXBFER_NDPA_BW,
    WMI_FAKE_TXBFER_NDPA_PREAMBLE,
    WMI_FAKE_TXBFER_NDPA_RATE,
    WMI_FAKE_TXBFER_NDP_BW,
    WMI_FAKE_TXBFER_NDP_NSS,
    WMI_TXBFEE_ENABLE_UPLOAD_H,
    WMI_TXBFEE_ENABLE_CAPTURE_H,
    WMI_TXBFEE_SET_CBF_TBL,
    WMI_TXBFEE_CBF_TBL_LSIG,
    WMI_TXBFEE_CBF_TBL_SIGA1,
    WMI_TXBFEE_CBF_TBL_SIGA2,
    WMI_TXBFEE_CBF_TBL_SIGB,
    WMI_TXBFEE_CBF_TBL_PAD,
    WMI_TXBFEE_CBF_TBL_DUR,
    WMI_TXBFEE_SU_NCIDX,
    WMI_TXBFEE_CBIDX,
    WMI_TXBFEE_NGIDX,
} WMI_TXBF_PARAM_ID;

typedef struct {
    A_UINT32 tlv_header; /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_txbf_cmd_fixed_param */
    /** parameter id   */
    A_UINT32 param_id;
    /** parameter value */
    A_UINT32 param_value;
} wmi_txbf_cmd_fixed_param;

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_upload_h_hdr */
    A_UINT32     h_length;
    A_UINT32     cv_length;
    /* This TLV is followed by array of bytes:
     * // h_cv info buffer
     *   A_UINT8 bufp[];
     */
} wmi_upload_h_hdr;

typedef struct {
    A_UINT32 tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_capture_h_event_hdr */
    A_UINT32 svd_num;
    A_UINT32 tone_num;
    A_UINT32 reserved;
} wmi_capture_h_event_hdr;

typedef struct {
    A_UINT32    tlv_header;                 /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_avoid_freq_range_desc */
    A_UINT32    start_freq;  //start frequency, not channel center freq
    A_UINT32    end_freq;   //end frequency
} wmi_avoid_freq_range_desc;

typedef struct {
    A_UINT32    tlv_header;                 /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_avoid_freq_ranges_event_fixed_param */
   //bad channel range count, multi range is allowed, 0 means all channel clear
   A_UINT32  num_freq_ranges;

   /* The TLVs will follow.
       * multi range with num_freq_ranges, LTE advance multi carrier, CDMA,etc
       *     wmi_avoid_freq_range_desc avd_freq_range[];     // message buffer, NULL terminated
       */
} wmi_avoid_freq_ranges_event_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_gtk_rekey_fail_event_fixed_param  */
    /** Reserved for future use */
    A_UINT32    reserved0;
} wmi_gtk_rekey_fail_event_fixed_param;
enum wmm_ac_downgrade_policy {
    WMM_AC_DOWNGRADE_DEPRIO,
    WMM_AC_DOWNGRADE_DROP,
    WMM_AC_DOWNGRADE_INVALID,
};

typedef struct {
    A_UINT32 tlv_header;
    A_UINT32 cwmin;
    A_UINT32 cwmax;
    A_UINT32 aifs;
    A_UINT32 txoplimit;
    A_UINT32 acm;
    A_UINT32 no_ack;
} wmi_wmm_vparams;

typedef struct {
    A_UINT32 tlv_header;
    A_UINT32 vdev_id;
    wmi_wmm_vparams wmm_params[4]; /* 0 be, 1 bk, 2 vi, 3 vo */
} wmi_vdev_set_wmm_params_cmd_fixed_param;


typedef struct
{
    A_UINT32 tlv_header;
    A_UINT32  vdev_id;
    A_UINT32 ac;
    A_UINT32 medium_time_us; /* per second unit, the Admitted time granted, unit in micro seconds */
    A_UINT32 downgrade_type;
} wmi_vdev_wmm_addts_cmd_fixed_param;

typedef struct
{
    A_UINT32 tlv_header;
    A_UINT32  vdev_id;
    A_UINT32 ac;
} wmi_vdev_wmm_delts_cmd_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_dfs_enable_cmd_fixed_param  */
    /** Reserved for future use */
    A_UINT32    reserved0;
} wmi_pdev_dfs_enable_cmd_fixed_param;

typedef struct {
    A_UINT32    tlv_header;     /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_pdev_dfs_disable_cmd_fixed_param  */
    /** Reserved for future use */
    A_UINT32    reserved0;
} wmi_pdev_dfs_disable_cmd_fixed_param;
/** TDLS COMMANDS */

/* WMI_TDLS_SET_STATE_CMDID */
/* TDLS State */
enum wmi_tdls_state {
    /** TDLS disable */
    WMI_TDLS_DISABLE,
    /** TDLS enabled - no firmware connection tracking/notifications */
    WMI_TDLS_ENABLE_PASSIVE,
    /** TDLS enabled - with firmware connection tracking/notifications */
    WMI_TDLS_ENABLE_ACTIVE,
};

/* TDLS Options */
#define WMI_TDLS_OFFCHAN_EN             (1 << 0) /** TDLS Off Channel support */
#define WMI_TDLS_BUFFER_STA_EN          (1 << 1) /** TDLS Buffer STA support */
#define WMI_TDLS_SLEEP_STA_EN           (1 << 2) /** TDLS Sleep STA support (not currently supported) */

typedef struct {
    /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_tdls_set_state_cmd_fixed_param  */
    A_UINT32 tlv_header;
    /** unique id identifying the VDEV */
    A_UINT32 vdev_id;
    /** Enable/Disable TDLS (wmi_tdls_state) */
    A_UINT32 state;
    /** Duration (in ms) over which to calculate tx threshold and rate values */
    A_UINT32 notification_interval_ms;
    /** bytes per second value OVER which notify/suggest TDLS Discovery:
     *  if current tx bps counter / notification interval >= threshold
     *  then a notification will be sent to host to advise TDLS Discovery */
    A_UINT32 tx_discovery_threshold;
    /** bytes per second value UNDER which notify/suggest TDLS Teardown:
     *  if current tx bps counter / notification interval < threshold
     *  then a notification will be sent to host to advise TDLS Tear down */
    A_UINT32 tx_teardown_threshold;
    /** Absolute RSSI value over which notify/suggest TDLS Teardown */
    A_UINT32 rssi_teardown_threshold;
    /** RSSI delta vs AP RSSI value over which to trigger a teardown */
    A_UINT32 rssi_delta;
    /** TDLS Option Control
     * Off-Channel, Buffer STA, (later)Sleep STA support */
    A_UINT32 tdls_options;
} wmi_tdls_set_state_cmd_fixed_param;

/* WMI_TDLS_PEER_UPDATE_CMDID */

enum wmi_tdls_peer_state {
    /** tx peer TDLS link setup now starting, traffic to DA should be
     * paused (except TDLS frames) until state is moved to CONNECTED (or
     * TEARDOWN on setup failure) */
    WMI_TDLS_PEER_STATE_PEERING,
    /** tx peer TDLS link established, running (all traffic to DA unpaused) */
    WMI_TDLS_PEER_STATE_CONNECTED,
    /** tx peer TDLS link tear down started (link paused, any frames
     * queued for DA will be requeued back through the AP)*/
    WMI_TDLS_PEER_STATE_TEARDOWN,
};

/* NB: These defines are fixed, and cannot be changed without breaking WMI compatibility */
#define WMI_TDLS_MAX_SUPP_CHANNELS 128
#define WMI_TDLS_MAX_SUPP_OPER_CLASSES 32
typedef struct {
    /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_tdls_peer_capabilities  */
    A_UINT32 tlv_header;
    /* Peer's QoS Info - for U-APSD */
    /* AC FLAGS  - accessed through macros below */
    /* Ack, SP, More Data Ack - accessed through macros below */
    A_UINT32 peer_qos;
    /*TDLS Peer's U-APSD Buffer STA Support*/
    A_UINT32 buff_sta_support;
    /*TDLS off channel related params */
    A_UINT32 off_chan_support;
    A_UINT32 peer_curr_operclass;
    A_UINT32 self_curr_operclass;
    A_UINT32 peer_chan_len;
    A_UINT8  peer_chan[WMI_TDLS_MAX_SUPP_CHANNELS];
    A_UINT32 peer_operclass_len;
    A_UINT8  peer_operclass[WMI_TDLS_MAX_SUPP_OPER_CLASSES];
} wmi_tdls_peer_capabilities;

#define WMI_TDLS_QOS_VO_FLAG           0
#define WMI_TDLS_QOS_VI_FLAG           1
#define WMI_TDLS_QOS_BK_FLAG           2
#define WMI_TDLS_QOS_BE_FLAG           3
#define WMI_TDLS_QOS_ACK_FLAG          4
#define WMI_TDLS_QOS_SP_FLAG           5
#define WMI_TDLS_QOS_MOREDATA_FLAG     7

#define WMI_TDLS_SET_QOS_FLAG(ppeer_caps,flag) do { \
        (ppeer_caps)->peer_qos |=  (1 << flag);      \
     } while(0)
#define WMI_TDLS_GET_QOS_FLAG(ppeer_caps,flag)   \
        (((ppeer_caps)->peer_qos & (1 << flag)) >> flag)

#define WMI_SET_TDLS_VO_UAPSD(ppeer_caps) \
    WMI_TDLS_SET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_VO_FLAG)
#define WMI_GET_TDLS_VO_UAPSD(ppeer_caps) \
    WMI_TDLS_GET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_VO_FLAG)
#define WMI_SET_TDLS_VI_UAPSD(ppeer_caps) \
    WMI_TDLS_SET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_VI_FLAG)
#define WMI_GET_TDLS_VI_UAPSD(ppeer_caps) \
    WMI_TDLS_GET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_VI_FLAG)
#define WMI_SET_TDLS_BK_UAPSD(ppeer_caps) \
    WMI_TDLS_SET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_BK_FLAG)
#define WMI_GET_TDLS_BK_UAPSD(ppeer_caps) \
    WMI_TDLS_GET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_BK_FLAG)
#define WMI_SET_TDLS_BE_UAPSD(ppeer_caps) \
    WMI_TDLS_SET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_BE_FLAG)
#define WMI_GET_TDLS_BE_UAPSD(ppeer_caps) \
    WMI_TDLS_GET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_BE_FLAG)
#define WMI_SET_TDLS_ACK_UAPSD(ppeer_caps) \
    WMI_TDLS_SET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_ACK_FLAG)
#define WMI_GET_TDLS_ACK_UAPSD(ppeer_caps) \
    WMI_TDLS_GET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_ACK_FLAG)
/* SP has 2 bits */
#define WMI_SET_TDLS_SP_UAPSD(ppeer_caps,val) do { \
     (ppeer_caps)->peer_qos |=  (((val)&0x3) << WMI_TDLS_QOS_SP_FLAG); \
     } while(0)
#define WMI_GET_TDLS_SP_UAPSD(ppeer_caps) \
    (((ppeer_caps)->peer_qos & (0x3 << WMI_TDLS_QOS_SP_FLAG)) >> WMI_TDLS_QOS_SP_FLAG)

#define WMI_SET_TDLS_MORE_DATA_ACK_UAPSD(ppeer_caps) \
    WMI_TDLS_SET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_MOREDATA_FLAG)
#define WMI_GET_TDLS_MORE_DATA_ACK_UAPSD(ppeer_caps) \
    WMI_TDLS_GET_QOS_FLAG(ppeer_caps, WMI_TDLS_QOS_MOREDATA_FLAG)


typedef struct {
    /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_tdls_peer_update_cmd_fixed_param  */
    A_UINT32    tlv_header;
    /** unique id identifying the VDEV */
    A_UINT32                    vdev_id;
    /** peer MAC address */
    wmi_mac_addr                peer_macaddr;
    /** new TDLS state for peer (wmi_tdls_peer_state) */
    A_UINT32                    peer_state;
    /* The TLV for wmi_tdls_peer_capabilities will follow.
     *     wmi_tdls_peer_capabilities  peer_caps;
     */
} wmi_tdls_peer_update_cmd_fixed_param;

/** TDLS EVENTS */
enum wmi_tdls_peer_notification {
    /** tdls discovery recommended for peer (based
     * on tx bytes per second > tx_discover threshold) */
    WMI_TDLS_SHOULD_DISCOVER,
    /** tdls link tear down recommended for peer
     * due to tx bytes per second below tx_teardown_threshold
     * NB: this notification sent once */
    WMI_TDLS_SHOULD_TEARDOWN,
    /** tx peer TDLS link tear down complete */
    WMI_TDLS_PEER_DISCONNECTED,
};

enum wmi_tdls_peer_reason {
    /** tdls teardown recommended due to low transmits */
    WMI_TDLS_TEARDOWN_REASON_TX,
    /** tdls link tear down recommended due to poor RSSI */
    WMI_TDLS_TEARDOWN_REASON_RSSI,
    /** tdls link tear down recommended due to offchannel scan */
    WMI_TDLS_TEARDOWN_REASON_SCAN,
    /** tdls peer disconnected due to peer deletion */
    WMI_TDLS_DISCONNECTED_REASON_PEER_DELETE,
};

/* WMI_TDLS_PEER_EVENTID */
typedef struct {
    /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_tdls_peer_event_fixed_param  */
    A_UINT32    tlv_header;
    /** peer MAC address */
    wmi_mac_addr    peer_macaddr;
    /** TDLS peer status (wmi_tdls_peer_notification)*/
    A_UINT32        peer_status;
    /** TDLS peer reason (wmi_tdls_peer_reason) */
    A_UINT32        peer_reason;
    /** unique id identifying the VDEV */
    A_UINT32        vdev_id;
} wmi_tdls_peer_event_fixed_param;

/* NOTE: wmi_vdev_mcc_bcn_intvl_change_event_fixed_param would be deprecated. Please
 don't use this for any new implementations */
typedef struct {
    A_UINT32 tlv_header; /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_vdev_mcc_bcn_intvl_change_event_fixed_param  */
    /** unique id identifying the VDEV, generated by the caller */
    A_UINT32 vdev_id;
    /* New beacon interval to be used for the specified VDEV suggested by firmware */
    A_UINT32 new_bcn_intvl;
} wmi_vdev_mcc_bcn_intvl_change_event_fixed_param;

/* WMI_RESMGR_ADAPTIVE_OCS_DISABLE_CMDID */
typedef struct {
    /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_resmgr_adaptive_ocs_disable_cmd_fixed_param */
    A_UINT32 tlv_header;
    A_UINT32 reserved0;
} wmi_resmgr_adaptive_ocs_disable_cmd_fixed_param;

/* WMI_RESMGR_SET_CHAN_TIME_QUOTA_CMDID */
typedef struct {
    /* Frequency of the channel for which the quota is set */
    A_UINT32 chan_mhz;
    /* Requested channel time quota expressed as percentage */
    A_UINT32 channel_time_quota;
} wmi_resmgr_chan_time_quota;

typedef struct {
    /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_resmgr_set_chan_time_quota_cmd_fixed_param */
    A_UINT32 tlv_header;
    /** number of channel time quota command structures
     * (wmi_resmgr_chan_time_quota) 1 or 2
     */
    A_UINT32 num_chans;
/* This TLV is followed by another TLV of array of bytes
 * A_UINT8 data[];
 * This data array contains
 * num_chans * size of(struct wmi_resmgr_chan_time_quota)
 */
} wmi_resmgr_set_chan_time_quota_cmd_fixed_param;

/* WMI_RESMGR_SET_CHAN_LATENCY_CMDID */
typedef struct {
    /* Frequency of the channel for which the latency is set */
    A_UINT32 chan_mhz;
    /* Requested channel latency in milliseconds */
    A_UINT32 latency;
} wmi_resmgr_chan_latency;

typedef struct {
    /** TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_resmgr_set_chan_latency_cmd_fixed_param */
    A_UINT32 tlv_header;
    /** number of channel latency command structures
     * (wmi_resmgr_chan_latency) 1 or 2
     */
    A_UINT32 num_chans;
/* This TLV is followed by another TLV of array of bytes
 * A_UINT8 data[];
 * This data array contains
 * num_chans * size of(struct wmi_resmgr_chan_latency)
 */
} wmi_resmgr_set_chan_latency_cmd_fixed_param;

/* WMI_STA_SMPS_FORCE_MODE_CMDID */

/** STA SMPS Forced Mode */
typedef enum {
    WMI_SMPS_FORCED_MODE_NONE = 0,
    WMI_SMPS_FORCED_MODE_DISABLED,
    WMI_SMPS_FORCED_MODE_STATIC,
    WMI_SMPS_FORCED_MODE_DYNAMIC
} wmi_sta_smps_forced_mode;

typedef struct {
    /** TLV tag and len; tag equals
     *  WMITLV_TAG_STRUC_wmi_sta_smps_force_mode_cmd_fixed_param */
    A_UINT32 tlv_header;
    /** Unique id identifying the VDEV */
    A_UINT32 vdev_id;
    /** The mode of SMPS that is to be forced in the FW. */
    A_UINT32 forced_mode;
} wmi_sta_smps_force_mode_cmd_fixed_param;

#ifdef __cplusplus
}
#endif

#endif /*_WMI_UNIFIED_H_*/

/**@}*/
