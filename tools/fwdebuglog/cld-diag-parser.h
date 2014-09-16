/*
 * Copyright (c) 2014 The Linux Foundation. All rights reserved.
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

#ifndef _CLD_DIAG_PARSER_H
#define _CLD_DIAG_PARSER_H

#include <stdint.h>
#include "event.h"
#include "msg.h"
#include "log.h"
#include "diag_lsm.h"
#include "diagpkt.h"
#include "diagcmd.h"
#include "diag.h"
#include "diagi.h"

/* KERNEL DEFS START */
#define DBGLOG_MAX_VDEVID 15 /* 0-15 */
#define DBGLOG_TIMESTAMP_OFFSET          0
#define DBGLOG_TIMESTAMP_MASK            0xFFFFFFFF /* Bit 0-15. Contains bit
                                                       8-23 of the LF0 timer */
#define DBGLOG_DBGID_OFFSET              0
#define DBGLOG_DBGID_MASK                0x000003FF /* Bit 0-9 */
#define DBGLOG_DBGID_NUM_MAX             256 /* Upper limit is width of mask */

#define DBGLOG_MODULEID_OFFSET           10
#define DBGLOG_MODULEID_MASK             0x0003FC00 /* Bit 10-17 */
#define DBGLOG_MODULEID_NUM_MAX          32 /* Upper limit is width of mask */

#define DBGLOG_VDEVID_OFFSET              18
#define DBGLOG_VDEVID_MASK                0x03FC0000 /* Bit 20-25*/
#define DBGLOG_VDEVID_NUM_MAX             16

#define DBGLOG_NUM_ARGS_OFFSET            26
#define DBGLOG_NUM_ARGS_MASK              0xFC000000 /* Bit 26-31 */
#define DBGLOG_NUM_ARGS_MAX               5 /* it is limited bcoz of limitations
                                              with Xtensa tool */

#define DBGLOG_LOG_BUFFER_SIZE            1500
#define DBGLOG_DBGID_DEFINITION_LEN_MAX   90

#define DBGLOG_HOST_LOG_BUFFER_SIZE            DBGLOG_LOG_BUFFER_SIZE

#define DBGLOG_GET_DBGID(arg) \
    ((arg & DBGLOG_DBGID_MASK) >> DBGLOG_DBGID_OFFSET)

#define DBGLOG_GET_MODULEID(arg) \
    ((arg & DBGLOG_MODULEID_MASK) >> DBGLOG_MODULEID_OFFSET)

#define DBGLOG_GET_VDEVID(arg) \
    ((arg & DBGLOG_VDEVID_MASK) >> DBGLOG_VDEVID_OFFSET)

#define DBGLOG_GET_NUMARGS(arg) \
    ((arg & DBGLOG_NUM_ARGS_MASK) >> DBGLOG_NUM_ARGS_OFFSET)

#define DBGLOG_GET_TIME_STAMP(arg) \
    ((arg & DBGLOG_TIMESTAMP_MASK) >> DBGLOG_TIMESTAMP_OFFSET)


#define DIAG_FWID_OFFSET            24
#define DIAG_FWID_MASK              0xFF000000 /* Bit 24-31 */

#define DIAG_TIMESTAMP_OFFSET       0
#define DIAG_TIMESTAMP_MASK         0x00FFFFFF /* Bit 0-23 */

#define DIAG_ID_OFFSET              16
#define DIAG_ID_MASK                0xFFFF0000 /* Bit 16-31 */

#define DIAG_VDEVID_OFFSET          11
#define DIAG_VDEVID_MASK            0x0000F800 /* Bit 11-15 */
#define DIAG_VDEVID_NUM_MAX         16

#define DIAG_VDEVLEVEL_OFFSET       8
#define DIAG_VDEVLEVEL_MASK         0x00000700 /* Bit 8-10 */

#define DIAG_PAYLEN_OFFSET          0
#define DIAG_PAYLEN_MASK            0x000000FF /* Bit 0-7 */

#define DIAG_PAYLEN_OFFSET16        0
#define DIAG_PAYLEN_MASK16          0x0000FFFF /* Bit 0-16 */

#define DIAG_GET_TYPE(arg) \
    ((arg & DIAG_FWID_MASK) >> DIAG_FWID_OFFSET)

#define DIAG_GET_TIME_STAMP(arg) \
    ((arg & DIAG_TIMESTAMP_MASK) >> DIAG_TIMESTAMP_OFFSET)

#define DIAG_GET_ID(arg) \
    ((arg & DIAG_ID_MASK) >> DIAG_ID_OFFSET)

#define DIAG_GET_VDEVID(arg) \
    ((arg & DIAG_VDEVID_MASK) >> DIAG_VDEVID_OFFSET)

#define DIAG_GET_VDEVLEVEL(arg) \
    ((arg & DIAG_VDEVLEVEL_MASK) >> DIAG_VDEVLEVEL_OFFSET)

#define DIAG_GET_PAYLEN(arg) \
    ((arg & DIAG_PAYLEN_MASK) >> DIAG_PAYLEN_OFFSET)

#define DIAG_GET_PAYLEN16(arg) \
    ((arg & DIAG_PAYLEN_MASK16) >> DIAG_PAYLEN_OFFSET16)

#define LOGFILE_FLAG           0x01
#define CONSOLE_FLAG           0x02
#define QXDM_FLAG              0x04
#define SILENT_FLAG            0x08
#define DEBUG_FLAG             0x0A

#define ATH6KL_FWLOG_PAYLOAD_SIZE              1500

#define HDRLEN 16
#define RECLEN (HDRLEN + ATH6KL_FWLOG_PAYLOAD_SIZE)
#define SIZEOF_NL_MSG_LOAD     28 /* sizeof nlmsg and load length */
#define SIZEOF_NL_MSG_UNLOAD   28 /* sizeof nlmsg and Unload length */
#define DIAG_TYPE_LOGS   1
#define DIAG_TYPE_EVENTS 2

/* Debug Log levels*/

typedef enum {
    DBGLOG_VERBOSE = 0,
    DBGLOG_INFO,
    DBGLOG_INFO_LVL_1,
    DBGLOG_INFO_LVL_2,
    DBGLOG_WARN,
    DBGLOG_ERR,
    DBGLOG_LVL_MAX
}DBGLOG_LOG_LVL;

enum cnss_diag_type {
    DIAG_TYPE_FW_EVENT,     /* send fw event- to diag*/
    DIAG_TYPE_FW_LOG,       /* send log event- to diag*/
    DIAG_TYPE_FW_DEBUG_MSG, /* send dbg message- to diag*/
    DIAG_TYPE_INIT_REQ,     /* cnss_diag nitialization- from diag */
    DIAG_TYPE_FW_MSG,       /* fw msg command-to diag */
    DIAG_TYPE_HOST_MSG,     /* host command-to diag */
    DIAG_TYPE_CRASH_INJECT, /*crash inject-from diag */
    DIAG_TYPE_DBG_LEVEL,    /* DBG LEVEL-from diag */
};

enum wlan_diag_frame_type {
    WLAN_DIAG_TYPE_CONFIG,
    WLAN_DIAG_TYPE_EVENT,
    WLAN_DIAG_TYPE_LOG,
    WLAN_DIAG_TYPE_MSG,
    WLAN_DIAG_TYPE_LEGACY_MSG,
};

struct dbglog_slot {
    unsigned int diag_type;
    unsigned int timestamp;
    unsigned int length;
    unsigned int dropped;
    /* max ATH6KL_FWLOG_PAYLOAD_SIZE bytes */
    u_int8_t payload[0];
}__packed;

typedef struct event_report_s {
    unsigned int diag_type;
    unsigned short event_id;
    unsigned short length;
} event_report_t;

typedef struct wlan_bringup_s {
    unsigned short wlanStatus;
    char driverVersion[10];
} wlan_bringup_t;

static inline unsigned int get_32(const unsigned char *pos)
{
    return pos[0] | (pos[1] << 8) | (pos[2] << 16) | (pos[3] << 24);
}

/* KENEL DEFS END */

#define WLAN_NL_MSG_CNSS_DIAG   27 /* Msg type between user space/wlan driver */
#define WLAN_NL_MSG_CNSS_MSG    28
#define CNSS_WLAN_DIAG          0x07
#define CNSS_WLAN_SSR_TYPE      0x01
#define CNSS_WLAN_LEVEL_TYPE    0x02
/* NL messgage Carries actual Logs from Driver */
#define ANI_NL_MSG_LOG_MSG_TYPE 89
/* NL message Registration Req/Response to and from Driver */
#define ANI_NL_MSG_LOG_REG_TYPE  1
#define MAX_MSG_SIZE 8192
#define DIAG_MSG_MAX_LEN 4096
#define DIAG_MSG_OVERHEAD_LEN 48

#define RESTART_LEVEL     \
    "echo related > /sys/bus/msm_subsys/devices/subsys4/restart_level"
#define DB_FILE_PATH        "/firmware/image/Data.msc"
#define BUF_SIZ  256

#define WLAN_LOG_TO_DIAG(xx_ss_id, xx_ss_mask, xx_fmt) \
    do { \
          if (xx_ss_mask & (MSG_BUILD_MASK_ ## xx_ss_id)) { \
              msg_const_type xx_msg = { \
                {__LINE__, (xx_ss_id), (xx_ss_mask)}, (NULL), msg_file}; \
                 xx_msg.fmt = xx_fmt; \
                 msg_send (&xx_msg); \
       } \
      } while  (0); \

/* General purpose MACROS to handle the WNI Netlink msgs */
#define ANI_NL_MASK        3


PACK(void *)cnss_wlan_handle(PACK(void *)req_pkt, uint16_t pkt_len);

static const diagpkt_user_table_entry_type cnss_wlan_tbl[] =
{ /* susbsys_cmd_code lo = 7 , susbsys_cmd_code hi = 7, call back function */
   {CNSS_WLAN_DIAG, CNSS_WLAN_DIAG,cnss_wlan_handle},
};

int32_t parser_init();

int32_t
dbglog_parse_debug_logs(u_int8_t *datap, u_int16_t len, u_int16_t dropped);

void
diag_initialize(boolean isDriverLoaded, int sock_fd, uint32_t optionflag);

void
process_diaghost_msg(uint8_t *datap, uint16_t len);


uint32_t
process_diagfw_msg(uint8_t *datap, uint16_t len, uint32_t optionflag,
        FILE *log_out, int32_t *record, int32_t max_records, int32_t version,
        int sock_fd);

#endif

