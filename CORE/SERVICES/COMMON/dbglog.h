/*
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
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

//------------------------------------------------------------------------------
// <copyright file="dbglog.h" company="Atheros">
//    Copyright (c) 2004-2010 Atheros Corporation.  All rights reserved.
// $ATH_LICENSE_HOSTSDK0_C$
//------------------------------------------------------------------------------
//==============================================================================
// Author(s): ="Atheros"
//==============================================================================

#ifndef _DBGLOG_H_
#define _DBGLOG_H_

#ifndef ATH_TARGET
#include "athstartpack.h"
#endif

#include "wlan_module_ids.h"

#ifdef __cplusplus
extern "C" {
#endif
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

PREPACK struct dbglog_buf_s {
    struct dbglog_buf_s *next;
    A_UINT8             *buffer;
    A_UINT32             bufsize;
    A_UINT32             length;
    A_UINT32             count;
    A_UINT32             free;
} POSTPACK;

PREPACK struct dbglog_hdr_s {
    struct dbglog_buf_s *dbuf;
    A_UINT32             dropped;
} POSTPACK;

PREPACK struct dbglog_buf_host {
    A_UINT32             next;
    A_UINT32             buffer;
    A_UINT32             bufsize;
    A_UINT32             length;
    A_UINT32             count;
    A_UINT32             free;
} POSTPACK;

PREPACK struct dbglog_hdr_host {
    A_UINT32             dbuf;
    A_UINT32             dropped;
} POSTPACK;

#define DBGLOG_MAX_VDEVID 15 /* 0-15 */

/** value representing all modules */
#define WMI_DEBUG_LOG_MODULE_ALL 0xffff

/* param definitions */

/**
  * Log level for a given module. Value contains both module id and log level.
  * here is the bitmap definition for value.
  * module Id   : 16
  *     Flags   :  reserved
  *     Level   :  8
  * if odule Id  is WMI_DEBUG_LOG_MODULE_ALL then  log level is  applied to all modules (global).
  * WMI_DEBUG_LOG_MIDULE_ALL will overwrites per module level setting.
  */
#define WMI_DEBUG_LOG_PARAM_LOG_LEVEL      0x1

#define WMI_DBGLOG_SET_LOG_LEVEL(val,lvl) do { \
        (val) |=  (lvl & 0xff);                \
     } while(0)

#define WMI_DBGLOG_GET_LOG_LEVEL(val) ((val) & 0xff)

#define WMI_DBGLOG_SET_MODULE_ID(val,mid) do { \
        (val) |=  ((mid & 0xffff) << 16);        \
     } while(0)

#define WMI_DBGLOG_GET_MODULE_ID(val) (( (val) >> 16) & 0xffff)

/**
  * Enable the debug log for a given vdev. Value is vdev id
  */
#define WMI_DEBUG_LOG_PARAM_VDEV_ENABLE    0x2

/**
  * Disable the debug log for a given vdev. Value is vdev id
  * All the log level  for a given VDEV is disabled except the ERROR log messages
  */
#define WMI_DEBUG_LOG_PARAM_VDEV_DISABLE   0x3

/**
  * set vdev enable bitmap. value is the vden enable bitmap
  */
#define WMI_DEBUG_LOG_PARAM_VDEV_ENABLE_BITMAP    0x4

/**
  * set a given log level to all the modules specified in the module bitmap.
  * and set the log levle for all other modules to DBGLOG_ERR.
  *  value: log levelt to be set.
  *  module_id_bitmap : identifies the modules for which the log level should be set and
  *                      modules for which the log level should be reset to DBGLOG_ERR.
  */
#define WMI_DEBUG_LOG_PARAM_MOD_ENABLE_BITMAP    0x5

#define NUM_MODULES_PER_ENTRY ((sizeof(A_UINT32)) << 3)

#define WMI_MODULE_ENABLE(pmid_bitmap,mod_id) \
    ( (pmid_bitmap)[(mod_id)/NUM_MODULES_PER_ENTRY] |= \
         (1 << ((mod_id)%NUM_MODULES_PER_ENTRY)) )

#define WMI_MODULE_DISABLE(pmid_bitmap,mod_id)     \
    ( (pmid_bitmap)[(mod_id)/NUM_MODULES_PER_ENTRY] &=  \
      ( ~(1 << ((mod_id)%NUM_MODULES_PER_ENTRY)) ) )

#define WMI_MODULE_IS_ENABLED(pmid_bitmap,mod_id) \
    ( ((pmid_bitmap)[(mod_id)/NUM_MODULES_PER_ENTRY ] &  \
       (1 << ((mod_id)%NUM_MODULES_PER_ENTRY)) ) != 0)

#define MAX_MODULE_ID_BITMAP_WORDS 16 /* 16*32=512 module ids. should be more than sufficient */
typedef struct {
	A_UINT32 tlv_header; /* TLV tag and len; tag equals WMITLV_TAG_STRUC_wmi_debug_log_config_cmd_fixed_param */
        A_UINT32 dbg_log_param; /** param types are defined above */
        A_UINT32 value;
	/* The below array will follow this tlv ->fixed length module_id_bitmap[]
        A_UINT32 module_id_bitmap[MAX_MODULE_ID_BITMAP_WORDS];
	 */
} wmi_debug_log_config_cmd_fixed_param;

#ifdef __cplusplus
}
#endif


#endif /* _DBGLOG_H_ */
