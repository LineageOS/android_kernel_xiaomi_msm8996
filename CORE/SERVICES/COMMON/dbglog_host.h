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

#ifndef _DBGLOG_HOST_H_
#define _DBGLOG_HOST_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dbglog_id.h"
#include "dbglog.h"
#include "ol_defines.h"

#define MAX_DBG_MSGS 256

#define CLD_NETLINK_USER 17

typedef enum {
    DBGLOG_PROCESS_DEFAULT = 0,
    DBGLOG_PROCESS_PRINT_RAW, /* print them in debug view */
    DBGLOG_PROCESS_POOL_RAW, /* user buffer pool to save them */
    DBGLOG_PROCESS_NET_RAW, /* user buffer pool to save them */
    DBGLOG_PROCESS_MAX,
} dbglog_process_t;

#define ATH6KL_FWLOG_PAYLOAD_SIZE              1500

#define HDRLEN 8
#define RECLEN (HDRLEN + ATH6KL_FWLOG_PAYLOAD_SIZE)

#define DBGLOG_PRINT_PREFIX "FWLOG: "

struct dbglog_slot {
    unsigned int timestamp;
    unsigned int length;

    /* max ATH6KL_FWLOG_PAYLOAD_SIZE bytes */
    u_int8_t payload[0];
};

#define ATH6KL_FWLOG_MAX_ENTRIES                20

#define ATH6KL_FWLOG_PAYLOAD_SIZE              1500

/*
 * set the dbglog parser type
 */
int
dbglog_parser_type_init(wmi_unified_t wmi_handle, int type);

/** dbglog_int - Registers a WMI event handle for WMI_DBGMSG_EVENT
* @brief wmi_handle - handle to wmi module
*/
int
dbglog_init(wmi_unified_t wmi_handle);

/** dbglog_deinit - UnRegisters a WMI event handle for WMI_DBGMSG_EVENT
* @brief wmi_handle - handle to wmi module
*/
int
dbglog_deinit(wmi_unified_t wmi_handle);

/** set the size of the report size
* @brief wmi_handle - handle to Wmi module
* @brief size - Report size
*/
int
dbglog_set_report_size(wmi_unified_t  wmi_handle, A_UINT16 size);

/** Set the resolution for time stamp
* @brief wmi_handle - handle to Wmi module
* @ brief tsr - time stamp resolution
*/
int
dbglog_set_timestamp_resolution(wmi_unified_t  wmi_handle, A_UINT16 tsr);

/** Enable reporting. If it is set to false then Traget wont deliver
* any debug information
*/
int
dbglog_report_enable(wmi_unified_t  wmi_handle, A_BOOL isenable);

/** Set the log level
* @brief DBGLOG_INFO - Information lowest log level
* @brief DBGLOG_WARNING
* @brief DBGLOG_ERROR - default log level
*/
int
dbglog_set_log_lvl(wmi_unified_t  wmi_handle, DBGLOG_LOG_LVL log_lvl);

/*
 * set the debug log level for a given module
 *  mod_id_lvl : the format is more user friendly.
 *    module_id =  mod_id_lvl/10;
 *    log_level =  mod_id_lvl%10;
 * example : mod_id_lvl is 153. then module id is 15 and log level is 3. this format allows
 *         user to pass a sinlge value (which is the most convenient way for most of the OSs)
 *         to be passed from user to the driver.
 */
int
dbglog_set_mod_log_lvl(wmi_unified_t  wmi_handle, A_UINT32 mod_id_lvl);

/** Enable/Disable the logging for VAP */
int
dbglog_vap_log_enable(wmi_unified_t  wmi_handle, A_UINT16 vap_id,
			   A_BOOL isenable);
/** Enable/Disable logging for Module */
int
dbglog_module_log_enable(wmi_unified_t  wmi_handle, A_UINT32 mod_id,
			      A_BOOL isenable);

/** set vap enablie bitmap */
void
dbglog_set_vap_enable_bitmap(wmi_unified_t  wmi_handle, A_UINT32 vap_enable_bitmap);

/** set log level for all the modules specified in the bitmap. for all other modules
  * with 0 in the bitmap (or) outside the bitmap , the log level be reset to DBGLOG_ERR.
  */
void
dbglog_set_mod_enable_bitmap(wmi_unified_t  wmi_handle,A_UINT32 log_level,
   A_UINT32 *mod_enable_bitmap, A_UINT32 bitmap_len );

/** Custome debug_print handlers */
/* Args:
   module Id
   vap id
   debug msg id
   Time stamp
   no of arguments
   pointer to the buffer holding the args
*/
typedef A_BOOL (*module_dbg_print) (A_UINT32, A_UINT16, A_UINT32, A_UINT32,
                                   A_UINT16, A_UINT32 *);

/** Register module specific dbg print*/
void dbglog_reg_modprint(A_UINT32 mod_id, module_dbg_print printfn);

#ifdef __cplusplus
}
#endif

#endif /* _DBGLOG_HOST_H_ */
