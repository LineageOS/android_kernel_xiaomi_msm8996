/*
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

/******************************************************************************
 * wlan_logging_sock_svc.h
 *
 ******************************************************************************/

#ifndef WLAN_LOGGING_SOCK_SVC_H
#define WLAN_LOGGING_SOCK_SVC_H

#include <wlan_nlink_srv.h>
#include <vos_status.h>
#include <wlan_hdd_includes.h>
#include <vos_trace.h>
#include <wlan_nlink_common.h>

int wlan_logging_sock_init_svc(void);
int wlan_logging_sock_deinit_svc(void);
int wlan_logging_sock_activate_svc(int log_fe_to_console, int num_buf);
int wlan_logging_sock_deactivate_svc(void);
int wlan_log_to_user(VOS_TRACE_LEVEL log_level, char *to_be_sent, int length);

#endif /* WLAN_LOGGING_SOCK_SVC_H */
