/*
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#if !defined WLAN_HDD_TSF_H
#define WLAN_HDD_TSF_H

/*---------------------------------------------------------------------------
  Include files
  -------------------------------------------------------------------------*/
#include <wlan_hdd_includes.h>

/*---------------------------------------------------------------------------
  Preprocessor definitions and constants
  -------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  Function declarations and documentation
  -------------------------------------------------------------------------*/

#ifdef WLAN_FEATURE_TSF
void wlan_hdd_tsf_init(hdd_context_t *hdd_ctx);
int hdd_capture_tsf(hdd_adapter_t *adapter, uint32_t *buf, int len);
int hdd_indicate_tsf(hdd_adapter_t *adapter, uint32_t *buf, int len);
#else
static inline void
wlan_hdd_tsf_init(hdd_context_t *hdd_ctx)
{
	return;
}

static inline int
hdd_indicate_tsf(hdd_adapter_t *adapter, uint32_t *buf, int len)
{
	return -ENOTSUPP;
}

static inline int
hdd_capture_tsf(hdd_adapter_t *adapter, uint32_t *buf, int len)
{
	return -ENOTSUPP;
}
#endif

#endif
