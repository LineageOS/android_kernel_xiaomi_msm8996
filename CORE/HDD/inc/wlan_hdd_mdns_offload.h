/*
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef __WLAN_HDD_MDNS_OFFLOAD_H__
#define __WLAN_HDD_MDNS_OFFLOAD_H__

/**
 *  wlan_hdd_mdns_offload.h - WLAN HDD mDNS Offload API
 */

#ifdef MDNS_OFFLOAD
bool wlan_hdd_set_mdns_offload(hdd_adapter_t *adapter);
#else
static inline bool wlan_hdd_set_mdns_offload(hdd_adapter_t *adapter)
{
	return FALSE;
}
#endif

#endif /* __WLAN_HDD_MDNS_OFFLOAD_H__ */
