/*
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
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
 * DOC: contains smart antenna HEAD file.
 */

#ifndef __SMART_ANT_H
#define __SMART_ANT_H

#include "vos_types.h"
#include "vos_trace.h"
#include "queue.h"
#include "i_vos_trace.h"
#include "adf_os_atomic.h"
#include "csrApi.h"
#include "halMsgApi.h"
#include "sirApi.h"
#include "if_smart_antenna.h"

#define SA_DPRINTK(smart_ant, _m, _fmt, ...) do {             \
    if (((smart_ant) == NULL) ||                               \
      ((smart_ant) != NULL &&                                  \
       ((_m) & (smart_ant)->sa_debug_mask))) {                \
        VOS_TRACE(VOS_MODULE_ID_HDD_SOFTAP, VOS_TRACE_LEVEL_DEBUG, _fmt, __VA_ARGS__);\
    }                                                    \
} while (0)

#define SMART_ANTENNA_FATAL             BIT(0)
#define SMART_ANTENNA_ERROR             BIT(1)
#define SMART_ANTENNA_DEBUG             BIT(2)
#define SMART_ANTENNA_INFO              BIT(3)
#define SMART_ANTENNA_DEFAULT_LEVEL    \
		SMART_ANTENNA_FATAL | SMART_ANTENNA_ERROR | \
		SMART_ANTENNA_DEBUG | SMART_ANTENNA_INFO

#define SMART_ANT_DEFAULT_ID            1
#define SA_MAX_SUPPORTED_RATES          128
#define SMART_ANTENNA_DEFAULT_INTERFACE "dft"

#define SMART_ANTENNA_ENABLED_MASK       0x1
#define SMART_ANTENNA_ENABLED_SHIFT      0

#define SMART_ANTENNA_DEBUG_LEVEL_MASK   0x1e
#define SMART_ANTENNA_DEBUG_LEVEL_SHIFT  0x1

#define SMART_ANTENNA(cfg, field)        \
		(((cfg) & SMART_ANTENNA_##field##_MASK) >> \
			SMART_ANTENNA_##field##_SHIFT)
#define SMART_ANTENNA_ENABLED(cfg)      SMART_ANTENNA(cfg, ENABLED)
#define SMART_ANTENNA_DEBUG_LEVEL(cfg)  SMART_ANTENNA(cfg, DEBUG_LEVEL)

/* State of this module */
#define SMART_ANT_STATE_ATTACHED              BIT(0)
#define SMART_ANT_STATE_INIT_DONE             BIT(1)
#define SMART_ANT_STATE_CB_REGISTERED         BIT(2)
#define SMART_ANT_STATE_AP_STARTED            BIT(3)

#define SMART_ANT_STATE_OK(state) \
  ((SMART_ANT_STATE_INIT_DONE | SMART_ANT_STATE_CB_REGISTERED) ==\
    ((SMART_ANT_STATE_INIT_DONE | SMART_ANT_STATE_CB_REGISTERED) & (state)))

#define SMART_ANT_NODE_MAX              32

#define MAC_ADDR_ARRAY(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

/** Mac Address string **/
#define MAC_ADDRESS_STR "%02x:%02x:%02x:%02x:%02x:%02x"

#define SMART_ANT_UNSUPPORTED_CHANNEL   (-1)
struct sa_node {
	TAILQ_ENTRY(sa_node) sa_elm;
	adf_os_atomic_t ref_count;
	struct sa_node_info node_info;
	void *node_ccp;
};

struct smart_ant {
	uint32_t sa_debug_mask;
	bool smart_ant_supported;
	bool smart_ant_enabled;
	uint32_t smart_ant_state;
	uint32_t curchan;
	adf_os_atomic_t sa_init;
	struct sa_ops sap_ops;
	struct smartantenna_ops *sa_callbacks;
	rwlock_t node_ref_lock;
	TAILQ_HEAD(, sa_node) node_list;
};
#endif
