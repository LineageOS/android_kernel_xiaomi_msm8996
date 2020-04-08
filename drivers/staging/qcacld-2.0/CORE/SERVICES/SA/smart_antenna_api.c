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
 * DOC: contains smart antenna APIs.
 */
#include "wlan_hdd_main.h"
#include "smart_ant.h"
#include "if_smart_antenna.h"

int register_smart_ant_ops(struct smartantenna_ops *sa_ops)
{
	struct smart_ant *sa_handle;

	sa_handle = sa_get_handle();
	if (!sa_handle) {
		SA_DPRINTK(sa_handle, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna module is not attached.",
			   __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	if (!sa_ops) {
		SA_DPRINTK(sa_handle, SMART_ANTENNA_FATAL,
			   "%s: Callback is NULL.", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	SA_DPRINTK(sa_handle, SMART_ANTENNA_INFO,
		   "%s: Smart Antenna Module registered.", __func__);

	sa_handle->sa_callbacks = sa_ops;
	adf_os_atomic_init(&sa_handle->sa_init);
	sa_handle->smart_ant_state |= SMART_ANT_STATE_CB_REGISTERED;
	smart_antenna_init(false);
	return SMART_ANT_STATUS_SUCCESS;
}
EXPORT_SYMBOL(register_smart_ant_ops);

int deregister_smart_ant_ops(char *dev_name)
{
	struct smart_ant *sa_handle;
	sa_handle = sa_get_handle();
	if (!sa_handle) {
		SA_DPRINTK(sa_handle, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna module is not attached.",
			   __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	sa_handle->sa_callbacks = NULL;
	sa_handle->smart_ant_state &= ~SMART_ANT_STATE_CB_REGISTERED;
	return SMART_ANT_STATUS_SUCCESS;
}
EXPORT_SYMBOL(deregister_smart_ant_ops);

int set_smart_ant_control(uint32_t magic)
{
	struct hdd_context_s *hdd_ctx;
	v_CONTEXT_t vos_ctx;
	struct smart_ant *sa_handle;

	sa_handle = sa_get_handle();
	if (!sa_handle) {
		SA_DPRINTK(sa_handle, SMART_ANTENNA_FATAL,
			   "%s: Smart antenna module is not attached.",
			   __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	vos_ctx = vos_get_global_context(VOS_MODULE_ID_SYS, NULL);
	if (!vos_ctx) {
		SA_DPRINTK(sa_handle, SMART_ANTENNA_FATAL,
			   "%s:Invalid global VOSS context", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}

	hdd_ctx = vos_get_context(VOS_MODULE_ID_HDD, vos_ctx);

	if (!hdd_ctx) {
		SA_DPRINTK(sa_handle, SMART_ANTENNA_FATAL,
			   "%s:Invalid HDD Context", __func__);
		return SMART_ANT_STATUS_FAILURE;
	}
	sme_set_rx_antenna(hdd_ctx->hHal, magic);
	return SMART_ANT_STATUS_SUCCESS;
}
EXPORT_SYMBOL(set_smart_ant_control);
