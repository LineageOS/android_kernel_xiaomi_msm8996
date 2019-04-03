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
	if (adf_os_atomic_read(&sa_handle->sa_init) == 0 ) {
		sa_handle->sa_callbacks = NULL;
		sa_handle->smart_ant_state &= ~SMART_ANT_STATE_CB_REGISTERED;
	}
	return SMART_ANT_STATUS_SUCCESS;
}
EXPORT_SYMBOL(deregister_smart_ant_ops);

int set_smart_ant_control(uint32_t magic)
{
	return SMART_ANT_STATUS_SUCCESS;
}
EXPORT_SYMBOL(set_smart_ant_control);
