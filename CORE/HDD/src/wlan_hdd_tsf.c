/*
 * Copyright (c) 2015-2017 The Linux Foundation. All rights reserved.
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
 * wlan_hdd_tsf.c - WLAN Host Device Driver tsf related implementation
 */

#include "wlan_hdd_main.h"
#include "wlan_hdd_tsf.h"
#include "wma_api.h"

/**
 * enum hdd_tsf_op_result - result of tsf operation
 *
 * HDD_TSF_OP_SUCC:  succeed
 * HDD_TSF_OP_FAIL:  fail
 */
enum hdd_tsf_op_result {
	HDD_TSF_OP_SUCC,
	HDD_TSF_OP_FAIL
};

static
enum hdd_tsf_get_state hdd_tsf_check_conn_state(hdd_adapter_t *adapter)
{
	enum hdd_tsf_get_state ret = TSF_RETURN;
	hdd_station_ctx_t *hdd_sta_ctx;

	if (adapter->device_mode == WLAN_HDD_INFRA_STATION ||
			adapter->device_mode == WLAN_HDD_P2P_CLIENT) {
		hdd_sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(adapter);
		if (hdd_sta_ctx->conn_info.connState !=
				eConnectionState_Associated) {
			hddLog(VOS_TRACE_LEVEL_ERROR,
				FL("failed to cap tsf, not connect with ap"));
			ret = TSF_STA_NOT_CONNECTED_NO_TSF;
		}
	} else if ((adapter->device_mode == WLAN_HDD_SOFTAP ||
				adapter->device_mode == WLAN_HDD_P2P_GO) &&
			!(test_bit(SOFTAP_BSS_STARTED,
					&adapter->event_flags))) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
			FL("Soft AP / P2p GO not beaconing"));
		ret = TSF_SAP_NOT_STARTED_NO_TSF;
	}
	return ret;
}

static bool hdd_tsf_is_initialized(hdd_adapter_t *adapter)
{
	hdd_context_t *hddctx;

	if (!adapter) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
			FL("invalid adapter"));
		return false;
	}

	hddctx = WLAN_HDD_GET_CTX(adapter);
	if (!hddctx) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
		       FL("invalid hdd context"));
		return false;
	}

	if (!adf_os_atomic_read(&hddctx->tsf_ready_flag)) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
		       FL("TSF is not initialized"));
		return false;
	}

	return true;
}

static inline int hdd_reset_tsf_gpio(hdd_adapter_t *adapter)
{
	return process_wma_set_command((int)adapter->sessionId,
			(int)GEN_PARAM_RESET_TSF_GPIO,
			adapter->sessionId,
			GEN_CMD);
}

static enum hdd_tsf_op_result hdd_capture_tsf_internal(
	hdd_adapter_t *adapter, uint32_t *buf, int len)
{
	int ret;
	hdd_context_t *hddctx;

	if (adapter == NULL || buf == NULL) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
				FL("invalid pointer"));
		return HDD_TSF_OP_FAIL;
	}

	if (len != 1)
		return HDD_TSF_OP_FAIL;

	hddctx = WLAN_HDD_GET_CTX(adapter);
	if (!hddctx) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
				FL("invalid hdd context"));
		return HDD_TSF_OP_FAIL;
	}

	if (!hdd_tsf_is_initialized(adapter)) {
		buf[0] = TSF_NOT_READY;
		return HDD_TSF_OP_SUCC;
	}

	buf[0] = hdd_tsf_check_conn_state(adapter);
	if (buf[0] != TSF_RETURN)
		return HDD_TSF_OP_SUCC;

	if (adf_os_atomic_inc_return(&hddctx->cap_tsf_flag) > 1) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
				FL("current in capture state"));
		buf[0] = TSF_CURRENT_IN_CAP_STATE;
		return HDD_TSF_OP_SUCC;
	}

	/* record adapter for cap_tsf_irq_handler  */
	hddctx->cap_tsf_context = adapter;

	hddLog(VOS_TRACE_LEVEL_INFO, FL("+ioctl issue cap tsf cmd"));

	/* Reset TSF value for new capture */
	adapter->cur_target_time = 0;

	buf[0] = TSF_RETURN;
	ret = process_wma_set_command((int)adapter->sessionId,
			(int)GEN_PARAM_CAPTURE_TSF,
			adapter->sessionId,
			GEN_CMD);

	if (0 != ret) {
		hddLog(VOS_TRACE_LEVEL_ERROR, FL("cap tsf fail"));
		buf[0] = TSF_CAPTURE_FAIL;
		hddctx->cap_tsf_context = NULL;
		adf_os_atomic_set(&hddctx->cap_tsf_flag, 0);
		return HDD_TSF_OP_SUCC;
	}
	hddLog(VOS_TRACE_LEVEL_INFO,
			FL("-ioctl return cap tsf cmd"));
	return HDD_TSF_OP_SUCC;
}

static enum hdd_tsf_op_result hdd_indicate_tsf_internal(
	hdd_adapter_t *adapter, uint32_t *buf, int len)
{
	int ret;
	hdd_context_t *hddctx;

	if (adapter == NULL || buf == NULL) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
				FL("invalid pointer"));
		return HDD_TSF_OP_FAIL;
	}

	if (len != 3)
		return HDD_TSF_OP_FAIL;

	hddctx = WLAN_HDD_GET_CTX(adapter);
	if (!hddctx) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
				FL("invalid hdd context"));
		return HDD_TSF_OP_FAIL;
	}

	buf[1] = 0;
	buf[2] = 0;

	if (!hdd_tsf_is_initialized(adapter)) {
		buf[0] = TSF_NOT_READY;
		return HDD_TSF_OP_SUCC;
	}

	buf[0] = hdd_tsf_check_conn_state(adapter);
	if (buf[0] != TSF_RETURN)
		return HDD_TSF_OP_SUCC;

	if (adapter->cur_target_time == 0) {
		hddLog(VOS_TRACE_LEVEL_INFO,
				FL("not getting tsf value"));
		buf[0] = TSF_NOT_RETURNED_BY_FW;
		return HDD_TSF_OP_SUCC;
	} else {
		buf[0] = TSF_RETURN;
		buf[1] = (uint32_t)(adapter->cur_target_time & 0xffffffff);
		buf[2] = (uint32_t)((adapter->cur_target_time >> 32) &
				0xffffffff);

		if (!adf_os_atomic_read(&hddctx->cap_tsf_flag)) {
			hddLog(VOS_TRACE_LEVEL_INFO,
				FL("old: status=%u, tsf_low=%u, tsf_high=%u"),
				buf[0], buf[1], buf[2]);
			return HDD_TSF_OP_SUCC;
		}

		ret = hdd_reset_tsf_gpio(adapter);
		if (0 != ret) {
			hddLog(VOS_TRACE_LEVEL_ERROR,
					FL("reset tsf gpio fail"));
			buf[0] = TSF_RESET_GPIO_FAIL;
			return HDD_TSF_OP_SUCC;
		}
		hddctx->cap_tsf_context = NULL;
		adf_os_atomic_set(&hddctx->cap_tsf_flag, 0);
		hddLog(VOS_TRACE_LEVEL_INFO,
			FL("get tsf cmd,status=%u, tsf_low=%u, tsf_high=%u"),
			buf[0], buf[1], buf[2]);
		return HDD_TSF_OP_SUCC;
	}
}

int hdd_capture_tsf(hdd_adapter_t *adapter, uint32_t *buf, int len)
{
	return (hdd_capture_tsf_internal(adapter, buf, len) ==
		HDD_TSF_OP_SUCC ? 0 : -EINVAL);
}

int hdd_indicate_tsf(hdd_adapter_t *adapter, uint32_t *buf, int len)
{
	return (hdd_indicate_tsf_internal(adapter, buf, len) ==
		HDD_TSF_OP_SUCC ? 0 : -EINVAL);
}

/**
 * hdd_get_tsf_cb() - handle tsf callback
 *
 * @pcb_cxt: pointer to the hdd_contex
 * @ptsf: pointer to struct stsf
 *
 * This function handle the event that reported by firmware at first.
 * The event contains the vdev_id, current tsf value of this vdev,
 * tsf value is 64bits, discripted in two varaible tsf_low and tsf_high.
 * These two values each is uint32.
 *
 * Return: Describe the execute result of this routine
 */
static int hdd_get_tsf_cb(void *pcb_cxt, struct stsf *ptsf)
{
	hdd_context_t *hddctx;
	hdd_adapter_t *adapter;
	int status;

	if (pcb_cxt == NULL || ptsf == NULL) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
			FL("HDD context is not valid"));
			return -EINVAL;
	}

	hddctx = (hdd_context_t *)pcb_cxt;
	status = wlan_hdd_validate_context(hddctx);
	if (0 != status)
		return -EINVAL;

	adapter = hdd_get_adapter_by_vdev(hddctx, ptsf->vdev_id);

	if (NULL == adapter) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
			FL("failed to find adapter"));
		return -EINVAL;
	}

	if (!hdd_tsf_is_initialized(adapter)) {
		hddLog(VOS_TRACE_LEVEL_ERROR,
			FL("tsf is not init, ignore tsf event"));
		return -EINVAL;
	}

	hddLog(VOS_TRACE_LEVEL_INFO,
		FL("tsf cb handle event, device_mode is %d"),
		adapter->device_mode);

	adapter->cur_target_time = ((uint64_t)ptsf->tsf_high << 32 |
			 ptsf->tsf_low);

	hddLog(VOS_TRACE_LEVEL_INFO,
		FL("hdd_get_tsf_cb sta=%u, tsf_low=%u, tsf_high=%u"),
		ptsf->vdev_id, ptsf->tsf_low, ptsf->tsf_high);
	return 0;
}

void wlan_hdd_tsf_init(hdd_context_t *hdd_ctx)
{
	eHalStatus hal_status;

	if (!hdd_ctx)
		return;

	if (adf_os_atomic_inc_return(&hdd_ctx->tsf_ready_flag) > 1)
		return;

	adf_os_atomic_init(&hdd_ctx->cap_tsf_flag);

	if (hdd_ctx->cfg_ini->tsf_gpio_pin == TSF_GPIO_PIN_INVALID)
		goto fail;

	hal_status = sme_set_tsf_gpio(hdd_ctx->hHal,
			hdd_ctx->cfg_ini->tsf_gpio_pin);
	if (eHAL_STATUS_SUCCESS != hal_status) {
		hddLog(LOGE, FL("set tsf GPIO failed, status: %d"),
				hal_status);
		goto fail;
	}

	hal_status = sme_set_tsfcb(hdd_ctx->hHal, hdd_get_tsf_cb, hdd_ctx);
	if (eHAL_STATUS_SUCCESS != hal_status) {
		hddLog(LOGE, FL("set tsf cb failed, status: %d"),
				hal_status);
		goto fail;
	}

	return;

fail:
	adf_os_atomic_set(&hdd_ctx->tsf_ready_flag, 0);
	return;
}

void wlan_hdd_tsf_deinit(hdd_context_t *hdd_ctx)
{
	eHalStatus hal_status;

	if (!hdd_ctx)
		return;

	if (!adf_os_atomic_read(&hdd_ctx->tsf_ready_flag))
		return;

	hal_status = sme_set_tsfcb(hdd_ctx->hHal, NULL, NULL);
	if (eHAL_STATUS_SUCCESS != hal_status) {
		hddLog(LOGE, FL("reset tsf cb failed, status: %d"),
				hal_status);
	}

	adf_os_atomic_set(&hdd_ctx->tsf_ready_flag, 0);
	adf_os_atomic_set(&hdd_ctx->cap_tsf_flag, 0);
}
