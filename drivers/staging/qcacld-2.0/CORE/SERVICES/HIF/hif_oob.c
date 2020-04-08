/*
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
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

#include <linux/gpio.h>
#include <hif_oob.h>
#include <vos_api.h>
#if defined(HIF_SDIO)
#include <hif_internal.h>
#endif
#define ATH_MODULE_NAME hif
#include "a_debug.h"

#if defined(HIF_SDIO)
#define hif_device_oob_ctx(device) (&((device)->hif_oob))
#define hif_oob_irq_handler_ctx(device) ((device)->func)
#else
/*Please add oob context if USB, PCIE supports OOB*/
#define hif_device_oob_ctx(device) NULL
#define hif_oob_irq_handler_ctx(device) NULL
#endif

#define OOB_INVALID_GPIO 255
/**
 * hif_oob_irq() - oob irq handler
 * @irq: irq number
 * @dev_id: HIF DEVICE
 *
 * Return: IRQ_HANDLED
 */
static irqreturn_t hif_oob_irq(int irq, void *dev)
{
	struct hif_oob_ctx *hif_oob = hif_device_oob_ctx((HIF_DEVICE *)dev);

	if (!hif_oob) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("NULL hif oob\n"));

		return IRQ_HANDLED;
	}

	if (hif_oob->oob_gpio_flag & GPIO_OOB_INTERRUPT_ENABLE)
		up(&hif_oob->oob_sem);

	return IRQ_HANDLED;
}

/**
 * oob_task() - thread to handle all the oob interrupts
 * @pm_oob: HIF DEVICE
 *
 * Return: 0
 */
static int oob_task(void *pm_oob)
{
	struct hif_oob_ctx *hif_oob = hif_device_oob_ctx((HIF_DEVICE *)pm_oob);

	if (!hif_oob) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("NULL hif oob\n"));

		return A_ERROR;
	}
	while (!hif_oob->oob_shutdown) {
		if (down_interruptible(&hif_oob->oob_sem) != 0)
			continue;
		while (!gpio_get_value(hif_oob->oob_gpio_num)) {
			if (hif_oob->wow_maskint)
				break;
			hif_oob->oob_irq_handler(
				hif_oob_irq_handler_ctx((HIF_DEVICE *)pm_oob));
		}
	}

	complete_and_exit(&hif_oob->oob_completion, 0);

	return 0;
}

int hif_oob_claim_irq(oob_irq_handler_t handler, HIF_DEVICE *hif_device)
{
	struct sched_param param = { .sched_priority = 1 };
	struct hif_oob_ctx *hif_oob = hif_device_oob_ctx(hif_device);

	if (!hif_oob) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("NULL hif oob\n"));

		return A_ERROR;
	}
	if (hif_oob->oob_task) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("oob task already created"));
		return 0;
	}
	sema_init(&hif_oob->oob_sem, 0);
	hif_oob->oob_task = kthread_create(oob_task, hif_device,
					   "koobirqd");
	if (IS_ERR(hif_oob->oob_task)) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("fail to create oob task"));
		hif_oob->oob_task = NULL;
		return A_ERROR;
	} else {
		hif_oob->oob_irq_handler = handler;
		hif_oob->oob_shutdown = 0;
		sched_setscheduler(hif_oob->oob_task, SCHED_FIFO,
				   &param);
		wake_up_process(hif_oob->oob_task);
		up(&hif_oob->oob_sem);
		AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("start oob task"));
	}

	return 0;
}

int hif_oob_release_irq(HIF_DEVICE *hif_device)
{
	struct hif_oob_ctx *hif_oob = hif_device_oob_ctx(hif_device);

	if (!hif_oob) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("NULL hif oob\n"));

		return A_ERROR;
	}
	if (!hif_oob->oob_task) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("oob_task is NULL. return"));
	} else {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("try to kill the oob task"));
		init_completion(&hif_oob->oob_completion);
		hif_oob->oob_shutdown = 1;
		up(&hif_oob->oob_sem);
		wait_for_completion(&hif_oob->oob_completion);
		hif_oob->oob_task = NULL;
	}

	return 0;
}

void hif_oob_gpio_deinit(HIF_DEVICE *device)
{
	struct hif_oob_ctx *hif_oob = hif_device_oob_ctx(device);

	if (!hif_oob) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("NULL hif oob\n"));

		return;
	}

	if (hif_oob->oob_irq_num >= 0 && hif_oob->oob_gpio_flag) {
		if (hif_oob->oob_irq_wake_enabled) {
			if (!disable_irq_wake(hif_oob->oob_irq_num))
				hif_oob->oob_irq_wake_enabled = false;
		}
		disable_irq(hif_oob->oob_irq_num);
		free_irq(hif_oob->oob_irq_num, device);
		gpio_free(hif_oob->oob_gpio_num);
		hif_oob->oob_irq_num = -1;
	}
}

int hif_oob_gpio_init(HIF_DEVICE *device, uint32_t oob_gpio,
		      uint32_t oob_gpio_flag)
{
	int ret = 0;
	unsigned long irq_flags = 0;
	struct hif_oob_ctx *hif_oob = hif_device_oob_ctx(device);

	if (!hif_oob) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("NULL hif oob\n"));

		return A_ERROR;
	}

	ret = gpio_request(oob_gpio, "oob_irq");

	if (ret) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("gpio_request %d ret %d", oob_gpio, ret));
		goto err_oob_req;
	}

	ret = gpio_direction_input(oob_gpio);

	if (ret) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("gpio_direction_input %d ret %d", oob_gpio, ret));
		goto err_oob_int;
	}

	hif_oob->oob_irq_num = gpio_to_irq(oob_gpio);
	if (hif_oob->oob_irq_num < 0) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("%s: gpio_to_irq %d ret %d", __func__, oob_gpio, ret));
		goto err_oob_int;
	}

	if (oob_gpio_flag & GPIO_OOB_INTERRUPT_ENABLE)
		irq_flags = IRQF_TRIGGER_FALLING;
	else
		irq_flags = IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING;

	ret = request_irq(hif_oob->oob_irq_num, hif_oob_irq, irq_flags,
			  "oob_irq", device);
	if (ret) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("%s: request_irq %d ret %d", __func__, oob_gpio, ret));
		goto err_oob_int;
	} else {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("%s: gpio %d request oob irq", __func__, oob_gpio));
		if (oob_gpio_flag & GPIO_OOB_WAKEUP_ENABLE) {
			ret = enable_irq_wake(hif_oob->oob_irq_num);
			if (ret) {
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("enable irq wake failed %d", ret));
				hif_oob->oob_irq_wake_enabled = false;
				goto err_oob_wakeup;
			} else {
				hif_oob->oob_irq_wake_enabled = true;
			}
		}
	}
	hif_oob->oob_gpio_num = oob_gpio;
	hif_oob->oob_gpio_flag = oob_gpio_flag;

	return ret;

err_oob_wakeup:
	disable_irq(hif_oob->oob_irq_num);
	free_irq(hif_oob->oob_irq_num, device);
err_oob_int:
	gpio_free(oob_gpio);
err_oob_req:
	hif_oob->oob_irq_num = -1;
	hif_oob->oob_gpio_num = OOB_INVALID_GPIO;
	hif_oob->oob_irq_wake_enabled = false;
	return ret;
}

int hif_set_wow_maskint(HIF_DEVICE *device, bool value)
{
	struct hif_oob_ctx *hif_oob = hif_device_oob_ctx(device);

	if (!hif_oob) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("NULL hif oob\n"));

		return A_ERROR;
	}

	hif_oob->wow_maskint = value;

	return A_OK;
}
