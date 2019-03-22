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

#ifndef _HIF_OOB_H_
#define _HIF_OOB_H_

#include <linux/kthread.h>

#include <hif.h>

#define GPIO_OOB_WAKEUP_ENABLE    (1 << 0)

#define GPIO_OOB_INTERRUPT_ENABLE (1 << 1)

#ifdef CONFIG_GPIO_OOB
typedef void (*oob_irq_handler_t) (void *dev_para);

struct hif_oob_ctx {
	struct semaphore oob_sem;
	struct completion oob_completion;
	struct task_struct *oob_task;
	int oob_irq_num;
	uint32_t oob_gpio_num;
	uint32_t oob_gpio_flag;
	bool oob_irq_wake_enabled;
	bool oob_shutdown;
	oob_irq_handler_t oob_irq_handler;
	bool wow_maskint;
};

/**
 * hif_oob_gpio_init() - initialize gpio oob
 * @device: HIF handle
 * @oob_gpio: oob gpio number
 * @oob_gpio_flag: oob gpio flag
 *
 * Return: 0 if succeeds.
 */
int hif_oob_gpio_init(HIF_DEVICE *device, uint32_t oob_gpio,
		      uint32_t oob_gpio_flag);

/**
 * hif_oob_gpio_deinit() - deinitialize gpio oob
 * @device: HIF handle
 *
 * Return: NULL
 */
void hif_oob_gpio_deinit(HIF_DEVICE *device);

/**
 * hif_oob_claim_irq() - create oob task
 * @handler: oob irq handler
 * @hif_device: HIF DEVICE
 *
 * Return: 0 if succeeds
 */
int hif_oob_claim_irq(oob_irq_handler_t handler, HIF_DEVICE *hif_device);

/**
 * hif_oob_release_irq() - delete oob task
 * @hif_device: HIF DEVICE
 *
 * Return: 0
 */
int hif_oob_release_irq(HIF_DEVICE *hif_device);

/**
 * hif_set_wow_maskint() - configure wow maskint
 * @hif_device: HIF DEVICE
 * @value: value to set
 *
 * Return: 0 if succeeds
 */
int hif_set_wow_maskint(HIF_DEVICE *device, bool value);
#else
static inline int hif_oob_gpio_init(HIF_DEVICE *device, uint32_t oob_gpio,
				    uint32_t oob_gpio_flag)
{
	return 0;
}

static inline void hif_oob_gpio_deinit(HIF_DEVICE *device)
{
}

static inline int hif_set_wow_maskint(HIF_DEVICE *device, bool value)
{
	return 0;
}
#endif

#endif
