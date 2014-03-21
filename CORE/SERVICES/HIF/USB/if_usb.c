/*
 * Copyright (c) 2013-2014 The Linux Foundation. All rights reserved.
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
#include <osdep.h>
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/if_arp.h>
#include "if_usb.h"
#include "hif_usb_internal.h"
#include "bmi_msg.h"		/* TARGET_TYPE_ */
#include "regtable.h"
#include "ol_fw.h"
#include <osapi_linux.h>
#include "vos_api.h"
#include "wma_api.h"
#include "wlan_hdd_main.h"

#ifdef WLAN_BTAMP_FEATURE
#include "wlan_btc_svc.h"
#include "wlan_nlink_common.h"
#endif

#ifndef REMOVE_PKT_LOG
#include "ol_txrx_types.h"
#include "pktlog_ac_api.h"
#include "pktlog_ac.h"
#endif
#define VENDOR_ATHR             0x0CF3
#define AR9888_DEVICE_ID (0x003c)
#define AR6320_DEVICE_ID (0x003e)

unsigned int msienable;
module_param(msienable, int, 0644);

static int
hif_usb_configure(struct hif_usb_softc *sc, hif_handle_t *hif_hdl,
		  struct usb_interface *interface)
{
	int ret = 0;

	if (HIF_USBDeviceInserted(interface, sc)) {
		pr_err("ath: %s: Target probe failed.\n", __func__);
		ret = -EIO;
		goto err_stalled;
	}

	*hif_hdl = sc->hif_device;
	return 0;

err_stalled:

	return ret;
}

static void hif_nointrs(struct hif_usb_softc *sc)
{
}

static int
hif_usb_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
	int ret = 0;
	u_int32_t hif_type, target_type;
	struct hif_usb_softc *sc;
	struct ol_softc *ol_sc;
	struct usb_device *pdev = interface_to_usbdev(interface);
	int vendor_id, product_id;

	pr_info("hif_usb_probe\n");
	usb_get_dev(pdev);
	vendor_id = le16_to_cpu(pdev->descriptor.idVendor);
	product_id = le16_to_cpu(pdev->descriptor.idProduct);

	ret = 0;

	sc = A_MALLOC(sizeof(*sc));
	if (!sc) {
		ret = -ENOMEM;
		goto err_alloc;
	}

	OS_MEMZERO(sc, sizeof(*sc));
	sc->pdev = (void *)pdev;
	sc->dev = &pdev->dev;

	sc->aps_osdev.bdev = pdev;
	sc->aps_osdev.device = &pdev->dev;
	sc->aps_osdev.bc.bc_bustype = HAL_BUS_TYPE_AHB;
	sc->devid = AR6320_DEVICE_ID;

	adf_os_spinlock_init(&sc->target_lock);

	switch (sc->devid) {
	case AR9888_DEVICE_ID:
		hif_type = HIF_TYPE_AR9888;
		target_type = TARGET_TYPE_AR9888;
		break;
	case AR6320_DEVICE_ID:
		hif_type = HIF_TYPE_AR6320;
		target_type = TARGET_TYPE_AR6320;
		break;
	default:
		pr_err("unsupported device id\n");
		ret = -ENODEV;
		goto err_tgtstate;
	}

	ol_sc = A_MALLOC(sizeof(*ol_sc));
	if (!ol_sc)
		goto err_attach;
	OS_MEMZERO(ol_sc, sizeof(*ol_sc));
	ol_sc->sc_osdev = &sc->aps_osdev;
	ol_sc->hif_sc = (void *)sc;
	sc->ol_sc = ol_sc;
	ol_sc->target_type = target_type;

	if ((usb_control_msg(pdev, usb_sndctrlpipe(pdev, 0),
			     USB_REQ_SET_CONFIGURATION, 0, 1, 0, NULL, 0,
			     HZ)) < 0) {
		pr_info("%s[%d]\n\r", __func__, __LINE__);
	}
	usb_set_interface(pdev, 0, 0);

	if (hif_usb_configure(sc, &ol_sc->hif_hdl, interface))
		goto err_config;

	ol_sc->enableuartprint = 1;
	ol_sc->enablefwlog = 0;
	ol_sc->enablesinglebinary = TRUE;

	init_waitqueue_head(&ol_sc->sc_osdev->event_queue);

	ret = hdd_wlan_startup(&pdev->dev, ol_sc);

	if (ret) {
		hif_nointrs(sc);
		goto err_config;
	}
#ifndef REMOVE_PKT_LOG
	if (vos_get_conparam() != VOS_FTM_MODE) {
		/*
		 * pktlog initialization
		 */
		ol_pl_sethandle(&ol_sc->pdev_txrx_handle->pl_dev, ol_sc);

		if (pktlogmod_init(ol_sc))
			pr_err("%s: pktlogmod_init failed\n", __func__);
	}
#endif

#ifdef WLAN_BTAMP_FEATURE
	/* Send WLAN UP indication to Nlink Service */
	send_btc_nlink_msg(WLAN_MODULE_UP_IND, 0);
#endif

	return 0;

err_config:
	A_FREE(ol_sc);
err_attach:
	ret = -EIO;
err_tgtstate:
	A_FREE(sc);
err_alloc:
	usb_put_dev(pdev);

	return ret;
}

static void hif_usb_remove(struct usb_interface *interface)
{
	HIF_DEVICE_USB *device = usb_get_intfdata(interface);
	struct hif_usb_softc *sc = device->sc;
	struct ol_softc *scn;

	usb_put_dev(interface_to_usbdev(interface));
	/* Attach did not succeed, all resources have been
	 * freed in error handler
	 */
	if (!sc)
		return;

	scn = sc->ol_sc;

#ifndef REMOVE_PKT_LOG
	if (vos_get_conparam() != VOS_FTM_MODE)
		pktlogmod_exit(scn);
#endif

	__hdd_wlan_exit();
	hif_nointrs(sc);
	HIF_USBDeviceDetached(interface, 1);
	A_FREE(scn);
	A_FREE(sc);

	pr_info("hif_usb_remove!!!!!!\n");
}

#ifdef WLAN_LINK_UMAC_SUSPEND_WITH_BUS_SUSPEND
void hdd_suspend_wlan(void (*callback) (void *callbackContext),
		      void *callbackContext);
#endif

static int hif_usb_suspend(struct usb_interface *interface, pm_message_t state)
{
	HIF_DEVICE_USB *device = usb_get_intfdata(interface);
	void *vos = vos_get_global_context(VOS_MODULE_ID_HIF, NULL);

#ifdef WLAN_LINK_UMAC_SUSPEND_WITH_BUS_SUSPEND
	hdd_suspend_wlan(NULL, NULL);
#endif

	/* No need to send WMI_PDEV_SUSPEND_CMDID to FW if WOW is enabled */
	if (wma_is_wow_mode_selected(vos_get_context(VOS_MODULE_ID_WDA, vos))) {
		if (wma_enable_wow_in_fw
		    (vos_get_context(VOS_MODULE_ID_WDA, vos))) {
			pr_warn("%s[%d]: fail\n", __func__, __LINE__);
			return -1;
		}
	} else if (state.event == PM_EVENT_FREEZE
		   || (PM_EVENT_SUSPEND & state.event) == PM_EVENT_SUSPEND) {
		if (wma_suspend_target
		    (vos_get_context(VOS_MODULE_ID_WDA, vos), 0)) {
			pr_warn("%s[%d]: fail\n", __func__, __LINE__);
			return -1;
		}
	}
	usb_hif_flush_all(device);
	return 0;
}

#ifdef WLAN_LINK_UMAC_SUSPEND_WITH_BUS_SUSPEND
void hdd_resume_wlan(void);
#endif

static int hif_usb_resume(struct usb_interface *interface)
{
	HIF_DEVICE_USB *device = usb_get_intfdata(interface);
	void *vos_context = vos_get_global_context(VOS_MODULE_ID_HIF, NULL);

	usb_hif_start_recv_pipes(device);

#ifdef USB_HIF_TEST_INTERRUPT_IN
	usb_hif_post_recv_transfers(&device->pipes[HIF_RX_INT_PIPE],
				    HIF_USB_RX_BUFFER_SIZE);
#endif
	/* No need to send WMI_PDEV_RESUME_CMDID to FW if WOW is enabled */
	if (!wma_is_wow_mode_selected
	    (vos_get_context(VOS_MODULE_ID_WDA, vos_context))) {
		    wma_resume_target(vos_get_context
				      (VOS_MODULE_ID_WDA, vos_context));
	}
#ifdef WLAN_LINK_UMAC_SUSPEND_WITH_BUS_SUSPEND
	hdd_resume_wlan();
#endif
	return 0;
}

static struct usb_device_id hif_usb_id_table[] = {
	{USB_DEVICE_AND_INTERFACE_INFO(VENDOR_ATHR, 0x9378, 0xFF, 0xFF, 0xFF)},
	{}			/* Terminating entry */
};

MODULE_DEVICE_TABLE(usb, hif_usb_id_table);
struct usb_driver hif_usb_drv_id = {

	.name = "hif_usb",
	.id_table = hif_usb_id_table,
	.probe = hif_usb_probe,
	.disconnect = hif_usb_remove,
#ifdef ATH_BUS_PM
	.suspend = hif_usb_suspend,
	.resume = hif_usb_resume,
#endif
	.supports_autosuspend = true,
};

void hif_init_adf_ctx(adf_os_device_t adf_dev, void *ol_sc)
{
	struct ol_softc *sc = (struct ol_softc *)ol_sc;
	struct hif_usb_softc *hif_sc = (struct hif_usb_softc *)sc->hif_sc;
	adf_dev->drv = &hif_sc->aps_osdev;
	adf_dev->drv_hdl = hif_sc->aps_osdev.bdev;
	adf_dev->dev = hif_sc->aps_osdev.device;
	sc->adf_dev = adf_dev;
}

int hif_register_driver(void)
{
	return usb_register(&hif_usb_drv_id);
}

void hif_unregister_driver(void)
{
	usb_deregister(&hif_usb_drv_id);
}

void hif_init_pdev_txrx_handle(void *ol_sc, void *txrx_handle)
{
	struct ol_softc *sc = (struct ol_softc *)ol_sc;
	sc->pdev_txrx_handle = txrx_handle;
}

void hif_disable_isr(void *ol_sc)
{
	/* TODO */
}

void hif_reset_soc(void *ol_sc)
{
	/* TODO */
}
MODULE_LICENSE("Dual BSD/GPL");
