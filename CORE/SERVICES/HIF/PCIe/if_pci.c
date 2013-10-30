/*
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
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
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/if_arp.h>
#include "if_pci.h"
#include "copy_engine_api.h"
#include "bmi_msg.h" /* TARGET_TYPE_ */
#include "regtable.h"
#include "ol_fw.h"
#include <osapi_linux.h>
#include "vos_api.h"
#include "wma_api.h"

#ifdef WLAN_BTAMP_FEATURE
#include "wlan_btc_svc.h"
#include "wlan_nlink_common.h"
#endif

#ifndef REMOVE_PKT_LOG
#include "ol_txrx_types.h"
#include "pktlog_ac_api.h"
#include "pktlog_ac.h"
#endif

#define AR9888_DEVICE_ID (0x003c)
#define AR6320_DEVICE_ID (0x003e)

unsigned int msienable = 0;
module_param(msienable, int, 0644);

int hif_pci_configure(struct hif_pci_softc *sc, hif_handle_t *hif_hdl);
void hif_nointrs(struct hif_pci_softc *sc);

static struct pci_device_id hif_pci_id_table[] = {
	{ 0x168c, 0x003c, PCI_ANY_ID, PCI_ANY_ID },
	{ 0x168c, 0x003e, PCI_ANY_ID, PCI_ANY_ID },
	{ 0 }
};

#ifndef REMOVE_PKT_LOG
struct ol_pl_os_dep_funcs *g_ol_pl_os_dep_funcs = NULL;
#endif

/* Setting SOC_GLOBAL_RESET during driver unload causes intermittent PCIe data bus error
 * As workaround for this issue - changing the reset sequence to use TargetCPU warm reset 
 * instead of SOC_GLOBAL_RESET
 */
#define CPU_WARM_RESET_WAR

/*
 * Top-level interrupt handler for all PCI interrupts from a Target.
 * When a block of MSI interrupts is allocated, this top-level handler
 * is not used; instead, we directly call the correct sub-handler.
 */
static irqreturn_t
hif_pci_interrupt_handler(int irq, void *arg)
{
    struct hif_pci_softc *sc = (struct hif_pci_softc *) arg;
    volatile int tmp;

    if (LEGACY_INTERRUPTS(sc)) {
        /* Clear Legacy PCI line interrupts */
        /* IMPORTANT: INTR_CLR regiser has to be set after INTR_ENABLE is set to 0, */
        /*            otherwise interrupt can not be really cleared */
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS), 0);
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_CLR_ADDRESS), PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL);
        /* IMPORTANT: this extra read transaction is required to flush the posted write buffer */
        tmp = A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
    }
    /* TBDXXX: Add support for WMAC */

    sc->irq_event = irq;
    tasklet_schedule(&sc->intr_tq);

    return IRQ_HANDLED;
}

static irqreturn_t
hif_pci_msi_fw_handler(int irq, void *arg)
{
    struct hif_pci_softc *sc = (struct hif_pci_softc *) arg;

    (irqreturn_t)HIF_fw_interrupt_handler(sc->irq_event, sc);

    return IRQ_HANDLED;
}

bool
hif_pci_targ_is_awake(struct hif_pci_softc *sc, void *__iomem *mem)
{
    A_UINT32 val;
    val = A_PCI_READ32(mem + PCIE_LOCAL_BASE_ADDRESS + RTC_STATE_ADDRESS);
    return (RTC_STATE_V_GET(val) == RTC_STATE_V_ON);
}

bool hif_pci_targ_is_present(A_target_id_t targetid, void *__iomem *mem)
{
    return 1; /* FIX THIS */
}

bool hif_max_num_receives_reached(unsigned int count)
{
#ifdef EPPING_TEST
    return (count > 120);
#else
    /* Not implemented yet */
    return 0;
#endif
}

void hif_init_adf_ctx(adf_os_device_t adf_dev, void *ol_sc)
{
	struct ol_softc *sc = (struct ol_softc *)ol_sc;
	struct hif_pci_softc *hif_sc = sc->hif_sc;
	adf_dev->drv = &hif_sc->aps_osdev;
	adf_dev->drv_hdl = hif_sc->aps_osdev.bdev;
	adf_dev->dev = hif_sc->aps_osdev.device;
	sc->adf_dev = adf_dev;
}
#define A_PCIE_LOCAL_REG_READ(mem, addr) \
        A_PCI_READ32((char *)(mem) + PCIE_LOCAL_BASE_ADDRESS + (A_UINT32)(addr))

#define A_PCIE_LOCAL_REG_WRITE(mem, addr, val) \
        A_PCI_WRITE32(((char *)(mem) + PCIE_LOCAL_BASE_ADDRESS + (A_UINT32)(addr)), (val))

#define ATH_PCI_RESET_WAIT_MAX 10 /* Ms */
static void
hif_pci_device_reset(struct hif_pci_softc *sc)
{
    void __iomem *mem = sc->mem;
    int i;
    u_int32_t val;

    /* NB: Don't check resetok here.  This form of reset is integral to correct operation. */

    if (!SOC_GLOBAL_RESET_ADDRESS) {
        return;
    }

    if (!mem) {
        return;
    }

    printk("Reset Device \n");

    /*
     * NB: If we try to write SOC_GLOBAL_RESET_ADDRESS without first
     * writing WAKE_V, the Target may scribble over Host memory!
     */
    A_PCIE_LOCAL_REG_WRITE(mem, PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
    for (i=0; i<ATH_PCI_RESET_WAIT_MAX; i++) {
        if (hif_pci_targ_is_awake(sc, mem)) {
            break;
        }

        A_MDELAY(1);
    }

    /* Put Target, including PCIe, into RESET. */
    val = A_PCIE_LOCAL_REG_READ(mem, SOC_GLOBAL_RESET_ADDRESS);
    val |= 1;
    A_PCIE_LOCAL_REG_WRITE(mem, SOC_GLOBAL_RESET_ADDRESS, val);
    for (i=0; i<ATH_PCI_RESET_WAIT_MAX; i++) {
        if (A_PCIE_LOCAL_REG_READ(mem, RTC_STATE_ADDRESS) & RTC_STATE_COLD_RESET_MASK) {
            break;
        }

        A_MDELAY(1);
    }

    /* Pull Target, including PCIe, out of RESET. */
    val &= ~1;
    A_PCIE_LOCAL_REG_WRITE(mem, SOC_GLOBAL_RESET_ADDRESS, val);
    for (i=0; i<ATH_PCI_RESET_WAIT_MAX; i++) {
        if (!(A_PCIE_LOCAL_REG_READ(mem, RTC_STATE_ADDRESS) & RTC_STATE_COLD_RESET_MASK)) {
            break;
        }

        A_MDELAY(1);
    }

    A_PCIE_LOCAL_REG_WRITE(mem, PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);
}


/* CPU warm reset function 
 * Steps:
 * 	1. Disable all pending interrupts - so no pending interrupts on WARM reset
 * 	2. Clear the FW_INDICATOR_ADDRESS -so Traget CPU intializes FW correctly on WARM reset 
 *      3. Clear TARGET CPU LF timer interrupt
 *      4. Reset all CEs to clear any pending CE tarnsactions
 *      5. Warm reset CPU
 */
void
hif_pci_device_warm_reset(struct hif_pci_softc *sc)
{
    void __iomem *mem = sc->mem;
    int i;
    u_int32_t val;
    u_int32_t fw_indicator;

    /* NB: Don't check resetok here.  This form of reset is integral to correct operation. */

    if (!mem) {
        return;
    }

    printk("Target Warm Reset\n");

    /*
     * NB: If we try to write SOC_GLOBAL_RESET_ADDRESS without first
     * writing WAKE_V, the Target may scribble over Host memory!
     */
    A_PCIE_LOCAL_REG_WRITE(mem, PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
    for (i=0; i<ATH_PCI_RESET_WAIT_MAX; i++) {
        if (hif_pci_targ_is_awake(sc, mem)) {
            break;
        }
        A_MDELAY(1);
    }

    /*
     * Disable Pending interrupts
     */
    val = A_PCI_READ32(mem + (SOC_CORE_BASE_ADDRESS | PCIE_INTR_CAUSE_ADDRESS));
    printk("Host Intr Cause reg 0x%x : value : 0x%x \n", (SOC_CORE_BASE_ADDRESS | PCIE_INTR_CAUSE_ADDRESS), val);
    /* Target CPU Intr Cause */
    val = A_PCI_READ32(mem + (SOC_CORE_BASE_ADDRESS | CPU_INTR_ADDRESS));
    printk("Target CPU Intr Cause 0x%x \n", val);

    val = A_PCI_READ32(mem + (SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
    A_PCI_WRITE32((mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS)), 0);
    A_PCI_WRITE32((mem+(SOC_CORE_BASE_ADDRESS+PCIE_INTR_CLR_ADDRESS)), 0xffffffff);

    A_MDELAY(100);

    /* Clear FW_INDICATOR_ADDRESS */
    fw_indicator = A_PCI_READ32(mem + FW_INDICATOR_ADDRESS);
    A_PCI_WRITE32(mem+FW_INDICATOR_ADDRESS, 0);

    /* Clear Target LF Timer interrupts */
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS + SOC_LF_TIMER_CONTROL0_ADDRESS));
    printk("addr 0x%x :  0x%x \n", (RTC_SOC_BASE_ADDRESS + SOC_LF_TIMER_CONTROL0_ADDRESS), val);
    val &= ~SOC_LF_TIMER_CONTROL0_ENABLE_MASK;
    A_PCI_WRITE32(mem+(RTC_SOC_BASE_ADDRESS + SOC_LF_TIMER_CONTROL0_ADDRESS), val);

    /* Reset CE */
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    val |= SOC_RESET_CONTROL_CE_RST_MASK;
    A_PCI_WRITE32((mem+(RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS)), val);
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    A_MDELAY(10);

    /* CE unreset */
    val &= ~SOC_RESET_CONTROL_CE_RST_MASK;
    A_PCI_WRITE32(mem+(RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS), val);
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    A_MDELAY(10);

    /* Read Target CPU Intr Cause */
    val = A_PCI_READ32(mem + (SOC_CORE_BASE_ADDRESS | CPU_INTR_ADDRESS));
    printk("Target CPU Intr Cause after CE reset 0x%x \n", val);

    /* CPU warm RESET */
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    val |= SOC_RESET_CONTROL_CPU_WARM_RST_MASK;
    A_PCI_WRITE32(mem+(RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS), val);
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    printk("RESET_CONTROL after cpu warm reset 0x%x \n", val);

    A_MDELAY(100);
    printk("Target Warm reset complete\n");

}

/*
 * Handler for a per-engine interrupt on a PARTICULAR CE.
 * This is used in cases where each CE has a private
 * MSI interrupt.
 */
static irqreturn_t
CE_per_engine_handler(int irq, void *arg)
{
    struct hif_pci_softc *sc = (struct hif_pci_softc *) arg;
    int CE_id = irq - MSI_ASSIGN_CE_INITIAL;

    /*
     * NOTE: We are able to derive CE_id from irq because we
     * use a one-to-one mapping for CE's 0..5.
     * CE's 6 & 7 do not use interrupts at all.
     *
     * This mapping must be kept in sync with the mapping
     * used by firmware.
     */

    CE_per_engine_service(sc, CE_id);

    return IRQ_HANDLED;
}

static void
wlan_tasklet(unsigned long data)
{
    struct hif_pci_softc *sc = (struct hif_pci_softc *) data;
    volatile int tmp;

    (irqreturn_t)HIF_fw_interrupt_handler(sc->irq_event, sc);
    CE_per_engine_service_any(sc->irq_event, sc);
    if (LEGACY_INTERRUPTS(sc)) {
        /* Enable Legacy PCI line interrupts */
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS), 
		    PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL); 
        /* IMPORTANT: this extra read transaction is required to flush the posted write buffer */
        tmp = A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
    }
}

#define ATH_PCI_PROBE_RETRY_MAX 3

int
hif_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    void __iomem *mem;
    int ret = 0;
    u_int32_t hif_type, target_type;
    struct hif_pci_softc *sc;
    struct ol_softc *ol_sc;
    int probe_again = 0;
    u_int16_t device_id;

    u_int32_t lcr_val;

    printk(KERN_INFO "hif_pci_probe\n");

again:
    ret = 0;

#define BAR_NUM 0
    /*
     * Without any knowledge of the Host, the Target
     * may have been reset or power cycled and its
     * Config Space may no longer reflect the PCI
     * address space that was assigned earlier
     * by the PCI infrastructure.  Refresh it now.
     */
     /*WAR for EV#117307, if PCI link is down, return from probe() */
     pci_read_config_word(pdev,PCI_DEVICE_ID,&device_id);
     printk("PCI device id is %04x :%04x\n",device_id,id->device);
     if(device_id != id->device)  {
	printk(KERN_ERR "ath: PCI link is down.\n");
	/* pci link is down, so returing with error code */
	return -EIO;
     }

    /* FIXME: temp. commenting out assign_resource 
     * call for dev_attach to work on 2.6.38 kernel
     */ 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0) && !defined(__LINUX_ARM_ARCH__)
    if (pci_assign_resource(pdev, BAR_NUM)) {
        printk(KERN_ERR "ath: cannot assign PCI space\n");
        return -EIO;
    }
#endif

    if (pci_enable_device(pdev)) {
        printk(KERN_ERR "ath: cannot enable PCI device\n");
        return -EIO;
    }

#define BAR_NUM 0
    /* Request MMIO resources */
    ret = pci_request_region(pdev, BAR_NUM, "ath");
    if (ret) {
        dev_err(&pdev->dev, "ath: PCI MMIO reservation error\n");
        ret = -EIO;
        goto err_region;
    }

    ret =  pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
    if (!ret) {
        ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));

        if (ret) {
            printk(KERN_ERR "ath: Cannot enable 64-bit consistent DMA\n");
            goto err_dma;
        }
    } else {
        ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));

        if (!ret) {
            ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
            if (ret) {
                printk(KERN_ERR "ath: Cannot enable 32-bit consistent DMA\n");
                goto err_dma;
            }
        }
    }


    /* Set bus master bit in PCI_COMMAND to enable DMA */
    pci_set_master(pdev);

    /* Temporary FIX: disable ASPM on peregrine. Will be removed after the OTP is programmed */
    pci_read_config_dword(pdev, 0x80, &lcr_val);
    pci_write_config_dword(pdev, 0x80, (lcr_val & 0xffffff00));

    /* Arrange for access to Target SoC registers. */
    mem = pci_iomap(pdev, BAR_NUM, 0);
    if (!mem) {
        printk(KERN_ERR "ath: PCI iomap error\n") ;
        ret = -EIO;
        goto err_iomap;
    }
    sc = A_MALLOC(sizeof(*sc));
    if (!sc) {
        ret = -ENOMEM;
        goto err_alloc;
    }

    OS_MEMZERO(sc, sizeof(*sc));
    sc->mem = mem;
    sc->pdev = pdev;
    sc->dev = &pdev->dev;

    sc->aps_osdev.bdev = pdev;
    sc->aps_osdev.device = &pdev->dev;
    sc->aps_osdev.bc.bc_handle = (void *)mem;
    sc->aps_osdev.bc.bc_bustype = HAL_BUS_TYPE_PCI;
    sc->devid = id->device;

    adf_os_spinlock_init(&sc->target_lock);

    sc->cacheline_sz = dma_get_cache_alignment();

    switch (id->device) {
    case AR9888_DEVICE_ID:
	    hif_type = HIF_TYPE_AR9888;
	    target_type = TARGET_TYPE_AR9888;
	    break;
    case AR6320_DEVICE_ID:
	    hif_type = HIF_TYPE_AR6320;
	    target_type = TARGET_TYPE_AR6320;
	    break;
    default:
	    printk(KERN_ERR "unsupported device id\n");
	    ret = -ENODEV;
	    goto err_tgtstate;
    }
    /*
     * Attach Target register table.  This is needed early on --
     * even before BMI -- since PCI and HIF initialization (and BMI init)
     * directly access Target registers (e.g. CE registers).
     */

    hif_register_tbl_attach(sc, hif_type);
    target_register_tbl_attach(sc, target_type);
    {
        A_UINT32 fw_indicator;
#if PCIE_BAR0_READY_CHECKING
        int wait_limit = 200;
#endif

        /*
         * Verify that the Target was started cleanly.
         *
         * The case where this is most likely is with an AUX-powered
         * Target and a Host in WoW mode. If the Host crashes,
         * loses power, or is restarted (without unloading the driver)
         * then the Target is left (aux) powered and running.  On a
         * subsequent driver load, the Target is in an unexpected state.
         * We try to catch that here in order to reset the Target and
         * retry the probe.
         */
        A_PCI_WRITE32(mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
        while (!hif_pci_targ_is_awake(sc, mem)) {
		 ;
        }

#if PCIE_BAR0_READY_CHECKING
        /* Synchronization point: wait the BAR0 is configured */
        while (wait_limit-- &&
            !(A_PCI_READ32(mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_RDY_STATUS_ADDRESS) \
             & PCIE_SOC_RDY_STATUS_BAR_MASK)) {
            A_MDELAY(10);
        }
        if (wait_limit < 0) {
            /* AR6320v1 doesn't support checking of BAR0 configuration,
               takes one sec to wait BAR0 ready */
            printk(KERN_INFO "AR6320v1 waits two sec for BAR0 ready.\n");
        }
#endif

        fw_indicator = A_PCI_READ32(mem + FW_INDICATOR_ADDRESS);
        A_PCI_WRITE32(mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);

        if (fw_indicator & FW_IND_INITIALIZED) {
            probe_again++;
            printk(KERN_ERR "ath: Target is in an unknown state. Resetting (attempt %d).\n", probe_again);
            /* hif_pci_device_reset, below, will reset the target */
            ret = -EIO;
            goto err_tgtstate;
        }
    }

    ol_sc = A_MALLOC(sizeof(*ol_sc));
    if (!ol_sc)
	    goto err_attach;
    OS_MEMZERO(ol_sc, sizeof(*ol_sc));
    ol_sc->sc_osdev = &sc->aps_osdev;
    ol_sc->hif_sc = (void *)sc;
    sc->ol_sc = ol_sc;
    ol_sc->target_type = target_type;
    if (hif_pci_configure(sc, &ol_sc->hif_hdl))
	    goto err_config;

    ol_sc->enableuartprint = 0;
    ol_sc->enablefwlog = 0;
    ol_sc->enablesinglebinary = FALSE;

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
            printk(KERN_ERR "%s: pktlogmod_init failed\n", __func__);
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
    pci_set_drvdata(pdev, NULL);
    hif_pci_device_reset(sc);
    A_FREE(sc);
err_alloc:
    /* call HIF PCI free here */
    printk("%s: HIF PCI Free needs to happen here \n", __func__);
    pci_iounmap(pdev, mem);
err_iomap:
    pci_clear_master(pdev);
err_dma:
    pci_release_region(pdev, BAR_NUM);
err_region:
    pci_disable_device(pdev);

    if (probe_again && (probe_again <= ATH_PCI_PROBE_RETRY_MAX)) {
        int delay_time;

        /*
         * We can get here after a Host crash or power fail when
         * the Target has aux power.  We just did a device_reset,
         * so we need to delay a short while before we try to
         * reinitialize.  Typically only one retry with the smallest
         * delay is needed.  Target should never need more than a 100Ms
         * delay; that would not conform to the PCIe std.
         */

        printk(KERN_INFO "pci reprobe.\n");
        delay_time = max(100, 10 * (probe_again * probe_again)); /* 10, 40, 90, 100, 100, ... */
        A_MDELAY(delay_time);
        goto again;
    }
    return ret;
}

void
hif_nointrs(struct hif_pci_softc *sc)
{
    int i;

    if (sc->num_msi_intrs > 0) {
        /* MSI interrupt(s) */
        for (i = 0; i < sc->num_msi_intrs; i++) {
            free_irq(sc->pdev->irq + i, sc);
        }
        sc->num_msi_intrs = 0;
    } else {
        /* Legacy PCI line interrupt */
        free_irq(sc->pdev->irq, sc);
    }
}

int
hif_pci_configure(struct hif_pci_softc *sc, hif_handle_t *hif_hdl)
{
    int ret = 0;
    int num_msi_desired;
    u_int32_t val;

    BUG_ON(pci_get_drvdata(sc->pdev) != NULL);
    pci_set_drvdata(sc->pdev, sc);

    tasklet_init(&sc->intr_tq, wlan_tasklet, (unsigned long)sc);

	/*
	 * Interrupt Management is divided into these scenarios :
	 * A) We wish to use MSI and Multiple MSI is supported and we 
	 *    are able to obtain the number of MSI interrupts desired
	 *    (best performance)
	 * B) We wish to use MSI and Single MSI is supported and we are
	 *    able to obtain a single MSI interrupt
	 * C) We don't want to use MSI or MSI is not supported and we 
	 *    are able to obtain a legacy interrupt
	 * D) Failure
	 */
#if defined(FORCE_LEGACY_PCI_INTERRUPTS)
    num_msi_desired = 0; /* Use legacy PCI line interrupts rather than MSI */
#else
    num_msi_desired = MSI_NUM_REQUEST; /* Multiple MSI */
    if (!msienable) {
        num_msi_desired = 0;
    }
#endif

    printk("\n %s : num_desired MSI set to %d\n", __func__, num_msi_desired);

    if (num_msi_desired > 1) {
        int i;
        int rv;

        rv = pci_enable_msi_block(sc->pdev, MSI_NUM_REQUEST);

	if (rv == 0) { /* successfully allocated all MSI interrupts */
		/*
		 * TBDXXX: This path not yet tested,
		 * since Linux x86 does not currently
		 * support "Multiple MSIs".
		 */
		sc->num_msi_intrs = MSI_NUM_REQUEST;
		ret = request_irq(sc->pdev->irq+MSI_ASSIGN_FW, hif_pci_msi_fw_handler,
				  IRQF_SHARED, "wlan_pci", sc);
		if(ret) {
			dev_err(&sc->pdev->dev, "request_irq failed\n");
			goto err_intr;
		}
		for (i=MSI_ASSIGN_CE_INITIAL; i<=MSI_ASSIGN_CE_MAX; i++) {
			ret = request_irq(sc->pdev->irq+i, CE_per_engine_handler, IRQF_SHARED,
					  "wlan_pci", sc);
			if(ret) {
				dev_err(&sc->pdev->dev, "request_irq failed\n");
				goto err_intr;
			}
		}
	} else {
            if (rv < 0) {
                /* Can't get any MSI -- try for legacy line interrupts */
                num_msi_desired = 0;
            } else {
                /* Can't get enough MSI interrupts -- try for just 1 */
                num_msi_desired = 1;
            }
        }
    }
    
    if (num_msi_desired == 1) {
        /*
         * We are here because either the platform only supports
         * single MSI OR because we couldn't get all the MSI interrupts
         * that we wanted so we fall back to a single MSI.
         */
        if (pci_enable_msi(sc->pdev) < 0) {
            printk(KERN_ERR "ath: single MSI interrupt allocation failed\n");
            /* Try for legacy PCI line interrupts */
            num_msi_desired = 0;
        } else {
            /* Use a single Host-side MSI interrupt handler for all interrupts */
            num_msi_desired = 1;
        }
    }

    if ( num_msi_desired <= 1) {
	    /* We are here because we want to multiplex a single host interrupt among all 
	     * Target interrupt sources
	     */
	    ret = request_irq(sc->pdev->irq, hif_pci_interrupt_handler, IRQF_SHARED,
			      "wlan_pci", sc);
	    if(ret) {
		    dev_err(&sc->pdev->dev, "request_irq failed\n");
		    goto err_intr;
	    }

    }
#if CONFIG_PCIE_64BIT_MSI
    {
        struct ol_ath_softc_net80211 *scn = sc->scn;
        u_int8_t MSI_flag;
        u_int32_t reg;

#define OL_ATH_PCI_MSI_POS        0x50
#define MSI_MAGIC_RDY_MASK  0x00000001
#define MSI_MAGIC_EN_MASK   0x80000000

        pci_read_config_byte(sc->pdev, OL_ATH_PCI_MSI_POS + PCI_MSI_FLAGS, &MSI_flag);
        if (MSI_flag & PCI_MSI_FLAGS_ENABLE) {
            A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
            while (!ath_pci_targ_is_awake(sc->mem)) {
                ;
            }
            scn->MSI_magic = OS_MALLOC_CONSISTENT(scn->sc_osdev, 4, &scn->MSI_magic_dma, \
                             OS_GET_DMA_MEM_CONTEXT(scn, MSI_dmacontext), 0);
            A_PCI_WRITE32(sc->mem + SOC_PCIE_BASE_ADDRESS + MSI_MAGIC_ADR_ADDRESS,
                          scn->MSI_magic_dma);
            reg = A_PCI_READ32(sc->mem + SOC_PCIE_BASE_ADDRESS + MSI_MAGIC_ADDRESS);
            A_PCI_WRITE32(sc->mem + SOC_PCIE_BASE_ADDRESS + MSI_MAGIC_ADDRESS, reg | MSI_MAGIC_RDY_MASK);

            A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);
        }
    }
#endif


    if(num_msi_desired == 0) {
        printk("\n Using PCI Legacy Interrupt\n");
        
        /* Make sure to wake the Target before enabling Legacy Interrupt */
        A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
        while (!hif_pci_targ_is_awake(sc, sc->mem)) {
                ;
        }
        /* Use Legacy PCI Interrupts */
        /* 
         * A potential race occurs here: The CORE_BASE write depends on
         * target correctly decoding AXI address but host won't know
         * when target writes BAR to CORE_CTRL. This write might get lost
         * if target has NOT written BAR. For now, fix the race by repeating
         * the write in below synchronization checking.
         */
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS), 
                      PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL); 
        A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);
    }

    sc->num_msi_intrs = num_msi_desired;
    sc->ce_count = CE_COUNT;

    { /* Synchronization point: Wait for Target to finish initialization before we proceed. */
        int wait_limit = 1000; /* 10 sec */

        /* Make sure to wake Target before accessing Target memory */
        A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
        while (!hif_pci_targ_is_awake(sc, sc->mem)) {
                ;
        }
        while (wait_limit-- && !(A_PCI_READ32(sc->mem + FW_INDICATOR_ADDRESS) & FW_IND_INITIALIZED)) {
            if (num_msi_desired == 0) {
                /* Fix potential race by repeating CORE_BASE writes */
                A_PCI_WRITE32(sc->mem + (SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS),
                      PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL); 
            }
            A_MDELAY(10);
        }

        if (wait_limit < 0) {
            printk(KERN_ERR "ath: %s: TARGET STALLED: .\n", __FUNCTION__);
            A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);
            ret = -EIO;
            goto err_stalled;
        }
        A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);
    }

    if (HIF_PCIDeviceProbed(sc)) {
            printk(KERN_ERR "ath: %s: Target probe failed.\n", __FUNCTION__);
            ret = -EIO;
            goto err_stalled;
    }

    *hif_hdl = sc->hif_device;
     return 0;

err_stalled:
    /* Read Target CPU Intr Cause for debug */
    val = A_PCI_READ32(sc->mem + (SOC_CORE_BASE_ADDRESS | CPU_INTR_ADDRESS));
    printk("ERROR: Target Stalled : Target CPU Intr Cause 0x%x \n", val);
    hif_nointrs(sc);
err_intr:
    if (num_msi_desired) {
        pci_disable_msi(sc->pdev);
    }
    pci_set_drvdata(sc->pdev, NULL);

    return ret;
}

void
hif_pci_remove(struct pci_dev *pdev)
{
    struct hif_pci_softc *sc = pci_get_drvdata(pdev);
    struct ol_softc *scn;
    void __iomem *mem;

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

    mem = (void __iomem *)sc->mem;

    hif_nointrs(sc);
#if CONFIG_PCIE_64BIT_MSI
    OS_FREE_CONSISTENT(scn->sc_osdev, 4, scn->MSI_magic, scn->MSI_magic_dma,
                       OS_GET_DMA_MEM_CONTEXT(scn, MSI_dmacontext));
    scn->MSI_magic = NULL;
    scn->MSI_magic_dma = 0;
#endif
    /* Cancel the pending tasklet */
    tasklet_kill(&sc->intr_tq);

#if defined(CPU_WARM_RESET_WAR)
    /* Currently CPU warm reset sequence is tested only for AR9888_REV2
     * Need to enable for AR9888_REV1 once CPU warm reset sequence is 
     * verified for AR9888_REV1
     */
    if (scn->target_version == AR9888_REV2_VERSION) {
        hif_pci_device_warm_reset(sc);
    }
    else {
        hif_pci_device_reset(sc);
    }
#else
        hif_pci_device_reset(sc);
#endif

    pci_disable_msi(pdev);
    A_FREE(scn);
    A_FREE(sc);
    pci_set_drvdata(pdev, NULL);
    pci_iounmap(pdev, mem);
    pci_release_region(pdev, BAR_NUM);
    pci_clear_master(pdev);
    pci_disable_device(pdev);
    printk(KERN_INFO "pci_remove\n");
}


#define OL_ATH_PCI_PM_CONTROL 0x44

#ifdef WLAN_LINK_UMAC_SUSPEND_WITH_BUS_SUSPEND
void hdd_suspend_wlan(void);
#endif

static int
hif_pci_suspend(struct pci_dev *pdev, pm_message_t state)
{
    struct hif_pci_softc *sc = pci_get_drvdata(pdev);
    void *vos = vos_get_global_context(VOS_MODULE_ID_HIF, NULL);

    u32 val;

#ifdef WLAN_LINK_UMAC_SUSPEND_WITH_BUS_SUSPEND
    hdd_suspend_wlan();
    /* TODO: Wait until tx queue drains. Remove this hard coded delay */
    msleep(3*1000); /* 3 sec */
#endif
    /* Make sure to wake Target before accessing Target memory */
    A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
    while (!hif_pci_targ_is_awake(sc, sc->mem)) {
        ;
    }
    A_PCI_WRITE32(sc->mem + FW_INDICATOR_ADDRESS, (state.event << 16));
    A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);

    /* No need to send WMI_PDEV_SUSPEND_CMDID to FW if WOW is enabled */
    if (!wma_is_wow_enabled(vos_get_context(VOS_MODULE_ID_WDA, vos)) &&
        (state.event == PM_EVENT_FREEZE || state.event == PM_EVENT_SUSPEND)) {
           if (wma_suspend_target(vos_get_context(VOS_MODULE_ID_WDA, vos), 0))
                return (-1);
    }

    pci_read_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, &val);
    if ((val & 0x000000ff) != 0x3) {
        pci_save_state(pdev);
        pci_disable_device(pdev);
        pci_write_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, (val & 0xffffff00) | 0x03);
    }
    return 0;
}

#ifdef WLAN_LINK_UMAC_SUSPEND_WITH_BUS_SUSPEND
void hdd_resume_wlan(void);
#endif

static int
hif_pci_resume(struct pci_dev *pdev)
{
    struct hif_pci_softc *sc = pci_get_drvdata(pdev);
    void *vos_context = vos_get_global_context(VOS_MODULE_ID_HIF, NULL);
    u32 val;
    int err;

    err = pci_enable_device(pdev);
    if (err)
        return err;

    pci_read_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, &val);
    if ((val & 0x000000ff) != 0) {
        pci_restore_state(pdev);
        pci_write_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, val & 0xffffff00);

        /*
         * Suspend/Resume resets the PCI configuration space, so we have to
         * re-disable the RETRY_TIMEOUT register (0x41) to keep
         * PCI Tx retries from interfering with C3 CPU state
         *
         */
        pci_read_config_dword(pdev, 0x40, &val);

        if ((val & 0x0000ff00) != 0)
            pci_write_config_dword(pdev, 0x40, val & 0xffff00ff);
    }

    /* Make sure to wake Target before accessing Target memory */
    A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
    while (!hif_pci_targ_is_awake(sc, sc->mem)) {
        ;
    }
    val = A_PCI_READ32(sc->mem + FW_INDICATOR_ADDRESS) >> 16;
    A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);

    /* No need to send WMI_PDEV_RESUME_CMDID to FW if WOW is enabled */
    if (!wma_is_wow_enabled(vos_get_context(VOS_MODULE_ID_WDA, vos_context)) &&
        (val == PM_EVENT_HIBERNATE || val == PM_EVENT_SUSPEND)) {
	    return wma_resume_target(vos_get_context(VOS_MODULE_ID_WDA, vos_context));
    }

#ifdef WLAN_LINK_UMAC_SUSPEND_WITH_BUS_SUSPEND
    hdd_resume_wlan();
#endif

    return 0;
}

/* routine to modify the initial buffer count to be allocated on an os
 * platform basis. Platform owner will need to modify this as needed
 */
adf_os_size_t initBufferCount(adf_os_size_t maxSize)
{
    return maxSize;
}

MODULE_DEVICE_TABLE(pci, hif_pci_id_table);
struct pci_driver hif_pci_drv_id = {
	.name       = "hif_pci",
	.id_table   = hif_pci_id_table,
	.probe      = hif_pci_probe,
	.remove     = hif_pci_remove,
#ifdef ATH_BUS_PM
	.suspend    = hif_pci_suspend,
	.resume     = hif_pci_resume,
#endif
};

int hif_register_driver(void)
{
	return pci_register_driver(&hif_pci_drv_id);
}

void hif_unregister_driver(void)
{
	pci_unregister_driver(&hif_pci_drv_id);
}

void hif_init_pdev_txrx_handle(void *ol_sc, void *txrx_handle)
{
	struct ol_softc *sc = (struct ol_softc *)ol_sc;
	sc->pdev_txrx_handle = txrx_handle;
}
