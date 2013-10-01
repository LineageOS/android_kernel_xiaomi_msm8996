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

#if defined(CONFIG_ATH_PROCFS_DIAG_SUPPORT)
#include <linux/module.h>	/* Specifically, a module */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/version.h>	/* We're doing kernel work */
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <asm/uaccess.h>	/* for copy_from_user */
#include "if_pci.h"
#include "vos_api.h"

#define PROCFS_NAME		"athdiagpfs"
#define PROCFS_DIR		"cld"

/**
 * This structure hold information about the /proc file
 *
 */
static struct proc_dir_entry *proc_file, *proc_dir;

static ssize_t
ath_procfs_diag_read(char *buffer, char **buffer_location,
			off_t offset, int count,
			int *eof, void *data)
{
	struct hif_pci_softc *scn = (struct hif_pci_softc *)data;
	int rv;
	A_UINT8 *read_buffer = NULL;

	read_buffer = (A_UINT8 *)vos_mem_malloc(count);
	if (NULL == read_buffer) {
		pr_debug("%s: vos_mem_alloc failed\n", __func__);
		return -EINVAL;
	}

	pr_debug("rd buff 0x%p cnt %d off 0x%x data %p\n",
			read_buffer,count,
			(int)offset, data);
	if ((count == 4) && (((A_UINT32)offset & 3) == 0)) {
		/* reading a word? */
		rv = HIFDiagReadAccess(scn->ol_sc->hif_hdl,
				(A_UINT32)offset,
				(A_UINT32 *)read_buffer);
	} else {
		rv = HIFDiagReadMem(scn->ol_sc->hif_hdl,
				(A_UINT32)offset,
				(A_UINT8 *)read_buffer,
				count);
	}

	if(copy_to_user(buffer, read_buffer, count)) {
		vos_mem_free(read_buffer);
		return -EFAULT;
	} else
		vos_mem_free(read_buffer);

	if (rv == 0) {
		return count;
	} else {
		return -EIO;
	}
}

static int
ath_procfs_diag_write(struct file *file, const char *buffer,
			unsigned long count, void *data)
{
	struct hif_pci_softc *scn = (struct hif_pci_softc *)data;
	int rv;
	A_UINT32 *addbuff = (A_UINT32 *)buffer;
	A_UINT32 addr = *addbuff;
	A_UINT8 *write_buffer = NULL, *fbuf = NULL;

	write_buffer = (A_UINT8 *)vos_mem_malloc(count);
	if (NULL == write_buffer) {
		pr_debug("%s: vos_mem_alloc failed\n", __func__);
		return -EINVAL;
	}
	if(copy_from_user(write_buffer, buffer, count))
		return -EFAULT;
	fbuf = write_buffer;

	write_buffer += sizeof(A_UINT32);
	count -= sizeof(A_UINT32);
	pr_debug("wr buff 0x%p addr 0x%x len %lu data %p\n",
			write_buffer, addr, count, data);

	if ((count == 4) && ((addr & 3) == 0)) {
		/*reading a word?*/
		A_UINT32 value = *((A_UINT32 *)write_buffer);
		rv = HIFDiagWriteAccess(scn->ol_sc->hif_hdl,
					(A_UINT32)(*addbuff), value);
	} else {
		rv = HIFDiagWriteMem(scn->ol_sc->hif_hdl,
					(A_UINT32)(*addbuff),
					(A_UINT8 *)write_buffer, count);
	}

	vos_mem_free(fbuf);
	if (rv == 0) {
		return count;
	} else {
		return -EIO;
	}
}

/**
 *This function is called when the module is loaded
 *
 */
int athdiag_procfs_init(struct hif_pci_softc *scn)
{
	proc_dir = proc_mkdir(PROCFS_DIR, NULL);
	if (proc_dir == NULL) {
		remove_proc_entry(PROCFS_DIR, NULL);
		pr_debug("Error: Could not initialize /proc/%s\n",
				PROCFS_DIR);
		return -ENOMEM;
	}

	/* create the /proc file */
	proc_file = create_proc_entry(PROCFS_NAME, 0666, proc_dir);
	if (proc_file == NULL) {
		remove_proc_entry(PROCFS_NAME, proc_dir);
		pr_debug("Error: Could not initialize /proc/%s\n",
				PROCFS_NAME);
		return -ENOMEM;
	}

	proc_file->read_proc  = ath_procfs_diag_read;
	proc_file->write_proc = ath_procfs_diag_write;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
	proc_file->owner	= THIS_MODULE;
#endif
	proc_file->mode		= S_IFREG | S_IRUGO;
	proc_file->uid		= 0;
	proc_file->gid		= 0;
	proc_file->size		= 37;
	proc_file->data		= (void *)scn;

	pr_debug("/proc/%s/%s created\n", PROCFS_DIR, PROCFS_NAME);
	return 0;	/* everything is ok */
}

/**
 *This function is called when the module is unloaded
 *
 */
void athdiag_procfs_remove()
{
	remove_proc_entry(PROCFS_NAME, proc_dir);
	pr_debug("/proc/%s/%s removed\n", PROCFS_DIR, PROCFS_NAME);
	remove_proc_entry(PROCFS_DIR, NULL);
	pr_debug("/proc/%s removed\n", PROCFS_DIR);
}
#endif
