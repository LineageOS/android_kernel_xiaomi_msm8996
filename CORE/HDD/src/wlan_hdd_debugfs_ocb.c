/*
 * Copyright (c) 2017 The Linux Foundation. All rights reserved.
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

#ifdef WLAN_OPEN_SOURCE
#include <wlan_hdd_includes.h>
#include <vos_sched.h>
#include "wlan_hdd_debugfs.h"
#include "wlan_hdd_debugfs_ocb.h"
#include "ol_tx.h"

/**
 * __per_pkt_tx_stats_read() - read DSRC per-packet tx stats by DSRC app
 * @file: file pointer
 * @buf: buffer
 * @count: count
 * @pos: position pointer
 *
 * Return: bytes read on success, error number otherwise
 */
static ssize_t __per_pkt_tx_stats_read(struct file *file,
				       char __user *buf,
				       size_t count, loff_t *pos)
{
	hdd_adapter_t *adapter;
	ssize_t ret = 0;
	struct ol_tx_per_pkt_stats tx_stats;
	long rc;

	ENTER();
	adapter = (hdd_adapter_t *)file->private_data;
	if ((NULL == adapter) || (WLAN_HDD_ADAPTER_MAGIC != adapter->magic)) {
		hddLog(LOGE,FL("Invalid adapter or adapter has invalid magic"));
		return -EINVAL;
	}

	ret = wlan_hdd_validate_context(WLAN_HDD_GET_CTX(adapter));
	if (ret)
		return ret;

	ret = ol_tx_stats_ring_deque(&tx_stats);
	if (ret) {
		ret = sizeof(tx_stats);
		rc = copy_to_user(buf, &tx_stats, sizeof(tx_stats));
		if (rc)
			ret = -EFAULT;
	}

	EXIT();
	return ret;
}

static ssize_t per_pkt_tx_stats_read(struct file *file,
				     char __user *buf,
				     size_t count, loff_t *pos)
{
	int ret;

	vos_ssr_protect(__func__);
	ret = __per_pkt_tx_stats_read(file, buf, count, pos);
	vos_ssr_unprotect(__func__);

	return ret;
}

/**
 * __enable_per_pkt_tx_stats() - en/disable DSRC tx stats
 * @enable: 1 for enable, 0 for disable
 *
 * Return: 0 on success, error number otherwise
 */
static int __enable_per_pkt_tx_stats(int enable)
{
	static int __enable = 0;
	int ret = 0;

	if ((__enable && enable) || (!__enable && !enable))
		return ret;

	ol_per_pkt_tx_stats_enable(enable);
	__enable = enable;

	return ret;
}

/**
 * __per_pkt_tx_stats_write() - en/disable DSRC tx stats by DSRC app
 * @file: file pointer
 * @buf: buffer
 * @count: count
 * @ppos: position pointer
 *
 * Return: @count on success, error number otherwise
 */
static ssize_t __per_pkt_tx_stats_write(struct file *file,
					const char __user *buf,
					size_t count, loff_t *pos)
{
	hdd_adapter_t *pAdapter;
	int ret = -EINVAL;
	char *cmd = 0;
	v_U8_t enable = 0;

	ENTER();

	pAdapter = (hdd_adapter_t *)file->private_data;
	if ((NULL == pAdapter) || (WLAN_HDD_ADAPTER_MAGIC != pAdapter->magic)) {
		hddLog(LOGE,FL("Invalid adapter or adapter has invalid magic"));
		return -EINVAL;
	}

	ret = wlan_hdd_validate_context(WLAN_HDD_GET_CTX(pAdapter));
	if (ret)
		return ret;

	/* Get command from user */
	if (count <= MAX_USER_COMMAND_SIZE_FRAME) {
		cmd = vos_mem_malloc(count + 1);
	} else {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Command length is larger than %d bytes.",
			  __func__, MAX_USER_COMMAND_SIZE_FRAME);
		return -EINVAL;
	}

	if (!cmd) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Memory allocation for cmd failed!", __func__);
		return -EFAULT;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		goto failure;
	}
	cmd[count] = '\0';

	if (kstrtou8(cmd, 0, &enable)) {
		ret = -EINVAL;
		goto failure;
	}

	__enable_per_pkt_tx_stats((int)enable);

	vos_mem_free(cmd);
	EXIT();
	return count;

failure:
	vos_mem_free(cmd);
	return ret;
}

static ssize_t per_pkt_tx_stats_write(struct file *file,
				      const char __user *buf,
				      size_t count, loff_t *pos)
{
	ssize_t ret;

	vos_ssr_protect(__func__);
	ret = __per_pkt_tx_stats_write(file, buf, count, pos);
	vos_ssr_unprotect(__func__);

	return ret;
}

static const struct file_operations fops_dsrc_tx_stats = {
	.read = per_pkt_tx_stats_read,
	.write = per_pkt_tx_stats_write,
	.open = wlan_hdd_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

/**
 * wlan_hdd_create_dsrc_tx_stats_file() - API to create dsrc tx stats file
 * @adapter: HDD adapter
 * @hdd_ctx: HDD context
 *
 * Return: 0 on success, -%ENODEV otherwise.
 */
int wlan_hdd_create_dsrc_tx_stats_file(hdd_adapter_t *adapter,
				       hdd_context_t *hdd_ctx)
{
	if (NULL == debugfs_create_file("dsrc_tx_stats",
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
					hdd_ctx->debugfs_phy, adapter,
					&fops_dsrc_tx_stats))
		return -ENODEV;

	return 0;
}
#endif /* WLAN_OPEN_SOURCE */
