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

#include <wlan_hdd_includes.h>
#include <wlan_hdd_spectral.h>
#include <vos_api.h>
#include <linux/relay.h>

#define HDD_SPEC_LOG(LVL, fmt, args...) VOS_TRACE(VOS_MODULE_ID_HDD, LVL, "%s:%d: "fmt, __func__, __LINE__, ## args)

static void dump_fft_sample(fft_sample_t *fft_sample, size_t data_len)
{
	int i;

	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "---dump fft sample---");
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "type: %d", fft_sample->tlv.type);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "length: %d", __be16_to_cpu(fft_sample->tlv.length));

	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "chan_width_mhz: %d", fft_sample->chan_width_mhz);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "freq1: %d", __be16_to_cpu(fft_sample->freq1));
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "freq2: %d", __be16_to_cpu(fft_sample->freq2));
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "noise: %d", __be16_to_cpu(fft_sample->noise));
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "max_magnitude: %d", __be16_to_cpu(fft_sample->max_magnitude));
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "total_gain_db: %d", __be16_to_cpu(fft_sample->total_gain_db));
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "base_pwr_db: %d", __be16_to_cpu(fft_sample->base_pwr_db));
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "tsf: %lld", __be64_to_cpu(fft_sample->tsf));
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "max_index: %d", fft_sample->max_index);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "rssi: %d", fft_sample->rssi);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "relpwr_db: %d", fft_sample->relpwr_db);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "avgpwr_db: %d", fft_sample->avgpwr_db);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "max_magnitude: %d", fft_sample->max_magnitude);

	for(i=0; i<data_len; i++)
		HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "data[%d]: %d", i, fft_sample->data[i]);

	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "***dump fft sample***");
}

static void dump_single_phyerr_rx_hdr(wmi_single_phyerr_rx_hdr *hdr)
{
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "---dump wmi_single_phyerr_rx_hdr---");
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "tsf_timestamp: 0x%x", hdr->tsf_timestamp);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "freq_info_1: 0x%x", hdr->freq_info_1);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "freq_info_2: 0x%x", hdr->freq_info_2);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "rssi_chain0: 0x%x", hdr->rssi_chain0);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "rssi_chain1: 0x%x", hdr->rssi_chain1);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "rssi_chain2: 0x%x", hdr->rssi_chain2);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "rssi_chain3: 0x%x", hdr->rssi_chain3);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "nf_list_1: 0x%x", hdr->nf_list_1);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "nf_list_2: 0x%x", hdr->nf_list_2);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "buf_len: 0x%x", hdr->buf_len);
	HDD_SPEC_LOG(VOS_TRACE_LEVEL_DEBUG, "***dump wmi_single_phyerr_rx_hdr***");
}

static void send_fft_sample(fft_sample_tlv_t *fft_sample_tlv)
{
	v_CONTEXT_t vos_ctx;
	hdd_context_t *hdd_ctx;
	hdd_spectral_t *spec;
	int length;

	vos_ctx = vos_get_global_context(VOS_MODULE_ID_HDD, NULL);
	if (NULL == vos_ctx)
		return;

	hdd_ctx = vos_get_context(VOS_MODULE_ID_HDD, vos_ctx);
	if (NULL == hdd_ctx)
		return;

	spec = hdd_ctx->hdd_spec;
	if (NULL == spec->rfs_chan_spec_scan)
		return;

	length = __be16_to_cpu(fft_sample_tlv->length) + sizeof(*fft_sample_tlv);
	relay_write(spec->rfs_chan_spec_scan, fft_sample_tlv, length);
}


static uint8_t get_max_exp(int8_t max_index, uint16_t max_magnitude, size_t bin_len,
			   uint8_t *data)
{
	int dc_pos;
	uint8_t max_exp;

	dc_pos = bin_len / 2;

	/* peak index outside of bins */
	if (dc_pos < max_index || -dc_pos >= max_index)
		return 0;

	for (max_exp = 0; max_exp < 8; max_exp++) {
		if (data[dc_pos + max_index] == (max_magnitude >> max_exp))
			break;
	}

	/* max_exp not found */
	if (data[dc_pos + max_index] != (max_magnitude >> max_exp))
		return 0;

	return max_exp;
}

static int spectral_process_fft(wmi_single_phyerr_rx_hdr *phyerr,
				const struct phyerr_fft_report *fftr,
				size_t bin_len, uint64_t tsf)
{
	fft_sample_t *fft_sample;
	uint8_t buf[sizeof(*fft_sample) + HDD_SPECTRAL_MAX_NUM_BINS];
	uint16_t freq1, freq2, total_gain_db, base_pwr_db, length, peak_mag;
	uint32_t reg0, reg1;
	uint8_t chain_idx, *bins;
	int dc_pos;
	uint16_t chan_width_mhz;

	dump_single_phyerr_rx_hdr(phyerr);

	fft_sample = (fft_sample_t *)&buf;

	if (bin_len < 64 || bin_len > HDD_SPECTRAL_MAX_NUM_BINS)
		return -EINVAL;

	reg0 = __le32_to_cpu(fftr->reg0);
	reg1 = __le32_to_cpu(fftr->reg1);

	length = sizeof(*fft_sample) - sizeof(fft_sample_tlv_t) + bin_len;
	fft_sample->tlv.type = FFT_SAMPLE;
	fft_sample->tlv.length = __cpu_to_be16(length);

	/* TODO: there might be a reason why the hardware reports 20/40/80 MHz,
	 * but the results/plots suggest that its actually 22/44/88 MHz.
	 */
	chan_width_mhz = WMI_UNIFIED_CHWIDTH_GET(phyerr);
	switch (chan_width_mhz) {
	case 20:
		fft_sample->chan_width_mhz = 22;
		break;
	case 40:
		fft_sample->chan_width_mhz = 44;
		break;
	case 80:
		/* TODO: As experiments with an analogue sender and various
		 * configurations (fft-sizes of 64/128/256 and 20/40/80 Mhz)
		 * show, the particular configuration of 80 MHz/64 bins does
		 * not match with the other samples at all. Until the reason
		 * for that is found, don't report these samples.
		 */
		if (bin_len == 64)
		        return -EINVAL;
		fft_sample->chan_width_mhz = 88;
		break;
	default:
		fft_sample->chan_width_mhz = chan_width_mhz;
	}

	fft_sample->relpwr_db = MS(reg1, SEARCH_FFT_REPORT_REG1_RELPWR_DB);
	fft_sample->avgpwr_db = MS(reg1, SEARCH_FFT_REPORT_REG1_AVGPWR_DB);

	peak_mag = MS(reg1, SEARCH_FFT_REPORT_REG1_PEAK_MAG);
	fft_sample->max_magnitude = __cpu_to_be16(peak_mag);
	fft_sample->max_index = MS(reg0, SEARCH_FFT_REPORT_REG0_PEAK_SIDX);
	fft_sample->rssi = WMI_UNIFIED_RSSI_COMB_GET(phyerr);

	total_gain_db = MS(reg0, SEARCH_FFT_REPORT_REG0_TOTAL_GAIN_DB);
	base_pwr_db = MS(reg0, SEARCH_FFT_REPORT_REG0_BASE_PWR_DB);
	fft_sample->total_gain_db = __cpu_to_be16(total_gain_db);
	fft_sample->base_pwr_db = __cpu_to_be16(base_pwr_db);

	freq1 = WMI_UNIFIED_FREQ_INFO_GET(phyerr, 1);
	freq2 = WMI_UNIFIED_FREQ_INFO_GET(phyerr, 2);
	fft_sample->freq1 = __cpu_to_be16(freq1);
	fft_sample->freq2 = __cpu_to_be16(freq2);

	chain_idx = MS(reg0, SEARCH_FFT_REPORT_REG0_FFT_CHN_IDX);
	switch (chain_idx) {
	case 0:
		fft_sample->noise = __cpu_to_be16(WMI_UNIFIED_NF_CHAIN_GET(phyerr, 0));
		break;
	case 1:
		fft_sample->noise = __cpu_to_be16(WMI_UNIFIED_NF_CHAIN_GET(phyerr, 1));
		break;
	case 2:
		fft_sample->noise = __cpu_to_be16(WMI_UNIFIED_NF_CHAIN_GET(phyerr, 2));
		break;
	case 3:
		fft_sample->noise = __cpu_to_be16(WMI_UNIFIED_NF_CHAIN_GET(phyerr, 3));
		break;
	}

	bins = (uint8_t *)fftr;
	bins += sizeof(*fftr) + 0;

	fft_sample->tsf = __cpu_to_be64(tsf);

	/* max_exp has been directly reported by previous hardware (ath9k),
	 * maybe its possible to get it by other means?
	 */
	fft_sample->max_exp = get_max_exp(fft_sample->max_index, peak_mag,
	                                  bin_len, bins);

	memcpy(fft_sample->data, bins, bin_len);

	/* DC value (value in the middle) is the blind spot of the spectral
	 * sample and invalid, interpolate it.
	 */
	dc_pos = bin_len / 2;
	fft_sample->data[dc_pos] = (fft_sample->data[dc_pos + 1] +
	                            fft_sample->data[dc_pos - 1]) / 2;

	dump_fft_sample(fft_sample, bin_len);
	send_fft_sample(&fft_sample->tlv);

	return 0;
}

void spectral_process_phyerr(wmi_single_phyerr_rx_event *ev, uint64_t fulltsf)
{
	int i = 0, tlv_len;
	struct spectral_phyerr_tlv *tlv;
	void *tlv_buf;
	struct phyerr_fft_report *fftr;
	size_t fftr_len;

	int buf_len = ev->hdr.buf_len;
	uint8_t *buf = &ev->bufp[0];
	while (i < buf_len) {
		if (i + sizeof(*tlv) > buf_len) {
			HDD_SPEC_LOG(VOS_TRACE_LEVEL_ERROR,
				     "failed to parse phyerr tlv header at byte %d", i);
			return;
		}

		tlv = (struct spectral_phyerr_tlv *)&buf[i];
		tlv_len = tlv->len;
		tlv_buf = &buf[i + sizeof(*tlv)];

		if (i + sizeof(*tlv) + tlv_len > buf_len) {
			HDD_SPEC_LOG(VOS_TRACE_LEVEL_ERROR,
				     "failed to parse phyerr tlv payload at byte %d", i);
			return;
		}

		switch (tlv->tag) {
			case PHYERR_TLV_TAG_SEARCH_FFT_REPORT:

			if (sizeof(*fftr) > tlv_len) {
				HDD_SPEC_LOG(VOS_TRACE_LEVEL_ERROR,
					     "failed to parse fft report at byte %d", i);
			        return;
			}

			fftr_len = tlv_len - sizeof(*fftr);
			fftr = tlv_buf;

			spectral_process_fft(&ev->hdr, fftr, fftr_len, fulltsf);

			break;
		}

		i += sizeof(*tlv) + tlv_len;
	}
}

static hdd_adapter_t *get_spectral_adapter(hdd_context_t *hdd_ctx)
{
	hdd_adapter_list_node_t *adapter_node = NULL, *next_node = NULL;
	hdd_adapter_t *adapter;
	VOS_STATUS status;

	/* if there already is a adapter doing spectral, return that. */
	status = hdd_get_front_adapter(hdd_ctx, &adapter_node);
	while ((NULL != adapter_node) && (VOS_STATUS_SUCCESS == status)) {
		adapter = adapter_node->pAdapter;
		if (adapter->spectral_enabled)
			return adapter;

		status = hdd_get_next_adapter(hdd_ctx, adapter_node, &next_node);
	        adapter_node = next_node;
	}

	/* otherwise, return the first adapter. */
	return hdd_get_adapter_by_vdev(hdd_ctx, 0);
}

static int hdd_spectral_scan_enable_req(hdd_context_t *hdd_ctx, uint32_t vdev_id,
					uint32_t trigger_cmd, uint32_t enable_cmd)
{
	sir_spectral_enable_params_t params;
	eHalStatus status;

	params.vdev_id = vdev_id;
	params.trigger_cmd = trigger_cmd;
	params.enable_cmd = enable_cmd;

	status = sme_spectral_scan_enable(hdd_ctx->hHal, &params);
	if (!HAL_STATUS_SUCCESS(status)) {
		return -EINVAL;
	}

	return 0;
}

static int hdd_spectral_scan_config_req(hdd_context_t *hdd_ctx, uint32_t vdev_id,
					uint32_t scan_count, uint32_t scan_fft_size)
{
	sir_spectral_config_params_t params;
	eHalStatus status;

	params.vdev_id = vdev_id;
	params.spectral_scan_count = scan_count;
	params.spectral_scan_period = HDD_SPECTRAL_PERIOD_DEFAULT;
	params.spectral_scan_priority = HDD_SPECTRAL_PRIORITY_DEFAULT;
	params.spectral_scan_fft_size = scan_fft_size;
	params.spectral_scan_gc_ena = HDD_SPECTRAL_GC_ENA_DEFAULT;
	params.spectral_scan_restart_ena = HDD_SPECTRAL_RESTART_ENA_DEFAULT;
	params.spectral_scan_noise_floor_ref = HDD_SPECTRAL_NOISE_FLOOR_REF_DEFAULT;
	params.spectral_scan_init_delay = HDD_SPECTRAL_INIT_DELAY_DEFAULT;
	params.spectral_scan_nb_tone_thr = HDD_SPECTRAL_NB_TONE_THR_DEFAULT;
	params.spectral_scan_str_bin_thr = HDD_SPECTRAL_STR_BIN_THR_DEFAULT;
	params.spectral_scan_wb_rpt_mode = HDD_SPECTRAL_WB_RPT_MODE_DEFAULT;
	params.spectral_scan_rssi_rpt_mode = HDD_SPECTRAL_RSSI_RPT_MODE_DEFAULT;
	params.spectral_scan_rssi_thr = HDD_SPECTRAL_RSSI_THR_DEFAULT;
	params.spectral_scan_pwr_format = HDD_SPECTRAL_PWR_FORMAT_DEFAULT;
	params.spectral_scan_rpt_mode = HDD_SPECTRAL_RPT_MODE_DEFAULT;
	params.spectral_scan_bin_scale = HDD_SPECTRAL_BIN_SCALE_DEFAULT;
	params.spectral_scan_dbm_adj = HDD_SPECTRAL_DBM_ADJ_DEFAULT;
	params.spectral_scan_chn_mask = HDD_SPECTRAL_CHN_MASK_DEFAULT;

	status = sme_spectral_scan_config(hdd_ctx->hHal, &params);
        if (!HAL_STATUS_SUCCESS(status)) {
                return -EINVAL;
        }

	return 0;
}

static int hdd_spectral_scan_trigger(hdd_context_t *hdd_ctx)
{
	hdd_adapter_t *adapter;
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;
	int res;
	int vdev_id;

	adapter = get_spectral_adapter(hdd_ctx);
	if (!adapter)
		return -ENODEV;
	vdev_id = adapter->sessionId;

	if (spec->mode == HDD_SPECTRAL_DISABLED)
		return 0;

	res = hdd_spectral_scan_enable_req(hdd_ctx, vdev_id,
					   HDD_SPECTRAL_TRIGGER_CMD_CLEAR,
					   HDD_SPECTRAL_ENABLE_CMD_ENABLE);
	if (res < 0)
		return res;

	res = hdd_spectral_scan_enable_req(hdd_ctx, vdev_id,
					   HDD_SPECTRAL_TRIGGER_CMD_TRIGGER,
					   HDD_SPECTRAL_ENABLE_CMD_ENABLE);
	if (res < 0)
		return res;

	return 0;
}

static int hdd_spectral_scan_config(hdd_context_t *hdd_ctx,
				    enum spectral_mode mode)
{
	hdd_adapter_t *adapter;
        hdd_spectral_t *spec = hdd_ctx->hdd_spec;
	int vdev_id, count, res = 0;

	adapter = get_spectral_adapter(hdd_ctx);
        if (!adapter)
		return -ENODEV;

	vdev_id = adapter->sessionId;

	adapter->spectral_enabled = (mode != HDD_SPECTRAL_DISABLED);
	spec->mode = mode;

	res = hdd_spectral_scan_enable_req(hdd_ctx, vdev_id,
					   HDD_SPECTRAL_TRIGGER_CMD_CLEAR,
					   HDD_SPECTRAL_ENABLE_CMD_DISABLE);
	if (res < 0) {
		hddLog(LOGE, "failed to enable spectral scan: %d\n", res);
		return res;
	}

	if (mode == HDD_SPECTRAL_DISABLED)
		return 0;

	if (mode == HDD_SPECTRAL_BACKGROUND)
		count = HDD_SPECTRAL_COUNT_DEFAULT;
	else
		count = max_t(u8, 1, spec->config.count);

	res = hdd_spectral_scan_config_req(hdd_ctx, vdev_id,
					   count, spec->config.fft_size);
	if (res < 0) {
		hddLog(LOGE, "failed to configure spectral scan: %d\n", res);
		return res;
	}

	return 0;
}

static ssize_t read_file_spec_scan_ctl(struct file *file, char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	hdd_context_t *hdd_ctx = file->private_data;
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;
	char *mode = "";
	size_t len;
	enum spectral_mode spec_mode;

	spec_mode = spec->mode;

	switch (spec_mode) {
	case HDD_SPECTRAL_DISABLED:
		mode = "disable";
		break;
	case HDD_SPECTRAL_BACKGROUND:
		mode = "background";
		break;
	case HDD_SPECTRAL_MANUAL:
		mode = "manual";
		break;
	}

	len = strlen(mode);
	return simple_read_from_buffer(user_buf, count, ppos, mode, len);
}

static ssize_t write_file_spec_scan_ctl(struct file *file,
					const char __user *user_buf,
					size_t count, loff_t *ppos)
{
	hdd_context_t *hdd_ctx = file->private_data;
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;
	char buf[32];
	ssize_t len;
	int res;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';

	if (strncmp("trigger", buf, 7) == 0) {
		if (spec->mode == HDD_SPECTRAL_MANUAL ||
		    spec->mode == HDD_SPECTRAL_BACKGROUND) {
			/* reset the configuration to adopt possibly changed
			 * debugfs parameters
			 */
			res = hdd_spectral_scan_config(hdd_ctx, spec->mode);
			if (res < 0) {
				hddLog(LOGW, "failed to reconfigure spectral scan: %d\n",
				       res);
			}
			res = hdd_spectral_scan_trigger(hdd_ctx);
			if (res < 0) {
				hddLog(LOGW, "failed to trigger spectral scan: %d\n",
				       res);
			}
		} else {
			res = -EINVAL;
		}
	} else if (strncmp("background", buf, 10) == 0) {
		res = hdd_spectral_scan_config(hdd_ctx, HDD_SPECTRAL_BACKGROUND);
	} else if (strncmp("manual", buf, 6) == 0) {
		res = hdd_spectral_scan_config(hdd_ctx, HDD_SPECTRAL_MANUAL);
	} else if (strncmp("disable", buf, 7) == 0) {
		res = hdd_spectral_scan_config(hdd_ctx, HDD_SPECTRAL_DISABLED);
	} else {
		res = -EINVAL;
	}

	if (res < 0)
		return res;

	return count;
}

static const struct file_operations fops_spec_scan_ctl = {
	.read = read_file_spec_scan_ctl,
	.write = write_file_spec_scan_ctl,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_spectral_count(struct file *file,
					char __user *user_buf,
					size_t count, loff_t *ppos)
{
	hdd_context_t *hdd_ctx = file->private_data;
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;
	char buf[32];
	size_t len;
	u8 spectral_count;

	spectral_count = spec->config.count;

	len = snprintf(buf, 32, "%d\n", spectral_count);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t write_file_spectral_count(struct file *file,
					 const char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	hdd_context_t *hdd_ctx = file->private_data;
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;
	unsigned long val;
	char buf[32];
	ssize_t len;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtoul(buf, 0, &val))
		return -EINVAL;

	if (val > 255)
		return -EINVAL;

	spec->config.count = val;

	return count;
}

static const struct file_operations fops_spectral_count = {
	.read = read_file_spectral_count,
	.write = write_file_spectral_count,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_spectral_bins(struct file *file,
				       char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	hdd_context_t *hdd_ctx = file->private_data;
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;
	char buf[32];
	unsigned int bins, fft_size, bin_scale;
	size_t len;

	fft_size = spec->config.fft_size;
	bin_scale = HDD_SPECTRAL_BIN_SCALE_DEFAULT;
	bins = 1 << (fft_size - bin_scale);

	len = snprintf(buf, 32, "%d\n", bins);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t write_file_spectral_bins(struct file *file,
					const char __user *user_buf,
					size_t count, loff_t *ppos)
{
	hdd_context_t *hdd_ctx  = file->private_data;
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;
	unsigned long val;
	char buf[32];
	ssize_t len;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtoul(buf, 0, &val))
		return -EINVAL;

	if (val < 64 || val > HDD_SPECTRAL_MAX_NUM_BINS)
		return -EINVAL;

	if (!is_power_of_2(val))
		return -EINVAL;

	spec->config.fft_size = ilog2(val);
	spec->config.fft_size += HDD_SPECTRAL_BIN_SCALE_DEFAULT;

	return count;
}

static const struct file_operations fops_spectral_bins = {
	.read = read_file_spectral_bins,
	.write = write_file_spectral_bins,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static struct dentry *create_buf_file_handler(const char *filename,
					      struct dentry *parent,
					      umode_t mode,
					      struct rchan_buf *buf,
					      int *is_global)
{
	struct dentry *buf_file;

	buf_file = debugfs_create_file(filename, mode, parent, buf,
				       &relay_file_operations);
	*is_global = 1;
	return buf_file;
}

static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);

	return 0;
}

static struct rchan_callbacks rfs_spec_scan_cb = {
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
};

VOS_STATUS hdd_spectral_debugfs_init(hdd_context_t *hdd_ctx)
{
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;

	spec->debugfs_dir =
		debugfs_create_dir("spectral", hdd_ctx->wiphy->debugfsdir);
	if (NULL == spec->debugfs_dir)
		return VOS_STATUS_E_FAILURE;

	if (NULL == debugfs_create_file("spectral_scan_ctl",
					S_IRUSR | S_IWUSR,
					spec->debugfs_dir, hdd_ctx,
					&fops_spec_scan_ctl))
		return VOS_STATUS_E_FAILURE;

	if (NULL == debugfs_create_file("spectral_count",
					S_IRUSR | S_IWUSR,
					spec->debugfs_dir, hdd_ctx,
					&fops_spectral_count))
		return VOS_STATUS_E_FAILURE;

	if (NULL == debugfs_create_file("spectral_bins",
					S_IRUSR | S_IWUSR,
					spec->debugfs_dir, hdd_ctx,
					&fops_spectral_bins))
		return VOS_STATUS_E_FAILURE;

	spec->rfs_chan_spec_scan = relay_open("spectral_scan",
					      spec->debugfs_dir,
					      1140, 2500,
					      &rfs_spec_scan_cb, NULL);
	if (NULL == spec->rfs_chan_spec_scan)
		return VOS_STATUS_E_FAILURE;

	return VOS_STATUS_SUCCESS;
}

VOS_STATUS hdd_spectral_debugfs_deinit(hdd_context_t *hdd_ctx)
{
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;

	if (spec->rfs_chan_spec_scan) {
		relay_close(spec->rfs_chan_spec_scan);
		spec->rfs_chan_spec_scan = NULL;
	}
	if (spec->debugfs_dir) {
		debugfs_remove_recursive(spec->debugfs_dir);
		spec->debugfs_dir = NULL;
	}

	return VOS_STATUS_SUCCESS;
}

VOS_STATUS hdd_spectral_setting_init(hdd_context_t *hdd_ctx)
{
	hdd_spectral_t *spec = hdd_ctx->hdd_spec;

	spec->mode = HDD_SPECTRAL_DISABLED;
	spec->config.count = HDD_SPECTRAL_COUNT_DEFAULT;
	spec->config.fft_size = HDD_SPECTRAL_FFT_SIZE_DEFAULT;

	return VOS_STATUS_SUCCESS;
}

VOS_STATUS hdd_spectral_init(hdd_context_t *hdd_ctx)
{
	hdd_ctx->hdd_spec = vos_mem_malloc(sizeof(*hdd_ctx->hdd_spec));
	if (NULL == hdd_ctx->hdd_spec)
		return VOS_STATUS_E_FAILURE;
	vos_mem_zero(hdd_ctx->hdd_spec, sizeof(*hdd_ctx->hdd_spec));

	if (VOS_STATUS_SUCCESS != hdd_spectral_debugfs_init(hdd_ctx))
		return VOS_STATUS_E_FAILURE;

	if (VOS_STATUS_SUCCESS != hdd_spectral_setting_init(hdd_ctx))
		return VOS_STATUS_E_FAILURE;

	return VOS_STATUS_SUCCESS;
}

VOS_STATUS hdd_spectral_deinit(hdd_context_t *hdd_ctx)
{

	hdd_spectral_debugfs_deinit(hdd_ctx);

	if (hdd_ctx->hdd_spec) {
		vos_mem_free(hdd_ctx->hdd_spec);
		hdd_ctx->hdd_spec = NULL;
	}

	return VOS_STATUS_SUCCESS;
}
