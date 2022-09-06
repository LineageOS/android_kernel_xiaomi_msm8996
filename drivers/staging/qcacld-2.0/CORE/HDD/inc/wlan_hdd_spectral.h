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

#ifndef WLAN_HDD_SPECTRAL_H
#define WLAN_HDD_SPECTRAL_H

#include <wmi_unified.h>

/* enum spectral_mode:
 *
 * @SPECTRAL_DISABLED: spectral mode is disabled
 * @SPECTRAL_BACKGROUND: hardware sends samples when it is not busy with
 *	something else.
 * @SPECTRAL_MANUAL: spectral scan is enabled, triggering for samples
 *	is performed manually.
 */
enum spectral_mode {
	HDD_SPECTRAL_DISABLED = 0,
	HDD_SPECTRAL_BACKGROUND,
	HDD_SPECTRAL_MANUAL,
};

#define HDD_SPECTRAL_TRIGGER_CMD_TRIGGER	1
#define HDD_SPECTRAL_TRIGGER_CMD_CLEAR		2
#define HDD_SPECTRAL_ENABLE_CMD_ENABLE		1
#define HDD_SPECTRAL_ENABLE_CMD_DISABLE		2

#define HDD_SPECTRAL_ENABLE_DEFAULT		0
#define HDD_SPECTRAL_COUNT_DEFAULT		0
#define HDD_SPECTRAL_PERIOD_DEFAULT		35
#define HDD_SPECTRAL_PRIORITY_DEFAULT		1
#define HDD_SPECTRAL_FFT_SIZE_DEFAULT		7
#define HDD_SPECTRAL_GC_ENA_DEFAULT		1
#define HDD_SPECTRAL_RESTART_ENA_DEFAULT	0
#define HDD_SPECTRAL_NOISE_FLOOR_REF_DEFAULT	-96
#define HDD_SPECTRAL_INIT_DELAY_DEFAULT		80
#define HDD_SPECTRAL_NB_TONE_THR_DEFAULT	12
#define HDD_SPECTRAL_STR_BIN_THR_DEFAULT	8
#define HDD_SPECTRAL_WB_RPT_MODE_DEFAULT	0
#define HDD_SPECTRAL_RSSI_RPT_MODE_DEFAULT	0
#define HDD_SPECTRAL_RSSI_THR_DEFAULT		0xf0
#define HDD_SPECTRAL_PWR_FORMAT_DEFAULT		0
#define HDD_SPECTRAL_RPT_MODE_DEFAULT		2
#define HDD_SPECTRAL_BIN_SCALE_DEFAULT		1
#define HDD_SPECTRAL_DBM_ADJ_DEFAULT		1
#define HDD_SPECTRAL_CHN_MASK_DEFAULT		1

#define HDD_SPECTRAL_MAX_NUM_BINS		256

typedef struct fft_sample_tlv {
	uint8_t type;
	uint16_t length;
} __packed fft_sample_tlv_t;

typedef struct fft_sample {
	struct fft_sample_tlv tlv;
	uint8_t chan_width_mhz;
	uint16_t freq1;
	uint16_t freq2;
	uint16_t noise;
	uint16_t max_magnitude;
	uint16_t total_gain_db;
	uint16_t base_pwr_db;
	uint64_t tsf;
	int8_t max_index;
	uint8_t rssi;
	uint8_t relpwr_db;
	uint8_t avgpwr_db;
	uint8_t max_exp;
	uint8_t data[0];
} __packed fft_sample_t;

#define SEARCH_FFT_REPORT_REG0_TOTAL_GAIN_DB_MASK	0xFF800000
#define SEARCH_FFT_REPORT_REG0_TOTAL_GAIN_DB_LSB	23

#define SEARCH_FFT_REPORT_REG0_BASE_PWR_DB_MASK		0x007FC000
#define SEARCH_FFT_REPORT_REG0_BASE_PWR_DB_LSB		14

#define SEARCH_FFT_REPORT_REG0_FFT_CHN_IDX_MASK		0x00003000
#define SEARCH_FFT_REPORT_REG0_FFT_CHN_IDX_LSB		12

#define SEARCH_FFT_REPORT_REG0_PEAK_SIDX_MASK		0x00000FFF
#define SEARCH_FFT_REPORT_REG0_PEAK_SIDX_LSB		0

#define SEARCH_FFT_REPORT_REG1_RELPWR_DB_MASK		0xFC000000
#define SEARCH_FFT_REPORT_REG1_RELPWR_DB_LSB		26

#define SEARCH_FFT_REPORT_REG1_AVGPWR_DB_MASK		0x03FC0000
#define SEARCH_FFT_REPORT_REG1_AVGPWR_DB_LSB		18

#define SEARCH_FFT_REPORT_REG1_PEAK_MAG_MASK		0x0003FF00
#define SEARCH_FFT_REPORT_REG1_PEAK_MAG_LSB		8

#define SEARCH_FFT_REPORT_REG1_NUM_STR_BINS_IB_MASK	0x000000FF
#define SEARCH_FFT_REPORT_REG1_NUM_STR_BINS_IB_LSB	0

#define PHYERR_TLV_SIG                          0xBB
#define PHYERR_TLV_TAG_SEARCH_FFT_REPORT        0xFB
#define PHYERR_TLV_TAG_RADAR_PULSE_SUMMARY      0xF8
#define PHYERR_TLV_TAG_SPECTRAL_SUMMARY_REPORT  0xF9

struct spectral_phyerr_tlv {
	uint16_t len;
	uint8_t  tag;
	uint8_t  sig;
};

struct phyerr_fft_report {
	uint32_t reg0; /* SEARCH_FFT_REPORT_REG0_ * */
	uint32_t reg1; /* SEARCH_FFT_REPORT_REG1_ * */
};

enum fft_sample_type {
	FFT_SAMPLE_HT20 = 1,
	FFT_SAMPLE_HT20_40,
	FFT_SAMPLE,
};

void spectral_process_phyerr(wmi_single_phyerr_rx_event *ev, uint64_t fulltsf);

VOS_STATUS hdd_spectral_init(hdd_context_t *hdd_ctx);

VOS_STATUS hdd_spectral_deinit(hdd_context_t *hdd_ctx);

#endif
