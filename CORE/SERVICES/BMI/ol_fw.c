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

#include <linux/firmware.h>
#include "ol_if_athvar.h"
#include "ol_fw.h"
#include "targaddrs.h"
#include "bmi.h"
#include "ol_cfg.h"
#include "vos_api.h"
#include "wma_api.h"
#include "wma.h"
#if defined(HIF_PCI)
#include "if_pci.h"
#elif defined(HIF_USB)
#include "if_usb.h"
#else
#include "if_ath_sdio.h"
#include "regtable.h"
#endif


#define ATH_MODULE_NAME bmi
#include "a_debug.h"
#include "fw_one_bin.h"
#include "bin_sig.h"
#include "ar6320v2_dbg_regtable.h"

#if defined(QCA_WIFI_2_0) && !defined(QCA_WIFI_ISOC) && defined(CONFIG_CNSS)
#include <net/cnss.h>
#endif

#ifdef HIF_PCI
static u_int32_t refclk_speed_to_hz[] = {
	48000000, /* SOC_REFCLK_48_MHZ */
	19200000, /* SOC_REFCLK_19_2_MHZ */
	24000000, /* SOC_REFCLK_24_MHZ */
	26000000, /* SOC_REFCLK_26_MHZ */
	37400000, /* SOC_REFCLK_37_4_MHZ */
	38400000, /* SOC_REFCLK_38_4_MHZ */
	40000000, /* SOC_REFCLK_40_MHZ */
	52000000, /* SOC_REFCLK_52_MHZ */
};
#endif

#ifdef HIF_SDIO
static struct ol_fw_files FW_FILES_QCA6174_FW_1_1 = {
"qwlan11.bin", "bdwlan11.bin", "otp11.bin", "utf11.bin", "utfbd11.bin"};
static struct ol_fw_files FW_FILES_QCA6174_FW_2_0 = {
"qwlan20.bin", "bdwlan20.bin", "otp20.bin", "utf20.bin", "utfbd20.bin"};
static struct ol_fw_files FW_FILES_QCA6174_FW_1_3 = {
"qwlan13.bin", "bdwlan13.bin", "otp13.bin", "utf13.bin", "utfbd13.bin"};
static struct ol_fw_files FW_FILES_QCA6174_FW_3_0 = {
"qwlan30.bin", "bdwlan30.bin", "otp30.bin", "utf30.bin", "utfbd30.bin"};
static struct ol_fw_files FW_FILES_DEFAULT = {
"qwlan.bin", "bdwlan.bin", "otp.bin", "utf.bin", "utfbd.bin"};

static A_STATUS ol_sdio_extra_initialization(struct ol_softc *scn);

static int ol_get_fw_files_for_target(struct ol_fw_files *pfw_files,
                                 u32 target_version)
{
    if (!pfw_files)
        return -ENODEV;

    switch (target_version) {
    case AR6320_REV1_VERSION:
    case AR6320_REV1_1_VERSION:
            memcpy(pfw_files, &FW_FILES_QCA6174_FW_1_1, sizeof(*pfw_files));
            break;
    case AR6320_REV1_3_VERSION:
            memcpy(pfw_files, &FW_FILES_QCA6174_FW_1_3, sizeof(*pfw_files));
            break;
    case AR6320_REV2_1_VERSION:
            memcpy(pfw_files, &FW_FILES_QCA6174_FW_2_0, sizeof(*pfw_files));
            break;
    case AR6320_REV3_VERSION:
            memcpy(pfw_files, &FW_FILES_QCA6174_FW_3_0, sizeof(*pfw_files));
            break;
    default:
            memcpy(pfw_files, &FW_FILES_DEFAULT, sizeof(*pfw_files));
            pr_err("%s version mismatch 0x%X ",
                            __func__, target_version);
            break;
    }
    return 0;
}
#endif

extern int
dbglog_parse_debug_logs(ol_scn_t scn, u_int8_t *datap, u_int32_t len);

static int ol_transfer_single_bin_file(struct ol_softc *scn,
				       u_int32_t address,
				       bool compressed)
{
	int status = EOK;
	const char *filename = AR61X4_SINGLE_FILE;
	const struct firmware *fw_entry;
	u_int32_t fw_entry_size;
	u_int8_t *temp_eeprom = NULL;
	FW_ONE_BIN_META_T *one_bin_meta_header = NULL;
	FW_BIN_HEADER_T *one_bin_header = NULL;
	SIGN_HEADER_T *sign_header = NULL;
	unsigned char *fw_entry_data = NULL;
	u_int32_t groupid = WLAN_GROUP_ID;
	u_int32_t binary_offset = 0;
	u_int32_t binary_len = 0;
	u_int32_t next_tag_offset = 0;
	u_int32_t param = 0;
	bool meta_header = FALSE;
	bool fw_sign = FALSE;
	bool is_group = FALSE;

#ifdef QCA_WIFI_FTM
	if (vos_get_conparam() == VOS_FTM_MODE)
		groupid = UTF_GROUP_ID;
#endif

	if (groupid == WLAN_GROUP_ID) {
		AR_DEBUG_PRINTF(ATH_DEBUG_TRC,
				("%s: Downloading mission mode firmware\n",
				 __func__));
	}
	else {
		AR_DEBUG_PRINTF(ATH_DEBUG_TRC,
				("%s: Downloading test mode firmware\n",
				__func__));
	}

	if (request_firmware(&fw_entry, filename, scn->sc_osdev->device) != 0)
	{
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("%s: Failed to get %s\n",
				__func__, filename));
		return -ENOENT;
	}

	fw_entry_size = fw_entry->size;
	fw_entry_data = (unsigned char *)fw_entry->data;
	binary_len = fw_entry_size;

	temp_eeprom = OS_MALLOC(scn->sc_osdev, fw_entry_size, GFP_ATOMIC);
	if (!temp_eeprom) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("%s: Memory allocation failed\n",
				__func__));
		release_firmware(fw_entry);
		return A_ERROR;
	}

	OS_MEMCPY(temp_eeprom, (u_int8_t *)fw_entry->data, fw_entry_size);

	is_group = FALSE;
	do {
		if (!meta_header) {
			if (fw_entry_size <= sizeof(FW_ONE_BIN_META_T)
			    + sizeof(FW_BIN_HEADER_T))
			{
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
						("%s: file size error!\n",
						__func__));
				status = A_ERROR;
				goto exit;
			}

			one_bin_meta_header = (FW_ONE_BIN_META_T*)fw_entry_data;
			if (one_bin_meta_header->magic_num != ONE_BIN_MAGIC_NUM)
			{
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("%s: one binary magic num err: %d\n",
					__func__,
					one_bin_meta_header->magic_num));
				status = A_ERROR;
				goto exit;
			}
			if (one_bin_meta_header->fst_tag_off
			    + sizeof(FW_BIN_HEADER_T) >= fw_entry_size)
			{
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("%s: one binary first tag offset error: %d\n",
					__func__, one_bin_meta_header->fst_tag_off));
				status = A_ERROR;
				goto exit;
			}

			one_bin_header = (FW_BIN_HEADER_T *)(
					 (u_int8_t *)fw_entry_data
					 + one_bin_meta_header->fst_tag_off);

                        while (one_bin_header->bin_group_id != groupid)
                        {
				if (one_bin_header->next_tag_off
				    + sizeof(FW_BIN_HEADER_T) > fw_entry_size)
				{
					AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
						("%s: tag offset is error: bin id: %d, bin len: %d, tag offset: %d \n",
						__func__, one_bin_header->binary_id,
						one_bin_header->binary_len,
						one_bin_header->next_tag_off));
					status = A_ERROR;
					goto exit;
				}

				one_bin_header = (FW_BIN_HEADER_T *)(
						(u_int8_t *)fw_entry_data
						+ one_bin_header->next_tag_off);
			}

			meta_header = TRUE;
		}

		binary_offset = one_bin_header->binary_off;
		binary_len = one_bin_header->binary_len;
		next_tag_offset = one_bin_header->next_tag_off;

		if (one_bin_header->action & ACTION_PARSE_SIG)
			fw_sign = TRUE;
		else
			fw_sign = FALSE;

		if (fw_sign)
		{
			if (binary_len < sizeof(SIGN_HEADER_T))
			{
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("%s: sign header size is error: bin id: %d, bin len: %d, sign header size: %zu \n",
					__func__, one_bin_header->binary_id,
					one_bin_header->binary_len,
					sizeof(SIGN_HEADER_T)));
				status = A_ERROR;
				goto exit;
			}
			sign_header = (SIGN_HEADER_T *)((u_int8_t *)fw_entry_data
					+ binary_offset);

			status = BMISignStreamStart(scn->hif_hdl, address,
						    (u_int8_t *)fw_entry_data
						    + binary_offset,
						    sizeof(SIGN_HEADER_T), scn);
			if (status != EOK)
			{
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("%s: unable to start sign stream\n",
					__func__));
				status = A_ERROR;
				goto exit;
			}

			binary_offset += sizeof(SIGN_HEADER_T);
			binary_len = sign_header->rampatch_len
				     - sizeof(SIGN_HEADER_T);
		}

		if (compressed)
			status = BMIFastDownload(scn->hif_hdl, address,
						 (u_int8_t *)fw_entry_data
						 + binary_offset,
						 binary_len, scn);
		else
			status = BMIWriteMemory(scn->hif_hdl, address,
						(u_int8_t *)fw_entry_data
						+ binary_offset,
						binary_len, scn);

		if (fw_sign)
		{
			binary_offset += binary_len;
			binary_len = sign_header->total_len
				     - sign_header->rampatch_len;

			if (binary_len > 0)
			{
				status = BMISignStreamStart(scn->hif_hdl, 0,
						(u_int8_t *)fw_entry_data
						+ binary_offset,
						binary_len, scn);
				if (status != EOK)
				{
					AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
						("%s:sign stream error\n",
						__func__));
				}
			}
		}

		if ((one_bin_header->action & ACTION_DOWNLOAD_EXEC)	\
						== ACTION_DOWNLOAD_EXEC)
		{
			param = 0;
			BMIExecute(scn->hif_hdl, address, &param, scn);
		}

		if ((next_tag_offset) > 0 &&
		    (one_bin_header->bin_group_id == groupid))
		{
			one_bin_header = (FW_BIN_HEADER_T *)(
					 (u_int8_t *)fw_entry_data
					 + one_bin_header->next_tag_off);
			if (one_bin_header->bin_group_id == groupid)
				is_group = TRUE;
			else
				is_group = FALSE;
		}
		else {
			is_group = FALSE;
		}

		if (!is_group)
			next_tag_offset = 0;

	} while (next_tag_offset > 0);

exit:
	if (temp_eeprom)
		OS_FREE(temp_eeprom);

	if (status != EOK) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("BMI operation failed: %d\n", __LINE__));
		release_firmware(fw_entry);
		return -1;
	}

	release_firmware(fw_entry);

	return status;
}

static int ol_transfer_bin_file(struct ol_softc *scn, ATH_BIN_FILE file,
			 u_int32_t address, bool compressed)
{
	int status = EOK;
	const char *filename = NULL;
	const struct firmware *fw_entry;
	u_int32_t fw_entry_size;
	u_int8_t *tempEeprom;
	u_int32_t board_data_size;
#ifdef QCA_SIGNED_SPLIT_BINARY_SUPPORT
	bool bin_sign = FALSE;
	int bin_off, bin_len;
	SIGN_HEADER_T *sign_header;
#endif
	int ret;

	if (scn->enablesinglebinary && file != ATH_BOARD_DATA_FILE) {
		/*
		 * Fallback to load split binaries if single binary is not found
		 */
		ret = ol_transfer_single_bin_file(scn,
						  address,
						  compressed);

		if (!ret)
			return ret;

		if (ret != -ENOENT)
			return -1;
	}

	switch (file) {
	default:
		printk("%s: Unknown file type\n", __func__);
		return -1;
	case ATH_OTP_FILE:
#if defined(CONFIG_CNSS) || defined(HIF_SDIO)
		filename = scn->fw_files.otp_data;
#else
		filename = QCA_OTP_FILE;
#endif
#ifdef QCA_SIGNED_SPLIT_BINARY_SUPPORT
		bin_sign = TRUE;
#endif
		break;
	case ATH_FIRMWARE_FILE:
#ifdef QCA_WIFI_FTM
		if (vos_get_conparam() == VOS_FTM_MODE) {
#if defined(CONFIG_CNSS) || defined(HIF_SDIO)
			filename = scn->fw_files.utf_file;
#else
			filename = QCA_UTF_FIRMWARE_FILE;
#endif
#ifdef QCA_SIGNED_SPLIT_BINARY_SUPPORT
			bin_sign = TRUE;
#endif
			printk(KERN_INFO "%s: Loading firmware file %s\n",
			       __func__, filename);
			break;
		}
#endif
#if defined(CONFIG_CNSS) || defined(HIF_SDIO)
		filename = scn->fw_files.image_file;
#else
		filename = QCA_FIRMWARE_FILE;
#endif
#ifdef QCA_SIGNED_SPLIT_BINARY_SUPPORT
		bin_sign = TRUE;
#endif
		break;
	case ATH_PATCH_FILE:
		printk("%s: no Patch file defined\n", __func__);
		return EOK;
	case ATH_BOARD_DATA_FILE:
#ifdef QCA_WIFI_FTM
		if (vos_get_conparam() == VOS_FTM_MODE) {
#if defined(CONFIG_CNSS) || defined(HIF_SDIO)
			filename = scn->fw_files.utf_board_data;
#else
			filename = QCA_BOARD_DATA_FILE;
#endif
#ifdef QCA_SIGNED_SPLIT_BINARY_SUPPORT
			bin_sign = TRUE;
#endif
			printk(KERN_INFO "%s: Loading board data file %s\n",
				__func__, filename);
			break;
	}
#endif /* QCA_WIFI_FTM */
#if defined(CONFIG_CNSS) || defined(HIF_SDIO)
		filename = scn->fw_files.board_data;
#else
		filename = QCA_BOARD_DATA_FILE;
#endif
#ifdef QCA_SIGNED_SPLIT_BINARY_SUPPORT
		bin_sign = FALSE;
#endif
		break;
	}

	if (request_firmware(&fw_entry, filename, scn->sc_osdev->device) != 0)
	{
		printk("%s: Failed to get %s\n", __func__, filename);

		if (file == ATH_OTP_FILE)
			return -ENOENT;

#if defined(QCA_WIFI_FTM) && defined(CONFIG_CNSS) && defined(HIF_SDIO)
		/* Try default board data file if FTM specific
		 * board data file is not present. */
		if (filename == scn->fw_files.utf_board_data) {
			filename = scn->fw_files.board_data;
			printk("%s: Trying to load default %s\n",
				__func__, filename);
			if (request_firmware(&fw_entry, filename,
				scn->sc_osdev->device) != 0) {
				printk("%s: Failed to get %s\n",
					__func__, filename);
				return -1;
			}
		} else {
			return -1;
		}
#else
		return -1;
#endif
	}

        if (!fw_entry || !fw_entry->data) {
               printk("Invalid fw_entries\n");
               return A_ERROR;
        }

	fw_entry_size = fw_entry->size;
	tempEeprom = NULL;

	if (file == ATH_BOARD_DATA_FILE)
	{
		u_int32_t board_ext_address;
		int32_t board_ext_data_size;

		tempEeprom = OS_MALLOC(scn->sc_osdev, fw_entry_size, GFP_ATOMIC);
		if (!tempEeprom) {
			printk("%s: Memory allocation failed\n", __func__);
			release_firmware(fw_entry);
			return A_ERROR;
		}

		OS_MEMCPY(tempEeprom, (u_int8_t *)fw_entry->data, fw_entry_size);

		switch (scn->target_type) {
		default:
			board_data_size = 0;
			board_ext_data_size = 0;
			break;
		case TARGET_TYPE_AR6004:
			board_data_size =  AR6004_BOARD_DATA_SZ;
			board_ext_data_size = AR6004_BOARD_EXT_DATA_SZ;
		case TARGET_TYPE_AR9888:
			board_data_size =  AR9888_BOARD_DATA_SZ;
			board_ext_data_size = AR9888_BOARD_EXT_DATA_SZ;
			break;
		}

		/* Determine where in Target RAM to write Board Data */
		BMIReadMemory(scn->hif_hdl,
				HOST_INTEREST_ITEM_ADDRESS(scn->target_type, hi_board_ext_data),
				(u_int8_t *)&board_ext_address, 4, scn);
		printk("Board extended Data download address: 0x%x\n", board_ext_address);

		/*
		 * Check whether the target has allocated memory for extended board
		 * data and file contains extended board data
		 */
		if ((board_ext_address) && (fw_entry_size == (board_data_size + board_ext_data_size)))
		{
			u_int32_t param;

			status = BMIWriteMemory(scn->hif_hdl, board_ext_address,
					(u_int8_t *)(tempEeprom + board_data_size), board_ext_data_size, scn);

			if (status != EOK)
				goto end;

			/* Record the fact that extended board Data IS initialized */
			param = (board_ext_data_size << 16) | 1;
			BMIWriteMemory(scn->hif_hdl,
					HOST_INTEREST_ITEM_ADDRESS(scn->target_type, hi_board_ext_data_config),
					(u_int8_t *)&param, 4, scn);

			fw_entry_size = board_data_size;
		}
	}

#ifdef QCA_SIGNED_SPLIT_BINARY_SUPPORT
	if (bin_sign) {
		u_int32_t chip_id;

		if (fw_entry_size < sizeof(SIGN_HEADER_T)) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("%s: Invalid binary size %d\n", __func__,
				 fw_entry_size));
			status = A_ERROR;
			goto end;
		}

		sign_header = (SIGN_HEADER_T *)fw_entry->data;
		chip_id = cpu_to_le32(sign_header->product_id);
		if (sign_header->magic_num == SIGN_HEADER_MAGIC
		    && (chip_id == AR6320_REV1_1_VERSION
			|| chip_id == AR6320_REV1_3_VERSION
			|| chip_id == AR6320_REV2_1_VERSION)) {

			status = BMISignStreamStart(scn->hif_hdl, address,
						    (u_int8_t *)fw_entry->data,
						    sizeof(SIGN_HEADER_T), scn);
			if (status != EOK) {
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("%s: unable to start sign stream\n",
					__func__));
				status = A_ERROR;
				goto end;
			}

			bin_off = sizeof(SIGN_HEADER_T);
			bin_len = sign_header->rampatch_len
				  - sizeof(SIGN_HEADER_T);
		} else {
			bin_sign = FALSE;
			bin_off = 0;
			bin_len = fw_entry_size;
		}
	} else {
		bin_len = fw_entry_size;
		bin_off = 0;
	}

	if (compressed) {
		status = BMIFastDownload(scn->hif_hdl, address,
					 (u_int8_t *)fw_entry->data + bin_off,
					 bin_len, scn);
	} else {
		if (file == ATH_BOARD_DATA_FILE && fw_entry->data) {
			status = BMIWriteMemory(scn->hif_hdl, address,
						(u_int8_t *)tempEeprom,
						fw_entry_size, scn);
		} else {
			status = BMIWriteMemory(scn->hif_hdl, address,
						(u_int8_t *)fw_entry->data
						+ bin_off,
						bin_len, scn);
		}
	}

	if (bin_sign) {
		bin_off += bin_len;
		bin_len = sign_header->total_len
			  - sign_header->rampatch_len;

		if (bin_len > 0) {
			status = BMISignStreamStart(scn->hif_hdl, 0,
					(u_int8_t *)fw_entry->data + bin_off,
					bin_len, scn);
			if (status != EOK) {
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("%s:sign stream error\n",
					__func__));
			}
		}
	}
#else
	if (compressed) {
		status = BMIFastDownload(scn->hif_hdl, address,
					 (u_int8_t *)fw_entry->data,
					 fw_entry_size, scn);
	} else {
		if (file == ATH_BOARD_DATA_FILE && fw_entry->data) {
			status = BMIWriteMemory(scn->hif_hdl, address,
						(u_int8_t *)tempEeprom,
						fw_entry_size, scn);
		} else {
			status = BMIWriteMemory(scn->hif_hdl, address,
						(u_int8_t *)fw_entry->data,
						fw_entry_size, scn);
		}
	}
#endif	/* QCA_SIGNED_SPLIT_BINARY_SUPPORT */

end:
	if (tempEeprom) {
		OS_FREE(tempEeprom);
	}

	if (status != EOK) {
		printk("%s, BMI operation failed: %d\n", __func__, __LINE__);
		release_firmware(fw_entry);
		return A_ERROR;
	}

	release_firmware(fw_entry);

	VOS_TRACE(VOS_MODULE_ID_VOSS, VOS_TRACE_LEVEL_ERROR,
		"%s: transferring file: %s size %d bytes done!", __func__,
		(filename!=NULL)?filename:"", fw_entry_size);

	return status;
}

u_int32_t host_interest_item_address(u_int32_t target_type, u_int32_t item_offset)
{
	switch (target_type) {
	default:
		ASSERT(0);
	case TARGET_TYPE_AR6002:
		return (AR6002_HOST_INTEREST_ADDRESS + item_offset);
	case TARGET_TYPE_AR6003:
		return (AR6003_HOST_INTEREST_ADDRESS + item_offset);
	case TARGET_TYPE_AR6004:
		return (AR6004_HOST_INTEREST_ADDRESS + item_offset);
	case TARGET_TYPE_AR6006:
		return (AR6006_HOST_INTEREST_ADDRESS + item_offset);
	case TARGET_TYPE_AR9888:
		return (AR9888_HOST_INTEREST_ADDRESS + item_offset);
	case TARGET_TYPE_AR6320:
	case TARGET_TYPE_AR6320V2:
		return (AR6320_HOST_INTEREST_ADDRESS + item_offset);
	}
}

#if defined(QCA_WIFI_2_0) && !defined(QCA_WIFI_ISOC)
#ifdef HIF_PCI
int dump_CE_register(struct ol_softc *scn)
{
#ifdef HIF_USB
	struct hif_usb_softc *sc = scn->hif_sc;
#else
	struct hif_pci_softc *sc = scn->hif_sc;
#endif
	A_UINT32 CE_reg_address = CE0_BASE_ADDRESS;
	A_UINT32 CE_reg_values[8][CE_USEFUL_SIZE>>2];
	A_UINT32 CE_reg_word_size = CE_USEFUL_SIZE>>2;
	A_UINT16 i, j;

	for(i = 0; i < 8; i++, CE_reg_address += CE_OFFSET) {
		if (HIFDiagReadMem(scn->hif_hdl, CE_reg_address,
			(A_UCHAR*)&CE_reg_values[i][0],
			CE_reg_word_size * sizeof(A_UINT32)) != A_OK)
		{
			printk(KERN_ERR "Dumping CE register failed!\n");
			return -EACCES;
		}
	}

	for (i = 0; i < 8; i++) {
		printk("CE%d Registers:\n", i);
		for (j = 0; j < CE_reg_word_size; j++) {
			printk("0x%08x ", CE_reg_values[i][j]);
			if (!((j+1)%5) || (CE_reg_word_size - 1) == j)
				printk("\n");
		}

		msleep(1);
	}

	return EOK;
}
#endif
#endif

#if defined(QCA_WIFI_2_0) && !defined(QCA_WIFI_ISOC) && defined(CONFIG_CNSS)
static struct ol_softc *ramdump_scn;

int ol_copy_ramdump(struct ol_softc *scn)
{
	void __iomem *ramdump_base;
	unsigned long address;
	unsigned long size;
	int ret;

	/* Get RAM dump memory address and size */
	if (cnss_get_ramdump_mem(&address, &size)) {
		printk("No RAM dump will be collected since failed to get "
			"memory address or size!\n");
		ret = -EACCES;
		goto out;
	}

	ramdump_base = ioremap(address, size);
	if (!ramdump_base) {
		printk("No RAM dump will be collected since ramdump_base is NULL!\n");
		ret = -EACCES;
		goto out;
	}

	ret = ol_target_coredump(scn, ramdump_base, size);
	iounmap(ramdump_base);

out:
	return ret;
}

static void ramdump_work_handler(struct work_struct *ramdump)
{
	int ret;
	u_int32_t host_interest_address;
	u_int32_t dram_dump_values[4];

	if (!ramdump_scn) {
		printk("No RAM dump will be collected since ramdump_scn is NULL!\n");
		goto out_fail;
	}

#ifdef DEBUG
	ret = hif_pci_check_soc_status(ramdump_scn->hif_sc);
	if (ret)
		goto out_fail;

	ret = dump_CE_register(ramdump_scn);
	if (ret)
		goto out_fail;

	dump_CE_debug_register(ramdump_scn->hif_sc);
#endif

	if (HIFDiagReadMem(ramdump_scn->hif_hdl,
		host_interest_item_address(ramdump_scn->target_type,
		offsetof(struct host_interest_s, hi_failure_state)),
		(A_UCHAR *)&host_interest_address, sizeof(u_int32_t)) != A_OK) {
		printk(KERN_ERR "HifDiagReadiMem FW Dump Area Pointer failed!\n");
		dump_CE_register(ramdump_scn);
		dump_CE_debug_register(ramdump_scn->hif_sc);

		goto out_fail;
	}
	printk("Host interest item address: 0x%08x\n", host_interest_address);

	if (HIFDiagReadMem(ramdump_scn->hif_hdl, host_interest_address,
		(A_UCHAR *)&dram_dump_values[0], 4 * sizeof(u_int32_t)) != A_OK)
	{
		printk("HifDiagReadiMem FW Dump Area failed!\n");
		goto out_fail;
	}
	printk("FW Assertion at PC: 0x%08x BadVA: 0x%08x TargetID: 0x%08x\n",
		dram_dump_values[2], dram_dump_values[3], dram_dump_values[0]);

	if (ol_copy_ramdump(ramdump_scn))
		goto out_fail;

	printk("%s: RAM dump collecting completed!\n", __func__);
	msleep(250);

	/* Notify SSR framework the target has crashed. */
	cnss_device_crashed();
	return;

out_fail:
	/* Silent SSR on dump failure */
#ifdef CNSS_SELF_RECOVERY
	cnss_device_self_recovery();
#else
	cnss_device_crashed();
#endif
	return;
}

static DECLARE_WORK(ramdump_work, ramdump_work_handler);

void ol_schedule_ramdump_work(struct ol_softc *scn)
{
	ramdump_scn = scn;
	schedule_work(&ramdump_work);
}

static void fw_indication_work_handler(struct work_struct *fw_indication)
{
	cnss_device_self_recovery();
}

static DECLARE_WORK(fw_indication_work, fw_indication_work_handler);

void ol_schedule_fw_indication_work(struct ol_softc *scn)
{
	schedule_work(&fw_indication_work);
}
#endif

#define REGISTER_DUMP_LEN_MAX   60
#define REG_DUMP_COUNT		60

void ol_target_failure(void *instance, A_STATUS status)
{
	struct ol_softc *scn = (struct ol_softc *)instance;
#ifndef CONFIG_CNSS
	A_UINT32 reg_dump_area = 0;
	A_UINT32 reg_dump_values[REGISTER_DUMP_LEN_MAX];
	A_UINT32 reg_dump_cnt = 0;
	A_UINT32 i;
	A_UINT32 dbglog_hdr_address;
	struct dbglog_hdr_host dbglog_hdr;
	struct dbglog_buf_host dbglog_buf;
	A_UINT8 *dbglog_data;
	void *vos_context = vos_get_global_context(VOS_MODULE_ID_WDA, NULL);
	tp_wma_handle wma = vos_get_context(VOS_MODULE_ID_WDA, vos_context);
#else
	int ret;
#endif

	if (OL_TRGET_STATUS_RESET == scn->target_status) {
		printk("Target is already asserted, ignore!\n");
		return;
	}

	scn->target_status = OL_TRGET_STATUS_RESET;

#if defined(QCA_WIFI_2_0) && !defined(QCA_WIFI_ISOC)
	if (vos_is_load_unload_in_progress(VOS_MODULE_ID_VOSS, NULL)) {
		printk("%s: Loading/Unloading is in progress, ignore!\n",
			__func__);
		return;
	}
	vos_set_logp_in_progress(VOS_MODULE_ID_VOSS, TRUE);
#endif

#ifdef CONFIG_CNSS
	ret = hif_pci_check_fw_reg(scn->hif_sc);
	if (0 == ret) {
		ol_schedule_fw_indication_work(scn);
		return;
	} else if (-1 == ret) {
		return;
	}
#endif

	printk("XXX TARGET ASSERTED XXX\n");

#ifndef CONFIG_CNSS
	if (HIFDiagReadMem(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_failure_state)),
				(A_UCHAR *)&reg_dump_area,
				sizeof(A_UINT32))!= A_OK)
	{
		printk("HifDiagReadiMem FW Dump Area Pointer failed\n");
		return;
	}

	printk("Target Register Dump Location 0x%08X\n", reg_dump_area);

	reg_dump_cnt = REG_DUMP_COUNT;

	if (HIFDiagReadMem(scn->hif_hdl,
				reg_dump_area,
				(A_UCHAR*)&reg_dump_values[0],
				reg_dump_cnt * sizeof(A_UINT32))!= A_OK)
	{
		printk("HifDiagReadiMem for FW Dump Area failed\n");
		return;
	}

	printk("Target Register Dump\n");
	for (i = 0; i < reg_dump_cnt; i++) {
		printk("[%02d]   :  0x%08X\n", i, reg_dump_values[i]);
	}

	if (HIFDiagReadMem(scn->hif_hdl,
	            host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_dbglog_hdr)),
	            (A_UCHAR *)&dbglog_hdr_address,
	            sizeof(dbglog_hdr_address))!= A_OK)
	{
	    printk("HifDiagReadiMem FW dbglog_hdr_address failed\n");
	    return;
	}

	if (HIFDiagReadMem(scn->hif_hdl,
	            dbglog_hdr_address,
	            (A_UCHAR *)&dbglog_hdr,
	            sizeof(dbglog_hdr))!= A_OK)
	{
	    printk("HifDiagReadiMem FW dbglog_hdr failed\n");
	    return;
	}

	if (HIFDiagReadMem(scn->hif_hdl,
	            (A_UINT32)dbglog_hdr.dbuf,
	            (A_UCHAR *)&dbglog_buf,
	            sizeof(dbglog_buf))!= A_OK)
	{
	    printk("HifDiagReadiMem FW dbglog_buf failed\n");
	    return;
	}

	dbglog_data = adf_os_mem_alloc(scn->adf_dev,  dbglog_buf.length + 4);
	if (dbglog_data) {
	    if (HIFDiagReadMem(scn->hif_hdl,
	                (A_UINT32)dbglog_buf.buffer,
	                dbglog_data + 4,
	                dbglog_buf.length)!= A_OK)
	    {
	        printk("HifDiagReadiMem FW dbglog_data failed\n");
	    } else {
	        printk("dbglog_hdr.dbuf=%u dbglog_data=%p dbglog_buf.buffer=%u dbglog_buf.length=%u\n",
	                dbglog_hdr.dbuf, dbglog_data, dbglog_buf.buffer, dbglog_buf.length);


	        OS_MEMCPY(dbglog_data, &dbglog_hdr.dropped, 4);
		wma->is_fw_assert = 1;
	        (void)dbglog_parse_debug_logs(wma, dbglog_data, dbglog_buf.length + 4);
	    }

	    adf_os_mem_free(dbglog_data);
	}
#endif

#if defined(QCA_WIFI_2_0) && !defined(QCA_WIFI_ISOC) && defined(CONFIG_CNSS)
	/* Collect the RAM dump through a workqueue */
	ol_schedule_ramdump_work(scn);
#endif

	return;
}

int
ol_configure_target(struct ol_softc *scn)
{
	u_int32_t param;
#ifdef CONFIG_CNSS
	struct cnss_platform_cap cap;
#endif

	/* Tell target which HTC version it is used*/
	param = HTC_PROTOCOL_VERSION;
	if (BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_app_host_interest)),
				(u_int8_t *)&param,
				4, scn)!= A_OK)
	{
		printk("BMIWriteMemory for htc version failed \n");
		return -1;
	}

	/* set the firmware mode to STA/IBSS/AP */
	{
		if (BMIReadMemory(scn->hif_hdl,
					host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag)),
					(A_UCHAR *)&param,
					4, scn)!= A_OK)
		{
			printk("BMIReadMemory for setting fwmode failed \n");
			return A_ERROR;
		}

		/* TODO following parameters need to be re-visited. */
		param |= (1 << HI_OPTION_NUM_DEV_SHIFT); //num_device
		param |= (HI_OPTION_FW_MODE_AP << HI_OPTION_FW_MODE_SHIFT); //Firmware mode ??
		param |= (1 << HI_OPTION_MAC_ADDR_METHOD_SHIFT); //mac_addr_method
		param |= (0 << HI_OPTION_FW_BRIDGE_SHIFT);  //firmware_bridge
		param |= (0 << HI_OPTION_FW_SUBMODE_SHIFT); //fwsubmode

		printk("NUM_DEV=%d FWMODE=0x%x FWSUBMODE=0x%x FWBR_BUF %d\n",
				1, HI_OPTION_FW_MODE_AP, 0, 0);

		if (BMIWriteMemory(scn->hif_hdl,
					host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag)),
					(A_UCHAR *)&param,
					4, scn) != A_OK)
		{
			printk("BMIWriteMemory for setting fwmode failed \n");
			return A_ERROR;
		}
	}

#if defined(HIF_PCI)
#if (CONFIG_DISABLE_CDC_MAX_PERF_WAR)
	{
		/* set the firmware to disable CDC max perf WAR */
		if (BMIReadMemory(scn->hif_hdl,
					host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag2)),
					(A_UCHAR *)&param,
					4, scn)!= A_OK)
		{
			printk("BMIReadMemory for setting cdc max perf failed \n");
			return A_ERROR;
		}

		param |= HI_OPTION_DISABLE_CDC_MAX_PERF_WAR;
		if (BMIWriteMemory(scn->hif_hdl,
					host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag2)),
					(A_UCHAR *)&param,
					4, scn) != A_OK)
		{
			printk("BMIWriteMemory for setting cdc max perf failed \n");
			return A_ERROR;
		}
	}
#endif /* CONFIG_CDC_MAX_PERF_WAR */

#endif /*HIF_PCI*/

#ifdef CONFIG_CNSS
	{
		int ret;

		ret = cnss_get_platform_cap(&cap);
		if (ret)
			pr_err("platform capability info from CNSS not available\n");

		if (!ret && cap.cap_flag & CNSS_HAS_EXTERNAL_SWREG) {
			if (BMIReadMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type,
					offsetof(struct host_interest_s, hi_option_flag2)),
						(A_UCHAR *)&param, 4, scn)!= A_OK) {
				printk("BMIReadMemory for setting external SWREG failed\n");
				return A_ERROR;
			}

			param |= HI_OPTION_USE_EXT_LDO;
			if (BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type,
					offsetof(struct host_interest_s, hi_option_flag2)),
						(A_UCHAR *)&param, 4, scn) != A_OK) {
				printk("BMIWriteMemory for setting external SWREG failed\n");
				return A_ERROR;
			}
		}
	}
#endif

	/* If host is running on a BE CPU, set the host interest area */
	{
#ifdef BIG_ENDIAN_HOST
		param = 1;
#else
		param = 0;
#endif
		if (BMIWriteMemory(scn->hif_hdl,
					host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_be)),
					(A_UCHAR *)&param,
					4, scn) != A_OK)
		{
			printk("BMIWriteMemory for setting host CPU BE mode failed \n");
			return A_ERROR;
		}
	}

	/* FW descriptor/Data swap flags */
	{
		param = 0;
		if (BMIWriteMemory(scn->hif_hdl,
					host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_fw_swap)),
					(A_UCHAR *)&param,
					4, scn) != A_OK)
		{
			printk("BMIWriteMemory for setting FW data/desc swap flags failed \n");
			return A_ERROR;
		}
	}

	return A_OK;
}

static int
ol_check_dataset_patch(struct ol_softc *scn, u_int32_t *address)
{
	/* Check if patch file needed for this target type/version. */
	return 0;
}

#if defined(QCA_WIFI_2_0) && !defined(QCA_WIFI_ISOC)
#ifdef HIF_PCI

A_STATUS ol_fw_populate_clk_settings(A_refclk_speed_t refclk,
				struct cmnos_clock_s *clock_s)
{
	if (!clock_s)
		return A_ERROR;

	switch (refclk) {
	case SOC_REFCLK_48_MHZ:
		clock_s->wlan_pll.div = 0xE;
		clock_s->wlan_pll.rnfrac = 0x2AAA8;
		clock_s->pll_settling_time = 2400;
		break;
	case SOC_REFCLK_19_2_MHZ:
		clock_s->wlan_pll.div = 0x24;
		clock_s->wlan_pll.rnfrac = 0x2AAA8;
		clock_s->pll_settling_time = 960;
		break;
	case SOC_REFCLK_24_MHZ:
		clock_s->wlan_pll.div = 0x1D;
		clock_s->wlan_pll.rnfrac = 0x15551;
		clock_s->pll_settling_time = 1200;
		break;
	case SOC_REFCLK_26_MHZ:
		clock_s->wlan_pll.div = 0x1B;
		clock_s->wlan_pll.rnfrac = 0x4EC4;
		clock_s->pll_settling_time = 1300;
		break;
	case SOC_REFCLK_37_4_MHZ:
		clock_s->wlan_pll.div = 0x12;
		clock_s->wlan_pll.rnfrac = 0x34B49;
		clock_s->pll_settling_time = 1870;
		break;
	case SOC_REFCLK_38_4_MHZ:
		clock_s->wlan_pll.div = 0x12;
		clock_s->wlan_pll.rnfrac = 0x15551;
		clock_s->pll_settling_time = 1920;
		break;
	case SOC_REFCLK_40_MHZ:
		clock_s->wlan_pll.div = 0x11;
		clock_s->wlan_pll.rnfrac = 0x26665;
		clock_s->pll_settling_time = 2000;
		break;
	case SOC_REFCLK_52_MHZ:
		clock_s->wlan_pll.div = 0x1B;
		clock_s->wlan_pll.rnfrac = 0x4EC4;
		clock_s->pll_settling_time = 2600;
		break;
	case SOC_REFCLK_UNKNOWN:
		clock_s->wlan_pll.refdiv = 0;
		clock_s->wlan_pll.div = 0;
		clock_s->wlan_pll.rnfrac = 0;
		clock_s->wlan_pll.outdiv = 0;
		clock_s->pll_settling_time = 1024;
		clock_s->refclk_hz = 0;
	default:
		return A_ERROR;
	}

	clock_s->refclk_hz = refclk_speed_to_hz[refclk];
	clock_s->wlan_pll.refdiv = 0;
	clock_s->wlan_pll.outdiv = 1;

	return A_OK;
}

A_STATUS ol_patch_pll_switch(struct ol_softc * scn)
{
	HIF_DEVICE *hif_device = scn->hif_hdl;
	A_STATUS status;
	u_int32_t addr = 0;
	u_int32_t reg_val = 0;
	u_int32_t mem_val = 0;
	struct cmnos_clock_s clock_s;
	u_int32_t cmnos_core_clk_div_addr = 0;
	u_int32_t cmnos_cpu_pll_init_done_addr = 0;
	u_int32_t cmnos_cpu_speed_addr = 0;
#ifdef HIF_USB/* fail for USB case */
	struct hif_usb_softc *sc = scn->hif_sc;
#else
	struct hif_pci_softc *sc = scn->hif_sc;
#endif

	switch (scn->target_version) {
	case AR6320_REV1_1_VERSION:
		cmnos_core_clk_div_addr = AR6320_CORE_CLK_DIV_ADDR;
		cmnos_cpu_pll_init_done_addr = AR6320_CPU_PLL_INIT_DONE_ADDR;
		cmnos_cpu_speed_addr = AR6320_CPU_SPEED_ADDR;
		break;
	case AR6320_REV1_3_VERSION:
	case AR6320_REV2_1_VERSION:
		cmnos_core_clk_div_addr = AR6320V2_CORE_CLK_DIV_ADDR;
		cmnos_cpu_pll_init_done_addr = AR6320V2_CPU_PLL_INIT_DONE_ADDR;
		cmnos_cpu_speed_addr = AR6320V2_CPU_SPEED_ADDR;
		break;
	case AR6320_REV3_VERSION:
		cmnos_core_clk_div_addr = AR6320V3_CORE_CLK_DIV_ADDR;
		cmnos_cpu_pll_init_done_addr = AR6320V3_CPU_PLL_INIT_DONE_ADDR;
		cmnos_cpu_speed_addr = AR6320V3_CPU_SPEED_ADDR;
		break;
	default:
		pr_err("%s: Unsupported target version %x\n", __func__,
		       scn->target_version);
		return A_ERROR;
	}

	addr = (RTC_SOC_BASE_ADDRESS | EFUSE_OFFSET);
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read EFUSE Addr\n");
		return status;
	}

	status = ol_fw_populate_clk_settings(EFUSE_XTAL_SEL_GET(reg_val),
					&clock_s);
	if (status != A_OK) {
		pr_err("Failed to set clock settings\n");
		return status;
	}
	pr_debug("crystal_freq: %dHz\n", clock_s.refclk_hz);

	/* ------Step 1----*/
	reg_val = 0;
	addr = (RTC_SOC_BASE_ADDRESS | BB_PLL_CONFIG_OFFSET);
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read PLL_CONFIG Addr\n");
		return status;
	}
	pr_debug("Step 1a: %8X\n", reg_val);

	reg_val &= ~(BB_PLL_CONFIG_FRAC_MASK | BB_PLL_CONFIG_OUTDIV_MASK);
	reg_val |= (BB_PLL_CONFIG_FRAC_SET(clock_s.wlan_pll.rnfrac) |
			BB_PLL_CONFIG_OUTDIV_SET(clock_s.wlan_pll.outdiv));
	status = BMIWriteSOCRegister(hif_device, addr, reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to write PLL_CONFIG Addr\n");
		return status;
	}

	reg_val = 0;
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read back PLL_CONFIG Addr\n");
		return status;
	}
	pr_debug("Step 1b: %8X\n", reg_val);

	/* ------Step 2----*/
	reg_val = 0;
	addr = (RTC_WMAC_BASE_ADDRESS | WLAN_PLL_SETTLE_OFFSET);
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read PLL_SETTLE Addr\n");
		return status;
	}
	pr_debug("Step 2a: %8X\n", reg_val);

	reg_val &= ~WLAN_PLL_SETTLE_TIME_MASK;
	reg_val |= WLAN_PLL_SETTLE_TIME_SET(clock_s.pll_settling_time);
	status = BMIWriteSOCRegister(hif_device, addr, reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to write PLL_SETTLE Addr\n");
		return status;
	}

	reg_val = 0;
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read back PLL_SETTLE Addr\n");
		return status;
	}
	pr_debug("Step 2b: %8X\n", reg_val);

	/* ------Step 3----*/
	reg_val = 0;
	addr = (RTC_SOC_BASE_ADDRESS | SOC_CORE_CLK_CTRL_OFFSET);
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read CLK_CTRL Addr\n");
		return status;
	}
	pr_debug("Step 3a: %8X\n", reg_val);

	reg_val &= ~SOC_CORE_CLK_CTRL_DIV_MASK;
	reg_val |= SOC_CORE_CLK_CTRL_DIV_SET(1);
	status = BMIWriteSOCRegister(hif_device, addr, reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to write CLK_CTRL Addr\n");
		return status;
	}

	reg_val = 0;
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read back CLK_CTRL Addr\n");
		return status;
	}
	pr_debug("Step 3b: %8X\n", reg_val);

	/* ------Step 4-----*/
	mem_val = 1;
	status = BMIWriteMemory(hif_device, cmnos_core_clk_div_addr,
			(A_UCHAR *)&mem_val, 4, scn);
	if (status != A_OK) {
		pr_err("Failed to write CLK_DIV Addr\n");
		return status;
	}

	/* ------Step 5-----*/
	reg_val = 0;
	addr = (RTC_WMAC_BASE_ADDRESS | WLAN_PLL_CONTROL_OFFSET);
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read PLL_CTRL Addr\n");
		return status;
	}
	pr_debug("Step 5a: %8X\n", reg_val);

	reg_val &= ~(WLAN_PLL_CONTROL_REFDIV_MASK | WLAN_PLL_CONTROL_DIV_MASK |
			WLAN_PLL_CONTROL_NOPWD_MASK);
	reg_val |=  (WLAN_PLL_CONTROL_REFDIV_SET(clock_s.wlan_pll.refdiv) |
			WLAN_PLL_CONTROL_DIV_SET(clock_s.wlan_pll.div) |
			WLAN_PLL_CONTROL_NOPWD_SET(1));
	status = BMIWriteSOCRegister(hif_device, addr, reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to write PLL_CTRL Addr\n");
		return status;
	}

	reg_val = 0;
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read back PLL_CTRL Addr\n");
		return status;
	}
	OS_DELAY(100);
	pr_debug("Step 5b: %8X\n", reg_val);

	/* ------Step 6-------*/
	do {
		reg_val = 0;
		status = BMIReadSOCRegister(hif_device, (RTC_WMAC_BASE_ADDRESS |
				RTC_SYNC_STATUS_OFFSET), &reg_val, scn);
		if (status != A_OK) {
			pr_err("Failed to read RTC_SYNC_STATUS Addr\n");
			return status;
		}
	} while(RTC_SYNC_STATUS_PLL_CHANGING_GET(reg_val));

	/* ------Step 7-------*/
	reg_val = 0;
	addr = (RTC_WMAC_BASE_ADDRESS | WLAN_PLL_CONTROL_OFFSET);
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read PLL_CTRL Addr for CTRL_BYPASS\n");
		return status;
	}
	pr_debug("Step 7a: %8X\n", reg_val);

	reg_val &= ~WLAN_PLL_CONTROL_BYPASS_MASK;
	reg_val |= WLAN_PLL_CONTROL_BYPASS_SET(0);
	status = BMIWriteSOCRegister(hif_device, addr, reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to write PLL_CTRL Addr for CTRL_BYPASS\n");
		return status;
	}

	reg_val = 0;
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read back PLL_CTRL Addr for CTRL_BYPASS\n");
		return status;
	}
	pr_debug("Step 7b: %8X\n", reg_val);

	/* ------Step 8--------*/
	do {
		reg_val = 0;
		status = BMIReadSOCRegister(hif_device,
			(RTC_WMAC_BASE_ADDRESS | RTC_SYNC_STATUS_OFFSET),
			&reg_val, scn);
		if (status != A_OK) {
			pr_err("Failed to read SYNC_STATUS Addr\n");
			return status;
		}
	} while(RTC_SYNC_STATUS_PLL_CHANGING_GET(reg_val));

	/* ------Step 9--------*/
	reg_val = 0;
	addr = (RTC_SOC_BASE_ADDRESS | SOC_CPU_CLOCK_OFFSET);
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read CPU_CLK Addr\n");
		return status;
	}
	pr_debug("Step 9a: %8X\n", reg_val);

	reg_val &= ~SOC_CPU_CLOCK_STANDARD_MASK;
	reg_val |= SOC_CPU_CLOCK_STANDARD_SET(1);;
	status = BMIWriteSOCRegister(hif_device, addr, reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to write CPU_CLK Addr\n");
		return status;
	}

	reg_val = 0;
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read back CPU_CLK Addr\n");
		return status;
	}
	pr_debug("Step 9b: %8X\n", reg_val);

	/* ------Step 10-------*/
	reg_val = 0;
	addr = (RTC_WMAC_BASE_ADDRESS | WLAN_PLL_CONTROL_OFFSET);
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read PLL_CTRL Addr for NOPWD\n");
		return status;
	}
	pr_debug("Step 10a: %8X\n", reg_val);

	reg_val &= ~WLAN_PLL_CONTROL_NOPWD_MASK;
	status = BMIWriteSOCRegister(hif_device, addr, reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to write PLL_CTRL Addr for NOPWD\n");
		return status;
	}

	reg_val = 0;
	status = BMIReadSOCRegister(hif_device, addr, &reg_val, scn);
	if (status != A_OK) {
		pr_err("Failed to read back PLL_CTRL Addr for NOPWD\n");
		return status;
	}
	pr_debug("Step 10b: %8X\n", reg_val);

	/* ------Step 11-------*/
	mem_val = 1;
	status = BMIWriteMemory(hif_device, cmnos_cpu_pll_init_done_addr,
			(A_UCHAR *)&mem_val, 4, scn);
	if (status != A_OK) {
		pr_err("Failed to write PLL_INIT Addr\n");
		return status;
	}

	mem_val = TARGET_CPU_FREQ;
	status = BMIWriteMemory(hif_device, cmnos_cpu_speed_addr,
			(A_UCHAR *)&mem_val, 4, scn);
	if (status != A_OK) {
		pr_err("Failed to write CPU_SPEED Addr\n");
		return status;
	}

	return status;
}
#endif
#endif

int ol_download_firmware(struct ol_softc *scn)
{
	u_int32_t param, address = 0;
	int status = !EOK;
#if defined(QCA_WIFI_2_0) && !defined(QCA_WIFI_ISOC)
#if defined(HIF_PCI)
	A_STATUS ret;
#endif
#endif

#ifdef CONFIG_CNSS
		if (0 != cnss_get_fw_files_for_target(&scn->fw_files,
						scn->target_type,
						scn->target_version)) {
			printk("%s: No FW files from CNSS driver\n", __func__);
			return -1;
		}
#elif defined(HIF_SDIO)
       if (0 != ol_get_fw_files_for_target(&scn->fw_files,
                                              scn->target_version)) {
                printk("%s: No FW files from driver\n", __func__);
                return -1;
       }
#endif
	/* Transfer Board Data from Target EEPROM to Target RAM */
	/* Determine where in Target RAM to write Board Data */
	BMIReadMemory(scn->hif_hdl,
			host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_board_data)),
			(u_int8_t *)&address, 4, scn);

	if (!address) {
		address = AR6004_REV5_BOARD_DATA_ADDRESS;
		printk("%s: Target address not known! Using 0x%x\n", __func__, address);
	}

#if defined(QCA_WIFI_2_0) && !defined(QCA_WIFI_ISOC)
#if defined(HIF_PCI)
	ret = ol_patch_pll_switch(scn);
	if (ret) {
		pr_err("pll switch failed. status %d\n", ret);
		return -1;
	}
#endif
#endif

	if (scn->cal_in_flash) {
		/* Write EEPROM or Flash data to Target RAM */
		status = ol_transfer_bin_file(scn, ATH_FLASH_FILE, address, FALSE);
	}

	if (status == EOK) {
		/* Record the fact that Board Data is initialized */
		param = 1;
		BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type,
					offsetof(struct host_interest_s, hi_board_data_initialized)),
				(u_int8_t *)&param, 4, scn);
	} else {
		/* Flash is either not available or invalid */
		if (ol_transfer_bin_file(scn, ATH_BOARD_DATA_FILE, address, FALSE) != EOK) {
			return -1;
		}

		/* Record the fact that Board Data is initialized */
		param = 1;
		BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type,
					offsetof(struct host_interest_s, hi_board_data_initialized)),
				(u_int8_t *)&param, 4, scn);

		/* Transfer One Time Programmable data */
		address = BMI_SEGMENTED_WRITE_ADDR;
		printk("%s: Using 0x%x for the remainder of init\n", __func__, address);

		if ( scn->enablesinglebinary == FALSE ) {
			status = ol_transfer_bin_file(scn, ATH_OTP_FILE,
						      address, TRUE);
			if (status == EOK) {
				/* Execute the OTP code only if entry found and downloaded */
				param = 0;
				BMIExecute(scn->hif_hdl, address, &param, scn);
			} else if (status < 0) {
				return status;
			}
		}
	}
	if (scn->target_version == AR6320_REV1_1_VERSION){
		/* To disable PCIe use 96 AXI memory as internal buffering,
		 *  highest bit of PCIE_TXBUF_ADDRESS need be set as 1
		 */
		u_int32_t addr = 0x3A058; /* PCIE_TXBUF_ADDRESS */
		u_int32_t value = 0;
		/* Disable PCIe AXI memory */
		BMIReadMemory(scn->hif_hdl, addr, (A_UCHAR*)&value, 4, scn);
		value |= 0x80000000; /* PCIE_TXBUF_BYPASS_SET(1) */
		BMIWriteMemory(scn->hif_hdl, addr, (A_UCHAR*)&value, 4, scn);
		value = 0;
		BMIReadMemory(scn->hif_hdl, addr, (A_UCHAR*)&value, 4, scn);
		printk("Disable PCIe use AXI memory:0x%08X-0x%08X\n", addr, value);
	}

	/* Download Target firmware - TODO point to target specific files in runtime */
	address = BMI_SEGMENTED_WRITE_ADDR;
	if (ol_transfer_bin_file(scn, ATH_FIRMWARE_FILE, address, TRUE) != EOK) {
		return -1;
	}

	/* Apply the patches */
	if (ol_check_dataset_patch(scn, &address))
	{
		if ((ol_transfer_bin_file(scn, ATH_PATCH_FILE, address, FALSE)) != EOK) {
			return -1;
		}
		BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_dset_list_head)),
				(u_int8_t *)&address, 4, scn);
	}

	if (scn->enableuartprint) {
		switch (scn->target_version){
			case AR6004_VERSION_REV1_3:
				param = 11;
				break;
			case AR6320_REV1_VERSION:
			case AR6320_REV2_VERSION:
			case AR6320_REV3_VERSION:
			case AR6320_REV4_VERSION:
			case AR6320_DEV_VERSION:
			/* for SDIO, debug uart output gpio is 29, otherwise it is 6. */
#ifdef HIF_SDIO
				param = 19;
#else
				param = 6;
#endif
				break;
			default:
			/* Configure GPIO AR9888 UART */
				param = 7;
			}

		BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_dbg_uart_txpin)),
				(u_int8_t *)&param, 4, scn);
		param = 1;
		BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_serial_enable)),
				(u_int8_t *)&param, 4, scn);
	} else {
		/*
		 * Explicitly setting UART prints to zero as target turns it on
		 * based on scratch registers.
		 */
		param = 0;
		BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s,hi_serial_enable)),
				(u_int8_t *)&param, 4, scn);
	}

#ifdef HIF_SDIO
	/* HACK override dbg TX pin to avoid side effects of default GPIO_6 */
	param = 19;
	BMIWriteMemory(scn->hif_hdl,
		host_interest_item_address(scn->target_type,
		offsetof(struct host_interest_s,
		hi_dbg_uart_txpin)),
		(u_int8_t *)&param, 4, scn);
#endif


	if (scn->enablefwlog) {
		BMIReadMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag)),
				(u_int8_t *)&param, 4, scn);

		param &= ~(HI_OPTION_DISABLE_DBGLOG);
		BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag)),
				(u_int8_t *)&param, 4, scn);
	} else {
		/*
		 * Explicitly setting fwlog prints to zero as target turns it on
		 * based on scratch registers.
		 */
		BMIReadMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag)),
				(u_int8_t *)&param, 4, scn);

		param |= HI_OPTION_DISABLE_DBGLOG;
		BMIWriteMemory(scn->hif_hdl,
				host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag)),
				(u_int8_t *)&param, 4, scn);
	}

#ifdef HIF_SDIO
	status = ol_sdio_extra_initialization(scn);
#endif

	return status;
}

#if defined(QCA_WIFI_2_0) && !defined(QCA_WIFI_ISOC)
#ifdef HIF_PCI
int ol_diag_read(struct ol_softc *scn, u_int8_t *buffer,
	u_int32_t pos, size_t count)
{
	int result = 0;

	if ((4 == count) && ((pos & 3) == 0)) {
		result = HIFDiagReadAccess(scn->hif_hdl, pos,
			(u_int32_t*)buffer);
	} else {
		size_t amountRead = 0;
		size_t readSize = PCIE_READ_LIMIT;
		size_t remainder = 0;
		if (count > PCIE_READ_LIMIT) {
			while ((amountRead < count) && (0 == result)) {
				result = HIFDiagReadMem(scn->hif_hdl, pos,
					buffer, readSize);
				if (0 == result) {
					buffer += readSize;
					pos += readSize;
					amountRead += readSize;
					remainder = count - amountRead;
					if (remainder < PCIE_READ_LIMIT)
						readSize = remainder;
				}

				msleep(5);
			}
		} else {
			result = HIFDiagReadMem(scn->hif_hdl, pos,
					buffer, count);
		}
	}

	if (!result) {
		return count;
	} else {
		return -EIO;
	}
}

static int ol_ath_get_reg_table(A_UINT32 target_version,
				tgt_reg_table *reg_table)
{
	int section_len = 0;

	if (!reg_table) {
		ASSERT(0);
		return section_len;
	}

	switch (target_version) {
	case AR6320_REV2_1_VERSION:
		reg_table->section = (tgt_reg_section *)&ar6320v2_reg_table[0];
		reg_table->section_size = sizeof(ar6320v2_reg_table)
					 /sizeof(ar6320v2_reg_table[0]);
		section_len = AR6320_REV2_1_REG_SIZE;
		break;
	default:
		reg_table->section = (void *)NULL;
		reg_table->section_size = 0;
		section_len = 0;
	}

	return section_len;
}

static int ol_diag_read_reg_loc(struct ol_softc *scn, u_int8_t *buffer,
		u_int32_t buffer_len)
{
	int i, len, section_len, fill_len;
	int dump_len, result = 0;
	tgt_reg_table reg_table;
	tgt_reg_section *curr_sec, *next_sec;

	section_len = ol_ath_get_reg_table(scn->target_version, &reg_table);

	if (!reg_table.section || !reg_table.section_size || !section_len) {
		printk(KERN_ERR "%s: failed to get reg table\n", __func__);
		result = -EIO;
		goto out;
	}

	curr_sec = reg_table.section;
	for (i = 0; i < reg_table.section_size; i++) {

		dump_len = curr_sec->end_addr - curr_sec->start_addr;

		if ((buffer_len - result) < dump_len) {
			printk("Not enough memory to dump the registers:"
					" %d: 0x%08x-0x%08x\n", i,
					curr_sec->start_addr,
					curr_sec->end_addr);
			goto out;
		}

		len = ol_diag_read(scn, buffer, curr_sec->start_addr, dump_len);

		if (len != -EIO) {
			buffer += len;
			result += len;
		} else {
			printk(KERN_ERR "%s: can't read reg 0x%08x len = %d\n",
			       __func__, curr_sec->start_addr, dump_len);
			result = -EIO;
			goto out;
		}

		if (result < section_len) {
			next_sec = (tgt_reg_section *)((u_int8_t *)curr_sec
							+ sizeof(*curr_sec));
			fill_len = next_sec->start_addr - curr_sec->end_addr;
			if ((buffer_len - result) < fill_len) {
				printk("Not enough memory to fill registers:"
						" %d: 0x%08x-0x%08x\n", i,
						curr_sec->end_addr,
						next_sec->start_addr);
				goto out;
			}

			if (fill_len) {
				adf_os_mem_set(buffer,
					       INVALID_REG_LOC_DUMMY_DATA,
					       fill_len);
				buffer += fill_len;
				result += fill_len;
			}
		}
		curr_sec++;
	}

out:
	return result;
}

/**---------------------------------------------------------------------------
 *   \brief  ol_target_coredump
 *
 *   Function to perform core dump for the target
 *
 *   \param:   scn - ol_softc handler
 *             memoryBlock - non-NULL reserved memory location
 *             blockLength - size of the dump to collect
 *
 *   \return:  None
 * --------------------------------------------------------------------------*/
int ol_target_coredump(void *inst, void *memoryBlock, u_int32_t blockLength)
{
	struct ol_softc *scn = (struct ol_softc *)inst;
	char *bufferLoc = memoryBlock;
	int result = 0;
	int ret = 0;
	u_int32_t amountRead = 0;
	u_int32_t sectionCount = 0;
	u_int32_t pos = 0;
	u_int32_t readLen = 0;

	/*
	* SECTION = DRAM
	* START   = 0x00400000
	* LENGTH  = 0x00070000
	*
	* SECTION = IRAM
	* START   = 0x00980000
	* LENGTH  = 0x00038000
	*
	* SECTION = AXI
	* START   = 0x000a0000
	* LENGTH  = 0x00018000
	*
	* SECTION = REG
	* START   = 0x00000800
	* LENGTH  = 0x0007F820
	*/

	while ((sectionCount < 4) && (amountRead < blockLength)) {
		switch (sectionCount) {
		case 0:
			/* DRAM SECTION */
			pos = DRAM_LOCATION;
			readLen = DRAM_SIZE;
			break;
		case 1:
			/* IRAM SECTION */
			pos = IRAM_LOCATION;
			readLen = IRAM_SIZE;
			break;
		case 2:
			/* AXI SECTION */
			pos = AXI_LOCATION;
			readLen = AXI_SIZE;
			printk("%s: Dumping AXI section...\n", __func__);
			break;
		case 3:
			/* REG SECTION */
			pos = REGISTER_LOCATION;
			/* ol_diag_read_reg_loc checks for buffer overrun */
			readLen = 0;
			printk("%s: Dumping Register section...\n", __func__);
			break;
		}

		if ((blockLength - amountRead) >= readLen) {
			if (pos == REGISTER_LOCATION)
				result = ol_diag_read_reg_loc(scn, bufferLoc,
						blockLength - amountRead);
			else
				result = ol_diag_read(scn, bufferLoc,
						      pos, readLen);
			if (result != -EIO) {
				amountRead += result;
				bufferLoc += result;
				sectionCount++;
			} else {
#ifdef CONFIG_HL_SUPPORT
#else
				printk(KERN_ERR "Could not read dump section!\n");
				dump_CE_register(scn);
				dump_CE_debug_register(scn->hif_sc);
				ret = -EACCES;
#endif
				break; /* Could not read the section */
			}
		} else {
			printk(KERN_ERR "Insufficient room in dump buffer!\n");
			break; /* Insufficient room in buffer */
		}
	}
	return ret;
}
#endif
#endif

#if defined(CONFIG_HL_SUPPORT)
#define MAX_SUPPORTED_PEERS_REV1_1 8
#define MAX_SUPPORTED_PEERS_REV1_3 8
#else
#define MAX_SUPPORTED_PEERS_REV1_1 14
#define MAX_SUPPORTED_PEERS_REV1_3 32
#endif

u_int8_t ol_get_number_of_peers_supported(struct ol_softc *scn)
{
	u_int8_t max_no_of_peers = 0;

	switch (scn->target_version) {
		case AR6320_REV1_1_VERSION:
		case AR6320_REV2_1_VERSION:
			if(scn->max_no_of_peers > MAX_SUPPORTED_PEERS_REV1_1)
				max_no_of_peers = MAX_SUPPORTED_PEERS_REV1_1;
			else
				max_no_of_peers = scn->max_no_of_peers;
			break;

		default:
			if(scn->max_no_of_peers > MAX_SUPPORTED_PEERS_REV1_3)
				max_no_of_peers = MAX_SUPPORTED_PEERS_REV1_3;
			else
				max_no_of_peers = scn->max_no_of_peers;
			break;

	}
	return max_no_of_peers;
}

#ifdef HIF_SDIO
/*Setting SDIO block size, mbox ISR yield limit for SDIO based HIF*/
static A_STATUS
ol_sdio_extra_initialization(struct ol_softc *scn)
{

	A_STATUS status;

#ifdef CONFIG_DISABLE_SLEEP_BMI_OPTION
	uint32 value;
#endif

	do{
		A_UINT32 blocksizes[HTC_MAILBOX_NUM_MAX];
		unsigned int MboxIsrYieldValue = 99;
		A_UINT32 TargetType = TARGET_TYPE_AR6320;
		/* get the block sizes */
		status = HIFConfigureDevice(scn->hif_hdl, HIF_DEVICE_GET_MBOX_BLOCK_SIZE,
									blocksizes, sizeof(blocksizes));

		if (A_FAILED(status)) {
			printk("Failed to get block size info from HIF layer...\n");
			break;
		}
			/* note: we actually get the block size for mailbox 1, for SDIO the block
						size on mailbox 0 is artificially set to 1 must be a power of 2 */
		A_ASSERT((blocksizes[1] & (blocksizes[1] - 1)) == 0);

		/* set the host interest area for the block size */
		status = BMIWriteMemory(scn->hif_hdl,
					HOST_INTEREST_ITEM_ADDRESS(TargetType, hi_mbox_io_block_sz),
					(A_UCHAR *)&blocksizes[1],
					4,
					scn);

		if (A_FAILED(status)) {
			printk("BMIWriteMemory for IO block size failed \n");
			break;
		}

		if (MboxIsrYieldValue != 0) {
				/* set the host interest area for the mbox ISR yield limit */
			status = BMIWriteMemory(scn->hif_hdl,
						HOST_INTEREST_ITEM_ADDRESS(TargetType,
						hi_mbox_isr_yield_limit),
						(A_UCHAR *)&MboxIsrYieldValue,
						4,
						scn);

			if (A_FAILED(status)) {
				printk("BMIWriteMemory for yield limit failed \n");
				break;
			}
		}

#ifdef CONFIG_DISABLE_SLEEP_BMI_OPTION

		printk("%s: prevent ROME from sleeping\n",__func__);
		BMIReadSOCRegister(scn->hif_hdl,
			MBOX_BASE_ADDRESS + LOCAL_SCRATCH_OFFSET,
			/* this address should be 0x80C0 for ROME*/
			&value,
			scn);

		value |= SOC_OPTION_SLEEP_DISABLE;

		BMIWriteSOCRegister(scn->hif_hdl,
			MBOX_BASE_ADDRESS + LOCAL_SCRATCH_OFFSET,
			value,
			scn);
#endif

	}while(FALSE);

	return status;
}
#endif
