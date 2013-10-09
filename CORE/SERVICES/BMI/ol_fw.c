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

#include <linux/firmware.h>
#include "ol_if_athvar.h"
#include "ol_fw.h"
#include "targaddrs.h"
#include "bmi.h"
#include "ol_cfg.h"
#include "vos_api.h"
#include "wma_api.h"
#include "wma.h"

#define ATH_MODULE_NAME bmi
#include "a_debug.h"
#include "fw_one_bin.h"
#include "bin_sig.h"

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

		switch (one_bin_header->chip_id)
		{
		default:
			fw_sign = FALSE;
			break;
		case AR6320_1_0_CHIP_ID:
			fw_sign = FALSE;
			break;
		case AR6320_1_1_CHIP_ID:
			fw_sign = TRUE;
			break;
		}

		if (fw_sign)
		{
			if (binary_len < sizeof(SIGN_HEADER_T))
			{
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("%s: sign header size is error: bin id: %d, bin len: %d, sign header size: %d \n",
					__func__, one_bin_header->binary_id,
					one_bin_header->binary_len,
					sizeof(SIGN_HEADER_T)));
				status = A_ERROR;
				goto exit;
			}
			sign_header = (SIGN_HEADER_T *)(u_int8_t *)fw_entry_data
					+ binary_offset;

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

		if (one_bin_header->action == ACTION_DOWNLOAD_EXEC)
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
		filename = QCA_OTP_FILE;
		break;
	case ATH_FIRMWARE_FILE:
#ifdef QCA_WIFI_FTM
		if (vos_get_conparam() == VOS_FTM_MODE) {
			filename = QCA_UTF_FIRMWARE_FILE;
			printk(KERN_INFO "%s: Loading firmware file %s\n",
			       __func__, filename);
			break;
		}
#endif
		filename = QCA_FIRMWARE_FILE;
		break;
	case ATH_PATCH_FILE:
		printk("%s: no Patch file defined\n", __func__);
		return EOK;
	case ATH_BOARD_DATA_FILE:
		filename = QCA_BOARD_DATA_FILE;
		break;
	}

	if (request_firmware(&fw_entry, filename, scn->sc_osdev->device) != 0)
	{
		printk("%s: Failed to get %s\n", __func__, filename);

		if (file == ATH_OTP_FILE)
			return -ENOENT;
		return -1;
	}

	fw_entry_size = fw_entry->size;
	tempEeprom = NULL;

	if (file == ATH_BOARD_DATA_FILE && fw_entry->data)
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

			if (status != EOK) {
				printk("%s: BMI operation failed: %d\n", __func__, __LINE__);
				release_firmware(fw_entry);
				return -1;
			}

			/* Record the fact that extended board Data IS initialized */
			param = (board_ext_data_size << 16) | 1;
			BMIWriteMemory(scn->hif_hdl,
					HOST_INTEREST_ITEM_ADDRESS(scn->target_type, hi_board_ext_data_config),
					(u_int8_t *)&param, 4, scn);

			fw_entry_size = board_data_size;
		}
	}

	if (compressed) {
		status = BMIFastDownload(scn->hif_hdl, address, (u_int8_t *)fw_entry->data, fw_entry_size, scn);
	} else {
		if (file==ATH_BOARD_DATA_FILE && fw_entry->data) {
			status = BMIWriteMemory(scn->hif_hdl, address, (u_int8_t *)tempEeprom, fw_entry_size, scn);
		} else {
			status = BMIWriteMemory(scn->hif_hdl, address, (u_int8_t *)fw_entry->data, fw_entry_size, scn);
		}
	}

	if (tempEeprom) {
		OS_FREE(tempEeprom);
	}

	if (status != EOK) {
		printk("BMI operation failed: %d\n", __LINE__);
		release_firmware(fw_entry);
		return -1;
	}

	release_firmware(fw_entry);

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
		return (AR6320_HOST_INTEREST_ADDRESS + item_offset);
	}
}

#define REGISTER_DUMP_LEN_MAX   60
#define REG_DUMP_COUNT		60

void ol_target_failure(void *instance, A_STATUS status)
{
	struct ol_softc *scn = (struct ol_softc *)instance;
	A_UINT32 reg_dump_area = 0;
	A_UINT32 reg_dump_values[REGISTER_DUMP_LEN_MAX];
	A_UINT32 reg_dump_cnt = 0;
	A_UINT32 i;
	A_UINT32 dbglog_hdr_address;
	struct dbglog_hdr_s dbglog_hdr;
	struct dbglog_buf_s dbglog_buf;
	struct dbglog_hdr_host dbglog_hdr_temp;
	struct dbglog_buf_host dbglog_buf_temp;
	A_UINT8 *dbglog_data;
	void *vos_context = vos_get_global_context(VOS_MODULE_ID_WDA, NULL);
	tp_wma_handle wma = vos_get_context(VOS_MODULE_ID_WDA, vos_context);

	printk("XXX TARGET ASSERTED XXX\n");
	scn->target_status = OL_TRGET_STATUS_RESET;
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
	            (A_UCHAR *)&dbglog_hdr_temp,
	            sizeof(dbglog_hdr_temp))!= A_OK)
	{
	    printk("HifDiagReadiMem FW dbglog_hdr failed\n");
	    return;
	}

	dbglog_hdr.dbuf = (struct dbglog_buf_s *)dbglog_hdr_temp.dbuf;
	dbglog_hdr.dropped = dbglog_hdr_temp.dropped;

	if (HIFDiagReadMem(scn->hif_hdl,
	            (A_UINT32)dbglog_hdr.dbuf,
	            (A_UCHAR *)&dbglog_buf_temp,
	            sizeof(dbglog_buf_temp))!= A_OK)
	{
	    printk("HifDiagReadiMem FW dbglog_buf failed\n");
	    return;
	}

	dbglog_buf.next = (struct dbglog_buf_s *)dbglog_buf_temp.next;
	dbglog_buf.buffer = (A_UINT8 *)dbglog_buf_temp.buffer;
	dbglog_buf.bufsize = dbglog_buf_temp.bufsize;
	dbglog_buf.length = dbglog_buf_temp.length;
	dbglog_buf.count = dbglog_buf_temp.count;
	dbglog_buf.free = dbglog_buf_temp.free;

	dbglog_data = adf_os_mem_alloc(scn->adf_dev,  dbglog_buf.length + 4);
	if (dbglog_data) {
	    if (HIFDiagReadMem(scn->hif_hdl,
	                (A_UINT32)dbglog_buf.buffer,
	                dbglog_data + 4,
	                dbglog_buf.length)!= A_OK)
	    {
	        printk("HifDiagReadiMem FW dbglog_data failed\n");
	    } else {
	        printk("dbglog_hdr.dbuf=%p dbglog_data=%p dbglog_buf.buffer=%p dbglog_buf.length=%u\n",
	                dbglog_hdr.dbuf, dbglog_data, dbglog_buf.buffer, dbglog_buf.length);


	        OS_MEMCPY(dbglog_data, &dbglog_hdr.dropped, 4);
		wma->is_fw_assert = 1;
	        (void)dbglog_parse_debug_logs(wma, dbglog_data, dbglog_buf.length + 4);
	    }

	    adf_os_mem_free(dbglog_data);
	}

	return;
}

int
ol_configure_target(struct ol_softc *scn)
{
	u_int32_t param;

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

int ol_download_firmware(struct ol_softc *scn)
{
	u_int32_t param, address = 0;
	int status = !EOK;

	/* Transfer Board Data from Target EEPROM to Target RAM */
	/* Determine where in Target RAM to write Board Data */
	BMIReadMemory(scn->hif_hdl,
			host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_board_data)),
			(u_int8_t *)&address, 4, scn);

	if (!address) {
		address = AR6004_REV5_BOARD_DATA_ADDRESS;
		printk("%s: Target address not known! Using 0x%x\n", __func__, address);
	}

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
		if ((scn->target_version == AR6320_REV1_VERSION) || (scn->target_version == AR6320_REV1_1_VERSION))
			param = 6;
		else
			/* Configure GPIO AR9888 UART */
			param = 7;
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

	return EOK;
}
