/*
 * Copyright (c) 2013-2014, 2016, 2018 The Linux Foundation. All rights reserved.
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

/*============================================================================
 * @file wlan_hdd_wowl.c
 *
 *
 * ==========================================================================*/

/*----------------------------------------------------------------------------
 * Include Files
 * -------------------------------------------------------------------------*/

#include <wlan_hdd_includes.h>
#include <wlan_hdd_wowl.h>

/*----------------------------------------------------------------------------
 * Preprocessor Definitions and Constants
 * -------------------------------------------------------------------------*/
#define WOWL_INTER_PTRN_TOKENIZER   ';'
#define WOWL_INTRA_PTRN_TOKENIZER   ':'

/*----------------------------------------------------------------------------
 * Type Declarations
 * -------------------------------------------------------------------------*/

static char *g_hdd_wowl_ptrns[WOWL_MAX_PTRNS_ALLOWED];
static v_BOOL_t g_hdd_wowl_ptrns_debugfs[WOWL_MAX_PTRNS_ALLOWED] = {0};
static v_U8_t g_hdd_wowl_ptrns_count = 0;

int hdd_parse_hex(unsigned char c)
{
  if (c >= '0' && c <= '9')
    return c-'0';
  if (c >= 'a' && c <= 'f')
    return c-'a'+10;
  if (c >= 'A' && c <= 'F')
    return c-'A'+10;

  return 0;
}

static inline int find_ptrn_len(const char* ptrn)
{
  int len = 0;
  while (*ptrn != '\0' && *ptrn != WOWL_INTER_PTRN_TOKENIZER)
  {
    len++; ptrn++;
  }
  return len;
}

static void hdd_wowl_callback( void *pContext, eHalStatus halStatus )
{
  VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO,
      "%s: Return code = (%d)", __func__, halStatus );
}

#ifdef WLAN_WAKEUP_EVENTS
static void hdd_wowl_wakeIndication_callback( void *pContext,
    tpSirWakeReasonInd pWakeReasonInd )
{
  VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO, "%s: Wake Reason %d",
      __func__, pWakeReasonInd->ulReason );
  hdd_exit_wowl((hdd_adapter_t *)pContext);
}
#endif

static void dump_hdd_wowl_ptrn(tSirWowlAddBcastPtrn *ptrn)
{
  int i;

  VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO, "%s: ucPatetrnId = 0x%x", __func__,
      ptrn->ucPatternId);
  VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO, "%s: ucPatternByteOffset = 0x%x", __func__,
      ptrn->ucPatternByteOffset);
  VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO, "%s: ucPatternSize = 0x%x", __func__,
      ptrn->ucPatternSize);
  VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO, "%s: ucPatternMaskSize = 0x%x", __func__,
      ptrn->ucPatternMaskSize);
  VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO, "%s: Pattern: ", __func__);
  for(i = 0; i < ptrn->ucPatternSize; i++)
     VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO," %02X", ptrn->ucPattern[i]);
  VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO, "%s: PatternMask: ", __func__);
  for(i = 0; i<ptrn->ucPatternMaskSize; i++)
     VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO,"%02X", ptrn->ucPatternMask[i]);
}


/**============================================================================
  @brief hdd_add_wowl_ptrn() - Function which will add the WoWL pattern to be
  used when PBM filtering is enabled

  @param ptrn : [in]  pointer to the pattern string to be added

  @return     : FALSE if any errors encountered
              : TRUE otherwise
  ===========================================================================*/
v_BOOL_t hdd_add_wowl_ptrn (hdd_adapter_t *pAdapter, const char * ptrn)
{
  tSirWowlAddBcastPtrn localPattern;
  int i, first_empty_slot, len, offset;
  eHalStatus halStatus;
  const char *temp;
  tHalHandle hHal = WLAN_HDD_GET_HAL_CTX(pAdapter);
  v_U8_t sessionId = pAdapter->sessionId;
  unsigned char invalid_ptrn = 0;

  len = find_ptrn_len(ptrn);

  /* There has to have atleast 1 byte for each field (pattern size, mask size,
   * pattern, mask) e.g. PP:QQ:RR:SS ==> 11 chars */
  while ( len >= 11 )
  {
    // Detect duplicate pattern
    for (i=0; i<WOWL_MAX_PTRNS_ALLOWED; i++) {
      if (g_hdd_wowl_ptrns[i] == NULL) continue;

      if (strlen(g_hdd_wowl_ptrns[i]) == len) {
        if (!memcmp(ptrn, g_hdd_wowl_ptrns[i], len)) {
          // Pattern Already configured, skip to next pattern
          VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
              "Trying to add duplicate WoWL pattern. Skip it!");
          ptrn += len;
          goto next_ptrn;
        }
      }
    }

    first_empty_slot = -1;

    // Find an empty slot to store the pattern
    for (i=0; i<WOWL_MAX_PTRNS_ALLOWED; i++) {
      if (g_hdd_wowl_ptrns[i] == NULL) {
        first_empty_slot = i;
        break;
      }
    }

    // Maximum number of patterns have been configured already
    if (first_empty_slot == -1) {
      VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
          "%s: Cannot add anymore patterns. No free slot!", __func__);
      return VOS_FALSE;
    }

    //Validate the pattern
    if (ptrn[2] != WOWL_INTRA_PTRN_TOKENIZER ||
        ptrn[5] != WOWL_INTRA_PTRN_TOKENIZER) {
      VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
          "%s: Malformed pattern string. Skip!", __func__);
      invalid_ptrn = 1;
      ptrn += len;
      goto next_ptrn;
    }

    // Extract the pattern size
    localPattern.ucPatternSize =
      ( hdd_parse_hex( ptrn[0] ) * 0x10 ) + hdd_parse_hex( ptrn[1] );

    // Extract the pattern mask size
    localPattern.ucPatternMaskSize =
      ( hdd_parse_hex( ptrn[3] ) * 0x10 ) + hdd_parse_hex( ptrn[4] );

    if (localPattern.ucPatternSize > SIR_WOWL_BCAST_PATTERN_MAX_SIZE ||
        localPattern.ucPatternMaskSize > WOWL_PTRN_MASK_MAX_SIZE) {
      VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
          "%s: Invalid length specified. Skip!", __func__);
      invalid_ptrn = 1;
      ptrn += len;
      goto next_ptrn;
    }

    //compute the offset of tokenizer after the pattern
    offset = 5 + 2*localPattern.ucPatternSize + 1;
    if (offset >= len || ptrn[offset] != WOWL_INTRA_PTRN_TOKENIZER) {
      VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
          "%s: Malformed pattern string..skip!", __func__);
      invalid_ptrn = 1;
      ptrn += len;
      goto next_ptrn;
    }

    /* Compute the end of pattern string */
    offset = offset + 2*localPattern.ucPatternMaskSize;
    if (offset+1 != len) { //offset begins with 0
      VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
          "%s: Malformed pattern string...skip!", __func__);
      invalid_ptrn = 1;
      ptrn += len;
      goto next_ptrn;
    }

    temp = ptrn;

    // Now advance to where pattern begins
    ptrn += 6;

    // Extract the pattern
    for (i=0; i < localPattern.ucPatternSize; i++) {
      localPattern.ucPattern[i] =
        (hdd_parse_hex( ptrn[0] ) * 0x10 ) + hdd_parse_hex( ptrn[1] );
      ptrn += 2; //skip to next byte
    }

    ptrn++; /* Skip over the ':' separator after the pattern */

    // Extract the pattern Mask
    for (i=0; i < localPattern.ucPatternMaskSize; i++) {
      localPattern.ucPatternMask[i] =
        (hdd_parse_hex( ptrn[0] ) * 0x10 ) + hdd_parse_hex( ptrn[1] );
      ptrn += 2; //skip to next byte
    }

    //All is good. Store the pattern locally
    g_hdd_wowl_ptrns[first_empty_slot] = (char*) vos_mem_malloc(len+1);
    if (g_hdd_wowl_ptrns[first_empty_slot] == NULL) {
      VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
          "%s: kmalloc failure", __func__);
      return VOS_FALSE;
    }

    memcpy(g_hdd_wowl_ptrns[first_empty_slot], temp, len);
    g_hdd_wowl_ptrns[first_empty_slot][len] = '\0';
    localPattern.ucPatternId = first_empty_slot;
    localPattern.ucPatternByteOffset = 0;
    localPattern.sessionId = sessionId;

    // Register the pattern downstream
    halStatus = sme_WowlAddBcastPattern( hHal, &localPattern, sessionId );
    if ( !HAL_STATUS_SUCCESS( halStatus ) )
    {
      // Add failed, so invalidate the local storage
      VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
          "sme_WowlAddBcastPattern failed with error code (%d)", halStatus );
      vos_mem_free(g_hdd_wowl_ptrns[first_empty_slot]);
      g_hdd_wowl_ptrns[first_empty_slot] = NULL;
    }

    dump_hdd_wowl_ptrn(&localPattern);

 next_ptrn:
    if (*ptrn ==  WOWL_INTER_PTRN_TOKENIZER)
    {
      ptrn += 1; // move past the tokenizer
      len = find_ptrn_len(ptrn);
      continue;
    }
    else
      break;
  }

  if (invalid_ptrn)
    return VOS_FALSE;

  return VOS_TRUE;
}

/**============================================================================
  @brief hdd_del_wowl_ptrn() - Function which will remove a WoWL pattern

  @param ptrn : [in]  pointer to the pattern string to be removed

  @return     : FALSE if any errors encountered
              : TRUE otherwise
  ===========================================================================*/
v_BOOL_t hdd_del_wowl_ptrn (hdd_adapter_t *pAdapter, const char * ptrn)
{
  tSirWowlDelBcastPtrn delPattern;
  unsigned char id;
  tHalHandle hHal = WLAN_HDD_GET_HAL_CTX(pAdapter);
  v_BOOL_t patternFound = VOS_FALSE;
  eHalStatus halStatus;
  v_U8_t sessionId = pAdapter->sessionId;

  // Detect pattern
  for (id=0; id<WOWL_MAX_PTRNS_ALLOWED && g_hdd_wowl_ptrns[id] != NULL; id++)
  {
    if(!strcmp(ptrn, g_hdd_wowl_ptrns[id]))
    {
      patternFound = VOS_TRUE;
      break;
    }
  }

  // If pattern present, remove it from downstream
  if(patternFound)
  {
    delPattern.ucPatternId = id;
    halStatus = sme_WowlDelBcastPattern( hHal, &delPattern, sessionId );
    if ( HAL_STATUS_SUCCESS( halStatus ) )
    {
      // Remove from local storage as well
      VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
          "Deleted pattern with id %d [%s]", id, g_hdd_wowl_ptrns[id]);

      vos_mem_free(g_hdd_wowl_ptrns[id]);
      g_hdd_wowl_ptrns[id] = NULL;
      return VOS_TRUE;
    }
  }
  return VOS_FALSE;
}

/**============================================================================
  @brief hdd_add_wowl_ptrn_debugfs() - Function which will add a WoW pattern
  sent from debugfs interface

  @param pAdapter       : [in] pointer to the adapter
         pattern_idx    : [in] index of the pattern to be added
         pattern_offset : [in] offset of the pattern in the frame payload
         pattern_buf    : [in] pointer to the pattern hex string to be added
         pattern_mask   : [in] pointer to the pattern mask hex string

  @return               : FALSE if any errors encountered
                        : TRUE otherwise
  ===========================================================================*/
v_BOOL_t hdd_add_wowl_ptrn_debugfs(hdd_adapter_t *pAdapter, v_U8_t pattern_idx,
                                   v_U8_t pattern_offset, char *pattern_buf,
                                   char *pattern_mask)
{
  tSirWowlAddBcastPtrn localPattern;
  eHalStatus halStatus;
  tHalHandle hHal = WLAN_HDD_GET_HAL_CTX(pAdapter);
  v_U8_t sessionId = pAdapter->sessionId;
  v_U16_t pattern_len, mask_len, i;

  if (pattern_idx > (WOWL_MAX_PTRNS_ALLOWED - 1))
  {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
               "%s: WoW pattern index %d is out of range (0 ~ %d).",
               __func__, pattern_idx, WOWL_MAX_PTRNS_ALLOWED - 1);

    return VOS_FALSE;
  }

  pattern_len = strlen(pattern_buf);

  /* Since the pattern is a hex string, 2 characters represent 1 byte. */
  if (pattern_len % 2)
  {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
               "%s: Malformed WoW pattern!", __func__);

    return VOS_FALSE;
  }
  else
    pattern_len >>= 1;

  if (!pattern_len || pattern_len > WOWL_PTRN_MAX_SIZE)
  {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
               "%s: WoW pattern length %d is out of range (1 ~ %d).",
               __func__, pattern_len, WOWL_PTRN_MAX_SIZE);

    return VOS_FALSE;
  }

  localPattern.ucPatternId = pattern_idx;
  localPattern.ucPatternByteOffset = pattern_offset;
  localPattern.ucPatternSize = pattern_len;
  localPattern.sessionId = sessionId;

  if (localPattern.ucPatternSize > SIR_WOWL_BCAST_PATTERN_MAX_SIZE) {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
             "%s: WoW pattern size (%d) greater than max (%d)",
             __func__, localPattern.ucPatternSize,
             SIR_WOWL_BCAST_PATTERN_MAX_SIZE);
    return VOS_FALSE;
  }
  /* Extract the pattern */
  for (i = 0; i < localPattern.ucPatternSize; i++)
  {
    localPattern.ucPattern[i] =
      (hdd_parse_hex(pattern_buf[0]) << 4) + hdd_parse_hex(pattern_buf[1]);

    /* Skip to next byte */
    pattern_buf += 2;
  }

  /* Get pattern mask size by pattern length */
  localPattern.ucPatternMaskSize = pattern_len >> 3;
  if (pattern_len % 8)
    localPattern.ucPatternMaskSize += 1;

  mask_len = strlen(pattern_mask);
  if ((mask_len % 2) || (localPattern.ucPatternMaskSize != (mask_len >> 1)))
  {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
               "%s: Malformed WoW pattern mask!", __func__);

    return VOS_FALSE;
  }
  if (localPattern.ucPatternMaskSize > WOWL_PTRN_MASK_MAX_SIZE) {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
             "%s: WoW pattern mask size (%d) greater than max (%d)",
             __func__, localPattern.ucPatternMaskSize, WOWL_PTRN_MASK_MAX_SIZE);
    return VOS_FALSE;
  }
  /* Extract the pattern mask */
  for (i = 0; i < localPattern.ucPatternMaskSize; i++)
  {
    localPattern.ucPatternMask[i] =
      (hdd_parse_hex(pattern_mask[0]) << 4) + hdd_parse_hex(pattern_mask[1]);

    /* Skip to next byte */
    pattern_mask += 2;
  }

  /* Register the pattern downstream */
  halStatus = sme_WowlAddBcastPattern(hHal, &localPattern, sessionId);

  if (!HAL_STATUS_SUCCESS(halStatus))
  {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
               "%s: sme_WowlAddBcastPattern failed with error code (%d).",
               __func__, halStatus);

    return VOS_FALSE;
  }

  /* All is good. */
  if (!g_hdd_wowl_ptrns_debugfs[pattern_idx])
  {
    g_hdd_wowl_ptrns_debugfs[pattern_idx] = 1;
    g_hdd_wowl_ptrns_count++;
  }

  dump_hdd_wowl_ptrn(&localPattern);

  return VOS_TRUE;
}

/**============================================================================
  @brief hdd_del_wowl_ptrn_debugfs() - Function which will remove a WoW pattern
  sent from debugfs interface

  @param pAdapter    : [in] pointer to the adapter
         pattern_idx : [in] index of the pattern to be removed

  @return            : FALSE if any errors encountered
                     : TRUE otherwise
  ===========================================================================*/
v_BOOL_t hdd_del_wowl_ptrn_debugfs(hdd_adapter_t *pAdapter, v_U8_t pattern_idx)
{
  tSirWowlDelBcastPtrn delPattern;
  tHalHandle hHal = WLAN_HDD_GET_HAL_CTX(pAdapter);
  eHalStatus halStatus;
  v_U8_t sessionId = pAdapter->sessionId;

  if (pattern_idx > (WOWL_MAX_PTRNS_ALLOWED - 1))
  {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
               "%s: WoW pattern index %d is not in the range (0 ~ %d).",
               __func__, pattern_idx, WOWL_MAX_PTRNS_ALLOWED - 1);

    return VOS_FALSE;
  }

  if (!g_hdd_wowl_ptrns_debugfs[pattern_idx])
  {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
               "%s: WoW pattern %d is not in the table.",
               __func__, pattern_idx);

    return VOS_FALSE;
  }

  delPattern.ucPatternId = pattern_idx;
  halStatus = sme_WowlDelBcastPattern(hHal, &delPattern, sessionId);

  if (!HAL_STATUS_SUCCESS(halStatus))
  {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
               "%s: sme_WowlDelBcastPattern failed with error code (%d).",
               __func__, halStatus);

    return VOS_FALSE;
  }

  g_hdd_wowl_ptrns_debugfs[pattern_idx] = 0;
  g_hdd_wowl_ptrns_count--;

  return VOS_TRUE;
}

/**============================================================================
  @brief hdd_enter_wowl() - Function which will enable WoWL. Atleast one
  of MP and PBM must be enabled

  @param enable_mp  : [in] Whether to enable magic packet WoWL mode
  @param enable_pbm : [in] Whether to enable pattern byte matching WoWL mode

  @return           : FALSE if any errors encountered
                    : TRUE otherwise
  ===========================================================================*/
v_BOOL_t hdd_enter_wowl (hdd_adapter_t *pAdapter, v_BOOL_t enable_mp, v_BOOL_t enable_pbm)
{
  tSirSmeWowlEnterParams wowParams;
  eHalStatus halStatus;
  tHalHandle hHal = WLAN_HDD_GET_HAL_CTX(pAdapter);

  vos_mem_zero( &wowParams, sizeof( tSirSmeWowlEnterParams));

  wowParams.ucPatternFilteringEnable = enable_pbm;
  wowParams.ucMagicPktEnable = enable_mp;
  wowParams.sessionId = pAdapter->sessionId;
  if(enable_mp)
  {
    vos_copy_macaddr( (v_MACADDR_t *)&(wowParams.magicPtrn),
                    &(pAdapter->macAddressCurrent) );
  }

#ifdef WLAN_WAKEUP_EVENTS
  wowParams.ucWoWEAPIDRequestEnable = VOS_TRUE;
  wowParams.ucWoWEAPOL4WayEnable = VOS_TRUE;
  wowParams.ucWowNetScanOffloadMatch = VOS_TRUE;
  wowParams.ucWowGTKRekeyError = VOS_TRUE;
  wowParams.ucWoWBSSConnLoss = VOS_TRUE;
#endif // WLAN_WAKEUP_EVENTS


  // Request to put Libra into WoWL
  halStatus = sme_EnterWowl( hHal, hdd_wowl_callback,
                             pAdapter,
#ifdef WLAN_WAKEUP_EVENTS
                             hdd_wowl_wakeIndication_callback,
                             pAdapter,
#endif // WLAN_WAKEUP_EVENTS
                             &wowParams, pAdapter->sessionId);

  if ( !HAL_STATUS_SUCCESS( halStatus ) )
  {
    if ( eHAL_STATUS_PMC_PENDING != halStatus )
    {
      // We failed to enter WoWL
      VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
          "sme_EnterWowl failed with error code (%d)", halStatus );
      return VOS_FALSE;
    }
  }
  return VOS_TRUE;
}

/**============================================================================
  @brief hdd_exit_wowl() - Function which will disable WoWL

  @return           : FALSE if any errors encountered
                    : TRUE otherwise
  ===========================================================================*/
v_BOOL_t hdd_exit_wowl (hdd_adapter_t*pAdapter)
{
  tSirSmeWowlExitParams wowParams;
  tHalHandle hHal = WLAN_HDD_GET_HAL_CTX(pAdapter);
  eHalStatus halStatus;

  wowParams.sessionId = pAdapter->sessionId;

  halStatus = sme_ExitWowl( hHal, &wowParams);
  if ( !HAL_STATUS_SUCCESS( halStatus ) )
  {
    VOS_TRACE( VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
      "sme_ExitWowl failed with error code (%d)", halStatus );
    return VOS_FALSE;
  }

  return VOS_TRUE;
}

/**============================================================================
  @brief hdd_init_wowl() - Init function which will initialize the WoWL module
  and perform any required initial configuration

  @return           : FALSE if any errors encountered
                    : TRUE otherwise
  ===========================================================================*/
v_BOOL_t hdd_init_wowl (hdd_adapter_t*pAdapter)
{
  hdd_context_t *pHddCtx = NULL;
  pHddCtx = pAdapter->pHddCtx;

  memset(g_hdd_wowl_ptrns, 0, sizeof(g_hdd_wowl_ptrns));

  //Add any statically configured patterns
  hdd_add_wowl_ptrn(pAdapter, pHddCtx->cfg_ini->wowlPattern);

  return VOS_TRUE;
}

#ifdef FEATURE_PBM_MAGIC_WOW
/**
 * struct easy_wow_wake_source - a record of wakeup source
 * @valid: wakeup source valid/invalid
 * @flags: status of this record
 * @ip_ver: ip version of this record
 * @proto: proto type of this record
 * @offset: optional data len between ip head and proto head
 * @src_port: source port to wakeup, 0 means not compare
 * @dst_port: destination port to wakeup, 0 means not compare
 */
struct easy_wow_wake_source
{
	uint8_t valid;
	uint8_t flags;
	uint8_t ip_ver;
	uint8_t proto;
	uint8_t offset;
	uint16_t src_port;
	uint16_t dst_port;
};

/**
 * struct easy_wow_context - save easy wow context
 * @easy_wow_cache: wakeup source records saved in context
 * @pattern_data: pattern data to be set
 * @data_len: pattern data len to be set
 * @pattern_mask: pattern mask to be set
 * @mask_len: pattern mask len to be set
 */
struct easy_wow_context
{
	struct easy_wow_wake_source easy_wow_cache[MAX_PATTERN_NUMBER];
	uint8_t pattern_data[MAX_PATTERN_DATA_LEN];
	uint8_t data_len;
	uint8_t pattern_mask[MAX_PATTERN_MASK_LEN];
	uint8_t mask_len;
};

VOS_STATUS hdd_easy_wow_init(hdd_context_t *hdd_ctx)
{
	if (MAX_PATTERN_NUMBER + WOWL_MAX_PTRNS_ALLOWED >
			hdd_ctx->cfg_ini->maxWoWFilters) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "wow filter number config err %d+%d>%d",
			  MAX_PATTERN_NUMBER, WOWL_MAX_PTRNS_ALLOWED,
			  hdd_ctx->cfg_ini->maxWoWFilters);
		return VOS_STATUS_E_INVAL;
	}

	hdd_ctx->easy_wow_ctx = vos_mem_malloc(sizeof(struct easy_wow_context));
	if (!hdd_ctx->easy_wow_ctx) {
		return VOS_STATUS_E_NOMEM;
	}
	vos_mem_set(hdd_ctx->easy_wow_ctx, sizeof(struct easy_wow_context), 0);
	return VOS_STATUS_SUCCESS;
}

void hdd_easy_wow_deinit(hdd_context_t *hdd_ctx)
{
	if (hdd_ctx->easy_wow_ctx) {
		vos_mem_free(hdd_ctx->easy_wow_ctx);
		hdd_ctx->easy_wow_ctx = NULL;
	}
}

static VOS_STATUS
easy_wow_save_unique(hdd_context_t *hdd_ctx, uint8_t ipv, uint8_t proto,
		     uint8_t offset, uint16_t src_port, uint16_t dst_port,
		     uint8_t *ptrn_id)
{
	uint32_t i;
	int32_t first_empty_slot = -1;
	struct easy_wow_context *ewc = hdd_ctx->easy_wow_ctx;

	for (i = 0; i < ARRAY_LENGTH(ewc->easy_wow_cache); i++) {
		if (!ewc->easy_wow_cache[i].valid) {
			if (first_empty_slot == -1)
				first_empty_slot = i;
			continue;
		}
		if (ipv != ewc->easy_wow_cache[i].ip_ver)
			continue;
		if (proto != ewc->easy_wow_cache[i].proto)
			continue;
		if (offset != ewc->easy_wow_cache[i].offset)
			continue;
		if (src_port != ewc->easy_wow_cache[i].src_port)
			continue;
		if (dst_port != ewc->easy_wow_cache[i].dst_port)
			continue;
		return VOS_STATUS_E_EXISTS;
	}
	if (first_empty_slot == -1)
		return VOS_STATUS_E_RESOURCES;

	ewc->easy_wow_cache[first_empty_slot].ip_ver = ipv;
	ewc->easy_wow_cache[first_empty_slot].proto = proto;
	ewc->easy_wow_cache[first_empty_slot].offset = offset;
	ewc->easy_wow_cache[first_empty_slot].src_port = src_port;
	ewc->easy_wow_cache[first_empty_slot].dst_port = dst_port;
	ewc->easy_wow_cache[first_empty_slot].flags = 0;
	ewc->easy_wow_cache[first_empty_slot].valid = 1;
	if (ptrn_id)
		*ptrn_id = (uint8_t)first_empty_slot;
	return VOS_STATUS_SUCCESS;
}

static int32_t
easy_wow_find(hdd_context_t *hdd_ctx, uint8_t ipv, uint8_t proto,
	      uint8_t offset, uint16_t src_port, uint16_t dst_port)
{
	int32_t i;
	struct easy_wow_context *ewc = hdd_ctx->easy_wow_ctx;

	for (i = 0; i < ARRAY_LENGTH(ewc->easy_wow_cache); i++) {
		if (!ewc->easy_wow_cache[i].valid)
			continue;
		if (ipv == ewc->easy_wow_cache[i].ip_ver &&
		    proto == ewc->easy_wow_cache[i].proto &&
		    offset == ewc->easy_wow_cache[i].offset &&
		    src_port == ewc->easy_wow_cache[i].src_port &&
		    dst_port == ewc->easy_wow_cache[i].dst_port) {
			return i;
		}
	}
	return -1;
}

static VOS_STATUS
easy_wow_remove_unique(hdd_context_t *hdd_ctx, uint8_t ipv, uint8_t proto,
		       uint8_t offset, uint16_t src_port, uint16_t dst_port)
{
	int32_t i;
	struct easy_wow_context *ewc = hdd_ctx->easy_wow_ctx;

	i = easy_wow_find(hdd_ctx, ipv, proto, offset, src_port, dst_port);
	if (i > 0) {
		vos_mem_set(&ewc->easy_wow_cache[i],
			    sizeof(ewc->easy_wow_cache[i]), 0);
		return VOS_STATUS_SUCCESS;
	}
	return VOS_STATUS_E_FAILURE;
}

static void easy_wow_reset_pattern_match(struct easy_wow_context *ewc)
{
	vos_mem_set(ewc->pattern_data, sizeof(ewc->pattern_data), 0);
	ewc->data_len = 0;
	vos_mem_set(ewc->pattern_mask, sizeof(ewc->pattern_mask), 0);
	ewc->mask_len = 0;
}

static bool
easy_wow_set_pattern_match(struct easy_wow_context *ewc, uint32_t offset,
			   uint8_t *match_data, uint32_t match_len)
{
	uint32_t i, byte_order, bit_order;

	if (offset + match_len > MAX_PATTERN_DATA_LEN) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "Offset %d match %d check fail", offset, match_len);
		return false;
	}

	for (i = 0; i < match_len; i++) {
		ewc->pattern_data[offset + i] = match_data[i];
		byte_order = (offset + i) >> 3;
		bit_order = (offset + i) & 7;
		ewc->pattern_mask[byte_order] |= (1 << (7 - bit_order));
	}
	return true;
}

static bool
easy_wow_port_convert(hdd_context_t *hdd_ctx, bool ipv4, bool tcp_or_udp,
		      uint8_t offset, uint16_t src_port, uint16_t dst_port)
{
	uint8_t ipv4_eth_type[2] = {0x08, 0x00};
	uint8_t ipv6_eth_type[2] = {0x86, 0xdd};
	uint8_t proto_tcp[1] = {0x06};
	uint8_t proto_udp[1] = {0x11};
	uint16_t port;
	uint32_t byte_offset = 12; //Offset of EthII head ether type
	struct easy_wow_context *ewc = hdd_ctx->easy_wow_ctx;
	bool ret1 = true, ret2 = true, ret3 = true;

	easy_wow_reset_pattern_match(ewc);

	if (ipv4) {
		//ipv4 match
		easy_wow_set_pattern_match(ewc, byte_offset, ipv4_eth_type, 2);
		byte_offset += 2; //Offset of IPv4 head
		byte_offset += 9; //Offset of IPv4 proto type

		if (tcp_or_udp)
			ret1 = easy_wow_set_pattern_match(ewc, byte_offset,
							  proto_tcp, 1);
		else
			ret1 = easy_wow_set_pattern_match(ewc, byte_offset,
							  proto_udp, 1);

		byte_offset += 11; //Offset to IPv4 end
		/* Skip optional data, Offset to TCP/UDP head src port */
		byte_offset += offset;
		if (src_port) {
			port = vos_cpu_to_be16(src_port);
			ret2 = easy_wow_set_pattern_match(ewc, byte_offset,
							  (uint8_t *)&port, 2);
		}
		byte_offset += 2; //Offset to TCP/UDP head dst port
		if (dst_port) {
			port = vos_cpu_to_be16(dst_port);
			ret3 = easy_wow_set_pattern_match(ewc, byte_offset,
							  (uint8_t *)&port, 2);
		}
		byte_offset += 2; //Offset to TCP/UDP head dst port end
	} else {
		//ipv6 match
		easy_wow_set_pattern_match(ewc, byte_offset, ipv6_eth_type, 2);
		byte_offset += 2; //Offset of IPv6 head
		if (!offset) { //No offset means TCP/UDP head is next to IPv6 head
			byte_offset += 6; //Offset to next_hdr
			if (tcp_or_udp)
				ret1 = easy_wow_set_pattern_match(ewc,
								  byte_offset,
								  proto_tcp, 1);
			else
				ret1 = easy_wow_set_pattern_match(ewc,
								  byte_offset,
								  proto_udp, 1);

			byte_offset += 34; //Offset to TCP/UDP head src port
			if (src_port) {
				port = vos_cpu_to_be16(src_port);
				ret2 = easy_wow_set_pattern_match(
						ewc,
						byte_offset,
						(uint8_t *)&port,
						2);
			}
			byte_offset += 2; //Offset to TCP/UDP head dst port
			if (dst_port) {
				port = vos_cpu_to_be16(dst_port);
				ret3 = easy_wow_set_pattern_match(
						ewc,
						byte_offset,
						(uint8_t *)&port,
						2);
			}
		} else {
			byte_offset += 40; // Offset to IPv6 head end
			/* Skip extened head len, Offset to TCP/UDP head */
			byte_offset += offset;
			/*
			 * Limitation:can't tell where next_hdr of last
			 * extended header which is tcp/udp proto
			 */
			if (src_port) {
				port = vos_cpu_to_be16(src_port);
				ret1 = easy_wow_set_pattern_match(
						ewc,
						byte_offset,
						(uint8_t *)&port,
						2);
			}
			byte_offset += 2; //Offset to TCP/UDP head dst port
			if (dst_port) {
				port = vos_cpu_to_be16(dst_port);
				ret2 = easy_wow_set_pattern_match(
						ewc,
						byte_offset,
						(uint8_t *)&port,
						2);
			}
		}
		byte_offset += 2; //Offset to TCP/UDP head dst port end
	}

	ewc->data_len = byte_offset;
	ewc->mask_len = ((byte_offset)>>3) + 1;

	return ret1 && ret2 && ret3;
}

static bool hdd_post_easy_wow_to_wma(hdd_adapter_t *adapter, uint8_t ptrn_id)
{
	tHalHandle hal = WLAN_HDD_GET_HAL_CTX(adapter);
	eHalStatus hal_status;
	hdd_context_t *hdd_ctx = adapter->pHddCtx;
	struct easy_wow_context *ewc = hdd_ctx->easy_wow_ctx;
	tSirWowlAddBcastPtrn local_pattern;
	uint8_t session_id = adapter->sessionId;

	VOS_ASSERT(ewc->data_len <= sizeof(local_pattern.ucPattern));
	VOS_ASSERT(ewc->mask_len <= sizeof(local_pattern.ucPatternMask));

	local_pattern.ucPatternSize = ewc->data_len;
	local_pattern.ucPatternMaskSize = ewc->mask_len;
	vos_mem_copy(local_pattern.ucPattern, ewc->pattern_data, ewc->data_len);
	vos_mem_copy(local_pattern.ucPatternMask,
		     ewc->pattern_mask, ewc->mask_len);

	local_pattern.ucPatternByteOffset = 0;
	local_pattern.sessionId = session_id;
	local_pattern.ucPatternId = ptrn_id + EASY_WOW_PTRN_ID_BASE;

	dump_hdd_wowl_ptrn(&local_pattern);

	hal_status = sme_WowlAddBcastPattern(hal, &local_pattern, session_id);
	if (!HAL_STATUS_SUCCESS(hal_status)) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: failed with error code (%d)",
			  __func__, hal_status);
		return false;
	}
	return true;
}

bool
hdd_del_easy_wow_ptrn(hdd_adapter_t *adapter, uint32_t ipv, uint32_t proto,
		      uint32_t offset,uint32_t src_port, uint32_t dst_port)
{
	tSirWowlDelBcastPtrn del_pattern;
	hdd_context_t *hdd_ctx = adapter->pHddCtx;
	eHalStatus hal_status;
	tHalHandle hal = WLAN_HDD_GET_HAL_CTX(adapter);
	int32_t i;

	i = easy_wow_find(hdd_ctx, ipv, proto, offset, src_port, dst_port);

	if (i < 0) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "%s: Not found!", __func__);
		return false;
	}

	del_pattern.ucPatternId = i + EASY_WOW_PTRN_ID_BASE;
	hal_status = sme_WowlDelBcastPattern(hal,
					     &del_pattern,
					     adapter->sessionId);
	if (HAL_STATUS_SUCCESS(hal_status)) {
		easy_wow_remove_unique(hdd_ctx, ipv, proto, offset,
				       src_port, dst_port);
		return true;
	}
	VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
		  "%s: failed with error code (%d)",
		  __func__, hal_status);
	return false;
}

bool
hdd_add_easy_wow_ptrn(hdd_adapter_t *adapter, uint32_t ipv, uint32_t proto,
		      uint32_t offset, uint32_t src_port, uint32_t dst_port)
{
	hdd_context_t *hdd_ctx = adapter->pHddCtx;
	bool is_ipv4, tcp_or_udp, remove_at_last = false;
	VOS_STATUS status;
	uint8_t ptrn_id;

	if (ipv == 4)
		is_ipv4 = true;
	else if (ipv == 6)
		is_ipv4 = false;
	else
		goto invalid_param;

	if (proto == 6)
		tcp_or_udp = true;
	else if (proto == 17)
		tcp_or_udp = false;
	else
		goto invalid_param;

	if (offset)
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO,
			  "offset non zero %d", offset);

	if (offset + 34 > MAX_PATTERN_DATA_LEN)
		goto invalid_param;

	if (src_port > 65535 || dst_port > 65535 || (!src_port && !dst_port))
		goto invalid_param;

	//save it to context
	status = easy_wow_save_unique(hdd_ctx, (uint8_t)ipv, (uint8_t)proto,
				      (uint8_t)offset, (uint16_t)src_port,
				      (uint16_t)dst_port, &ptrn_id);
	if (status == VOS_STATUS_E_EXISTS) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_INFO,
			  "Port already exist");
		return true;
	} else if (status == VOS_STATUS_E_RESOURCES) {
		VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
			  "Port list full");
		return false;
	}

	if (!easy_wow_port_convert(hdd_ctx, is_ipv4, tcp_or_udp,
				   (uint8_t)offset, (uint16_t)src_port,
				   (uint16_t)dst_port)) {
		remove_at_last = true;
		goto invalid_param;
	}

	if (!hdd_post_easy_wow_to_wma(adapter, ptrn_id)) {
		remove_at_last = true;
		goto internal_err;
	}

	return true;

invalid_param:
	VOS_TRACE(VOS_MODULE_ID_HDD, VOS_TRACE_LEVEL_ERROR,
		  "Check input parameters");
internal_err:
	if (remove_at_last)
		easy_wow_remove_unique(hdd_ctx, (uint8_t)ipv, (uint8_t)proto,
				       (uint8_t)offset, (uint16_t)src_port,
				       (uint16_t)dst_port);
	return false;
}
#else
VOS_STATUS hdd_easy_wow_init(hdd_context_t *hdd_ctx)
{
	return VOS_STATUS_SUCCESS;
}
void hdd_easy_wow_deinit(hdd_context_t *hdd_ctx)
{
}
#endif
