/*
* Copyright (c) 2012-2013 Qualcomm Atheros, Inc.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

/*===========================================================================

                                dfs_phyerr.h

  OVERVIEW:

  Source code borrowed from QCA_MAIN DFS module

  DEPENDENCIES:

  Are listed for each API below.

===========================================================================*/

/*===========================================================================

                      EDIT HISTORY FOR FILE


  This section contains comments describing changes made to the module.
  Notice that changes are listed in reverse chronological order.



  when        who     what, where, why
----------    ---    --------------------------------------------------------

===========================================================================*/

#ifndef  __DFS_PHYERR_H__
#define  __DFS_PHYERR_H__

extern   int dfs_process_phyerr_bb_tlv(struct ath_dfs *dfs, void *buf,
       u_int16_t datalen, u_int8_t rssi, u_int8_t ext_rssi,
       u_int32_t rs_tstamp, u_int64_t fulltsf, struct dfs_phy_err *e);

#endif   /* __DFS_PHYERR_H__ */
