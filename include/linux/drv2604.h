/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */
#ifndef _DRV2604_H_
#define _DRV2604_H_

#ifdef CONFIG_TSPDRV
void drv2604_disable_haptics(void);
void drv2604_enable_haptics(void);
#else
static inline void drv2604_disable_haptics(void)
{
}
static inline void drv2604_enable_haptics(void)
{
}
#endif

#endif /* _DRV2604_H_ */
