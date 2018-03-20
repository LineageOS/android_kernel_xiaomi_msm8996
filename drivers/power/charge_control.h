/* Copyright (c) 2017-2018 Andrzej Perczak aka xNombre kartapolska@gmail.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __CHGCTL_KERNEL_H
#define __CHGCTL_KERNEL_H

#define module_version_major 2
#define module_version_minor 1

/* Documentation:
 * charge_limit: 0 - disabled, 1-99 - limit charging %, 100 -> full_charge_every=1
 * charging battery to 80% can increase its lifetime sginificantly
 * must be greater than recharge_at
 *
 * recharge_at: 0 - disabled, 1-99 - start charging again on given %
 * must be lower than charge_limit
 * 
 * maximum_qc_current: 900-3000 mAh
 * this could prevent issues with heating and broken hardware
 * 
 * force_fast_charge: 0/1 - enables charging up to 900mAh and higher current detection (on unknown sources)
 * 
 * full_charge_every: 0 - disabled, 1-100
 * this could help with battery 'calibration' issues as probably
 * charging the battery up to ~80% every time makes it to loss its actual value
 *  
 */
extern struct smbchg_chip *chip_pointer;

extern bool __read_mostly trigger_full_charge;
extern bool __read_mostly force_fast_charge;
extern int __read_mostly charge_limit;
extern int __read_mostly recharge_at;
extern int maximum_qc_current;
extern int full_charge_every;
extern int charges_counter;

extern void count_charge(void);
extern void finish_full_charge(void);
int smbchg_set_fastchg_current_user(struct smbchg_chip *chip, int current_ma);

#endif
