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

#define module_version 2.0

// Known knob to force 900mA charging
extern bool force_fast_charge;

// Variable to manipulate maximum charge percent
// Charging battery to 80% can insrease its lifetime sginificantly
extern int charge_limit;

// When battery percentage falls behind this value enable charging again
// When 0 this feature is disabled
// Allowed input is between 1-99
extern int __read_mostly recharge_at;

// Variable to change maximum current from QC3.0 charger
// This could prevent issues with heating and broken hardware
// By default lowered than on stock
extern int maximum_qc_current;

// Trigger full charge every x times
// This could help with battery 'calibration' issues as probably
// charging the battery up to ~80% every time makes it to loss its actual value
// 0 = don't use this feature
// 1 = do a full charge every time
// x = do a full charge every x times 
extern int full_charge_every;
// Every time full_charge_every is changed counter is resetted
extern int charges_counter;
extern bool __read_mostly trigger_full_charge;

extern void count_charge();
extern void finish_full_charge();

#endif
