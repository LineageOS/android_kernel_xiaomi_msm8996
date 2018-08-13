/* Copyright (c) 2017 The Linux Foundation. All rights reserved.
 * Copyright (c) xNombre kartapolska@gmail.com
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

// Known knob to force 900mA charging
extern bool force_fast_charge;

// Variable to manipulate maximum charge percent
// Charging battery to 80% can insrease its lifetime sginificantly
extern int charge_limit;

// Variable to change maximum current from QC3.0 charger
// This could prevent issues with heating and broken hardware
// By default lowered than on stock
extern int maximum_qc_current;

#endif
