/*
 * Author: JonasCardoso
 * 
 * Copyright 2017
 * Version 1.3.0
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/printk.h>

/*****************************************/
// Function declarations
/*****************************************/

// tfa98xx.c exported functions for sound control engine
int get_speaker_show(void);
int get_speaker(void);
void set_speaker_boost(int vol_speaker_boost);
