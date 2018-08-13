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

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "charge_control.h"

#define ATTR_RW(_name)  \
static struct kobj_attribute _name##_attr = \
	__ATTR(_name, 0644, _name##_show, _name##_store)

// Define variables
bool force_fast_charge = 0;
int charge_limit = 100;
int maximum_qc_current = 2800;

static ssize_t maximum_qc_current_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", maximum_qc_current);
}
static ssize_t maximum_qc_current_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int val;
	if (kstrtoint(buf, 0, &val))
		return -EINVAL;
	if(val < 900 && val > 3000)
		return -EINVAL;

	maximum_qc_current = val;

	return count;
}
ATTR_RW(maximum_qc_current);

static ssize_t charge_limit_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", charge_limit);
}
static ssize_t charge_limit_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int val;
	if (kstrtoint(buf, 0, &val))
		return -EINVAL;
	if(val < 1 && val > 100)
		return -EINVAL;

	charge_limit = val;

	return count;
}
ATTR_RW(charge_limit);

static ssize_t force_fast_charge_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", force_fast_charge);
}
static ssize_t force_fast_charge_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	if (strtobool(buf, &force_fast_charge))
		return -EINVAL;

	return count;
}
ATTR_RW(force_fast_charge);

static struct attribute *charge_control_attrs[] = {
	&force_fast_charge_attr.attr,
	&charge_limit_attr.attr,
	&maximum_qc_current_attr.attr,
	NULL,
};

static struct attribute_group charge_control_group = {
	.attrs = charge_control_attrs,
};

static struct kobject *charge_control_kobj;

static int __init chgctl_init(void) {
	int err;

	charge_control_kobj = kobject_create_and_add("fast_charge", kernel_kobj);
	if (!charge_control_kobj) {
		pr_err("Your memory is fucked! :(");
		return -ENOMEM;
	}

	err = sysfs_create_group(charge_control_kobj, &charge_control_group);
	if(err) {
		pr_err("Your device is fucked! :(");
		kobject_put(charge_control_kobj);
		return err;
	}

	return 0;
}

static void chgctl_exit(void) {
	kobject_put(charge_control_kobj);
}

module_init(chgctl_init);
module_exit(chgctl_exit);
