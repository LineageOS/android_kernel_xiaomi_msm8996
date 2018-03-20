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

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "charge_control.h"

#define ATTR_RW(_name)  \
static struct kobj_attribute _name##_attr = \
	__ATTR(_name, 0644, _name##_show, _name##_store)

#define ATTR_RO(_name)  \
static struct kobj_attribute _name##_attr = \
	__ATTR(_name, 0444, _name##_show, _name##_store)

// Define variables
struct smbchg_chip *chip_pointer;
bool force_fast_charge = 1;
int charge_limit = 0;
int recharge_at = 0;
int maximum_qc_current = 2700;
int full_charge_every = 1;
int charges_counter = 1;
bool trigger_full_charge = 1;

void count_charge() {
	charges_counter++;

	if(charges_counter == full_charge_every){
		charges_counter = 1;
		trigger_full_charge = 1;
	}
}

void finish_full_charge() {
	if(full_charge_every != 1) {
		trigger_full_charge = 0;
	}

	charges_counter = 1;
}

static ssize_t maximum_qc_current_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", maximum_qc_current);
}
static ssize_t maximum_qc_current_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int val, err;
	if (kstrtoint(buf, 0, &val))
		return -EINVAL;
	if(val < 900 && val > 3000)
		return -EINVAL;

	maximum_qc_current = val;
	err = smbchg_set_fastchg_current_user(chip_pointer, val);
	if(err)
		pr_warn("%s: Failed to set current limit!", __func__);

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
	if(val < 0 && val > 100 && recharge_at > val)
		return -EINVAL;
	if(val == 100){
		full_charge_every = 1;
		val = 0;
	}
	else if(full_charge_every == 1) {
		full_charge_every = 0;
		finish_full_charge();
	}

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

static ssize_t recharge_at_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", recharge_at);
}
static ssize_t recharge_at_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int val;
	if (kstrtoint(buf, 0, &val))
		return -EINVAL;
	if(val < 0 && val > 99 && charge_limit < val)
		return -EINVAL;

	recharge_at = val;

	return count;
}
ATTR_RW(recharge_at);

static ssize_t full_charge_every_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", full_charge_every);
}
static ssize_t full_charge_every_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int val;
	if (kstrtoint(buf, 0, &val))
		return -EINVAL;
	if(val < 0 && val > 100)
		return -EINVAL;
	if(val == 1) {
		charge_limit = 0;
		trigger_full_charge = 1;
	}

	full_charge_every = val;
	finish_full_charge();

	return count;
}
ATTR_RW(full_charge_every);

static ssize_t charges_counter_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return (full_charge_every ? sprintf(buf, "%d\n", charges_counter) : -EINVAL);
}
static ssize_t charges_counter_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	return -EINVAL;
}
ATTR_RO(charges_counter);

static struct attribute *charge_control_attrs[] = {
	&force_fast_charge_attr.attr,
	&charge_limit_attr.attr,
	&maximum_qc_current_attr.attr,
	&recharge_at_attr.attr,
	&full_charge_every_attr.attr,
	&charges_counter_attr.attr,
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

	pr_info("Charge Control ver. %d.%d loaded!\n", module_version_major, module_version_minor);

	return 0;
}

static void chgctl_exit(void) {
	kobject_put(charge_control_kobj);
}

module_init(chgctl_init);
module_exit(chgctl_exit);
