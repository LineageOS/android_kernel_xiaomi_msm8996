/*
 * Author: andip71, 17.11.2012
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


#include <linux/kobject.h>
#include <linux/sysfs.h>
#include "printk_interface.h"


int printk_mode;


/* sysfs interface for printk mode */

static ssize_t printk_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{

	// print current mode
	if (printk_mode == 0)
	{
		return sprintf(buf, "printk mode: %d (disabled)", printk_mode);
	}
	else
	{
		return sprintf(buf, "printk mode: %d (enabled)", printk_mode);
	}

}


static ssize_t printk_mode_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{

	unsigned int ret = -EINVAL;
	int val;

	// read value from input buffer
	ret = sscanf(buf, "%d", &val);

	// check value and store if valid
	if ((val == 0) ||  (val == 1))
	{
		printk_mode = val;
	}

	return count;
}


/* Initialize printk_mode sysfs folder */

static struct kobj_attribute printk_mode_attribute =
__ATTR(printk_mode, 0644, printk_mode_show, printk_mode_store);

static struct attribute *printk_mode_attrs[] = {
&printk_mode_attribute.attr,
NULL,
};

static struct attribute_group printk_mode_attr_group = {
.attrs = printk_mode_attrs,
};

static struct kobject *printk_mode_kobj;

int printk_mode_init(void)
{
	int printk_mode_retval;

        printk_mode_kobj = kobject_create_and_add("printk_mode", kernel_kobj);

        if (!printk_mode_kobj) {
                return -ENOMEM;
        }

        printk_mode_retval = sysfs_create_group(printk_mode_kobj, &printk_mode_attr_group);

        if (printk_mode_retval)
	{
			kobject_put(printk_mode_kobj);
	}

	// initialize printk mode to 1 (enabled) as default
	printk_mode = 1;

        return (printk_mode_retval);
}


void printk_mode_exit(void)
{
	kobject_put(printk_mode_kobj);
}


/* define driver entry points */
module_init(printk_mode_init);
module_exit(printk_mode_exit);
