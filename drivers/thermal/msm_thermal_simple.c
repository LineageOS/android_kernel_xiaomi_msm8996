/*
 * drivers/thermal/msm_thermal_simple.c
 *
 * Copyright (C) 2014-2016, Sultanxda <sultanxda@gmail.com>
 *
 * Originally based off the MSM8x60 thermal implementation by:
 * Copyright (c) 2012, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) "msm-thermal: " fmt

#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/qpnp/qpnp-adc.h>
#include <linux/slab.h>

/* For MSM8996 */
#define LITTLE_CPU_ID	0
#define BIG_CPU_ID	2

#define DEFAULT_SAMPLING_MS 3000

/* Sysfs attr group must be manually updated in order to change this */
#define NR_THERMAL_ZONES 12

#define UNTHROTTLE_ZONE (-1)

struct throttle_policy {
	int32_t curr_zone;
	uint32_t freq[2];
};

struct thermal_config {
	struct qpnp_vadc_chip *vadc_dev;
	enum qpnp_vadc_channels adc_chan;
	uint8_t enabled;
	uint32_t sampling_ms;
	uint32_t user_maxfreq;
};

struct thermal_zone {
	uint32_t freq[2];
	int64_t trip_degC;
	int64_t reset_degC;
};

struct thermal_policy {
	spinlock_t lock;
	struct delayed_work dwork;
	struct thermal_config conf;
	struct throttle_policy throttle;
	struct thermal_zone zone[NR_THERMAL_ZONES];
	struct workqueue_struct *wq;
};

static struct thermal_policy *t_policy_g;

static void update_online_cpu_policy(void);

static void msm_thermal_main(struct work_struct *work)
{
	struct thermal_policy *t = container_of(work, typeof(*t), dwork.work);
	struct qpnp_vadc_result result;
	int32_t curr_zone, old_zone;
	int32_t i, ret;
	int64_t temp;

	ret = qpnp_vadc_read(t->conf.vadc_dev, t->conf.adc_chan, &result);
	if (ret) {
		pr_err("Unable to read ADC channel\n");
		goto reschedule;
	}

	temp = result.physical;
	old_zone = t->throttle.curr_zone;

	spin_lock(&t->lock);

	for (i = 0; i < NR_THERMAL_ZONES; i++) {
		if (!t->zone[i].freq[0]) {
			/*
			 * The current thermal zone is not configured, so use
			 * the previous one and exit.
			 */
			t->throttle.curr_zone = i - 1;
			break;
		}

		if (i == (NR_THERMAL_ZONES - 1)) {
			/* Highest zone has been reached, so use it and exit */
			t->throttle.curr_zone = i;
			break;
		}

		if (temp > t->zone[i].reset_degC) {
			/*
			 * If temp is less than the trip temp for the next
			 * thermal zone and is greater than or equal to the
			 * trip temp for the current zone, then exit here and
			 * use the current index as the thermal zone.
			 * Otherwise, keep iterating until this is true (or
			 * until we hit the highest thermal zone).
			 */
			if (temp < t->zone[i + 1].trip_degC &&
				(temp >= t->zone[i].trip_degC ||
				old_zone != UNTHROTTLE_ZONE)) {
				t->throttle.curr_zone = i;
				break;
			} else if (!i && old_zone == UNTHROTTLE_ZONE &&
				temp < t->zone[0].trip_degC) {
				/*
				 * Don't keep looping if the CPU is currently
				 * unthrottled and the temp is below the first
				 * zone's trip point.
				 */
				break;
			}
		} else if (!i) {
			/*
			 * Unthrottle CPU if temp is at or below the first
			 * zone's reset temp.
			 */
			t->throttle.curr_zone = UNTHROTTLE_ZONE;
			break;
		}
	}

	curr_zone = t->throttle.curr_zone;

	/*
	 * Update throttle freq. Setting throttle.freq to 0
	 * tells the CPU notifier to unthrottle.
	 */
	if (curr_zone == UNTHROTTLE_ZONE) {
		memset(&t->throttle.freq[0], 0, sizeof(uint32_t) * 2);
	} else {
		/* Throttle both clusters */
		t->throttle.freq[0] = t->zone[curr_zone].freq[0];
		t->throttle.freq[1] = t->zone[curr_zone].freq[1];
	}

	spin_unlock(&t->lock);

	/* Only update CPU policy when the throttle zone changes */
	if (curr_zone != old_zone)
		update_online_cpu_policy();

reschedule:
	queue_delayed_work(t->wq, &t->dwork,
				msecs_to_jiffies(t->conf.sampling_ms));
}

static int do_cpu_throttle(struct notifier_block *nb,
		unsigned long val, void *data)
{
	struct cpufreq_policy *policy = data;
	struct thermal_policy *t = t_policy_g;
	uint32_t throttle_freq, user_max;

	if (val != CPUFREQ_ADJUST)
		return NOTIFY_OK;

	spin_lock(&t->lock);
	throttle_freq =
		t->throttle.freq[policy->cpu < BIG_CPU_ID ? 0 : 1];
	user_max = t->conf.user_maxfreq;
	spin_unlock(&t->lock);

	if (throttle_freq) {
		if (user_max && (user_max < throttle_freq))
			policy->max = user_max;
		else
			policy->max = throttle_freq;
	} else {
		policy->max = user_max ? user_max : policy->cpuinfo.max_freq;
	}

	if (policy->min > policy->max)
		policy->min = policy->max;

	return NOTIFY_OK;
}

static struct notifier_block cpu_throttle_nb = {
	.notifier_call = do_cpu_throttle,
};

static void update_online_cpu_policy(void)
{
	uint32_t cpu;

	/* Trigger cpufreq notifier for online CPUs */
	get_online_cpus();
	for_each_online_cpu(cpu)
		cpufreq_update_policy(cpu);
	put_online_cpus();
}

static uint32_t get_thermal_zone_number(const char *filename)
{
	uint32_t num;

	/* Thermal zone sysfs nodes are named as "zone#" */
	sscanf(filename, "zone%u", &num);

	return num;
}

static ssize_t enabled_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct thermal_policy *t = t_policy_g;
	uint32_t data;
	int ret;

	ret = sscanf(buf, "%u", &data);
	if (ret != 1)
		return -EINVAL;

	t->conf.enabled = data;

	cancel_delayed_work_sync(&t->dwork);

	if (data) {
		queue_delayed_work(t->wq, &t->dwork, 0);
	} else {
		/*
		 * Unthrottle all CPUS. No need to acquire lock here as we
		 * will immediately update CPU policy anyway.
		 */
		memset(&t->throttle.freq[0], 0, sizeof(uint32_t) * 2);
		update_online_cpu_policy();
	}

	return size;
}

static ssize_t sampling_ms_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct thermal_policy *t = t_policy_g;
	uint32_t data;
	int ret;

	ret = sscanf(buf, "%u", &data);
	if (ret != 1)
		return -EINVAL;

	spin_lock(&t->lock);
	t->conf.sampling_ms = data;
	spin_unlock(&t->lock);

	return size;
}

static ssize_t thermal_zone_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct thermal_policy *t = t_policy_g;
	uint32_t freq[2], idx;
	int64_t trip_degC, reset_degC;
	int ret;

	ret = sscanf(buf, "%u %u %lld %lld", &freq[0], &freq[1],
						&trip_degC, &reset_degC);
	if (ret != 4)
		return -EINVAL;

	idx = get_thermal_zone_number(attr->attr.name);

	spin_lock(&t->lock);
	/* freq[0] is assigned to LITTLE cluster, freq[1] to big cluster */
	t->zone[idx].freq[0] = freq[0];
	t->zone[idx].freq[1] = freq[1];
	t->zone[idx].trip_degC = trip_degC;
	t->zone[idx].reset_degC = reset_degC;
	spin_unlock(&t->lock);

	return size;
}

static ssize_t user_maxfreq_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct thermal_policy *t = t_policy_g;
	uint32_t data;
	int ret;

	ret = sscanf(buf, "%u", &data);
	if (ret != 1)
		return -EINVAL;

	spin_lock(&t->lock);
	t->conf.user_maxfreq = data;
	spin_unlock(&t->lock);

	return size;
}

static ssize_t enabled_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct thermal_policy *t = t_policy_g;

	return snprintf(buf, PAGE_SIZE, "%u\n", t->conf.enabled);
}

static ssize_t sampling_ms_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct thermal_policy *t = t_policy_g;

	return snprintf(buf, PAGE_SIZE, "%u\n", t->conf.sampling_ms);
}

static ssize_t thermal_zone_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct thermal_policy *t = t_policy_g;
	uint32_t idx;

	idx = get_thermal_zone_number(attr->attr.name);

	return snprintf(buf, PAGE_SIZE, "%u %u %lld %lld\n",
			t->zone[idx].freq[0], t->zone[idx].freq[1],
			t->zone[idx].trip_degC, t->zone[idx].reset_degC);
}

static ssize_t user_maxfreq_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct thermal_policy *t = t_policy_g;

	return snprintf(buf, PAGE_SIZE, "%u\n", t->conf.user_maxfreq);
}

static DEVICE_ATTR(enabled, 0644, enabled_read, enabled_write);
static DEVICE_ATTR(sampling_ms, 0644, sampling_ms_read, sampling_ms_write);
static DEVICE_ATTR(user_maxfreq, 0644, user_maxfreq_read, user_maxfreq_write);
static DEVICE_ATTR(zone0, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone1, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone2, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone3, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone4, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone5, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone6, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone7, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone8, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone9, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone10, 0644, thermal_zone_read, thermal_zone_write);
static DEVICE_ATTR(zone11, 0644, thermal_zone_read, thermal_zone_write);

static struct attribute *msm_thermal_attr[] = {
	&dev_attr_enabled.attr,
	&dev_attr_sampling_ms.attr,
	&dev_attr_user_maxfreq.attr,
	&dev_attr_zone0.attr,
	&dev_attr_zone1.attr,
	&dev_attr_zone2.attr,
	&dev_attr_zone3.attr,
	&dev_attr_zone4.attr,
	&dev_attr_zone5.attr,
	&dev_attr_zone6.attr,
	&dev_attr_zone7.attr,
	&dev_attr_zone8.attr,
	&dev_attr_zone9.attr,
	&dev_attr_zone10.attr,
	&dev_attr_zone11.attr,
	NULL
};

static struct attribute_group msm_thermal_attr_group = {
	.attrs = msm_thermal_attr,
};

static int sysfs_thermal_init(void)
{
	struct kobject *kobj;
	int ret;

	kobj = kobject_create_and_add("msm_thermal", kernel_kobj);
	if (!kobj) {
		pr_err("Failed to create kobject\n");
		return -ENOMEM;
	}

	ret = sysfs_create_group(kobj, &msm_thermal_attr_group);
	if (ret) {
		pr_err("Failed to create sysfs interface\n");
		kobject_put(kobj);
	}

	return ret;
}

static int msm_thermal_parse_dt(struct platform_device *pdev,
			struct thermal_policy *t)
{
	struct device_node *np = pdev->dev.of_node;
	int ret;

	t->conf.vadc_dev = qpnp_get_vadc(&pdev->dev, "thermal");
	if (IS_ERR(t->conf.vadc_dev)) {
		ret = PTR_ERR(t->conf.vadc_dev);
		if (ret != -EPROBE_DEFER)
			pr_err("VADC property missing\n");
		return ret;
	}

	ret = of_property_read_u32(np, "qcom,adc-channel", &t->conf.adc_chan);
	if (ret)
		pr_err("ADC-channel property missing\n");

	return ret;
}

static struct thermal_policy *alloc_thermal_policy(void)
{
	struct thermal_policy *t;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t) {
		pr_err("Failed to allocate thermal policy\n");
		return NULL;
	}

	t->wq = alloc_workqueue("msm_thermal_wq", WQ_HIGHPRI, 0);
	if (!t->wq) {
		pr_err("Failed to allocate workqueue\n");
		goto free_t;
	}

	return t;

free_t:
	kfree(t);
	return NULL;
}

static int msm_thermal_probe(struct platform_device *pdev)
{
	struct thermal_policy *t;
	int ret;

	t = alloc_thermal_policy();
	if (!t)
		return -ENOMEM;

	ret = msm_thermal_parse_dt(pdev, t);
	if (ret)
		goto free_mem;

	t->conf.sampling_ms = DEFAULT_SAMPLING_MS;

	/* Boot up unthrottled */
	t->throttle.curr_zone = UNTHROTTLE_ZONE;

	/* Allow global thermal policy access */
	t_policy_g = t;

	spin_lock_init(&t->lock);

	INIT_DELAYED_WORK(&t->dwork, msm_thermal_main);

	ret = sysfs_thermal_init();
	if (ret)
		goto free_mem;

	cpufreq_register_notifier(&cpu_throttle_nb, CPUFREQ_POLICY_NOTIFIER);

	return 0;

free_mem:
	kfree(t);
	return ret;
}

static struct of_device_id msm_thermal_match_table[] = {
	{.compatible = "qcom,msm-thermal-simple"},
	{ },
};

static struct platform_driver msm_thermal_device = {
	.probe = msm_thermal_probe,
	.driver = {
		.name = "msm-thermal-simple",
		.owner = THIS_MODULE,
		.of_match_table = msm_thermal_match_table,
	},
};

static int __init msm_thermal_init(void)
{
	return platform_driver_register(&msm_thermal_device);
}
device_initcall(msm_thermal_init);
