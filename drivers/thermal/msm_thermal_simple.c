/*
 * drivers/thermal/msm_thermal_simple.c
 *
 * Copyright (C) 2014-2015, Sultanxda <sultanxda@gmail.com>
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

#define DEFAULT_SAMPLING_MS 3000

enum thermal_state {
	UNTHROTTLE,
	LOW_THROTTLE,
	MID_THROTTLE,
	HIGH_THROTTLE,
};

struct throttle_policy {
	enum thermal_state cpu_throttle;
	unsigned int throttle_freq;
};

static struct throttle_policy *t_pol;
static struct delayed_work thermal_work;
static struct workqueue_struct *thermal_wq;

struct thermal_config {
	struct qpnp_vadc_chip *vadc_dev;
	enum qpnp_vadc_channels adc_chan;
	unsigned int freq_high_KHz;
	unsigned int freq_mid_KHz;
	unsigned int freq_low_KHz;
	unsigned int trip_high_degC;
	unsigned int trip_mid_degC;
	unsigned int trip_low_degC;
	unsigned int reset_high_degC;
	unsigned int reset_mid_degC;
	unsigned int reset_low_degC;
	unsigned int sampling_ms;
	unsigned int enabled;
	unsigned int user_maxfreq;
};

static struct thermal_config *t_conf;

static void update_online_cpu_policy(void)
{
	unsigned int cpu;

	/* Trigger cpufreq notifier for online CPUs */
	get_online_cpus();
	for_each_online_cpu(cpu)
		cpufreq_update_policy(cpu);
	put_online_cpus();
}

static void msm_thermal_main(struct work_struct *work)
{
	struct qpnp_vadc_result result;
	enum thermal_state old_throttle;
	int64_t temp;
	int ret;

	ret = qpnp_vadc_read(t_conf->vadc_dev, t_conf->adc_chan, &result);
	if (ret) {
		pr_err("Unable to read ADC channel\n");
		goto reschedule;
	}

	temp = result.physical;
	old_throttle = t_pol->cpu_throttle;

	/* Low trip point */
	if ((temp >= t_conf->trip_low_degC) &&
		(temp < t_conf->trip_mid_degC) &&
		(t_pol->cpu_throttle == UNTHROTTLE)) {
		t_pol->throttle_freq = t_conf->freq_low_KHz;
		t_pol->cpu_throttle = LOW_THROTTLE;
	/* Low clear point */
	} else if ((temp <= t_conf->reset_low_degC) &&
		(t_pol->cpu_throttle > UNTHROTTLE)) {
		t_pol->cpu_throttle = UNTHROTTLE;
	/* Mid trip point */
	} else if ((temp >= t_conf->trip_mid_degC) &&
		(temp < t_conf->trip_high_degC) &&
		(t_pol->cpu_throttle < MID_THROTTLE)) {
		t_pol->throttle_freq = t_conf->freq_mid_KHz;
		t_pol->cpu_throttle = MID_THROTTLE;
	/* Mid clear point */
	} else if ((temp < t_conf->reset_mid_degC) &&
		(t_pol->cpu_throttle > LOW_THROTTLE)) {
		t_pol->throttle_freq = t_conf->freq_low_KHz;
		t_pol->cpu_throttle = LOW_THROTTLE;
	/* High trip point */
	} else if ((temp >= t_conf->trip_high_degC) &&
		(t_pol->cpu_throttle < HIGH_THROTTLE)) {
		t_pol->throttle_freq = t_conf->freq_high_KHz;
		t_pol->cpu_throttle = HIGH_THROTTLE;
	/* High clear point */
	} else if ((temp < t_conf->reset_high_degC) &&
		(t_pol->cpu_throttle > MID_THROTTLE)) {
		t_pol->throttle_freq = t_conf->freq_mid_KHz;
		t_pol->cpu_throttle = MID_THROTTLE;
	}

	/* Thermal state changed */
	if (t_pol->cpu_throttle != old_throttle) {
		if (t_pol->cpu_throttle)
			pr_warn("Setting CPU to %uKHz! temp: %lluC\n",
						t_pol->throttle_freq, temp);
		else
			pr_warn("CPU unthrottled! temp: %lluC\n", temp);
		/* Immediately enforce new thermal policy on online CPUs */
		update_online_cpu_policy();
	}

reschedule:
	queue_delayed_work(thermal_wq, &thermal_work,
				msecs_to_jiffies(t_conf->sampling_ms));
}

static void unthrottle_all_cpus(void)
{
	t_pol->cpu_throttle = UNTHROTTLE;
	update_online_cpu_policy();
}

static int cpu_do_throttle(struct notifier_block *nb, unsigned long val, void *data)
{
	struct cpufreq_policy *policy = data;
	unsigned int user_max = t_conf->user_maxfreq;

	if (val != CPUFREQ_ADJUST)
		return NOTIFY_OK;

	switch (t_pol->cpu_throttle) {
	case UNTHROTTLE:
		policy->max = user_max ? user_max : policy->cpuinfo.max_freq;
		break;
	case LOW_THROTTLE:
	case MID_THROTTLE:
	case HIGH_THROTTLE:
		if (user_max && (user_max < t_pol->throttle_freq))
			policy->max = user_max;
		else
			policy->max = t_pol->throttle_freq;
		break;
	}

	if (policy->min > policy->max)
		policy->min = policy->cpuinfo.min_freq;

	return NOTIFY_OK;
}

static struct notifier_block cpu_throttle_nb = {
	.notifier_call = cpu_do_throttle,
};

/*********************** SYSFS START ***********************/
static struct kobject *msm_thermal_kobject;

static ssize_t high_thresh_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int data[3];
	int ret = sscanf(buf, "%u %u %u", &data[0], &data[1], &data[2]);

	if (ret != 3)
		return -EINVAL;

	t_conf->freq_high_KHz = data[0];
	t_conf->trip_high_degC = data[1];
	t_conf->reset_high_degC = data[2];

	return size;
}

static ssize_t mid_thresh_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int data[3];
	int ret = sscanf(buf, "%u %u %u", &data[0], &data[1], &data[2]);

	if (ret != 3)
		return -EINVAL;

	t_conf->freq_mid_KHz = data[0];
	t_conf->trip_mid_degC = data[1];
	t_conf->reset_mid_degC = data[2];

	return size;
}

static ssize_t low_thresh_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int data[3];
	int ret = sscanf(buf, "%u %u %u", &data[0], &data[1], &data[2]);

	if (ret != 3)
		return -EINVAL;

	t_conf->freq_low_KHz = data[0];
	t_conf->trip_low_degC = data[1];
	t_conf->reset_low_degC = data[2];

	return size;
}

static ssize_t sampling_ms_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int data;
	int ret = sscanf(buf, "%u", &data);

	if (ret != 1)
		return -EINVAL;

	t_conf->sampling_ms = data;

	return size;
}

static ssize_t enabled_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int data;
	int ret = sscanf(buf, "%u", &data);

	if (ret != 1)
		return -EINVAL;

	t_conf->enabled = data;

	cancel_delayed_work_sync(&thermal_work);

	if (data)
		queue_delayed_work(thermal_wq, &thermal_work, 0);
	else
		unthrottle_all_cpus();

	return size;
}

static ssize_t user_maxfreq_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int data;
	int ret = sscanf(buf, "%u", &data);

	if (ret != 1)
		return -EINVAL;

	t_conf->user_maxfreq = data;

	return size;
}

static ssize_t high_thresh_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u %u %u\n", t_conf->freq_high_KHz,
			t_conf->trip_high_degC, t_conf->reset_high_degC);
}

static ssize_t mid_thresh_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u %u %u\n", t_conf->freq_mid_KHz,
			t_conf->trip_mid_degC, t_conf->reset_mid_degC);
}

static ssize_t low_thresh_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u %u %u\n", t_conf->freq_low_KHz,
			t_conf->trip_low_degC, t_conf->reset_low_degC);
}

static ssize_t sampling_ms_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", t_conf->sampling_ms);
}

static ssize_t enabled_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", t_conf->enabled);
}

static ssize_t user_maxfreq_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", t_conf->user_maxfreq);
}

static DEVICE_ATTR(high_thresh, 0644, high_thresh_read, high_thresh_write);
static DEVICE_ATTR(mid_thresh, 0644, mid_thresh_read, mid_thresh_write);
static DEVICE_ATTR(low_thresh, 0644, low_thresh_read, low_thresh_write);
static DEVICE_ATTR(sampling_ms, 0644, sampling_ms_read, sampling_ms_write);
static DEVICE_ATTR(enabled, 0644, enabled_read, enabled_write);
static DEVICE_ATTR(user_maxfreq, 0644, user_maxfreq_read, user_maxfreq_write);

static struct attribute *msm_thermal_attr[] = {
	&dev_attr_high_thresh.attr,
	&dev_attr_mid_thresh.attr,
	&dev_attr_low_thresh.attr,
	&dev_attr_sampling_ms.attr,
	&dev_attr_enabled.attr,
	&dev_attr_user_maxfreq.attr,
	NULL
};

static struct attribute_group msm_thermal_attr_group = {
	.attrs  = msm_thermal_attr,
};
/*********************** SYSFS END ***********************/

static int msm_thermal_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	int ret;

	t_pol = kzalloc(sizeof(struct throttle_policy), GFP_KERNEL);
	if (!t_pol) {
		pr_err("Failed to allocate thermal_policy struct\n");
		ret = -ENOMEM;
		goto err;
	}

	t_conf = kzalloc(sizeof(struct thermal_config), GFP_KERNEL);
	if (!t_conf) {
		pr_err("Failed to allocate thermal_config struct\n");
		ret = -ENOMEM;
		goto err;
	}

	t_conf->vadc_dev = qpnp_get_vadc(&pdev->dev, "thermal");
	if (IS_ERR(t_conf->vadc_dev)) {
		ret = PTR_ERR(t_conf->vadc_dev);
		if (ret != -EPROBE_DEFER)
			pr_err("VADC property missing\n");
		goto err;
	}

	ret = of_property_read_u32(np, "qcom,adc-channel", &t_conf->adc_chan);
	if (ret) {
		pr_err("ADC-channel property missing\n");
		goto err;
	}

	thermal_wq = alloc_workqueue("msm_thermal_wq",
					WQ_HIGHPRI | WQ_NON_REENTRANT, 0);
	if (!thermal_wq) {
		pr_err("Failed to allocate workqueue\n");
		ret = -EFAULT;
		goto err;
	}

	cpufreq_register_notifier(&cpu_throttle_nb, CPUFREQ_POLICY_NOTIFIER);

	t_conf->sampling_ms = DEFAULT_SAMPLING_MS;

	INIT_DELAYED_WORK(&thermal_work, msm_thermal_main);

	msm_thermal_kobject = kobject_create_and_add("msm_thermal", kernel_kobj);
	if (!msm_thermal_kobject) {
		pr_err("Failed to create kobject\n");
		ret = -ENOMEM;
		goto err;
	}

	ret = sysfs_create_group(msm_thermal_kobject, &msm_thermal_attr_group);
	if (ret) {
		pr_err("Failed to create sysfs interface\n");
		kobject_put(msm_thermal_kobject);
	}
err:
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
late_initcall(msm_thermal_init);
