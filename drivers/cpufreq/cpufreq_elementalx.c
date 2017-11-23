/*
 *  drivers/cpufreq/cpufreq_elementalx.c
 *
 *  Copyright (C)  2001 Russell King
 *            (C)  2003 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *                      Jun Nakajima <jun.nakajima@intel.com>
 *            (C)  2015 Aaron Segaert <asegaert@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include "cpufreq_governor.h"

/* elementalx governor macros */
#define DEF_FREQUENCY_UP_THRESHOLD		(90)
#define DEF_FREQUENCY_DOWN_DIFFERENTIAL		(20)
#define DEF_ACTIVE_FLOOR_FREQ			(960000)
#define MIN_SAMPLING_RATE			(10000)
#define DEF_SAMPLING_DOWN_FACTOR		(4)
#define MAX_SAMPLING_DOWN_FACTOR		(20)
#define FREQ_NEED_BURST(x)			(x < 800000 ? 1 : 0)
#define MAX(x,y)				(x > y ? x : y)
#define MIN(x,y)				(x < y ? x : y)
#define TABLE_SIZE				5

static DEFINE_PER_CPU(struct ex_cpu_dbs_info_s, ex_cpu_dbs_info);

static unsigned int up_threshold_level[2] __read_mostly = {95, 85};
static struct cpufreq_frequency_table *tbl = NULL;
static unsigned int *tblmap[TABLE_SIZE] __read_mostly;
static unsigned int tbl_select[4];

static struct ex_governor_data {
	unsigned int active_floor_freq;
	unsigned int prev_load;
} ex_data = {
	.active_floor_freq = DEF_ACTIVE_FLOOR_FREQ,
	.prev_load = 0,
};

static void dbs_init_freq_map_table(void)
{
	unsigned int min_diff, top1, top2;
	int cnt, i, j;
	struct cpufreq_policy *policy;

	policy = cpufreq_cpu_get(0);
	tbl = cpufreq_frequency_get_table(0);
	min_diff = policy->cpuinfo.max_freq;

	for (cnt = 0; (tbl[cnt].frequency != CPUFREQ_TABLE_END); cnt++) {
		if (cnt > 0)
			min_diff = MIN(tbl[cnt].frequency - tbl[cnt-1].frequency, min_diff);
	}

	top1 = (policy->cpuinfo.max_freq + policy->cpuinfo.min_freq) / 2;
	top2 = (policy->cpuinfo.max_freq + top1) / 2;

	for (i = 0; i < TABLE_SIZE; i++) {
		tblmap[i] = kmalloc(sizeof(unsigned int) * cnt, GFP_KERNEL);
		BUG_ON(!tblmap[i]);
		for (j = 0; j < cnt; j++)
			tblmap[i][j] = tbl[j].frequency;
	}

	for (j = 0; j < cnt; j++) {
		if (tbl[j].frequency < top1) {
			tblmap[0][j] += MAX((top1 - tbl[j].frequency)/3, min_diff);
		}

		if (tbl[j].frequency < top2) {
			tblmap[1][j] += MAX((top2 - tbl[j].frequency)/3, min_diff);
			tblmap[2][j] += MAX(((top2 - tbl[j].frequency)*2)/5, min_diff);
			tblmap[3][j] += MAX((top2 - tbl[j].frequency)/2, min_diff);
		} else {
			tblmap[3][j] += MAX((policy->cpuinfo.max_freq - tbl[j].frequency)/3, min_diff);
		}

		tblmap[4][j] += MAX((policy->cpuinfo.max_freq - tbl[j].frequency)/2, min_diff);
	}

	tbl_select[0] = 0;
	tbl_select[1] = 1;
	tbl_select[2] = 2;
	tbl_select[3] = 4;
}

static void dbs_deinit_freq_map_table(void)
{
	int i;

	if (!tbl)
		return;

	tbl = NULL;

	for (i = 0; i < TABLE_SIZE; i++)
		kfree(tblmap[i]);
}

static inline int get_cpu_freq_index(unsigned int freq)
{
	static int saved_index = 0;
	int index;

	if (!tbl) {
		pr_warn("tbl is NULL, use previous value %d\n", saved_index);
		return saved_index;
	}

	for (index = 0; (tbl[index].frequency != CPUFREQ_TABLE_END); index++) {
		if (tbl[index].frequency >= freq) {
			saved_index = index;
			break;
		}
	}

	return index;
}

static inline unsigned int ex_freq_increase(struct cpufreq_policy *p, unsigned int freq)
{
	if (freq > p->max) {
		return p->max;
	} 
	
	return freq;
}

static void ex_check_cpu(int cpu, unsigned int load)
{
	struct ex_cpu_dbs_info_s *dbs_info = &per_cpu(ex_cpu_dbs_info, cpu);
	struct cpufreq_policy *policy = dbs_info->cdbs.cur_policy;
	struct dbs_data *dbs_data = policy->governor_data;
	struct ex_dbs_tuners *ex_tuners = dbs_data->tuners;
	unsigned int max_load_freq = 0, freq_next = 0;
	unsigned int j, avg_load, cur_freq, max_freq, target_freq = 0;

	cur_freq = policy->cur;
	max_freq = policy->max;

	for_each_cpu(j, policy->cpus) {
		if (load > max_load_freq)
			max_load_freq = load * policy->cur;
	}
	avg_load = (ex_data.prev_load + load) >> 1;

	if (max_load_freq > up_threshold_level[1] * cur_freq) {
		int index = get_cpu_freq_index(cur_freq);

		if (FREQ_NEED_BURST(cur_freq) &&
				load > up_threshold_level[0]) {
			freq_next = max_freq;
		}
		
		else if (avg_load > up_threshold_level[0]) {
			freq_next = tblmap[tbl_select[3]][index];
		}
		
		else if (avg_load <= up_threshold_level[1]) {
			freq_next = tblmap[tbl_select[1]][index];
		}
	
		else {
			if (load > up_threshold_level[0]) {
				freq_next = tblmap[tbl_select[3]][index];
			}
		
			else {
				freq_next = tblmap[tbl_select[2]][index];
			}
		}

		target_freq = ex_freq_increase(policy, freq_next);

		__cpufreq_driver_target(policy, target_freq, CPUFREQ_RELATION_H);

		if (target_freq > ex_data.active_floor_freq)
			dbs_info->down_floor = 0;

		goto finished;
	}

	if (cur_freq == policy->min)
		goto finished;

	if (cur_freq >= ex_data.active_floor_freq) {
		if (++dbs_info->down_floor > ex_tuners->sampling_down_factor)
			dbs_info->down_floor = 0;
	} else {
		dbs_info->down_floor = 0;
	}

	if (max_load_freq <
	    (ex_tuners->up_threshold - ex_tuners->down_differential) *
	     cur_freq) {

		freq_next = max_load_freq /
				(ex_tuners->up_threshold -
				 ex_tuners->down_differential);

		if (dbs_info->down_floor) {
			freq_next = MAX(freq_next, ex_data.active_floor_freq);
		} else {
			freq_next = MAX(freq_next, policy->min);
			if (freq_next < ex_data.active_floor_freq)
				dbs_info->down_floor = ex_tuners->sampling_down_factor;
		}

		__cpufreq_driver_target(policy, freq_next,
			CPUFREQ_RELATION_L);
	}

finished:
	ex_data.prev_load = load;
	return;
}

static void ex_dbs_timer(struct work_struct *work)
{
	struct ex_cpu_dbs_info_s *dbs_info = container_of(work,
			struct ex_cpu_dbs_info_s, cdbs.work.work);
	unsigned int cpu = dbs_info->cdbs.cur_policy->cpu;
	struct ex_cpu_dbs_info_s *core_dbs_info = &per_cpu(ex_cpu_dbs_info,
			cpu);
	struct dbs_data *dbs_data = dbs_info->cdbs.cur_policy->governor_data;
	struct ex_dbs_tuners *ex_tuners = dbs_data->tuners;
	int delay = delay_for_sampling_rate(ex_tuners->sampling_rate);
	bool modify_all = true;

	mutex_lock(&core_dbs_info->cdbs.timer_mutex);
	if (!need_load_eval(&core_dbs_info->cdbs, ex_tuners->sampling_rate))
		modify_all = false;
	else
		dbs_check_cpu(dbs_data, cpu);

	gov_queue_work(dbs_data, dbs_info->cdbs.cur_policy, delay, modify_all);
	mutex_unlock(&core_dbs_info->cdbs.timer_mutex);
}

/************************** sysfs interface ************************/
static struct common_dbs_data ex_dbs_cdata;

static ssize_t store_sampling_rate(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct ex_dbs_tuners *ex_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	ex_tuners->sampling_rate = max(input, dbs_data->min_sampling_rate);
	return count;
}

static ssize_t store_up_threshold(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct ex_dbs_tuners *ex_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1 || input > 100 || input <= ex_tuners->down_differential)
		return -EINVAL;

	ex_tuners->up_threshold = input;
	return count;
}

static ssize_t store_down_differential(struct dbs_data *dbs_data,
		const char *buf, size_t count)
{
	struct ex_dbs_tuners *ex_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1 || input > 100 || input >= ex_tuners->up_threshold)
		return -EINVAL;

	ex_tuners->down_differential = input;
	return count;
}

static ssize_t store_active_floor_freq(struct dbs_data *dbs_data,
		const char *buf, size_t count)
{
	struct ex_dbs_tuners *ex_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	ex_tuners->active_floor_freq = input;
	ex_data.active_floor_freq = ex_tuners->active_floor_freq;
	return count;
}

static ssize_t store_sampling_down_factor(struct dbs_data *dbs_data,
		const char *buf, size_t count)
{
	struct ex_dbs_tuners *ex_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1 || input > MAX_SAMPLING_DOWN_FACTOR || input < 0)
		return -EINVAL;

	ex_tuners->sampling_down_factor = input;
	return count;
}

show_store_one(ex, sampling_rate);
show_store_one(ex, up_threshold);
show_store_one(ex, down_differential);
show_store_one(ex, active_floor_freq);
show_store_one(ex, sampling_down_factor);
declare_show_sampling_rate_min(ex);

gov_sys_pol_attr_rw(sampling_rate);
gov_sys_pol_attr_rw(up_threshold);
gov_sys_pol_attr_rw(down_differential);
gov_sys_pol_attr_rw(active_floor_freq);
gov_sys_pol_attr_rw(sampling_down_factor);
gov_sys_pol_attr_ro(sampling_rate_min);

static struct attribute *dbs_attributes_gov_sys[] = {
	&sampling_rate_min_gov_sys.attr,
	&sampling_rate_gov_sys.attr,
	&up_threshold_gov_sys.attr,
	&down_differential_gov_sys.attr,
	&active_floor_freq_gov_sys.attr,
	&sampling_down_factor_gov_sys.attr,
	NULL
};

static struct attribute_group ex_attr_group_gov_sys = {
	.attrs = dbs_attributes_gov_sys,
	.name = "elementalx",
};

static struct attribute *dbs_attributes_gov_pol[] = {
	&sampling_rate_min_gov_pol.attr,
	&sampling_rate_gov_pol.attr,
	&up_threshold_gov_pol.attr,
	&down_differential_gov_pol.attr,
	&active_floor_freq_gov_pol.attr,
	&sampling_down_factor_gov_pol.attr,
	NULL
};

static struct attribute_group ex_attr_group_gov_pol = {
	.attrs = dbs_attributes_gov_pol,
	.name = "elementalx",
};

/************************** sysfs end ************************/

static int ex_init(struct dbs_data *dbs_data)
{
	struct ex_dbs_tuners *tuners;

	tuners = kzalloc(sizeof(*tuners), GFP_KERNEL);
	if (!tuners) {
		pr_err("%s: kzalloc failed\n", __func__);
		return -ENOMEM;
	}

	tuners->up_threshold = DEF_FREQUENCY_UP_THRESHOLD;
	tuners->down_differential = DEF_FREQUENCY_DOWN_DIFFERENTIAL;
	tuners->ignore_nice_load = 0;
	tuners->active_floor_freq = DEF_ACTIVE_FLOOR_FREQ;
	tuners->sampling_down_factor = DEF_SAMPLING_DOWN_FACTOR;

	dbs_data->tuners = tuners;
	dbs_data->min_sampling_rate = MIN_SAMPLING_RATE;

	dbs_init_freq_map_table();

	mutex_init(&dbs_data->mutex);
	return 0;
}

static void ex_exit(struct dbs_data *dbs_data)
{
	dbs_deinit_freq_map_table();
	kfree(dbs_data->tuners);
}

define_get_cpu_dbs_routines(ex_cpu_dbs_info);

static struct common_dbs_data ex_dbs_cdata = {
	.governor = GOV_ELEMENTALX,
	.attr_group_gov_sys = &ex_attr_group_gov_sys,
	.attr_group_gov_pol = &ex_attr_group_gov_pol,
	.get_cpu_cdbs = get_cpu_cdbs,
	.get_cpu_dbs_info_s = get_cpu_dbs_info_s,
	.gov_dbs_timer = ex_dbs_timer,
	.gov_check_cpu = ex_check_cpu,
	.init = ex_init,
	.exit = ex_exit,
};

static int ex_cpufreq_governor_dbs(struct cpufreq_policy *policy,
				   unsigned int event)
{
	return cpufreq_governor_dbs(policy, &ex_dbs_cdata, event);
}

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_ELEMENTALX
static
#endif
struct cpufreq_governor cpufreq_gov_elementalx = {
	.name			= "elementalx",
	.governor		= ex_cpufreq_governor_dbs,
	.max_transition_latency	= TRANSITION_LATENCY_LIMIT,
	.owner			= THIS_MODULE,
};

static int __init cpufreq_gov_dbs_init(void)
{
	return cpufreq_register_governor(&cpufreq_gov_elementalx);
}

static void __exit cpufreq_gov_dbs_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_elementalx);
}

MODULE_AUTHOR("Aaron Segaert <asegaert@gmail.com>");
MODULE_DESCRIPTION("'cpufreq_elementalx' - multiphase cpufreq governor");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_ELEMENTALX
fs_initcall(cpufreq_gov_dbs_init);
#else
module_init(cpufreq_gov_dbs_init);
#endif
module_exit(cpufreq_gov_dbs_exit);
