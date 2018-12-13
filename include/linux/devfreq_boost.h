// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 Sultan Alsawaf <sultan@kerneltoast.com>.
 */
#ifndef _DEVFREQ_BOOST_H_
#define _DEVFREQ_BOOST_H_

#include <linux/devfreq.h>

enum df_device {
	DEVFREQ_MSM_CPUBW,
	DEVFREQ_MAX
};

struct boost_dev {
	struct workqueue_struct *wq;
	struct devfreq *df;
	struct work_struct input_boost;
	struct delayed_work input_unboost;
	struct work_struct max_boost;
	struct delayed_work max_unboost;
	unsigned long abs_min_freq;
	unsigned long boost_freq;
	unsigned long max_boost_expires;
	unsigned long max_boost_jiffies;
	bool disable;
	spinlock_t lock;
};

#ifdef CONFIG_DEVFREQ_BOOST
void devfreq_boost_kick(enum df_device device);
void devfreq_boost_kick_max(enum df_device device, unsigned int duration_ms);
void devfreq_register_boost_device(enum df_device device, struct devfreq *df);
struct boost_dev *devfreq_get_boost_dev(enum df_device device);
#else
static inline
void devfreq_boost_kick(enum df_device device)
{
}
static inline
void devfreq_boost_kick_max(enum df_device device, unsigned int duration_ms)
{
}
static inline
void devfreq_register_boost_device(enum df_device device, struct devfreq *df)
{
}
static inline
struct boost_dev *devfreq_get_boost_dev(enum df_device device)
{
	return NULL;
}
#endif

#endif /* _DEVFREQ_BOOST_H_ */
