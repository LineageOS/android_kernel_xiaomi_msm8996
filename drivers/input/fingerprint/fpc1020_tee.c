/*
 * FPC1020 Fingerprint sensor device driver
 *
 * Copyright (c) 2015 Fingerprint Cards AB <tech@fingerprints.com>:
 *	Aleksej Makarov
 * 	Henrik Tillman <henrik.tillman@fingerprints.com>
 * Copyright (C) 2016 XiaoMi, Inc.
 * Copyright (C) 2017 Sultanxda <sultanxda@gmail.com>
 * Copyright (C) 2018 xNombre <kartapolska@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License Version 2
 * as published by the Free Software Foundation.
 *
 * This driver will control the platform resouretes that the FPC fingerprint
 * sensor needs to operate. The major things are probing the sensor to check
 * that it is actually connected and let the Kernel know this and with that also
 * enabling and disabling of regulators, enabling and disabling of platform
 * clocks, controlling GPIOs such as SPI chip select, sensor reset line, sensor
 * IRQ line, MISO and MOSI lines.
 *
 * The driver will expose most of its available functionality in sysfs which
 * enables dynamic control of these features from eg. a user space process.
 *
 * The sensor's IRQ events will be pushed to Kernel's event handling system and
 * are exposed in the drivers event node. This makes it possible for a user
 * space process to poll the input node and receive IRQ events easily. Usually
 * this node is available under /dev/input/eventX where 'X' is a number given by
 * the event system. A user space process will need to traverse all the event
 * nodes and ask for its parent's name (through EVIOCGNAME) which should match
 * the value in device tree named input-device-name.
 *
 * This driver will NOT send any SPI commands to the sensor it only controls the
 * electrical parts.
 */

#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/pm_wakeup.h>
#include <linux/fpc1020.h>

#define FPC_TTW_HOLD_TIME_MS	(1000)
#define FPC1020_NAME "fpc1020"

atomic_t fp_hal_pid;

struct fpc1020_data {
	struct device *dev;
	struct notifier_block fb_notif;
	struct completion irq_sent;
	struct work_struct pm_work;
	struct pinctrl         *ts_pinctrl;
	struct pinctrl_state   *gpio_state_active;
	struct pinctrl_state   *gpio_state_suspend;
 	struct input_handler input_handler;
	spinlock_t irq_lock;

	bool irq_disabled;
	bool proximity_state; /* 0:far 1:near */
	bool screen_off;
 	bool report_key_events;

	int irq_gpio;
	int fp_id_gpio; //do I need this ??
	int wakeup_enabled;
};

enum {
	FP_ID_LOW_0 = 0,
	FP_ID_HIGH_1,
	FP_ID_FLOAT_2,
	FP_ID_UNKNOWN
};

static void set_fpc_irq(struct fpc1020_data *f, bool enable)
{
	bool irq_disabled;

	spin_lock(&f->irq_lock);
	irq_disabled = f->irq_disabled;
	f->irq_disabled = !enable;
	spin_unlock(&f->irq_lock);

	if (enable == !irq_disabled)
		return;

	if (enable)
		enable_irq(gpio_to_irq(f->irq_gpio));
	else
		disable_irq(gpio_to_irq(f->irq_gpio));
}

static int fpc1020_request_named_gpio(struct fpc1020_data *f,
	const char *label, int *gpio)
{
	struct device *dev = f->dev;
	struct device_node *np = dev->of_node;
	int ret;

	ret = of_get_named_gpio(np, label, 0);
	if (ret < 0) {
		dev_err(dev, "failed to get '%s'\n", label);
		return ret;
	}

	*gpio = ret;

	ret = devm_gpio_request(dev, *gpio, label);
	if (ret) {
		dev_err(dev, "failed to request gpio %d\n", *gpio);
		return ret;
	}

	return 0;
}

static int input_connect(struct input_handler *handler,
 		struct input_dev *dev, const struct input_device_id *id) {
 	int rc;
 	struct input_handle *handle;
 	struct fpc1020_data *fpc1020 =
 		container_of(handler, struct fpc1020_data, input_handler);
 
 	if (!strstr(dev->name, "uinput-fpc"))
 		return -ENODEV;
 
 	handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
 	if (!handle)
 		return -ENOMEM;
 
 	handle->dev = dev;
 	handle->handler = handler;
 	handle->name = FPC1020_NAME;
 	handle->private = fpc1020;
 
 	rc = input_register_handle(handle);
 	if (rc)
 		goto err_input_register_handle;
 
 	rc = input_open_device(handle);
 	if (rc)
 		goto err_input_open_device;
 
 	return 0;
 
 err_input_open_device:
 	input_unregister_handle(handle);
 err_input_register_handle:
 	kfree(handle);
 	return rc;
}
 
static bool input_filter(struct input_handle *handle, unsigned int type,
 		unsigned int code, int value)
{
 	struct fpc1020_data *fpc1020 = handle->private;
 
 	return !fpc1020->report_key_events;
}
 
static void input_disconnect(struct input_handle *handle)
{
 	input_close_device(handle);
 	input_unregister_handle(handle);
 	kfree(handle);
}
 
static const struct input_device_id ids[] = {
 	{
 		.flags = INPUT_DEVICE_ID_MATCH_EVBIT,
 		.evbit = { BIT_MASK(EV_KEY) },
 	},
 	{ },
};

/*
 * sysfs node to check the interrupt status of the sensor, the interrupt
 * handler should perform sysf_notify to allow userland to poll the node.
 */
static ssize_t irq_get(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct fpc1020_data *f = dev_get_drvdata(dev);
	bool irq_disabled;
	int irq;
	ssize_t count;

	spin_lock(&f->irq_lock);
	irq_disabled = f->irq_disabled;
	spin_unlock(&f->irq_lock);

	irq = !irq_disabled && gpio_get_value(f->irq_gpio);
	count = scnprintf(buf, PAGE_SIZE, "%d\n", irq);

	complete(&f->irq_sent);

	return count;
}

/**
 * writing to the irq node will just drop a printk message
 * and return success, used for latency measurement.
 */
static ssize_t irq_ack(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	dev_dbg(dev, "%s\n", __func__);
	return count;
}

static ssize_t screen_state_get(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct fpc1020_data *f = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "%d\n", !f->screen_off);
}

static ssize_t proximity_state_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct fpc1020_data *f = dev_get_drvdata(dev);
	int ret, val;

	ret = kstrtoint(buf, 10, &val);
	if (ret)
		return -EINVAL;

	f->proximity_state = !!val;

	if (f->screen_off) {
		if(f->proximity_state)
			set_fpc_irq(f, false);
		else if (f->wakeup_enabled)
			set_fpc_irq(f, true);
	}

	return count;
}

static ssize_t enable_wakeup_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct fpc1020_data *f= dev_get_drvdata(dev);
	char c;

	c = f->wakeup_enabled ? '1' : '0';
	return scnprintf(buf, PAGE_SIZE, "%c\n", c);
}

static ssize_t enable_wakeup_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct fpc1020_data *f = dev_get_drvdata(dev);
	int i;

	if (sscanf(buf, "%u", &i) == 1 && i < 2) {
		f->wakeup_enabled = (i == 1);

		return count;
	} else
		return -EINVAL;
}

static ssize_t enable_key_events_show(struct device *dev,
 	struct device_attribute *attr, char *buf)
{
 	struct fpc1020_data *f = dev_get_drvdata(dev);
 
 	return sprintf(buf, "%d\n", f->report_key_events);
}
 
 static ssize_t enable_key_events_store(struct device *dev,
 	struct device_attribute *attr, const char *buf, size_t count)
{
 	int rc;
 	unsigned long input;
 	struct fpc1020_data *f = dev_get_drvdata(dev);
 
 	rc = kstrtoul(buf, 0, &input);
 	if (rc < 0)
 		return rc;
 
 	f->report_key_events = !!input;
 
 	return count;
}

static DEVICE_ATTR(enable_key_events, S_IWUSR | S_IRUSR, enable_key_events_show, enable_key_events_store);
static DEVICE_ATTR(enable_wakeup, S_IWUSR | S_IRUSR, enable_wakeup_show, enable_wakeup_store);
static DEVICE_ATTR(irq, S_IRUSR | S_IWUSR, irq_get, irq_ack);
static DEVICE_ATTR(proximity_state, S_IWUSR, NULL, proximity_state_set);
static DEVICE_ATTR(screen_state, S_IRUSR, screen_state_get, NULL);
	
static struct attribute *attributes[] = {
	&dev_attr_irq.attr,
	&dev_attr_proximity_state.attr,
	&dev_attr_screen_state.attr,
	&dev_attr_enable_key_events.attr,
	&dev_attr_enable_wakeup.attr,
	NULL
};

static const struct attribute_group fpc1020_attr_group = {
	.attrs = attributes,
};

static void set_fingerprint_hal_nice(int nice)
{
	struct task_struct *p;
	int pid = atomic_read(&fp_hal_pid);
	if(!pid) {
		return;
	}

	read_lock(&tasklist_lock);
	for_each_process(p) {
		if(p->pid == pid) {
			set_user_nice(p, nice);
			pr_debug("fp nice set!!");
			break;
		}
	}
	read_unlock(&tasklist_lock);
}

static void fpc1020_suspend_resume(struct work_struct *work)
{
	struct fpc1020_data *f = container_of(work, typeof(*f), pm_work);

	/* Escalate fingerprintd priority when screen is off */
	if (f->screen_off) {
		if(f->wakeup_enabled)
			set_fingerprint_hal_nice(MIN_NICE);
		else
			set_fpc_irq(f, false);
	} else {
		set_fpc_irq(f, true);
		set_fingerprint_hal_nice(0);
	}

	sysfs_notify(&f->dev->kobj, NULL, dev_attr_screen_state.attr.name);
}

static int fb_notifier_callback(struct notifier_block *nb,
		unsigned long action, void *data)
{
	struct fpc1020_data *f = container_of(nb, typeof(*f), fb_notif);
	struct fb_event *evdata = data;
	int *blank = evdata->data;

	if (action != FB_EARLY_EVENT_BLANK)
		return 0;

	if (*blank == FB_BLANK_UNBLANK) {
		cancel_work_sync(&f->pm_work);
		f->screen_off = false;
		queue_work(system_highpri_wq, &f->pm_work);
	} else if (*blank == FB_BLANK_POWERDOWN) {
		cancel_work_sync(&f->pm_work);
		f->screen_off = true;
		queue_work(system_highpri_wq, &f->pm_work);
	}

	return 0;
}

static irqreturn_t fpc1020_irq_handler(int irq, void *dev_id)
{
	struct fpc1020_data *f = dev_id;

	/* Make sure 'wakeup_enabled' is updated before using it
	** since this is interrupt context (other thread...) */
	smp_rmb();

	if (f->screen_off && f->wakeup_enabled)
		pm_wakeup_event(f->dev, FPC_TTW_HOLD_TIME_MS);

	sysfs_notify(&f->dev->kobj, NULL, dev_attr_irq.attr.name);

	reinit_completion(&f->irq_sent);
	wait_for_completion_timeout(&f->irq_sent, msecs_to_jiffies(100));

	return IRQ_HANDLED;

}

static int fpc1020_pinctrl_init_tee(struct fpc1020_data *fpc1020)
{
	int ret;
	struct device *dev = fpc1020->dev;

	fpc1020->ts_pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR_OR_NULL(fpc1020->ts_pinctrl)) {
		dev_err(dev, "Target does not use pinctrl\n");
		ret = PTR_ERR(fpc1020->ts_pinctrl);
		goto err;
	}

	fpc1020->gpio_state_active =
		pinctrl_lookup_state(fpc1020->ts_pinctrl, "pmx_fp_active");
	if (IS_ERR_OR_NULL(fpc1020->gpio_state_active)) {
		dev_err(dev, "Cannot get active pinstate\n");
		ret = PTR_ERR(fpc1020->gpio_state_active);
		goto err;
	}

	fpc1020->gpio_state_suspend =
		pinctrl_lookup_state(fpc1020->ts_pinctrl, "pmx_fp_suspend");
	if (IS_ERR_OR_NULL(fpc1020->gpio_state_suspend)) {
		dev_err(dev, "Cannot get sleep pinstate\n");
		ret = PTR_ERR(fpc1020->gpio_state_suspend);
		goto err;
	}

	return 0;
err:
	fpc1020->ts_pinctrl = NULL;
	fpc1020->gpio_state_active = NULL;
	fpc1020->gpio_state_suspend = NULL;
	return ret;
}

static int fpc1020_pinctrl_select_tee(struct fpc1020_data *fpc1020, bool on)
{
	int ret = 0;
	struct pinctrl_state *pins_state;
	struct device *dev = fpc1020->dev;

	pins_state = on ? fpc1020->gpio_state_active : fpc1020->gpio_state_suspend;
	if (!IS_ERR_OR_NULL(pins_state)) {
		ret = pinctrl_select_state(fpc1020->ts_pinctrl, pins_state);
		if (ret) {
			dev_err(dev, "can not set %s pins\n",
				on ? "pmx_ts_active" : "pmx_ts_suspend");
			return ret;
		}
	} else {
		dev_err(dev, "not a valid '%s' pinstate\n",
			on ? "pmx_ts_active" : "pmx_ts_suspend");
	}

	return ret;
}

static int fpc1020_get_fp_id_tee(struct fpc1020_data *fpc1020)
{
	struct device *dev = fpc1020->dev;
	struct device_node *np = dev->of_node;
	int error, pull_up_value, pull_down_value;
	int fp_id = FP_ID_UNKNOWN;

	fpc1020->fp_id_gpio = of_get_named_gpio(np, "fpc,fp-id-gpio", 0);

	if (fpc1020->fp_id_gpio < 0) {
		dev_err(dev, "failed to get '%s'\n", "fpc,fp-id-gpio");
		return fp_id;
	}
	dev_info(dev, "%s - gpio: %d\n", "fp-id-gpio", fpc1020->fp_id_gpio);

	if (gpio_is_valid(fpc1020->fp_id_gpio)) {
		error = devm_gpio_request_one(fpc1020->dev, fpc1020->fp_id_gpio,
					      GPIOF_IN, "fpc1020_fp_id");
		if (error < 0) {
			dev_err(dev,
				"Failed to request fpc fp_id_gpio %d, error %d\n",
				fpc1020->fp_id_gpio, error);
			return fp_id;
		}

		error = gpio_direction_output(fpc1020->fp_id_gpio, 1);
		if (error) {
			dev_err(fpc1020->dev,
				"gpio_direction_output (fp_id_gpio = 1) failed.\n");
			return fp_id;
		}
		usleep_range(2000, 3000); /* 2000us abs min. */
		error = gpio_direction_input(fpc1020->fp_id_gpio);
		if (error) {
			dev_err(fpc1020->dev,
				"gpio_direction_input (fp_id_gpio) failed.\n");
			return fp_id;
		}
		usleep_range(2000, 3000); /* 2000us abs min. */
		pull_up_value = gpio_get_value(fpc1020->fp_id_gpio);
		usleep_range(2000, 3000); /* 2000us abs min. */
		error = gpio_direction_output(fpc1020->fp_id_gpio, 0);
		if (error) {
			dev_err(fpc1020->dev,
				"gpio_direction_output (fp_id_gpio = 0) failed.\n");
			return fp_id;
		}
		usleep_range(2000, 3000); /* 2000us abs min. */
		error = gpio_direction_input(fpc1020->fp_id_gpio);
		if (error) {
			dev_err(fpc1020->dev,
				"gpio_direction_input (fp_id_gpio) failed.\n");
			return fp_id;
		}
		usleep_range(2000, 3000); /* 2000us abs min. */
		pull_down_value = gpio_get_value(fpc1020->fp_id_gpio);
		usleep_range(2000, 3000); /* 2000us abs min. */
		if ((pull_up_value == pull_down_value) && (pull_up_value == 0)) {
			fp_id = FP_ID_LOW_0;
		} else if ((pull_up_value == pull_down_value) && (pull_up_value == 1)) {
			fp_id = FP_ID_HIGH_1;
		} else {
			fp_id = FP_ID_FLOAT_2;
		}
	} else {
		dev_err(dev, "fpc vendor id FP_GPIO is invalid !!!\n");
		fp_id = FP_ID_UNKNOWN;
	}
	return fp_id;
}

static int fpc1020_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;

	struct fpc1020_data *f;
	int id_gpio, ret;
	int fp_id = FP_ID_UNKNOWN;

	if (!np) {
		dev_err(dev, "no of node found\n");
		return -EINVAL;
	}

	f = devm_kzalloc(dev, sizeof(*f), GFP_KERNEL);
	if (!f) {
		dev_err(dev, "devm_kzalloc failed for struct fpc1020_data\n");
		return -ENOMEM;
	}

	f->dev = dev;
	dev_set_drvdata(dev, f);

	ret = fpc1020_request_named_gpio(f, "fpc,irq-gpio", &f->irq_gpio);
	if (ret)
		goto err1;

	ret = gpio_direction_input(f->irq_gpio);
	if (ret)
		goto err1;

	ret = fpc1020_pinctrl_init_tee(f);
	if (ret)
		goto err1;

	ret = fpc1020_pinctrl_select_tee(f, true);
	if (ret)
		goto err1;

	spin_lock_init(&f->irq_lock);
	INIT_WORK(&f->pm_work, fpc1020_suspend_resume);
	init_completion(&f->irq_sent);

	ret = sysfs_create_group(&dev->kobj, &fpc1020_attr_group);
	if (ret) {
		dev_err(dev, "Could not create sysfs, ret: %d\n", ret);
		goto err1;
	}

	ret = devm_request_threaded_irq(dev, gpio_to_irq(f->irq_gpio),
			NULL, fpc1020_irq_handler,
			IRQF_TRIGGER_RISING | IRQF_ONESHOT | IRQF_NO_SUSPEND,
			dev_name(dev), f);
	if (ret) {
		dev_err(dev, "Could not request irq, ret: %d\n", ret);
		goto err2;
	}

	f->wakeup_enabled = 1;
	f->report_key_events = false;

 	f->input_handler.filter = input_filter;
 	f->input_handler.connect = input_connect;
 	f->input_handler.disconnect = input_disconnect;
 	f->input_handler.name = FPC1020_NAME;
 	f->input_handler.id_table = ids;

 	ret = input_register_handler(&f->input_handler);
 	if (ret)
		goto err3;

	fp_id = fpc1020_get_fp_id_tee(f);
	dev_dbg(f->dev,
		"fpc vendor fp_id is %d (0:low 1:high 2:float 3:unknown)\n", fp_id);

	f->fb_notif.notifier_call = fb_notifier_callback;
	ret = fb_register_client(&f->fb_notif);
	if (ret) {
		dev_err(dev, "Unable to register fb_notifier, ret: %d\n", ret);
		goto err3;
	}

	device_init_wakeup(dev, 1);

	return 0;
err3:
	devm_free_irq(dev, gpio_to_irq(f->irq_gpio), f);
err2:
	sysfs_remove_group(&dev->kobj, &fpc1020_attr_group);
err1:
	devm_kfree(dev, f);
	return ret;
}

static int fpc1020_sys_suspend(struct device *dev)
{
	struct fpc1020_data *f = dev_get_drvdata(dev);

	enable_irq_wake(gpio_to_irq(f->irq_gpio));
	return 0;
}

static int fpc1020_sys_resume(struct device *dev)
{
	struct fpc1020_data *f = dev_get_drvdata(dev);

	disable_irq_wake(gpio_to_irq(f->irq_gpio));
	return 0;
}

static const struct of_device_id fpc1020_of_match[] = {
	{ .compatible = "fpc,fpc1020", },
	{ }
};

static const struct dev_pm_ops fpc1020_pm_ops = {
	.suspend = fpc1020_sys_suspend,
	.resume = fpc1020_sys_resume,
};

static struct platform_driver fpc1020_driver = {
	.probe = fpc1020_probe,
	.driver = {
		.name = FPC1020_NAME,
		.owner = THIS_MODULE,
		.of_match_table = fpc1020_of_match,
		.pm = &fpc1020_pm_ops,
	},
};

static int __init fpc1020_init(void)
{
	return platform_driver_register(&fpc1020_driver);
}
device_initcall(fpc1020_init);

