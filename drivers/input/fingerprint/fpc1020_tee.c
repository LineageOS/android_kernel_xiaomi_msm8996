/*
 * FPC1020 Fingerprint sensor device driver
 *
 * This driver will control the platform resources that the FPC fingerprint
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
 *
 *
 * Copyright (c) 2015 Fingerprint Cards AB <tech@fingerprints.com>
 * Copyright (C) 2016 XiaoMi, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License Version 2
 * as published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/regulator/consumer.h>
#include <linux/wakelock.h>
#include <soc/qcom/scm.h>
#ifdef CONFIG_FB
#include <linux/notifier.h>
#include <linux/fb.h>
#endif

#define FPC1020_NAME "fpc1020"

#define FPC1020_RESET_LOW_US 1000
#define FPC1020_RESET_HIGH1_US 100
#define FPC1020_RESET_HIGH2_US 1250
#define FPC_TTW_HOLD_TIME 1000

struct fpc1020_data {
	struct device *dev;
	int  irq_gpio;
	bool irq_enabled;
	int  rst_gpio;
	int  fp_id_gpio;
	int  wakeup_enabled;

	struct pinctrl         *ts_pinctrl;
	struct pinctrl_state   *gpio_state_active;
	struct pinctrl_state   *gpio_state_suspend;
	struct wake_lock        ttw_wl;
#ifdef CONFIG_FB
	struct notifier_block fb_notifier;
	struct work_struct reset_work;
	struct workqueue_struct *reset_workqueue;
#endif

	bool screen_on;
	int proximity_state; /* 0:far 1:near */
	spinlock_t irq_lock;
	struct completion irq_sent;
	struct mutex lock;

	struct input_handler input_handler;
	bool report_key_events;
	struct work_struct pm_work;
};

enum {
	FP_ID_LOW_0 = 0,
	FP_ID_HIGH_1,
	FP_ID_FLOAT_2,
	FP_ID_UNKNOWN
};

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

static void set_fingerprintd_nice(int nice)
{
	struct task_struct *p;

	read_lock(&tasklist_lock);
	for_each_process(p) {
		if (!memcmp(p->comm, "fingerprintd", 13)) {
			set_user_nice(p, nice);
			break;
		}
	}
	read_unlock(&tasklist_lock);
}

static void set_fpc_irq(struct fpc1020_data *fpc1020, bool enable)
{
	bool irq_enabled;

	spin_lock(&fpc1020->irq_lock);
	irq_enabled = fpc1020->irq_enabled;
	fpc1020->irq_enabled = enable;
	spin_unlock(&fpc1020->irq_lock);

	if (enable == irq_enabled)
		return;

	if (enable)
		enable_irq(gpio_to_irq(fpc1020->irq_gpio));
	else
		disable_irq(gpio_to_irq(fpc1020->irq_gpio));
}

static void fpc1020_suspend_resume(struct work_struct *work)
{
	struct fpc1020_data *fpc1020 =
		container_of(work, typeof(*fpc1020), pm_work);

	if (fpc1020->screen_on) {
		/* Unconditionally enable IRQ when screen turns on */
		set_fpc_irq(fpc1020, true);

		/* Restore fingerprintd priority to defaults */
		set_fingerprintd_nice(0);
	} else {
		if (fpc1020->wakeup_enabled == 0) {
			/* Disable IRQ when screen turns off,
			   only if fingerprint wake up is disabled */
			set_fpc_irq(fpc1020, false);
		} else {
			/* Elevate fingerprintd priority when screen is off to ensure
			 * the fingerprint sensor is responsive and that the haptic
			 * response on successful verification always fires */
			set_fingerprintd_nice(-1);
		}
	}
}

#ifdef CONFIG_FB
static int fpc1020_fb_notifier_cb(struct notifier_block *self,
		unsigned long event, void *data)
{
	int *transition;
	struct fb_event *evdata = data;
	struct fpc1020_data *fpc1020 =
			container_of(self, struct fpc1020_data,
			fb_notifier);

	if (evdata && evdata->data && fpc1020) {
		transition = evdata->data;
		if (event == FB_EVENT_BLANK) {
			if (*transition == FB_BLANK_POWERDOWN) {
				fpc1020->screen_on = false;
				queue_work(system_highpri_wq, &fpc1020->pm_work);
			}
		} else if (event == FB_EARLY_EVENT_BLANK) {
			if (*transition == FB_BLANK_UNBLANK || *transition == FB_BLANK_NORMAL) {
				fpc1020->screen_on = true;
				queue_work(system_highpri_wq, &fpc1020->pm_work);
			}
		}
	}
	return 0;
}
#endif

static int fpc1020_request_named_gpio(struct fpc1020_data *fpc1020,
		const char *label, int *gpio)
{
	struct device *dev = fpc1020->dev;
	struct device_node *np = dev->of_node;
	int rc = of_get_named_gpio(np, label, 0);
	if (rc < 0) {
		dev_err(dev, "failed to get '%s'\n", label);
		return rc;
	}
	*gpio = rc;
	rc = devm_gpio_request(dev, *gpio, label);
	if (rc) {
		dev_err(dev, "failed to request gpio %d\n", *gpio);
		return rc;
	}
	dev_info(dev, "%s - gpio: %d\n", label, *gpio);
	return 0;
}

/* -------------------------------------------------------------------- */
static int fpc1020_pinctrl_init_tee(struct fpc1020_data *fpc1020)
{
	int ret = 0;
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

/* -------------------------------------------------------------------- */
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

/**
 * sysf node to check the interrupt status of the sensor, the interrupt
 * handler should perform sysf_notify to allow userland to poll the node.
 */
static ssize_t irq_get(struct device *device,
			     struct device_attribute *attribute,
			     char *buffer)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(device);
	int irq = gpio_get_value(fpc1020->irq_gpio);
	complete(&fpc1020->irq_sent);
	return scnprintf(buffer, PAGE_SIZE, "%i\n", irq);
}


/**
 * writing to the irq node will just drop a printk message
 * and return success, used for latency measurement.
 */
static ssize_t irq_ack(struct device *device,
			     struct device_attribute *attribute,
			     const char *buffer, size_t count)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(device);
	dev_dbg(fpc1020->dev, "%s\n", __func__);
	return count;
}
static DEVICE_ATTR(irq, S_IRUSR | S_IWUSR, irq_get, irq_ack);

static ssize_t enable_key_events_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", fpc1020->report_key_events);
}

static ssize_t enable_key_events_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	int rc;
	unsigned long input;
	struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);

	rc = kstrtoul(buf, 0, &input);
	if (rc < 0)
		return rc;

	fpc1020->report_key_events = !!input;

	return count;
}
static DEVICE_ATTR(enable_key_events, S_IWUSR | S_IRUSR, enable_key_events_show,
		   enable_key_events_store);

static ssize_t enable_wakeup_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	char c;

	c = fpc1020->wakeup_enabled ? '1' : '0';
	return scnprintf(buf, PAGE_SIZE, "%c\n", c);
}

static ssize_t enable_wakeup_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	int i;

	if (sscanf(buf, "%u", &i) == 1 && i < 2) {
		fpc1020->wakeup_enabled = (i == 1);

		dev_info(dev, "%s\n", i ? "wakeup enabled" : "wakeup disabled");
		return count;
	} else {
		dev_info(dev, "wakeup_enabled write error\n");
		return -EINVAL;
	}
}
static DEVICE_ATTR(enable_wakeup, S_IWUSR | S_IRUSR, enable_wakeup_show,
		   enable_wakeup_store);

static ssize_t proximity_state_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	int rc, val;

	rc = kstrtoint(buf, 10, &val);
	if (rc)
		return -EINVAL;

	fpc1020->proximity_state = !!val;

	if (!fpc1020->screen_on) {
		if (fpc1020->proximity_state == 1) {
			/* Disable IRQ when screen is off and proximity sensor is covered */
			set_fpc_irq(fpc1020, false);
		} else if (fpc1020->wakeup_enabled == 1) {
			/* Enable IRQ when screen is off and proximity sensor is uncovered,
			   but only if fingerprint wake up is enabled */
			set_fpc_irq(fpc1020, true);
		}
	}

	return count;
}

static DEVICE_ATTR(proximity_state, S_IWUSR, NULL, proximity_state_set);

static struct attribute *attributes[] = {
	&dev_attr_irq.attr,
	&dev_attr_enable_key_events.attr,
	&dev_attr_enable_wakeup.attr,
	&dev_attr_proximity_state.attr,
	NULL
};

static const struct attribute_group attribute_group = {
	.attrs = attributes,
};

static irqreturn_t fpc1020_irq_handler(int irq, void *handle)
{
	struct fpc1020_data *fpc1020 = handle;
	dev_dbg(fpc1020->dev, "%s\n", __func__);

	/* Make sure 'wakeup_enabled' is updated before using it
	** since this is interrupt context (other thread...) */
	smp_rmb();

	if (fpc1020->wakeup_enabled) {
		wake_lock_timeout(&fpc1020->ttw_wl, msecs_to_jiffies(FPC_TTW_HOLD_TIME));
		dev_info(fpc1020->dev, "%s - wake_lock_timeout\n", __func__);
	}

	sysfs_notify(&fpc1020->dev->kobj, NULL, dev_attr_irq.attr.name);

	reinit_completion(&fpc1020->irq_sent);
	wait_for_completion_timeout(&fpc1020->irq_sent, msecs_to_jiffies(100));

	return IRQ_HANDLED;
}

/* -------------------------------------------------------------------- */
static int fpc1020_get_fp_id_tee(struct fpc1020_data *fpc1020)
{
	struct device *dev = fpc1020->dev;
	struct device_node *np = dev->of_node;
	int error = 0;
	int fp_id = FP_ID_UNKNOWN;
	int pull_up_value = 0;
	int pull_down_value = 0;

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
		if ((pull_up_value == pull_down_value) && (pull_up_value == 0))
			fp_id = FP_ID_LOW_0;
		else if ((pull_up_value == pull_down_value) && (pull_up_value == 1))
			fp_id = FP_ID_HIGH_1;
		else
			fp_id = FP_ID_FLOAT_2;

	} else {
		dev_err(dev,
				"fpc vendor id FP_GPIO is invalid !!!\n");
		fp_id = FP_ID_UNKNOWN;
	}
	return fp_id;
}
/* -------------------------------------------------------------------- */
static int fpc1020_tee_remove(struct platform_device *pdev)
{
#if 0
	struct fpc1020_data *fpc1020 = platform_get_drvdata(pdev);
#ifdef CONFIG_FB
	fb_unregister_client(&fpc1020->fb_notifier);
#endif
#endif
	return 0;
}

static int fpc1020_tee_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	int rc = 0;
	int irqf;
	int fp_id = FP_ID_UNKNOWN;
	struct device_node *np = dev->of_node;

	struct fpc1020_data *fpc1020 = devm_kzalloc(dev, sizeof(*fpc1020),
			GFP_KERNEL);
	if (!fpc1020) {
		dev_err(dev,
			"failed to allocate memory for struct fpc1020_data\n");
		rc = -ENOMEM;
		goto exit;
	}

	dev_info(dev, "%s -\n", __func__);

	fpc1020->dev = dev;
	dev_set_drvdata(dev, fpc1020);

	if (!np) {
		dev_err(dev, "no of node found\n");
		rc = -EINVAL;
		goto exit;
	}

	fpc1020->wakeup_enabled = 0;

	rc = fpc1020_request_named_gpio(fpc1020, "fpc,irq-gpio",
			&fpc1020->irq_gpio);
	if (rc)
		goto exit;

	rc = gpio_direction_input(fpc1020->irq_gpio);

	if (rc) {
		dev_err(fpc1020->dev,
			"gpio_direction_input (irq) failed.\n");
		goto exit;
	}

	rc = fpc1020_request_named_gpio(fpc1020, "fpc,reset-gpio",
			&fpc1020->rst_gpio);
	if (rc)
		goto exit;

	rc = fpc1020_pinctrl_init_tee(fpc1020);
	if (rc)
		goto exit;

	rc = fpc1020_pinctrl_select_tee(fpc1020, true);
	if (rc)
		goto exit;

	wake_lock_init(&fpc1020->ttw_wl, WAKE_LOCK_SUSPEND, "fpc_ttw_wl");

	spin_lock_init(&fpc1020->irq_lock);
	fpc1020->irq_enabled = true;

	irqf = IRQF_TRIGGER_RISING | IRQF_ONESHOT;
	mutex_init(&fpc1020->lock);
	init_completion(&fpc1020->irq_sent);
	rc = devm_request_threaded_irq(dev, gpio_to_irq(fpc1020->irq_gpio),
			NULL, fpc1020_irq_handler, irqf,
			dev_name(dev), fpc1020);
	if (rc) {
		dev_err(dev, "could not request irq %d\n",
				gpio_to_irq(fpc1020->irq_gpio));
		goto exit;
	}
	dev_info(dev, "requested irq %d\n", gpio_to_irq(fpc1020->irq_gpio));
	/* Request that the interrupt should be wakeable*/
	if (fpc1020->wakeup_enabled) {
		enable_irq_wake(gpio_to_irq(fpc1020->irq_gpio));
	}

	fpc1020->report_key_events = false;

	fpc1020->input_handler.filter = input_filter;
	fpc1020->input_handler.connect = input_connect;
	fpc1020->input_handler.disconnect = input_disconnect;
	fpc1020->input_handler.name = FPC1020_NAME;
	fpc1020->input_handler.id_table = ids;
	rc = input_register_handler(&fpc1020->input_handler);
	if (rc) {
		dev_err(dev, "failed to register key handler\n");
		goto exit;
	}

	rc = sysfs_create_group(&dev->kobj, &attribute_group);
	if (rc) {
		dev_err(dev, "could not create sysfs\n");
		goto exit;
	}

	rc = gpio_direction_output(fpc1020->rst_gpio, 1);

	if (rc) {
		dev_err(fpc1020->dev,
			"gpio_direction_output (reset) failed.\n");
		goto exit;
	}
	gpio_set_value(fpc1020->rst_gpio, 1);
	udelay(FPC1020_RESET_HIGH1_US);

	gpio_set_value(fpc1020->rst_gpio, 0);
	udelay(FPC1020_RESET_LOW_US);

	gpio_set_value(fpc1020->rst_gpio, 1);
	udelay(FPC1020_RESET_HIGH2_US);

	fp_id = fpc1020_get_fp_id_tee(fpc1020);
	dev_info(fpc1020->dev,
		"fpc vendor fp_id is %d (0:low 1:high 2:float 3:unknown)\n", fp_id);

	INIT_WORK(&fpc1020->pm_work, fpc1020_suspend_resume);

#ifdef CONFIG_FB
	fpc1020->fb_notifier.notifier_call = fpc1020_fb_notifier_cb;
	rc = fb_register_client(&fpc1020->fb_notifier);
	if (rc < 0) {
		dev_err(dev,
			"%s: Failed to register fb notifier client\n",
			__func__);
	}
#endif

	dev_info(dev, "%s: ok - end\n", __func__);
exit:
	return rc;
}


static struct of_device_id fpc1020_of_match[] = {
	{ .compatible = "fpc,fpc1020", },
	{}
};
MODULE_DEVICE_TABLE(of, fpc1020_of_match);

#ifdef CONFIG_PM
static int fpc1020_pm_suspend(struct device *dev)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	dev_dbg(fpc1020->dev, "%s \n", __func__);
	return 0;
}

static int fpc1020_pm_resume(struct device *dev)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	dev_dbg(fpc1020->dev, "%s \n", __func__);
	return 0;
}

static const struct dev_pm_ops fpc1020_dev_pm_ops = {
	.suspend = fpc1020_pm_suspend,
	.resume  = fpc1020_pm_resume,
};
#endif

static struct platform_driver fpc1020_driver = {
	.driver = {
		.name = FPC1020_NAME,
		.owner = THIS_MODULE,
		.of_match_table = fpc1020_of_match,
#ifdef CONFIG_PM
		.pm = &fpc1020_dev_pm_ops,
#endif
	},
	.probe = fpc1020_tee_probe,
	.remove = fpc1020_tee_remove,
};
module_platform_driver(fpc1020_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Aleksej Makarov");
MODULE_AUTHOR("Henrik Tillman <henrik.tillman@fingerprints.com>");
MODULE_DESCRIPTION("FPC1020 Fingerprint sensor device driver.");
