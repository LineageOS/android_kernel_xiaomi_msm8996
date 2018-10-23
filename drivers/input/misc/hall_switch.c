#include <linux/module.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/bitops.h>

#include <linux/platform_device.h>

#include <linux/interrupt.h>
#include <linux/input.h>
#include <linux/kernel.h>
#include <linux/of_gpio.h>
#include <linux/regulator/consumer.h>


static volatile int key_debug = 5;
#define HALL_GPIO 124

#define SSC_VDD_2P85_HPM_LOAD 600000 //uA


struct hall_switch_data{
    struct regulator *vdd;
    struct regulator *ssc_vdd;
    struct input_dev *input_dev;
    struct delayed_work hall_work;
    struct workqueue_struct *hall_workqueue;
    int irq_gpio;
    int hall_irq;
    int hall_gpio_val;
	struct device	*dev;
};
static struct hall_switch_data *hall_data = NULL;
static irqreturn_t misc_hall_irq(int irq, void *data)
{
    struct hall_switch_data *hall_data = data;
    int gpio_value;
    //int ret;

    if(hall_data == NULL)
        return 0;
    disable_irq_nosync(hall_data->hall_irq);
    gpio_value = gpio_get_value(HALL_GPIO);
    if(gpio_value){
        /*----hall far----*/
        if(key_debug == 5)
            printk("hall-switch %d,report: far\n",HALL_GPIO);
        input_event(hall_data->input_dev, EV_SW, SW_LID, 0);
        input_sync(hall_data->input_dev);
    }else{
        /*----hall near----*/
        if(key_debug == 5)
            printk("hall-switch %d,report: near!!!\n",HALL_GPIO);
        input_event(hall_data->input_dev, EV_SW, SW_LID, 1);
        input_sync(hall_data->input_dev);
    }
    enable_irq(hall_data->hall_irq);
    return IRQ_HANDLED;
}

static ssize_t hall_irq_gpio_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    int tmp = gpio_get_value(HALL_GPIO);
    return sprintf(buf, "%s\n", tmp==0?"0":"1");
}

static DEVICE_ATTR(hall_int_gpio, 0444, hall_irq_gpio_show, NULL);

static struct attribute *hall_attributes[] = {
    &dev_attr_hall_int_gpio.attr,
    NULL,
};

static struct attribute_group hall_attr_group = {
    .attrs = hall_attributes,
};

static int hall_probe(struct platform_device *pdev)
{
    static int is_probed = 0; /* Flag used to avoid double probe. */
    int retval = 0;

    int err = 0;
    struct device_node *np = pdev->dev.of_node;

    if (is_probed) {
        printk("%s: Already probed succesfully, ignored\n", __FUNCTION__);
        return 0;
    }

    hall_data = kzalloc(sizeof(struct hall_switch_data), GFP_KERNEL);
    if (!hall_data){
        err = -ENOMEM;
        goto exit;
    }

    /*hall_data->vdd = regulator_get(&pdev->dev,"vdd");
    if (!IS_ERR(hall_data->vdd)) {
        printk("%s,vdd is correct",__func__);
        err = regulator_enable(hall_data->vdd);
        if (err) {
            printk("%s,Regulator vdd enable failed ret=%d\n", __func__,err);
        }
    }

    hall_data->ssc_vdd = regulator_get(&pdev->dev,"ssc");
    if (!IS_ERR(hall_data->ssc_vdd)) {
        printk("%s,ssc_vdd is correct",__func__);
        err = regulator_enable(hall_data->ssc_vdd);
        if (err) {
            printk("%s,Regulator ssc_vdd enable failed ret=%d\n", __func__,err);
        }
    }*/

#if 1
			hall_data->ssc_vdd = devm_regulator_get(&pdev->dev, "ssc_vdd");
			if (IS_ERR(hall_data->ssc_vdd)) {
				pr_err("%s - ssc_vdd regulator_get fail\n", __func__);
				err = -ENODEV;
			}

			err = regulator_set_load(hall_data->ssc_vdd, SSC_VDD_2P85_HPM_LOAD);
			if (err < 0) {
				pr_err("%s:Unable to set current of ssc_vdd\n",__func__);
			}

			err = regulator_enable(hall_data->ssc_vdd);
			if (err) {
				pr_err("%s - enable ssc_vdd failed, err=%d\n",
				__func__, err);
			}


			usleep_range(1000, 1100);

#endif

    /*----Register to Input Device----*/
    hall_data->input_dev = input_allocate_device();
    if (hall_data->input_dev == NULL){
        err = -ENOMEM;
        printk("hall-switch: Failed to allocate input device!!! \n");
        goto exit_kfree;
    }

    hall_data->input_dev->name = "hall-switch";

    set_bit(EV_SYN, hall_data->input_dev->evbit);
    set_bit(EV_SW, hall_data->input_dev->evbit);
    set_bit(EV_ABS, hall_data->input_dev->evbit);

    set_bit(SW_LID, hall_data->input_dev->swbit);
    input_set_capability(hall_data->input_dev, EV_SW, SW_LID);

    /*set_bit(KEY_SPORT_B, hall_data->input_dev->keybit);
    input_set_capability(hall_data->input_dev, EV_KEY, KEY_SPORT_B);
    set_bit(KEY_SHOP_B, hall_data->input_dev->keybit);
    input_set_capability(hall_data->input_dev, EV_KEY, KEY_SHOP_B);*/

    retval = input_register_device(hall_data->input_dev);
    if(retval){
        printk("hall-switch: Failed to register input device!!!\n");
        goto exit_register_input;
    }

    hall_data->irq_gpio = of_get_named_gpio(np, "shenqi,hall-irq-gpio", 0);
    if (hall_data->irq_gpio < 0) {
        pr_err("failed to get hall's \"shenqi,hall-irq-gpio\"\n");
        goto exit_enable_irq;
    }

    retval = gpio_request(hall_data->irq_gpio, "hall_gpio");
    if (retval) {
        printk("hall-switch: irq gpio %d,request failed\n",hall_data->irq_gpio);
        goto exit_enable_irq;
    }
    retval = gpio_direction_input(hall_data->irq_gpio);
    if (retval) {
        printk("hall-switch: irq gpio %d,direction set failed\n",hall_data->irq_gpio);
        goto exit_free_gpio;
    }

    hall_data->hall_irq = gpio_to_irq(hall_data->irq_gpio);
    retval = request_threaded_irq( hall_data->hall_irq, NULL, misc_hall_irq, 
            IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING | IRQF_ONESHOT, "misc_hall_irq", hall_data);
    if(retval < 0){
        printk("hall-switch: Failed to create hall irq thread!!!i%d\n",hall_data->hall_irq);
        goto exit_free_gpio;
    }
    enable_irq_wake(hall_data->hall_irq);

    retval = sysfs_create_group(&pdev->dev.kobj, &hall_attr_group);
    if(retval) {
        printk(KERN_ERR "%s: Failed to create sysfs\n", __FUNCTION__);
    }
    printk("%s sysfs_create_group sucess\n", __func__);

    is_probed = 1;
    return retval;
exit_free_gpio:
    gpio_free(HALL_GPIO);
exit_enable_irq:
    input_unregister_device(hall_data->input_dev);

exit_register_input:
    input_free_device(hall_data->input_dev);
    hall_data->input_dev = NULL;

exit_kfree:
    kfree(hall_data);
exit:
    return err;
}

#ifdef CONFIG_OF
static struct of_device_id hall_match_table[] = {
    { .compatible = "shenqi,hall_switch",},
    { },
};
#else
#define hall_match_table NULL
#endif

static int hall_prepare(struct device *dev)
{
  /*int err = 0;
  err = regulator_enable(hall_data->ssc_vdd);
  if (err) {
      printk("%s,Regulator ssc_vdd enable failed ret=%d\n", __func__,err);
  }*/
	return 0;
}

static void hall_complete(struct device *dev)
{
  /*int err = 0;
  err = regulator_disable(hall_data->ssc_vdd);
  if (err) {
      printk("%s,Regulator ssc_vdd disable failed ret=%d\n", __func__,err);
  }*/
}

static const struct dev_pm_ops hall_pm = {
	.prepare = hall_prepare,
	.complete = hall_complete
};

static struct platform_driver msm_hall_driver = {
    .probe = hall_probe,
    .driver = {
        .name = "msm_hall_switch",
        .owner = THIS_MODULE,
        .of_match_table = hall_match_table,
        .pm	= &hall_pm,
    },
};

static int __init hall_init(void)
{
    return platform_driver_register(&msm_hall_driver);
}

module_init(hall_init);
MODULE_DESCRIPTION("Hall switch sensor driver");
MODULE_LICENSE("GPL");