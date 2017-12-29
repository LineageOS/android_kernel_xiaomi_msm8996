/* Copyright (c) 2014-2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2016 XiaoMi, Inc.
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

#define pr_fmt(fmt)	"%s: " fmt, __func__

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/spmi.h>
#include <linux/string.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/of_regulator.h>
#include <linux/qpnp/qpnp-revid.h>

#define QPNP_LABIBB_REGULATOR_DRIVER_NAME	"qcom,qpnp-labibb-regulator"

#define REG_PERPH_TYPE			0x04

#define QPNP_LAB_TYPE			0x24
#define QPNP_IBB_TYPE			0x20

/* Common register value for LAB/IBB */
#define REG_LAB_IBB_LCD_MODE		0x0
#define REG_LAB_IBB_AMOLED_MODE		BIT(7)
#define REG_LAB_IBB_SEC_ACCESS		0xD0
#define REG_LAB_IBB_SEC_UNLOCK_CODE	0xA5

/* LAB register offset definitions */
#define REG_LAB_STATUS1			0x08
#define REG_LAB_VOLTAGE			0x41
#define REG_LAB_RING_SUPPRESSION_CTL	0x42
#define REG_LAB_LCD_AMOLED_SEL		0x44
#define REG_LAB_MODULE_RDY		0x45
#define REG_LAB_ENABLE_CTL		0x46
#define REG_LAB_PD_CTL			0x47
#define REG_LAB_CLK_DIV			0x48
#define REG_LAB_IBB_EN_RDY		0x49
#define REG_LAB_CURRENT_LIMIT		0x4B
#define REG_LAB_CURRENT_SENSE		0x4C
#define REG_LAB_PS_CTL			0x50
#define REG_LAB_RDSON_MNGMNT		0x53
#define REG_LAB_PRECHARGE_CTL		0x5E
#define REG_LAB_SOFT_START_CTL		0x5F
#define REG_LAB_SPARE_CTL		0x60

/* LAB register bits definitions */

/* REG_LAB_STATUS1 */
#define LAB_STATUS1_VREG_OK_MASK	BIT(7)
#define LAB_STATUS1_VREG_OK		BIT(7)

/* REG_LAB_VOLTAGE */
#define LAB_VOLTAGE_OVERRIDE_EN		BIT(7)
#define LAB_VOLTAGE_SET_BITS		4
#define LAB_VOLTAGE_SET_MASK		((1 << LAB_VOLTAGE_SET_BITS) - 1)

/* REG_LAB_RING_SUPPRESSION_CTL */
#define LAB_RING_SUPPRESSION_CTL_EN	BIT(7)

/* REG_LAB_MODULE_RDY */
#define LAB_MODULE_RDY_EN		BIT(7)

/* REG_LAB_ENABLE_CTL */
#define LAB_ENABLE_CTL_EN		BIT(7)

/* REG_LAB_ENABLE_SOFT_START */
#define LAB_ENABLE_SOFT_START		BIT(5)

/* REG_LAB_SEL_PS_TABLE_1 */
#define LAB_SEL_PS_TABLE_1		BIT(2)

/* REG_LAB_PD_CTL */
#define LAB_PD_CTL_STRONG_PULL		BIT(0)
#define LAB_PD_CTL_STRENGTH_MASK	BIT(0)
#define LAB_PD_CTL_DISABLE_PD		BIT(1)
#define LAB_PD_CTL_EN_MASK		BIT(1)

/* REG_LAB_IBB_EN_RDY */
#define LAB_IBB_EN_RDY_EN		BIT(7)

/* REG_LAB_CURRENT_LIMIT */
#define LAB_CURRENT_LIMIT_BITS		3
#define LAB_CURRENT_LIMIT_MASK		((1 << LAB_CURRENT_LIMIT_BITS) - 1)
#define LAB_CURRENT_LIMIT_EN		BIT(7)

/* REG_LAB_CURRENT_SENSE */
#define LAB_CURRENT_SENSE_GAIN_BITS	2
#define LAB_CURRENT_SENSE_GAIN_MASK	((1 << LAB_CURRENT_SENSE_GAIN_BITS) \
					- 1)

/* REG_LAB_PS_CTL */
#define LAB_PS_CTL_BITS			2
#define LAB_PS_CTL_MASK			((1 << LAB_PS_CTL_BITS) - 1)
#define LAB_PS_CTL_EN			BIT(7)

/* REG_LAB_RDSON_MNGMNT */
#define LAB_RDSON_MNGMNT_NFET_SLEW_EN	BIT(5)
#define LAB_RDSON_MNGMNT_PFET_SLEW_EN	BIT(4)
#define LAB_RDSON_MNGMNT_NFET_BITS	2
#define LAB_RDSON_MNGMNT_NFET_MASK	((1 << LAB_RDSON_MNGMNT_NFET_BITS) - 1)
#define LAB_RDSON_MNGMNT_NFET_SHIFT	2
#define LAB_RDSON_MNGMNT_PFET_BITS	2
#define LAB_RDSON_MNGMNT_PFET_MASK	((1 << LAB_RDSON_MNGMNT_PFET_BITS) - 1)
#define LAB_RDSON_NFET_SW_SIZE_QUARTER	0x0
#define LAB_RDSON_PFET_SW_SIZE_QUARTER	0x0

/* REG_LAB_PRECHARGE_CTL */
#define LAB_PRECHARGE_CTL_EN		BIT(2)
#define LAB_PRECHARGE_CTL_EN_BITS	2
#define LAB_PRECHARGE_CTL_EN_MASK	((1 << LAB_PRECHARGE_CTL_EN_BITS) - 1)

/* REG_LAB_SOFT_START_CTL */
#define LAB_SOFT_START_CTL_BITS		2
#define LAB_SOFT_START_CTL_MASK		((1 << LAB_SOFT_START_CTL_BITS) - 1)

/* REG_LAB_SPARE_CTL */
#define LAB_SPARE_TOUCH_WAKE_BIT	BIT(3)
#define LAB_SPARE_DISABLE_SCP_BIT	BIT(0)

/* IBB register offset definitions */
#define REG_IBB_REVISION4		0x03
#define REG_IBB_STATUS1			0x08
#define REG_IBB_VOLTAGE		0x41
#define REG_IBB_RING_SUPPRESSION_CTL	0x42
#define REG_IBB_LCD_AMOLED_SEL		0x44
#define REG_IBB_MODULE_RDY		0x45
#define REG_IBB_ENABLE_CTL		0x46
#define REG_IBB_PD_CTL			0x47
#define REG_IBB_CLK_DIV			0x48
#define REG_IBB_CURRENT_LIMIT		0x4B
#define REG_IBB_PS_CTL			0x50
#define REG_IBB_RDSON_MNGMNT		0x53
#define REG_IBB_NONOVERLAP_TIME_1	0x56
#define REG_IBB_NONOVERLAP_TIME_2	0x57
#define REG_IBB_PWRUP_PWRDN_CTL_1	0x58
#define REG_IBB_PWRUP_PWRDN_CTL_2	0x59
#define REG_IBB_SOFT_START_CTL		0x5F
#define REG_IBB_SWIRE_CTL		0x5A
#define REG_IBB_SPARE_CTL		0x60
#define REG_IBB_NLIMIT_DAC		0x61

/* IBB register bits definition */

/* REG_IBB_STATUS1 */
#define IBB_STATUS1_VREG_OK_MASK	BIT(7)
#define IBB_STATUS1_VREG_OK		BIT(7)

/* REG_IBB_VOLTAGE */
#define IBB_VOLTAGE_OVERRIDE_EN		BIT(7)
#define IBB_VOLTAGE_SET_BITS		6
#define IBB_VOLTAGE_SET_MASK		((1 << IBB_VOLTAGE_SET_BITS) - 1)

/* REG_IBB_RING_SUPPRESSION_CTL */
#define IBB_RING_SUPPRESSION_CTL_EN	BIT(7)

/* REG_IBB_MODULE_RDY */
#define IBB_MODULE_RDY_EN		BIT(7)

/* REG_IBB_ENABLE_CTL */
#define IBB_ENABLE_CTL_MASK		(BIT(7) | BIT(6))
#define IBB_ENABLE_CTL_SWIRE_RDY	BIT(6)
#define IBB_ENABLE_CTL_MODULE_EN	BIT(7)

/* REG_IBB_PD_CTL */
#define IBB_PD_CTL_HALF_STRENGTH	BIT(0)
#define IBB_PD_CTL_STRENGTH_MASK	BIT(0)
#define IBB_PD_CTL_EN			BIT(7)
#define IBB_PD_CTL_EN_MASK		BIT(7)

/* REG_IBB_CURRENT_LIMIT */
#define IBB_CURRENT_LIMIT_BITS		5
#define IBB_CURRENT_LIMIT_MASK		((1 << IBB_CURRENT_LIMIT_BITS) - 1)
#define IBB_CURRENT_LIMIT_DEBOUNCE_SHIFT	5
#define IBB_CURRENT_LIMIT_EN		BIT(7)
#define IBB_ILIMIT_COUNT_CYC8		0
#define IBB_CURRENT_MAX_500MA		0xA

/* REG_IBB_PS_CTL */
#define IBB_PS_CTL_EN			0x85
#define IBB_PS_CTL_DISABLE		0x5

/* REG_IBB_RDSON_MNGMNT */
#define IBB_NFET_SLEW_EN		BIT(7)
#define IBB_PFET_SLEW_EN		BIT(6)
#define IBB_OVERRIDE_NFET_SW_SIZE	BIT(5)
#define IBB_OVERRIDE_PFET_SW_SIZE	BIT(2)
#define IBB_NFET_SW_SIZE_BITS		2
#define IBB_PFET_SW_SIZE_BITS		2
#define IBB_NFET_SW_SIZE_MASK		((1 << NFET_SW_SIZE_BITS) - 1)
#define IBB_PFET_SW_SIZE_MASK		((1 << PFET_SW_SIZE_BITS) - 1)
#define IBB_NFET_SW_SIZE_SHIFT		3

/* REG_IBB_NONOVERLAP_TIME_1 */
#define IBB_OVERRIDE_NONOVERLAP	BIT(6)
#define IBB_NONOVERLAP_NFET_BITS	3
#define IBB_NONOVERLAP_NFET_MASK	((1 << IBB_NONOVERLAP_NFET_BITS) - 1)
#define IBB_NFET_GATE_DELAY_2		0x3

/* REG_IBB_NONOVERLAP_TIME_2 */
#define IBB_N2P_MUX_SEL		BIT(0)

/* REG_IBB_SOFT_START_CTL */
#define IBB_SOFT_START_CHARGING_RESISTOR_16K	0x3

/* REG_IBB_SPARE_CTL */
#define IBB_BYPASS_PWRDN_DLY2_BIT	BIT(5)
#define IBB_POFF_CTL_MASK		BIT(4)
#define IBB_FASTER_PFET_OFF		BIT(4)
#define IBB_FAST_STARTUP		BIT(3)

/* REG_IBB_SWIRE_CTL */
#define IBB_OUTPUT_VOLTAGE_AT_ONE_PULSE_BITS	6
#define IBB_OUTPUT_VOLTAGE_AT_ONE_PULSE_MASK \
		((1 << IBB_OUTPUT_VOLTAGE_AT_ONE_PULSE_BITS) - 1)
#define MAX_OUTPUT_PULSE_VOLTAGE_MV	7700
#define MIN_OUTPUT_PULSE_VOLTAGE_MV	1400
#define OUTPUT_VOLTAGE_STEP_MV		100

/* REG_IBB_NLIMIT_DAC */
#define IBB_NLIMIT_DAC_EN		0x0
#define IBB_NLIMIT_DAC_DISABLE		0x5

/* REG_IBB_PWRUP_PWRDN_CTL_1 */
#define IBB_PWRUP_PWRDN_CTL_1_DLY1_BITS	2
#define IBB_PWRUP_PWRDN_CTL_1_DLY1_MASK	\
	((1 << IBB_PWRUP_PWRDN_CTL_1_DLY1_BITS) - 1)
#define IBB_PWRUP_PWRDN_CTL_1_DLY1_SHIFT	4
#define IBB_PWRUP_PWRDN_CTL_1_DLY2_BITS	2
#define IBB_PWRUP_PWRDN_CTL_1_DLY2_MASK	\
	((1 << IBB_PWRUP_PWRDN_CTL_1_DLY2_BITS) - 1)
#define IBB_PWRUP_PWRDN_CTL_1_LAB_VREG_OK	BIT(7)
#define IBB_PWRUP_PWRDN_CTL_1_EN_DLY1	BIT(6)
#define PWRUP_PWRDN_CTL_1_DISCHARGE_EN	BIT(2)

/* REG_IBB_PWRUP_PWRDN_CTL_2 */
#define IBB_DIS_DLY_BITS		2
#define IBB_DIS_DLY_MASK		((1 << IBB_DIS_DLY_BITS) - 1)
#define IBB_WAIT_MBG_OK			BIT(2)

/* Constants */
#define SWIRE_DEFAULT_2ND_CMD_DLY_MS		20
#define SWIRE_DEFAULT_IBB_PS_ENABLE_DLY_MS	200

enum pmic_subtype {
	PMI8994		= 10,
	PMI8950		= 17,
	PMI8996		= 19,
};

/**
 * enum qpnp_labibb_mode - working mode of LAB/IBB regulators
 * %QPNP_LABIBB_LCD_MODE:		configure LAB and IBB regulators
 * together to provide power supply for LCD
 * %QPNP_LABIBB_AMOLED_MODE:		configure LAB and IBB regulators
 * together to provide power supply for AMOLED
 * %QPNP_LABIBB_MAX_MODE		max number of configureable modes
 * supported by qpnp_labibb_regulator
 */
enum qpnp_labibb_mode {
	QPNP_LABIBB_LCD_MODE,
	QPNP_LABIBB_AMOLED_MODE,
	QPNP_LABIBB_MAX_MODE,
};

/**
 * IBB_SW_CONTROL_EN: Specifies IBB is enabled through software.
 * IBB_SW_CONTROL_DIS: Specifies IBB is disabled through software.
 * IBB_HW_CONTROL: Specifies IBB is controlled through SWIRE (hardware).
 */
enum ibb_mode {
	IBB_SW_CONTROL_EN,
	IBB_SW_CONTROL_DIS,
	IBB_HW_CONTROL,
	IBB_HW_SW_CONTROL,
};

static const int ibb_discharge_resistor_plan[] = {
	300,
	64,
	32,
	16,
};

static const int ibb_pwrup_dly_plan[] = {
	1000,
	2000,
	4000,
	8000,
};

static const int ibb_pwrdn_dly_plan[] = {
	1000,
	2000,
	4000,
	8000,
};

static const int lab_clk_div_plan[] = {
	3200,
	2740,
	2400,
	2130,
	1920,
	1750,
	1600,
	1480,
	1370,
	1280,
	1200,
	1130,
	1070,
	1010,
	960,
	910,
};

static const int ibb_clk_div_plan[] = {
	3200,
	2740,
	2400,
	2130,
	1920,
	1750,
	1600,
	1480,
	1370,
	1280,
	1200,
	1130,
	1070,
	1010,
	960,
	910,
};

static const int lab_current_limit_plan[] = {
	200,
	400,
	600,
	800,
};

static const char * const lab_current_sense_plan[] = {
	"0.5x",
	"1x",
	"1.5x",
	"2x"
};

static const int ibb_current_limit_plan[] = {
	0,
	50,
	100,
	150,
	200,
	250,
	300,
	350,
	400,
	450,
	500,
	550,
	600,
	650,
	700,
	750,
	800,
	850,
	900,
	950,
	1000,
	1050,
	1100,
	1150,
	1200,
	1250,
	1300,
	1350,
	1400,
	1450,
	1500,
	1550,
};

static const int ibb_debounce_plan[] = {
	8,
	16,
	32,
	64,
};

static const int lab_ps_threshold_plan[] = {
	20,
	30,
	40,
	50,
};

static const int lab_soft_start_plan[] = {
	200,
	400,
	600,
	800,
};

static const int lab_rdson_nfet_plan[] = {
	25,
	50,
	75,
	100,
};

static const int lab_rdson_pfet_plan[] = {
	25,
	50,
	75,
	100,
};

static const int lab_max_precharge_plan[] = {
	200,
	300,
	400,
	500,
};

struct lab_regulator {
	struct regulator_desc		rdesc;
	struct regulator_dev		*rdev;
	struct mutex			lab_mutex;

	int				lab_vreg_ok_irq;
	int				curr_volt;
	int				min_volt;

	int				step_size;
	int				slew_rate;
	int				soft_start;

	int				vreg_enabled;
};

struct ibb_regulator {
	struct regulator_desc		rdesc;
	struct regulator_dev		*rdev;
	struct mutex			ibb_mutex;

	int				curr_volt;
	int				min_volt;

	int				step_size;
	int				slew_rate;
	int				soft_start;

	u32				pwrup_dly;
	u32				pwrdn_dly;

	int				vreg_enabled;
};

struct qpnp_labibb {
	struct device			*dev;
	struct spmi_device		*spmi;
	struct pmic_revid_data		*pmic_rev_id;
	u16				lab_base;
	u16				ibb_base;
	struct lab_regulator		lab_vreg;
	struct ibb_regulator		ibb_vreg;
	enum qpnp_labibb_mode		mode;
	bool				standalone;
	bool				ttw_en;
	bool				in_ttw_mode;
	bool				ibb_settings_saved;
	bool				swire_control;
	bool				ttw_force_lab_on;
	bool				skip_2nd_swire_cmd;
	u32				swire_2nd_cmd_delay;
	u32				swire_ibb_ps_enable_delay;
};

enum ibb_settings_index {
	IBB_PD_CTL = 0,
	IBB_CURRENT_LIMIT,
	IBB_RDSON_MNGMNT,
	IBB_PWRUP_PWRDN_CTL_1,
	IBB_PWRUP_PWRDN_CTL_2,
	IBB_NLIMIT_DAC,
	IBB_PS_CTL,
	IBB_SOFT_START_CTL,
	IBB_SETTINGS_MAX,
};

enum lab_settings_index {
	LAB_SOFT_START_CTL = 0,
	LAB_PS_CTL,
	LAB_RDSON_MNGMNT,
	LAB_SETTINGS_MAX,
};

struct settings {
	u16	address;
	u8	value;
	bool	sec_access;
};

#define SETTING(_id, _sec_access)		\
	[_id] = {				\
		.address = REG_##_id,		\
		.sec_access = _sec_access,	\
	}

static struct settings ibb_settings[IBB_SETTINGS_MAX] = {
	SETTING(IBB_PD_CTL, false),
	SETTING(IBB_CURRENT_LIMIT, true),
	SETTING(IBB_RDSON_MNGMNT, false),
	SETTING(IBB_PWRUP_PWRDN_CTL_1, true),
	SETTING(IBB_PWRUP_PWRDN_CTL_2, true),
	SETTING(IBB_NLIMIT_DAC, false),
	SETTING(IBB_PS_CTL, false),
	SETTING(IBB_SOFT_START_CTL, false),
};

static struct settings lab_settings[LAB_SETTINGS_MAX] = {
	SETTING(LAB_SOFT_START_CTL, false),
	SETTING(LAB_PS_CTL, false),
	SETTING(LAB_RDSON_MNGMNT, false),
};

static int
qpnp_labibb_read(struct qpnp_labibb *labibb, u8 *val,
			u16 base, int count)
{
	int rc = 0;
	struct spmi_device *spmi = labibb->spmi;

	if (base == 0) {
		pr_err("base cannot be zero base=0x%02x sid=0x%02x rc=%d\n",
			base, spmi->sid, rc);
		return -EINVAL;
	}

	rc = spmi_ext_register_readl(spmi->ctrl, spmi->sid, base, val, count);
	if (rc) {
		pr_err("SPMI read failed base=0x%02x sid=0x%02x rc=%d\n", base,
				spmi->sid, rc);
		return rc;
	}
	return 0;
}

static int
qpnp_labibb_write(struct qpnp_labibb *labibb, u16 base,
			u8 *val, int count)
{
	int rc = 0;
	struct spmi_device *spmi = labibb->spmi;

	if (base == 0) {
		pr_err("base cannot be zero base=0x%02x sid=0x%02x rc=%d\n",
			base, spmi->sid, rc);
		return -EINVAL;
	}

	rc = spmi_ext_register_writel(spmi->ctrl, spmi->sid, base, val, count);
	if (rc) {
		pr_err("write failed base=0x%02x sid=0x%02x rc=%d\n",
			base, spmi->sid, rc);
		return rc;
	}

	return 0;
}

static int
qpnp_labibb_masked_write(struct qpnp_labibb *labibb, u16 base,
						u8 mask, u8 val)
{
	int rc;
	u8 reg;

	rc = qpnp_labibb_read(labibb, &reg, base, 1);
	if (rc) {
		pr_err("spmi read failed: addr=%03X, rc=%d\n", base, rc);
		return rc;
	}
	pr_debug("addr = 0x%x read 0x%x\n", base, reg);

	reg &= ~mask;
	reg |= val & mask;

	pr_debug("Writing 0x%x\n", reg);

	rc = qpnp_labibb_write(labibb, base, &reg, 1);
	if (rc) {
		pr_err("spmi write failed: addr=%03X, rc=%d\n", base, rc);
		return rc;
	}

	return 0;
}

static int qpnp_labibb_sec_write(struct qpnp_labibb *labibb, u16 base,
					u8 offset, u8 *val, int count)
{
	int rc;
	u8 sec_val = REG_LAB_IBB_SEC_UNLOCK_CODE;

	rc = qpnp_labibb_write(labibb, base + REG_LAB_IBB_SEC_ACCESS, &sec_val,
				1);
	if (rc) {
		pr_err("qpnp_lab_write register %x failed rc = %d\n",
			base + REG_LAB_IBB_SEC_ACCESS, rc);
		return rc;
	}

	rc = qpnp_labibb_write(labibb, base + offset, val, count);
	if (rc)
		pr_err("qpnp_labibb_write failed: addr=%03X, rc=%d\n",
			base + offset, rc);

	return rc;
}

static int qpnp_labibb_sec_masked_write(struct qpnp_labibb *labibb, u16 base,
					u8 offset, u8 mask, u8 val)
{
	int rc;
	u8 sec_val = REG_LAB_IBB_SEC_UNLOCK_CODE;

	rc = qpnp_labibb_write(labibb, base + REG_LAB_IBB_SEC_ACCESS, &sec_val,
				1);
	if (rc) {
		pr_err("qpnp_lab_write register %x failed rc = %d\n",
			base + REG_LAB_IBB_SEC_ACCESS, rc);
		return rc;
	}

	rc = qpnp_labibb_masked_write(labibb, base + offset, mask, val);
	if (rc)
		pr_err("qpnp_lab_write register %x failed rc = %d\n",
			base + offset, rc);

	return rc;
}

static int qpnp_labibb_get_matching_idx(const char *val)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(lab_current_sense_plan); i++)
		if (!strcmp(lab_current_sense_plan[i], val))
			return i;

	return -EINVAL;
}

static int qpnp_ibb_set_mode(struct qpnp_labibb *labibb, enum ibb_mode mode)
{
	int rc;
	u8 val;

	if (mode == IBB_SW_CONTROL_EN)
		val = IBB_ENABLE_CTL_MODULE_EN;
	else if (mode == IBB_HW_CONTROL)
		val = IBB_ENABLE_CTL_SWIRE_RDY;
	else if (mode == IBB_HW_SW_CONTROL)
		val = IBB_ENABLE_CTL_MODULE_EN | IBB_ENABLE_CTL_SWIRE_RDY;
	else if (mode == IBB_SW_CONTROL_DIS)
		val = 0;
	else
		return -EINVAL;

	rc = qpnp_labibb_masked_write(labibb,
		labibb->ibb_base + REG_IBB_ENABLE_CTL,
		IBB_ENABLE_CTL_MASK, val);
	if (rc)
		pr_err("Unable to configure IBB_ENABLE_CTL rc=%d\n", rc);

	return rc;
}

static int qpnp_ibb_ps_config(struct qpnp_labibb *labibb, bool enable)
{
	u8 val;
	int rc;

	val = enable ? IBB_PS_CTL_EN : IBB_PS_CTL_DISABLE;
	rc = qpnp_labibb_write(labibb, labibb->ibb_base + REG_IBB_PS_CTL,
								&val, 1);
	if (rc) {
		pr_err("qpnp_ibb_ps_config write register %x failed rc = %d\n",
						REG_IBB_PS_CTL, rc);
		return rc;
	}

	val = enable ? IBB_NLIMIT_DAC_EN : IBB_NLIMIT_DAC_DISABLE;
	rc = qpnp_labibb_write(labibb, labibb->ibb_base + REG_IBB_NLIMIT_DAC,
								&val, 1);
	if (rc)
		pr_err("qpnp_ibb_ps_config write register %x failed rc = %d\n",
						REG_IBB_NLIMIT_DAC, rc);
	return rc;
}

static int qpnp_lab_dt_init(struct qpnp_labibb *labibb,
				struct device_node *of_node)
{
	int rc = 0;
	u8 i, val;
	u32 tmp;

	if (labibb->mode == QPNP_LABIBB_LCD_MODE)
		val = REG_LAB_IBB_LCD_MODE;
	else
		val = REG_LAB_IBB_AMOLED_MODE;

	rc = qpnp_labibb_sec_write(labibb, labibb->lab_base,
			REG_LAB_LCD_AMOLED_SEL, &val, 1);

	if (rc) {
		pr_err("qpnp_lab_sec_write register %x failed rc = %d\n",
			REG_LAB_LCD_AMOLED_SEL, rc);
		return rc;
	}

	val = 0;

	if (of_property_read_bool(of_node, "qcom,qpnp-lab-full-pull-down"))
		val |= LAB_PD_CTL_STRONG_PULL;

	if (!of_property_read_bool(of_node, "qcom,qpnp-lab-pull-down-enable"))
		val |= LAB_PD_CTL_DISABLE_PD;

	rc = qpnp_labibb_write(labibb, labibb->lab_base + REG_LAB_PD_CTL,
				&val, 1);

	if (rc) {
		pr_err("qpnp_lab_dt_init write register %x failed rc = %d\n",
				REG_LAB_PD_CTL, rc);
		return rc;
	}

	rc = of_property_read_u32(of_node,
			"qcom,qpnp-lab-switching-clock-frequency", &tmp);
	if (rc) {
		pr_err("get qcom,qpnp-lab-switching-clock-frequency failed rc = %d\n",
			rc);
		return rc;
	}

	for (val = 0; val < ARRAY_SIZE(lab_clk_div_plan); val++)
		if (lab_clk_div_plan[val] == tmp)
			break;

	if (val == ARRAY_SIZE(lab_clk_div_plan)) {
		pr_err("Invalid property in qpnp-lab-switching-clock-frequency\n");
		return -EINVAL;
	}

	rc = qpnp_labibb_write(labibb, labibb->lab_base + REG_LAB_CLK_DIV,
				&val, 1);
	if (rc) {
		pr_err("qpnp_lab_dt_init write register %x failed rc = %d\n",
			REG_LAB_CLK_DIV, rc);
		return rc;
	}

	rc = of_property_read_u32(of_node,
		"qcom,qpnp-lab-limit-maximum-current", &tmp);

	if (rc) {
		pr_err("get qcom,qpnp-lab-limit-maximum-current failed rc = %d\n",
			rc);
		return rc;
	}

	for (val = 0; val < ARRAY_SIZE(lab_current_limit_plan); val++)
		if (lab_current_limit_plan[val] == tmp)
			break;

	if (val == ARRAY_SIZE(lab_current_limit_plan)) {
		pr_err("Invalid property in qcom,qpnp-lab-limit-maximum-current\n");
		return -EINVAL;
	}

	if (of_property_read_bool(of_node,
		"qcom,qpnp-lab-limit-max-current-enable"))
		val |= LAB_CURRENT_LIMIT_EN;

	rc = qpnp_labibb_write(labibb, labibb->lab_base +
				REG_LAB_CURRENT_LIMIT, &val, 1);
	if (rc) {
		pr_err("qpnp_lab_dt_init write register %x failed rc = %d\n",
				REG_LAB_CURRENT_LIMIT, rc);
		return rc;
	}

	if (of_property_read_bool(of_node,
		"qcom,qpnp-lab-ring-suppression-enable")) {
		val = LAB_RING_SUPPRESSION_CTL_EN;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
					REG_LAB_RING_SUPPRESSION_CTL,
					&val,
					1);
		if (rc) {
			pr_err("qpnp_lab_dt_init write register %x failed rc = %d\n",
				REG_LAB_RING_SUPPRESSION_CTL, rc);
			return rc;
		}
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-lab-ps-threshold", &tmp);

	if (rc) {
		pr_err("get qcom,qpnp-lab-ps-threshold failed rc = %d\n",
			rc);
		return rc;
	}

	for (val = 0; val < ARRAY_SIZE(lab_ps_threshold_plan); val++)
		if (lab_ps_threshold_plan[val] == tmp)
			break;

	if (val == ARRAY_SIZE(lab_ps_threshold_plan)) {
		pr_err("Invalid property in qcom,qpnp-lab-ps-threshold\n");
		return -EINVAL;
	}

	if (of_property_read_bool(of_node, "qcom,qpnp-lab-ps-enable"))
		val |= LAB_PS_CTL_EN;

	val |= LAB_ENABLE_SOFT_START | LAB_SEL_PS_TABLE_1;

	rc = qpnp_labibb_write(labibb, labibb->lab_base + REG_LAB_PS_CTL,
				&val, 1);

	if (rc) {
		pr_err("qpnp_lab_dt_init write register %x failed rc = %d\n",
				REG_LAB_PS_CTL, rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-lab-pfet-size", &tmp);

	if (rc) {
		pr_err("get qcom,qpnp-lab-pfet-size, rc = %d\n", rc);
		return rc;
	}

	for (val = 0; val < ARRAY_SIZE(lab_rdson_pfet_plan); val++)
		if (tmp == lab_rdson_pfet_plan[val])
			break;

	if (val == ARRAY_SIZE(lab_rdson_pfet_plan)) {
		pr_err("Invalid property in qcom,qpnp-lab-pfet-size\n");
		return -EINVAL;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-lab-nfet-size", &tmp);

	if (rc) {
		pr_err("get qcom,qpnp-lab-nfet-size, rc = %d\n", rc);
		return rc;
	}

	for (i = 0; i < ARRAY_SIZE(lab_rdson_nfet_plan); i++)
		if (tmp == lab_rdson_nfet_plan[i])
			break;

	if (i == ARRAY_SIZE(lab_rdson_nfet_plan)) {
		pr_err("Iniid property in qcom,qpnp-lab-nfet-size\n");
		return -EINVAL;
	}

	val |= i << LAB_RDSON_MNGMNT_NFET_SHIFT;
	val |= (LAB_RDSON_MNGMNT_NFET_SLEW_EN | LAB_RDSON_MNGMNT_PFET_SLEW_EN);

	rc = qpnp_labibb_write(labibb, labibb->lab_base + REG_LAB_RDSON_MNGMNT,
				&val, 1);
	if (rc) {
		pr_err("qpnp_lab_dt_init write register %x failed rc = %d\n",
			REG_LAB_RDSON_MNGMNT, rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-lab-init-voltage",
					&(labibb->lab_vreg.curr_volt));
	if (rc) {
		pr_err("get qcom,qpnp-lab-init-voltage failed, rc = %d\n", rc);
		return rc;
	}

	if (!of_property_read_bool(of_node,
			"qcom,qpnp-lab-use-default-voltage")) {
		if (labibb->lab_vreg.curr_volt < labibb->lab_vreg.min_volt) {
			pr_err("Invalid qcom,qpnp-lab-init-voltage property, qcom,qpnp-lab-init-voltage %d is less than the the minimum voltage %d",
				labibb->lab_vreg.curr_volt,
				labibb->lab_vreg.min_volt);
			return -EINVAL;
		}

		val = DIV_ROUND_UP(labibb->lab_vreg.curr_volt -
				labibb->lab_vreg.min_volt,
				labibb->lab_vreg.step_size);

		if (val > LAB_VOLTAGE_SET_MASK) {
			pr_err("Invalid qcom,qpnp-lab-init-voltage property, qcom,qpnp-lab-init-voltage %d is larger than the max supported voltage %d",
				labibb->lab_vreg.curr_volt,
				labibb->lab_vreg.min_volt +
				labibb->lab_vreg.step_size *
				LAB_VOLTAGE_SET_MASK);
			return -EINVAL;
		}

		labibb->lab_vreg.curr_volt = val * labibb->lab_vreg.step_size +
				labibb->lab_vreg.min_volt;
		val |= LAB_VOLTAGE_OVERRIDE_EN;
	} else {
		val = 0;
	}

	rc = qpnp_labibb_masked_write(labibb, labibb->lab_base +
				REG_LAB_VOLTAGE,
				LAB_VOLTAGE_SET_MASK |
				LAB_VOLTAGE_OVERRIDE_EN,
				val);

	if (rc) {
		pr_err("write to register %x failed rc = %d\n", REG_LAB_VOLTAGE,
			rc);
		return rc;
	}

	if (labibb->swire_control) {
		rc = qpnp_ibb_set_mode(labibb, IBB_HW_CONTROL);
		if (rc)
			pr_err("Unable to set SWIRE_RDY rc=%d\n", rc);
	}

	return rc;
}

static int qpnp_labibb_restore_settings(struct qpnp_labibb *labibb)
{
	int rc, i;

	for (i = 0; i < ARRAY_SIZE(ibb_settings); i++) {
		if (ibb_settings[i].sec_access)
			rc = qpnp_labibb_sec_write(labibb, labibb->ibb_base,
					ibb_settings[i].address,
					&ibb_settings[i].value, 1);
		else
			rc = qpnp_labibb_write(labibb, labibb->ibb_base +
					ibb_settings[i].address,
					&ibb_settings[i].value, 1);

		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				ibb_settings[i].address, rc);
			return rc;
		}
	}

	for (i = 0; i < ARRAY_SIZE(lab_settings); i++) {
		if (lab_settings[i].sec_access)
			rc = qpnp_labibb_sec_write(labibb, labibb->lab_base,
					lab_settings[i].address,
					&lab_settings[i].value, 1);
		else
			rc = qpnp_labibb_write(labibb, labibb->lab_base +
					lab_settings[i].address,
					&lab_settings[i].value, 1);

		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				lab_settings[i].address, rc);
			return rc;
		}
	}

	return 0;
}

static int qpnp_labibb_save_settings(struct qpnp_labibb *labibb)
{
	int rc, i;

	for (i = 0; i < ARRAY_SIZE(ibb_settings); i++) {
		rc = qpnp_labibb_read(labibb, &ibb_settings[i].value,
					labibb->ibb_base +
					ibb_settings[i].address, 1);
		if (rc) {
			pr_err("qpnp_labibb_read register %x failed rc = %d\n",
				ibb_settings[i].address, rc);
			return rc;
		}
	}

	for (i = 0; i < ARRAY_SIZE(lab_settings); i++) {
		rc = qpnp_labibb_read(labibb, &lab_settings[i].value,
					labibb->lab_base +
					lab_settings[i].address, 1);
		if (rc) {
			pr_err("qpnp_labibb_read register %x failed rc = %d\n",
				lab_settings[i].address, rc);
			return rc;
		}
	}

	return 0;
}

static int qpnp_labibb_ttw_enter_ibb_common(struct qpnp_labibb *labibb)
{
	int rc = 0;
	u8 val;

	val = 0;
	rc = qpnp_labibb_write(labibb, labibb->ibb_base + REG_IBB_PD_CTL,
				&val, 1);
	if (rc) {
		pr_err("qpnp_labibb_read register %x failed rc = %d\n",
			REG_IBB_PD_CTL, rc);
		return rc;
	}

	val = 0;
	rc = qpnp_labibb_sec_write(labibb, labibb->ibb_base,
				REG_IBB_PWRUP_PWRDN_CTL_1, &val, 1);
	if (rc) {
		pr_err("qpnp_labibb_write register %x failed rc = %d\n",
			REG_IBB_PWRUP_PWRDN_CTL_1, rc);
		return rc;
	}

	val = IBB_WAIT_MBG_OK;
	rc = qpnp_labibb_sec_masked_write(labibb, labibb->ibb_base,
				REG_IBB_PWRUP_PWRDN_CTL_2,
				IBB_DIS_DLY_MASK | IBB_WAIT_MBG_OK, val);
	if (rc) {
		pr_err("qpnp_labibb_sec_write register %x failed rc = %d\n",
			REG_IBB_PWRUP_PWRDN_CTL_2, rc);
		return rc;
	}

	val = IBB_NFET_SLEW_EN | IBB_PFET_SLEW_EN | IBB_OVERRIDE_NFET_SW_SIZE |
		IBB_OVERRIDE_PFET_SW_SIZE;
	rc = qpnp_labibb_masked_write(labibb, labibb->ibb_base +
				REG_IBB_RDSON_MNGMNT, 0xFF, val);
	if (rc) {
		pr_err("qpnp_labibb_write register %x failed rc = %d\n",
			REG_IBB_RDSON_MNGMNT, rc);
		return rc;
	}

	val = IBB_CURRENT_LIMIT_EN | IBB_CURRENT_MAX_500MA |
		(IBB_ILIMIT_COUNT_CYC8 << IBB_CURRENT_LIMIT_DEBOUNCE_SHIFT);
	rc = qpnp_labibb_sec_write(labibb, labibb->ibb_base,
				REG_IBB_CURRENT_LIMIT, &val, 1);
	if (rc)
		pr_err("qpnp_labibb_write register %x failed rc = %d\n",
			REG_IBB_CURRENT_LIMIT, rc);

	return rc;
}

static int qpnp_labibb_ttw_enter_ibb_pmi8996(struct qpnp_labibb *labibb)
{
	int rc;
	u8 val;

	val = IBB_BYPASS_PWRDN_DLY2_BIT | IBB_FAST_STARTUP;
	rc = qpnp_labibb_write(labibb, labibb->ibb_base + REG_IBB_SPARE_CTL,
				&val, 1);
	if (rc)
		pr_err("qpnp_labibb_write register %x failed rc = %d\n",
			REG_IBB_SPARE_CTL, rc);

	return rc;
}

static int qpnp_labibb_ttw_enter_ibb_pmi8950(struct qpnp_labibb *labibb)
{
	int rc;
	u8 val;

	rc = qpnp_ibb_ps_config(labibb, true);
	if (rc) {
		pr_err("Failed to enable ibb_ps_config rc=%d\n", rc);
		return rc;
	}

	val = IBB_SOFT_START_CHARGING_RESISTOR_16K;
	rc = qpnp_labibb_write(labibb, labibb->ibb_base +
				REG_IBB_SOFT_START_CTL, &val, 1);
	if (rc) {
		pr_err("qpnp_labibb_write register %x failed rc = %d\n",
			REG_IBB_SOFT_START_CTL, rc);
		return rc;
	}

	val = IBB_MODULE_RDY_EN;
	rc = qpnp_labibb_write(labibb, labibb->lab_base +
				REG_IBB_MODULE_RDY, &val, 1);
	if (rc)
		pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_IBB_MODULE_RDY, rc);

	return rc;
}

static int qpnp_labibb_regulator_ttw_mode_enter(struct qpnp_labibb *labibb)
{
	int rc = 0;
	u8 val;

	/* Save the IBB settings before they get modified for TTW mode */
	if (!labibb->ibb_settings_saved) {
		rc = qpnp_labibb_save_settings(labibb);
		if (rc) {
			pr_err("Error in storing IBB setttings, rc=%d\n", rc);
			return rc;
		}
		labibb->ibb_settings_saved = true;
	}

	if (labibb->ttw_force_lab_on) {
		val = LAB_MODULE_RDY_EN;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
					REG_LAB_MODULE_RDY, &val, 1);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_LAB_MODULE_RDY, rc);
			return rc;
		}

		/* Prevents LAB being turned off by IBB */
		val = LAB_ENABLE_CTL_EN;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
					REG_LAB_ENABLE_CTL, &val, 1);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_LAB_ENABLE_CTL, rc);
			return rc;
		}

		val = LAB_RDSON_MNGMNT_NFET_SLEW_EN |
			LAB_RDSON_MNGMNT_PFET_SLEW_EN |
			LAB_RDSON_NFET_SW_SIZE_QUARTER |
			LAB_RDSON_PFET_SW_SIZE_QUARTER;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
				REG_LAB_RDSON_MNGMNT, &val, 1);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_LAB_RDSON_MNGMNT, rc);
			return rc;
		}

		rc = qpnp_labibb_masked_write(labibb, labibb->lab_base +
				REG_LAB_PS_CTL, LAB_PS_CTL_EN, LAB_PS_CTL_EN);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_LAB_PS_CTL, rc);
			return rc;
		}
	} else {
		val = LAB_PD_CTL_DISABLE_PD;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
				REG_LAB_PD_CTL, &val, 1);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_LAB_PD_CTL, rc);
			return rc;
		}

		val = LAB_SPARE_DISABLE_SCP_BIT;
		if (labibb->pmic_rev_id->pmic_subtype != PMI8950)
			val |= LAB_SPARE_TOUCH_WAKE_BIT;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
				REG_LAB_SPARE_CTL, &val, 1);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_LAB_SPARE_CTL, rc);
			return rc;
		}

		val = 0;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
				REG_LAB_SOFT_START_CTL, &val, 1);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_LAB_SOFT_START_CTL, rc);
			return rc;
		}
	}

	rc = qpnp_labibb_ttw_enter_ibb_common(labibb);
	if (rc) {
		pr_err("Failed to apply TTW ibb common settings rc=%d\n", rc);
		return rc;
	}

	switch (labibb->pmic_rev_id->pmic_subtype) {
	case PMI8996:
		rc = qpnp_labibb_ttw_enter_ibb_pmi8996(labibb);
		break;
	case PMI8950:
		rc = qpnp_labibb_ttw_enter_ibb_pmi8950(labibb);
		break;
	}
	if (rc) {
		pr_err("Failed to configure TTW-enter for IBB rc=%d\n", rc);
		return rc;
	}

	rc = qpnp_ibb_set_mode(labibb, IBB_HW_CONTROL);
	if (rc) {
		pr_err("Unable to set SWIRE_RDY rc = %d\n", rc);
		return rc;
	}
	labibb->in_ttw_mode = true;
	return 0;
}

static int qpnp_labibb_ttw_exit_ibb_common(struct qpnp_labibb *labibb)
{
	int rc;
	u8 val;

	val = IBB_FASTER_PFET_OFF;
	rc = qpnp_labibb_write(labibb, labibb->ibb_base + REG_IBB_SPARE_CTL,
			&val, 1);
	if (rc)
		pr_err("qpnp_labibb_write register %x failed rc = %d\n",
			REG_IBB_SPARE_CTL, rc);

	return rc;
}

static int qpnp_labibb_regulator_ttw_mode_exit(struct qpnp_labibb *labibb)
{
	int rc = 0;
	u8 val;

	if (!labibb->ibb_settings_saved) {
		pr_err("IBB settings are not saved!\n");
		return -EINVAL;
	}

	/* Restore the IBB settings back to switch back to normal mode */
	rc = qpnp_labibb_restore_settings(labibb);
	if (rc) {
		pr_err("Error in restoring IBB setttings, rc=%d\n", rc);
		return rc;
	}

	if (labibb->ttw_force_lab_on) {
		val = 0;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
					REG_LAB_ENABLE_CTL, &val, 1);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_LAB_ENABLE_CTL, rc);
			return rc;
		}
	} else {
		val = LAB_PD_CTL_STRONG_PULL;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
					REG_LAB_PD_CTL,	&val, 1);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
						REG_LAB_PD_CTL, rc);
			return rc;
		}

		val = 0;
		rc = qpnp_labibb_write(labibb, labibb->lab_base +
					REG_LAB_SPARE_CTL, &val, 1);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
					REG_LAB_SPARE_CTL, rc);
			return rc;
		}
	}

	switch (labibb->pmic_rev_id->pmic_subtype) {
	case PMI8996:
	case PMI8994:
	case PMI8950:
		rc = qpnp_labibb_ttw_exit_ibb_common(labibb);
		break;
	}
	if (rc) {
		pr_err("Failed to configure TTW-exit for IBB rc=%d\n", rc);
		return rc;
	}

	labibb->in_ttw_mode = false;
	return rc;
}

static int qpnp_labibb_regulator_enable(struct qpnp_labibb *labibb)
{
	int rc;
	u8 val;
	int dly;
	int retries;
	bool enabled = false;

	if (labibb->ttw_en && !labibb->ibb_vreg.vreg_enabled &&
		labibb->in_ttw_mode) {
		rc = qpnp_labibb_regulator_ttw_mode_exit(labibb);
		if (rc) {
			pr_err("Error in exiting TTW mode rc = %d\n", rc);
			return rc;
		}
	}

	rc = qpnp_ibb_set_mode(labibb, IBB_SW_CONTROL_EN);
	if (rc) {
		pr_err("Unable to set IBB_MODULE_EN rc = %d\n", rc);
		return rc;
	}

	/* total delay time */
	dly = labibb->lab_vreg.soft_start + labibb->ibb_vreg.soft_start
				+ labibb->ibb_vreg.pwrup_dly;
	usleep_range(dly, dly + 100);

	/* after this delay, lab should be enabled */
	rc = qpnp_labibb_read(labibb, &val,
			labibb->lab_base + REG_LAB_STATUS1, 1);
	if (rc) {
		pr_err("read register %x failed rc = %d\n",
			REG_LAB_STATUS1, rc);
		goto err_out;
	}

	pr_debug("soft=%d %d up=%d dly=%d\n",
		labibb->lab_vreg.soft_start, labibb->ibb_vreg.soft_start,
				labibb->ibb_vreg.pwrup_dly, dly);

	if (!(val & LAB_STATUS1_VREG_OK)) {
		pr_err("failed for LAB %x\n", val);
		goto err_out;
	}

	/* poll IBB_STATUS to make sure ibb had been enabled */
	dly = labibb->ibb_vreg.soft_start + labibb->ibb_vreg.pwrup_dly;
	retries = 10;
	while (retries--) {
		rc = qpnp_labibb_read(labibb, &val,
				labibb->ibb_base + REG_IBB_STATUS1, 1);
		if (rc) {
			pr_err("read register %x failed rc = %d\n",
				REG_IBB_STATUS1, rc);
			goto err_out;
		}

		if (val & IBB_STATUS1_VREG_OK) {
			enabled = true;
			break;
		}
		usleep_range(dly, dly + 100);
	}

	if (!enabled) {
		pr_err("failed for IBB %x\n", val);
		goto err_out;
	}

	labibb->lab_vreg.vreg_enabled = 1;
	labibb->ibb_vreg.vreg_enabled = 1;

	return 0;
err_out:
	rc = qpnp_ibb_set_mode(labibb, IBB_SW_CONTROL_DIS);
	if (rc) {
		pr_err("Unable to set IBB_MODULE_EN rc = %d\n", rc);
		return rc;
	}
	return -EINVAL;
}

static int qpnp_labibb_regulator_disable(struct qpnp_labibb *labibb)
{
	int rc;
	u8 val;
	int dly;
	int retries;
	bool disabled = false;

	/*
	 * When TTW mode is enabled and LABIBB regulators are disabled, it is
	 * recommended not to disable IBB through IBB_ENABLE_CTL when switching
	 * to SWIRE control on entering TTW mode. Hence, just enter TTW mode
	 * and mark the regulators disabled. When we exit TTW mode, normal
	 * mode settings will be restored anyways and regulators will be
	 * enabled as before.
	 */
	if (labibb->ttw_en && !labibb->in_ttw_mode) {
		rc = qpnp_labibb_regulator_ttw_mode_enter(labibb);
		if (rc) {
			pr_err("Error in entering TTW mode rc = %d\n", rc);
			return rc;
		}
		labibb->lab_vreg.vreg_enabled = 0;
		labibb->ibb_vreg.vreg_enabled = 0;
		return 0;
	}

	rc = qpnp_ibb_set_mode(labibb, IBB_SW_CONTROL_DIS);
	if (rc) {
		pr_err("Unable to set IBB_MODULE_EN rc = %d\n", rc);
		return rc;
	}

	/* poll IBB_STATUS to make sure ibb had been disabled */
	dly = labibb->ibb_vreg.pwrdn_dly;
	retries = 2;
	while (retries--) {
		usleep_range(dly, dly + 100);
		rc = qpnp_labibb_read(labibb, &val,
				labibb->ibb_base + REG_IBB_STATUS1, 1);
		if (rc) {
			pr_err("read register %x failed rc = %d\n",
				REG_IBB_STATUS1, rc);
			return rc;
		}

		if (!(val & IBB_STATUS1_VREG_OK)) {
			disabled = true;
			break;
		}
	}

	if (!disabled) {
		pr_err("failed for IBB %x\n", val);
		return -EINVAL;
	}

	labibb->lab_vreg.vreg_enabled = 0;
	labibb->ibb_vreg.vreg_enabled = 0;

	return 0;
}

static int qpnp_lab_regulator_enable(struct regulator_dev *rdev)
{
	int rc;
	u8 val;

	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->skip_2nd_swire_cmd) {
		rc = qpnp_ibb_ps_config(labibb, false);
		if (rc) {
			pr_err("Failed to disable IBB PS rc=%d\n", rc);
			return rc;
		}
	}

	if (!labibb->lab_vreg.vreg_enabled && !labibb->swire_control) {

		if (!labibb->standalone)
			return qpnp_labibb_regulator_enable(labibb);

		val = LAB_ENABLE_CTL_EN;
		rc = qpnp_labibb_write(labibb,
			labibb->lab_base + REG_LAB_ENABLE_CTL, &val, 1);
		if (rc) {
			pr_err("qpnp_lab_regulator_enable write register %x failed rc = %d\n",
				REG_LAB_ENABLE_CTL, rc);
			return rc;
		}

		udelay(labibb->lab_vreg.soft_start);

		rc = qpnp_labibb_read(labibb, &val,
				labibb->lab_base + REG_LAB_STATUS1, 1);
		if (rc) {
			pr_err("qpnp_lab_regulator_enable read register %x failed rc = %d\n",
				REG_LAB_STATUS1, rc);
			return rc;
		}

		if ((val & LAB_STATUS1_VREG_OK_MASK) != LAB_STATUS1_VREG_OK) {
			pr_err("qpnp_lab_regulator_enable failed\n");
			return -EINVAL;
		}

		labibb->lab_vreg.vreg_enabled = 1;
	}

	return 0;
}

static int qpnp_lab_regulator_disable(struct regulator_dev *rdev)
{
	int rc;
	u8 val;
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->lab_vreg.vreg_enabled && !labibb->swire_control) {

		if (!labibb->standalone)
			return qpnp_labibb_regulator_disable(labibb);

		val = 0;
		rc = qpnp_labibb_write(labibb,
			labibb->lab_base + REG_LAB_ENABLE_CTL, &val, 1);
		if (rc) {
			pr_err("qpnp_lab_regulator_enable write register %x failed rc = %d\n",
				REG_LAB_ENABLE_CTL, rc);
			return rc;
		}

		labibb->lab_vreg.vreg_enabled = 0;
	}
	return 0;
}

static int qpnp_lab_regulator_is_enabled(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->swire_control)
		return 0;

	return labibb->lab_vreg.vreg_enabled;
}

static int qpnp_lab_regulator_set_voltage(struct regulator_dev *rdev,
				int min_uV, int max_uV, unsigned *selector)
{
	int rc, new_uV;
	u8 val;
	struct qpnp_labibb *labibb = rdev_get_drvdata(rdev);

	if (labibb->swire_control)
		return 0;

	if (min_uV < labibb->lab_vreg.min_volt) {
		pr_err("min_uV %d is less than min_volt %d", min_uV,
			labibb->lab_vreg.min_volt);
		return -EINVAL;
	}

	val = DIV_ROUND_UP(min_uV - labibb->lab_vreg.min_volt,
				labibb->lab_vreg.step_size);
	new_uV = val * labibb->lab_vreg.step_size + labibb->lab_vreg.min_volt;

	if (new_uV > max_uV) {
		pr_err("unable to set voltage %d (min:%d max:%d)\n", new_uV,
			min_uV, max_uV);
		return -EINVAL;
	}

	rc = qpnp_labibb_masked_write(labibb, labibb->lab_base +
				REG_LAB_VOLTAGE,
				LAB_VOLTAGE_SET_MASK |
				LAB_VOLTAGE_OVERRIDE_EN,
				val | LAB_VOLTAGE_OVERRIDE_EN);

	if (rc) {
		pr_err("write to register %x failed rc = %d\n", REG_LAB_VOLTAGE,
			rc);
		return rc;
	}

	if (new_uV > labibb->lab_vreg.curr_volt) {
		val = DIV_ROUND_UP(new_uV - labibb->lab_vreg.curr_volt,
				labibb->lab_vreg.step_size);
		udelay(val * labibb->lab_vreg.slew_rate);
	}
	labibb->lab_vreg.curr_volt = new_uV;

	return 0;
}

static int qpnp_skip_swire_command(struct qpnp_labibb *labibb)
{
	int rc = 0, retry = 50, dly;
	u8 reg;

	do {
		/* poll for ibb vreg_ok */
		rc = qpnp_labibb_read(labibb, &reg,
			labibb->ibb_base + REG_IBB_STATUS1, 1);
		if (rc) {
			pr_err("Failed to read ibb_status1 reg rc=%d\n", rc);
			return rc;
		}
		if ((reg & IBB_STATUS1_VREG_OK_MASK) == IBB_STATUS1_VREG_OK)
			break;

		/* poll delay */
		usleep_range(500, 600);

	} while (--retry);

	if (!retry) {
		pr_err("ibb vreg_ok failed to turn-on\n");
		return -EBUSY;
	}

	/* move to SW control */
	rc = qpnp_ibb_set_mode(labibb, IBB_SW_CONTROL_EN);
	if (rc) {
		pr_err("Failed switch to IBB_SW_CONTROL rc=%d\n", rc);
		return rc;
	}

	/* delay to skip the second swire command */
	dly = labibb->swire_2nd_cmd_delay * 1000;
	while (dly / 20000) {
		usleep_range(20000, 20010);
		dly -= 20000;
	}
	if (dly)
		usleep_range(dly, dly + 10);

	rc = qpnp_ibb_set_mode(labibb, IBB_HW_SW_CONTROL);
	if (rc) {
		pr_err("Failed switch to IBB_HW_SW_CONTROL rc=%d\n", rc);
		return rc;
	}

	/* delay for SPMI to SWIRE transition */
	usleep_range(1000, 1100);

	/* Move back to SWIRE control */
	rc = qpnp_ibb_set_mode(labibb, IBB_HW_CONTROL);
	if (rc)
		pr_err("Failed switch to IBB_HW_CONTROL rc=%d\n", rc);

	/* delay before enabling the PS mode */
	msleep(labibb->swire_ibb_ps_enable_delay);
	rc = qpnp_ibb_ps_config(labibb, true);
	if (rc)
		pr_err("Unable to enable IBB PS rc=%d\n", rc);

	return rc;
}

static irqreturn_t lab_vreg_ok_handler(int irq, void *_labibb)
{
	struct qpnp_labibb *labibb = _labibb;
	int rc;

	rc = qpnp_skip_swire_command(labibb);
	if (rc)
		pr_err("Failed in 'qpnp_skip_swire_command' rc=%d\n", rc);

	return IRQ_HANDLED;
}

static int qpnp_lab_regulator_get_voltage(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->swire_control)
		return 0;

	return labibb->lab_vreg.curr_volt;
}

static struct regulator_ops qpnp_lab_ops = {
	.enable			= qpnp_lab_regulator_enable,
	.disable		= qpnp_lab_regulator_disable,
	.is_enabled		= qpnp_lab_regulator_is_enabled,
	.set_voltage		= qpnp_lab_regulator_set_voltage,
	.get_voltage		= qpnp_lab_regulator_get_voltage,
};

static int register_qpnp_lab_regulator(struct qpnp_labibb *labibb,
					struct device_node *of_node)
{
	int rc = 0;
	struct regulator_init_data *init_data;
	struct regulator_desc *rdesc;
	struct regulator_config cfg = {};
	u8 val;
	const char *current_sense_str;
	bool config_current_sense = false;
	u32 tmp;

	if (!of_node) {
		dev_err(labibb->dev, "qpnp lab regulator device tree node is missing\n");
		return -EINVAL;
	}

	init_data = of_get_regulator_init_data(labibb->dev, of_node);
	if (!init_data) {
		pr_err("unable to get regulator init data for qpnp lab regulator\n");
		return -ENOMEM;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-lab-min-voltage",
					&(labibb->lab_vreg.min_volt));
	if (rc < 0) {
		pr_err("qcom,qpnp-lab-min-voltage is missing, rc = %d\n",
			rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-lab-step-size",
					&(labibb->lab_vreg.step_size));
	if (rc < 0) {
		pr_err("qcom,qpnp-lab-step-size is missing, rc = %d\n", rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-lab-slew-rate",
					&(labibb->lab_vreg.slew_rate));
	if (rc < 0) {
		pr_err("qcom,qpnp-lab-slew-rate is missing, rc = %d\n",
			rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-lab-soft-start",
					&(labibb->lab_vreg.soft_start));
	if (rc < 0) {
		pr_err("qcom,qpnp-lab-soft-start is missing, rc = %d\n",
			rc);
		return rc;
	}

	for (val = 0; val < ARRAY_SIZE(lab_soft_start_plan); val++)
		if (lab_soft_start_plan[val] == labibb->lab_vreg.soft_start)
			break;

	if (val == ARRAY_SIZE(lab_soft_start_plan))
		val = ARRAY_SIZE(lab_soft_start_plan) - 1;

	rc = qpnp_labibb_write(labibb, labibb->lab_base +
				REG_LAB_SOFT_START_CTL, &val, 1);
	if (rc) {
		pr_err("qpnp_labibb_write register %x failed rc = %d\n",
			REG_LAB_SOFT_START_CTL, rc);
		return rc;
	}

	labibb->lab_vreg.soft_start = lab_soft_start_plan
				[val & LAB_SOFT_START_CTL_MASK];

	rc = of_property_read_u32(of_node, "qcom,qpnp-lab-max-precharge-time",
				&tmp);
	if (rc) {
		pr_err("get qcom,qpnp-lab-max-precharge-time failed, rc = %d\n",
			rc);
		return rc;
	}

	for (val = 0; val < ARRAY_SIZE(lab_max_precharge_plan); val++)
		if (lab_max_precharge_plan[val] == tmp)
			break;

	if (val == ARRAY_SIZE(lab_max_precharge_plan)) {
		pr_err("Invalid property in qcom,qpnp-lab-max-precharge-time\n");
		return -EINVAL;
	}

	if (of_property_read_bool(of_node,
			"qcom,qpnp-lab-max-precharge-enable"))
		val |= LAB_PRECHARGE_CTL_EN;

	rc = qpnp_labibb_write(labibb, labibb->lab_base +
				REG_LAB_PRECHARGE_CTL, &val, 1);
	if (rc) {
		pr_err("qpnp_lab_dt_init write register %x failed rc = %d\n",
			REG_LAB_PRECHARGE_CTL, rc);
		return rc;
	}

	if (labibb->mode == QPNP_LABIBB_AMOLED_MODE) {
		/*
		 * default to 1.5 times current gain if
		 * user doesn't specify the current-sense
		 * dt parameter
		 */
		current_sense_str = "1.5x";
		val = qpnp_labibb_get_matching_idx(current_sense_str);
		config_current_sense = true;
	}

	if (of_find_property(of_node,
		"qpnp,qpnp-lab-current-sense", NULL)) {
		config_current_sense = true;
		rc = of_property_read_string(of_node,
			"qpnp,qpnp-lab-current-sense",
			&current_sense_str);
		if (!rc) {
			val = qpnp_labibb_get_matching_idx(
					current_sense_str);
		} else {
			pr_err("qpnp,qpnp-lab-current-sense configured incorrectly rc = %d\n",
				rc);
			return rc;
		}
	}

	if (config_current_sense) {
		rc = qpnp_labibb_masked_write(labibb, labibb->lab_base +
			REG_LAB_CURRENT_SENSE,
			LAB_CURRENT_SENSE_GAIN_MASK,
			val);
		if (rc) {
			pr_err("qpnp_labibb_write register %x failed rc = %d\n",
				REG_LAB_CURRENT_SENSE, rc);
			return rc;
		}
	}

	if (labibb->skip_2nd_swire_cmd) {
		rc = devm_request_threaded_irq(labibb->dev,
				labibb->lab_vreg.lab_vreg_ok_irq, NULL,
				lab_vreg_ok_handler,
				IRQF_ONESHOT | IRQF_TRIGGER_RISING,
				"lab-vreg-ok", labibb);
		if (rc) {
			pr_err("Failed to register 'lab-vreg-ok' irq rc=%d\n",
						rc);
			return rc;
		}
	}

	val = (labibb->standalone) ? 0 : LAB_IBB_EN_RDY_EN;
	rc = qpnp_labibb_sec_write(labibb, labibb->lab_base,
			REG_LAB_IBB_EN_RDY, &val, 1);

	if (rc) {
		pr_err("qpnp_lab_sec_write register %x failed rc = %d\n",
			REG_LAB_IBB_EN_RDY, rc);
		return rc;
	}

	rc = qpnp_labibb_read(labibb, &val,
				labibb->ibb_base + REG_IBB_ENABLE_CTL, 1);
	if (rc) {
		pr_err("qpnp_labibb_read register %x failed rc = %d\n",
			REG_IBB_ENABLE_CTL, rc);
		return rc;
	}

	if (!(val & (IBB_ENABLE_CTL_SWIRE_RDY | IBB_ENABLE_CTL_MODULE_EN))) {
		/* SWIRE_RDY and IBB_MODULE_EN not enabled */
		rc = qpnp_lab_dt_init(labibb, of_node);
		if (rc) {
			pr_err("qpnp-lab: wrong DT parameter specified: rc = %d\n",
				rc);
			return rc;
		}
	} else {
		rc = qpnp_labibb_read(labibb, &val,
			labibb->lab_base + REG_LAB_LCD_AMOLED_SEL, 1);
		if (rc) {
			pr_err("qpnp_labibb_read register %x failed rc = %d\n",
				REG_LAB_LCD_AMOLED_SEL, rc);
			return rc;
		}

		if (val == REG_LAB_IBB_AMOLED_MODE)
			labibb->mode = QPNP_LABIBB_AMOLED_MODE;
		else
			labibb->mode = QPNP_LABIBB_LCD_MODE;

		rc = qpnp_labibb_read(labibb, &val, labibb->lab_base +
					REG_LAB_VOLTAGE, 1);
		if (rc) {
			pr_err("qpnp_lab_read read register %x failed rc = %d\n",
				REG_LAB_VOLTAGE, rc);
			return rc;
		}

		if (val & LAB_VOLTAGE_OVERRIDE_EN) {
			labibb->lab_vreg.curr_volt =
					(val &
					LAB_VOLTAGE_SET_MASK) *
					labibb->lab_vreg.step_size +
					labibb->lab_vreg.min_volt;
		} else if (labibb->mode == QPNP_LABIBB_LCD_MODE) {
			rc = of_property_read_u32(of_node,
				"qcom,qpnp-lab-init-lcd-voltage",
				&(labibb->lab_vreg.curr_volt));
			if (rc) {
				pr_err("get qcom,qpnp-lab-init-lcd-voltage failed, rc = %d\n",
					rc);
				return rc;
			}
		} else {
			rc = of_property_read_u32(of_node,
				"qcom,qpnp-lab-init-amoled-voltage",
				&(labibb->lab_vreg.curr_volt));
			if (rc) {
				pr_err("get qcom,qpnp-lab-init-amoled-voltage failed, rc = %d\n",
					rc);
				return rc;
			}
		}

		labibb->lab_vreg.vreg_enabled = 1;
	}

	rc = qpnp_labibb_read(labibb, &val,
			labibb->lab_base + REG_LAB_MODULE_RDY, 1);
	if (rc) {
		pr_err("qpnp_lab_read read register %x failed rc = %d\n",
			REG_LAB_MODULE_RDY, rc);
		return rc;
	}

	if (!(val & LAB_MODULE_RDY_EN)) {
		val = LAB_MODULE_RDY_EN;

		rc = qpnp_labibb_write(labibb, labibb->lab_base +
			REG_LAB_MODULE_RDY, &val, 1);

		if (rc) {
			pr_err("qpnp_lab_dt_init write register %x failed rc = %d\n",
				REG_LAB_MODULE_RDY, rc);
			return rc;
		}
	}

	if (init_data->constraints.name) {
		rdesc			= &(labibb->lab_vreg.rdesc);
		rdesc->owner		= THIS_MODULE;
		rdesc->type		= REGULATOR_VOLTAGE;
		rdesc->ops		= &qpnp_lab_ops;
		rdesc->name		= init_data->constraints.name;

		cfg.dev = labibb->dev;
		cfg.init_data = init_data;
		cfg.driver_data = labibb;
		cfg.of_node = of_node;

		if (of_get_property(labibb->dev->of_node, "parent-supply",
				NULL))
			init_data->supply_regulator = "parent";

		init_data->constraints.valid_ops_mask
				|= REGULATOR_CHANGE_VOLTAGE |
					REGULATOR_CHANGE_STATUS;

		labibb->lab_vreg.rdev = regulator_register(rdesc, &cfg);
		if (IS_ERR(labibb->lab_vreg.rdev)) {
			rc = PTR_ERR(labibb->lab_vreg.rdev);
			labibb->lab_vreg.rdev = NULL;
			pr_err("unable to get regulator init data for qpnp lab regulator, rc = %d\n",
				rc);

			return rc;
		}
	} else {
		dev_err(labibb->dev, "qpnp lab regulator name missing\n");
		return -EINVAL;
	}

	mutex_init(&(labibb->lab_vreg.lab_mutex));
	return 0;
}

static int qpnp_ibb_dt_init(struct qpnp_labibb *labibb,
				struct device_node *of_node)
{
	int rc = 0;
	u32 i, tmp;
	u8 val;

	if (labibb->mode == QPNP_LABIBB_LCD_MODE)
		val = REG_LAB_IBB_LCD_MODE;
	else
		val = REG_LAB_IBB_AMOLED_MODE;

	rc = qpnp_labibb_sec_write(labibb, labibb->ibb_base,
			REG_LAB_LCD_AMOLED_SEL, &val, 1);

	if (rc) {
		pr_err("qpnp_labibb_sec_write register %x failed rc = %d\n",
			REG_IBB_LCD_AMOLED_SEL, rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-lab-pwrdn-delay",
					&tmp);
	if (rc < 0) {
		pr_err("qcom,qpnp-ibb-lab-pwrdn-delay is missing, rc = %d\n",
			rc);
		return rc;
	}

	val = 0;

	for (val = 0; val < ARRAY_SIZE(ibb_pwrdn_dly_plan); val++)
		if (ibb_pwrdn_dly_plan[val] == tmp)
			break;

	if (val == ARRAY_SIZE(ibb_pwrdn_dly_plan)) {
		pr_err("Invalid property in qcom,qpnp-ibb-lab-pwrdn-delay\n");
		return -EINVAL;
	}

	labibb->ibb_vreg.pwrdn_dly = tmp;

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-lab-pwrup-delay",
					&tmp);
	if (rc < 0) {
		pr_err("qcom,qpnp-ibb-lab-pwrup-delay is missing, rc = %d\n",
			rc);
		return rc;
	}

	for (i = 0; i < ARRAY_SIZE(ibb_pwrup_dly_plan); i++)
		if (ibb_pwrup_dly_plan[i] == tmp)
			break;

	if (i == ARRAY_SIZE(ibb_pwrup_dly_plan)) {
		pr_err("Invalid property in qcom,qpnp-ibb-lab-pwrup-delay\n");
		return -EINVAL;
	}

	labibb->ibb_vreg.pwrup_dly = tmp;

	val |= (i << IBB_PWRUP_PWRDN_CTL_1_DLY1_SHIFT);

	if (of_property_read_bool(of_node, "qcom,qpnp-ibb-en-discharge"))
		val |= PWRUP_PWRDN_CTL_1_DISCHARGE_EN;

	val |= (IBB_PWRUP_PWRDN_CTL_1_EN_DLY1 |
			IBB_PWRUP_PWRDN_CTL_1_LAB_VREG_OK);

	rc = qpnp_labibb_sec_write(labibb, labibb->ibb_base,
				REG_IBB_PWRUP_PWRDN_CTL_1,
				&val,
				1);
	if (rc) {
		pr_err("qpnp_labibb_sec_write register %x failed rc = %d\n",
			REG_IBB_PWRUP_PWRDN_CTL_1, rc);
		return rc;
	}

	val = 0;

	if (!of_property_read_bool(of_node, "qcom,qpnp-ibb-full-pull-down"))
		val |= IBB_PD_CTL_HALF_STRENGTH;

	if (of_property_read_bool(of_node, "qcom,qpnp-ibb-pull-down-enable"))
		val |= IBB_PD_CTL_EN;

	rc = qpnp_labibb_write(labibb, labibb->ibb_base + REG_IBB_PD_CTL,
				&val, 1);

	if (rc) {
		pr_err("qpnp_lab_dt_init write register %x failed rc = %d\n",
				REG_IBB_PD_CTL, rc);
		return rc;
	}

	rc = of_property_read_u32(of_node,
			"qcom,qpnp-ibb-switching-clock-frequency", &tmp);
	if (rc) {
		pr_err("get qcom,qpnp-ibb-switching-clock-frequency failed rc = %d\n",
			rc);
		return rc;
	}

	for (val = 0; val < ARRAY_SIZE(ibb_clk_div_plan); val++)
		if (ibb_clk_div_plan[val] == tmp)
			break;

	if (val == ARRAY_SIZE(ibb_clk_div_plan)) {
		pr_err("Invalid property in qpnp-ibb-switching-clock-frequency\n");
		return -EINVAL;
	}

	rc = qpnp_labibb_write(labibb, labibb->ibb_base + REG_IBB_CLK_DIV,
				&val, 1);
	if (rc) {
		pr_err("qpnp_ibb_dt_init write register %x failed rc = %d\n",
			REG_IBB_CLK_DIV, rc);
		return rc;
	}

	rc = of_property_read_u32(of_node,
		"qcom,qpnp-ibb-limit-maximum-current", &tmp);

	if (rc) {
		pr_err("get qcom,qpnp-ibb-limit-maximum-current failed rc = %d\n",
			rc);
		return rc;
	}

	for (val = 0; val < ARRAY_SIZE(ibb_current_limit_plan); val++)
		if (ibb_current_limit_plan[val] == tmp)
			break;

	if (val == ARRAY_SIZE(ibb_current_limit_plan)) {
		pr_err("Invalid property in qcom,qpnp-ibb-limit-maximum-current\n");
		return -EINVAL;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-debounce-cycle",
		&tmp);

	if (rc) {
		pr_err("get qcom,qpnp-ibb-debounce-cycle failed rc = %d\n",
			rc);
		return rc;
	}

	for (i = 0; i < ARRAY_SIZE(ibb_debounce_plan); i++)
		if (ibb_debounce_plan[i] == tmp)
			break;

	if (i == ARRAY_SIZE(ibb_debounce_plan)) {
		pr_err("Invalid property in qcom,qpnp-ibb-debounce-cycle\n");
		return -EINVAL;
	}

	val |= (i << IBB_CURRENT_LIMIT_DEBOUNCE_SHIFT);

	if (of_property_read_bool(of_node,
		"qcom,qpnp-ibb-limit-max-current-enable"))
		val |= IBB_CURRENT_LIMIT_EN;

	rc = qpnp_labibb_sec_write(labibb, labibb->ibb_base,
					REG_IBB_CURRENT_LIMIT,
					&val,
					1);
	if (rc) {
		pr_err("qpnp_labibb_sec_write register %x failed rc = %d\n",
				REG_IBB_CURRENT_LIMIT, rc);
		return rc;
	}

	if (of_property_read_bool(of_node,
		"qcom,qpnp-ibb-ring-suppression-enable")) {
		val = IBB_RING_SUPPRESSION_CTL_EN;
		rc = qpnp_labibb_write(labibb, labibb->ibb_base +
					REG_IBB_RING_SUPPRESSION_CTL,
					&val,
					1);
		if (rc) {
			pr_err("qpnp_ibb_dt_init write register %x failed rc = %d\n",
				REG_IBB_RING_SUPPRESSION_CTL, rc);
			return rc;
		}
	}

	if (of_property_read_bool(of_node, "qcom,qpnp-ibb-ps-enable")) {
		rc = qpnp_ibb_ps_config(labibb, true);
		if (rc) {
			pr_err("qpnp_ibb_dt_init PS enable failed rc=%d\n", rc);
			return rc;
		}
	} else {
		rc = qpnp_ibb_ps_config(labibb, false);
		if (rc) {
			pr_err("qpnp_ibb_dt_init PS disable failed rc=%d\n",
									rc);
			return rc;
		}
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-init-voltage",
					&(labibb->ibb_vreg.curr_volt));
	if (rc) {
		pr_err("get qcom,qpnp-ibb-init-voltage failed, rc = %d\n", rc);
		return rc;
	}

	if (!of_property_read_bool(of_node,
			"qcom,qpnp-ibb-use-default-voltage")) {
		if (labibb->ibb_vreg.curr_volt < labibb->ibb_vreg.min_volt) {
			pr_err("Invalid qcom,qpnp-ibb-init-voltage property, qcom,qpnp-ibb-init-voltage %d is less than the the minimum voltage %d",
				labibb->ibb_vreg.curr_volt,
				labibb->ibb_vreg.min_volt);
			return -EINVAL;
		}

		val = DIV_ROUND_UP(labibb->ibb_vreg.curr_volt -
				labibb->ibb_vreg.min_volt,
				labibb->ibb_vreg.step_size);

		if (val > IBB_VOLTAGE_SET_MASK) {
			pr_err("Invalid qcom,qpnp-ibb-init-voltage property, qcom,qpnp-lab-init-voltage %d is larger than the max supported voltage %d",
				labibb->ibb_vreg.curr_volt,
				labibb->ibb_vreg.min_volt +
				labibb->ibb_vreg.step_size *
				IBB_VOLTAGE_SET_MASK);
			return -EINVAL;
		}

		labibb->ibb_vreg.curr_volt = val * labibb->ibb_vreg.step_size +
				labibb->ibb_vreg.min_volt;
		val |= IBB_VOLTAGE_OVERRIDE_EN;
	} else {
		val = 0;
	}

	rc = qpnp_labibb_masked_write(labibb, labibb->ibb_base +
				REG_IBB_VOLTAGE,
				IBB_VOLTAGE_SET_MASK |
				IBB_VOLTAGE_OVERRIDE_EN,
				val);

	if (rc)
		pr_err("qpnp_ibb_masked_write write register %x failed rc = %d\n",
			REG_IBB_VOLTAGE, rc);


	return rc;
}

static int qpnp_ibb_regulator_enable(struct regulator_dev *rdev)
{
	int rc, delay, retries = 10;
	u8 val;
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (!labibb->ibb_vreg.vreg_enabled && !labibb->swire_control) {

		if (!labibb->standalone)
			return qpnp_labibb_regulator_enable(labibb);

		rc = qpnp_ibb_set_mode(labibb, IBB_SW_CONTROL_EN);
		if (rc) {
			pr_err("Unable to set IBB_MODULE_EN rc = %d\n", rc);
			return rc;
		}

		delay = labibb->ibb_vreg.soft_start;
		while (retries--) {
			/* Wait for a small period before reading IBB_STATUS1 */
			usleep_range(delay, delay + 100);

			rc = qpnp_labibb_read(labibb, &val,
					labibb->ibb_base + REG_IBB_STATUS1, 1);
			if (rc) {
				pr_err("qpnp_ibb_regulator_enable read register %x failed rc = %d\n",
					REG_IBB_STATUS1, rc);
				return rc;
			}

			if (val & IBB_STATUS1_VREG_OK)
				break;
		}

		if (!(val & IBB_STATUS1_VREG_OK)) {
			pr_err("qpnp_ibb_regulator_enable failed\n");
			return -EINVAL;
		}

		labibb->ibb_vreg.vreg_enabled = 1;
	}
	return 0;
}

static int qpnp_ibb_regulator_disable(struct regulator_dev *rdev)
{
	int rc;
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->ibb_vreg.vreg_enabled && !labibb->swire_control) {

		if (!labibb->standalone)
			return qpnp_labibb_regulator_disable(labibb);

		rc = qpnp_ibb_set_mode(labibb, IBB_SW_CONTROL_DIS);
		if (rc) {
			pr_err("Unable to set IBB_MODULE_EN rc = %d\n", rc);
			return rc;
		}

		labibb->ibb_vreg.vreg_enabled = 0;
	}
	return 0;
}

static int qpnp_ibb_regulator_is_enabled(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->swire_control)
		return 0;

	return labibb->ibb_vreg.vreg_enabled;
}

static int qpnp_ibb_regulator_set_voltage(struct regulator_dev *rdev,
				int min_uV, int max_uV, unsigned *selector)
{
	int rc, new_uV;
	u8 val;
	struct qpnp_labibb *labibb = rdev_get_drvdata(rdev);

	if (labibb->swire_control)
		return 0;

	if (min_uV < labibb->ibb_vreg.min_volt) {
		pr_err("min_uV %d is less than min_volt %d", min_uV,
			labibb->ibb_vreg.min_volt);
		return -EINVAL;
	}

	val = DIV_ROUND_UP(min_uV - labibb->ibb_vreg.min_volt,
				labibb->ibb_vreg.step_size);
	new_uV = val * labibb->ibb_vreg.step_size + labibb->ibb_vreg.min_volt;

	if (new_uV > max_uV) {
		pr_err("unable to set voltage %d (min:%d max:%d)\n", new_uV,
			min_uV, max_uV);
		return -EINVAL;
	}

	rc = qpnp_labibb_masked_write(labibb, labibb->ibb_base +
				REG_IBB_VOLTAGE,
				IBB_VOLTAGE_SET_MASK |
				IBB_VOLTAGE_OVERRIDE_EN,
				val | IBB_VOLTAGE_OVERRIDE_EN);

	if (rc) {
		pr_err("write to register %x failed rc = %d\n", REG_IBB_VOLTAGE,
			rc);
		return rc;
	}

	if (new_uV > labibb->ibb_vreg.curr_volt) {
		val = DIV_ROUND_UP(new_uV - labibb->ibb_vreg.curr_volt,
				labibb->ibb_vreg.step_size);
		udelay(val * labibb->ibb_vreg.slew_rate);
	}
	labibb->ibb_vreg.curr_volt = new_uV;

	return 0;
}

static int qpnp_ibb_regulator_get_voltage(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->swire_control)
		return 0;

	return labibb->ibb_vreg.curr_volt;
}

static struct regulator_ops qpnp_ibb_ops = {
	.enable			= qpnp_ibb_regulator_enable,
	.disable		= qpnp_ibb_regulator_disable,
	.is_enabled		= qpnp_ibb_regulator_is_enabled,
	.set_voltage		= qpnp_ibb_regulator_set_voltage,
	.get_voltage		= qpnp_ibb_regulator_get_voltage,
};

static int register_qpnp_ibb_regulator(struct qpnp_labibb *labibb,
					struct device_node *of_node)
{
	int rc = 0;
	struct regulator_init_data *init_data;
	struct regulator_desc *rdesc;
	struct regulator_config cfg = {};
	u8 val, ibb_enable_ctl;
	u32 tmp;

	if (!of_node) {
		dev_err(labibb->dev, "qpnp ibb regulator device tree node is missing\n");
		return -EINVAL;
	}

	init_data = of_get_regulator_init_data(labibb->dev, of_node);
	if (!init_data) {
		pr_err("unable to get regulator init data for qpnp ibb regulator\n");
		return -ENOMEM;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-min-voltage",
					&(labibb->ibb_vreg.min_volt));
	if (rc < 0) {
		pr_err("qcom,qpnp-ibb-min-voltage is missing, rc = %d\n",
			rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-step-size",
					&(labibb->ibb_vreg.step_size));
	if (rc < 0) {
		pr_err("qcom,qpnp-ibb-step-size is missing, rc = %d\n", rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-slew-rate",
					&(labibb->ibb_vreg.slew_rate));
	if (rc < 0) {
		pr_err("qcom,qpnp-ibb-slew-rate is missing, rc = %d\n",
			rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-soft-start",
					&(labibb->ibb_vreg.soft_start));
	if (rc < 0) {
		pr_err("qcom,qpnp-ibb-soft-start is missing, rc = %d\n",
			rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-discharge-resistor",
			&tmp);

	if (rc < 0) {
		pr_err("qcom,qpnp-ibb-discharge-resistor is missing, rc = %d\n",
			rc);
		return rc;
	}

	if (labibb->mode == QPNP_LABIBB_AMOLED_MODE) {
		/*
		 * AMOLED mode needs ibb discharge resistor to be
		 * configured for 300KOhm
		 */
		if (tmp < ibb_discharge_resistor_plan[0])
			tmp = ibb_discharge_resistor_plan[0];
	}

	for (val = 0; val < ARRAY_SIZE(ibb_discharge_resistor_plan); val++)
		if (ibb_discharge_resistor_plan[val] == tmp)
			break;

	if (val == ARRAY_SIZE(ibb_discharge_resistor_plan)) {
		pr_err("Invalid property in qcom,qpnp-ibb-discharge-resistor\n");
		return -EINVAL;
	}

	rc = qpnp_labibb_write(labibb, labibb->ibb_base +
			REG_IBB_SOFT_START_CTL, &val, 1);
	if (rc) {
		pr_err("qpnp_labibb_write register %x failed rc = %d\n",
			REG_IBB_SOFT_START_CTL, rc);
		return rc;
	}

	if (of_find_property(of_node, "qcom,output-voltage-one-pulse", NULL)) {
		if (!labibb->swire_control) {
			pr_err("Invalid property 'qcom,output-voltage-one-pulse', valid only in SWIRE config\n");
			return -EINVAL;
		}
		rc = of_property_read_u32(of_node,
				"qcom,output-voltage-one-pulse", &tmp);
		if (rc) {
			pr_err("failed to read qcom,output-voltage-one-pulse rc=%d\n",
									rc);
			return rc;
		}
		if (tmp > MAX_OUTPUT_PULSE_VOLTAGE_MV ||
					tmp < MIN_OUTPUT_PULSE_VOLTAGE_MV) {
			pr_err("Invalid one-pulse voltage range %d\n", tmp);
			return -EINVAL;
		}

		/*
		 * Set the output voltage 100mV lower as the IBB HW module
		 * counts one pulse less in SWIRE mode.
		 */
		val = DIV_ROUND_UP((tmp - MIN_OUTPUT_PULSE_VOLTAGE_MV),
						OUTPUT_VOLTAGE_STEP_MV) - 1;
		rc = qpnp_labibb_masked_write(labibb, labibb->ibb_base +
					REG_IBB_SWIRE_CTL,
					IBB_OUTPUT_VOLTAGE_AT_ONE_PULSE_MASK,
					val);
		if (rc) {
			pr_err("qpnp_labiibb_write register %x failed rc = %d\n",
				REG_IBB_SWIRE_CTL, rc);
			return rc;
		}
	}

	rc = qpnp_labibb_read(labibb, &ibb_enable_ctl,
				labibb->ibb_base + REG_IBB_ENABLE_CTL, 1);
	if (rc) {
		pr_err("qpnp_ibb_read register %x failed rc = %d\n",
			REG_IBB_ENABLE_CTL, rc);
		return rc;
	}

	if (ibb_enable_ctl &
		(IBB_ENABLE_CTL_SWIRE_RDY | IBB_ENABLE_CTL_MODULE_EN)) {
		/* SWIRE_RDY or IBB_MODULE_EN enabled */
		rc = qpnp_labibb_read(labibb, &val,
			labibb->ibb_base + REG_IBB_LCD_AMOLED_SEL, 1);
		if (rc) {
			pr_err("qpnp_labibb_read register %x failed rc = %d\n",
				REG_IBB_LCD_AMOLED_SEL, rc);
			return rc;
		}

		if (val == REG_LAB_IBB_AMOLED_MODE)
			labibb->mode = QPNP_LABIBB_AMOLED_MODE;
		else
			labibb->mode = QPNP_LABIBB_LCD_MODE;

		rc = qpnp_labibb_read(labibb, &val,
				labibb->ibb_base + REG_IBB_VOLTAGE, 1);
		if (rc) {
			pr_err("qpnp_labibb_read read register %x failed rc = %d\n",
				REG_IBB_VOLTAGE, rc);
			return rc;
		}

		if (val & IBB_VOLTAGE_OVERRIDE_EN) {
			labibb->ibb_vreg.curr_volt =
				(val & IBB_VOLTAGE_SET_MASK) *
				labibb->ibb_vreg.step_size +
				labibb->ibb_vreg.min_volt;
		} else if (labibb->mode == QPNP_LABIBB_LCD_MODE) {
			rc = of_property_read_u32(of_node,
				"qcom,qpnp-ibb-init-lcd-voltage",
				&(labibb->ibb_vreg.curr_volt));
			if (rc) {
				pr_err("get qcom,qpnp-ibb-init-lcd-voltage failed, rc = %d\n",
					rc);
				return rc;
			}
		} else {
			rc = of_property_read_u32(of_node,
				"qcom,qpnp-ibb-init-amoled-voltage",
				&(labibb->ibb_vreg.curr_volt));
			if (rc) {
				pr_err("get qcom,qpnp-ibb-init-amoled-voltage failed, rc = %d\n",
					rc);
				return rc;
			}

		}

		rc = qpnp_labibb_read(labibb, &val, labibb->ibb_base +
					REG_IBB_PWRUP_PWRDN_CTL_1, 1);
		if (rc) {
			pr_err("qpnp_labibb_config_init read register %x failed rc = %d\n",
				REG_IBB_PWRUP_PWRDN_CTL_1, rc);
			return rc;
		}

		labibb->ibb_vreg.pwrup_dly = ibb_pwrup_dly_plan[
					(val >>
					IBB_PWRUP_PWRDN_CTL_1_DLY1_SHIFT) &
					IBB_PWRUP_PWRDN_CTL_1_DLY1_MASK];
		labibb->ibb_vreg.pwrdn_dly =  ibb_pwrdn_dly_plan[val &
					IBB_PWRUP_PWRDN_CTL_1_DLY2_MASK];

		labibb->ibb_vreg.vreg_enabled = 1;
	} else {
		/* SWIRE_RDY and IBB_MODULE_EN not enabled */
		rc = qpnp_ibb_dt_init(labibb, of_node);
		if (rc) {
			pr_err("qpnp-ibb: wrong DT parameter specified: rc = %d\n",
				rc);
			return rc;
		}
	}

	if (labibb->mode == QPNP_LABIBB_AMOLED_MODE) {
		val = IBB_OVERRIDE_NONOVERLAP | IBB_NFET_GATE_DELAY_2;
		rc = qpnp_labibb_sec_masked_write(labibb, labibb->ibb_base,
			REG_IBB_NONOVERLAP_TIME_1,
			IBB_OVERRIDE_NONOVERLAP | IBB_NONOVERLAP_NFET_MASK,
			val);

		if (rc) {
			pr_err("qpnp_labibb_sec_masked_write register %x failed rc = %d\n",
				REG_IBB_NONOVERLAP_TIME_1, rc);
			return rc;
		}

		val = IBB_N2P_MUX_SEL;
		rc = qpnp_labibb_sec_write(labibb, labibb->ibb_base,
			REG_IBB_NONOVERLAP_TIME_2, &val, 1);

		if (rc) {
			pr_err("qpnp_labibb_sec_write register %x failed rc = %d\n",
				REG_IBB_NONOVERLAP_TIME_2, rc);
			return rc;
		}

		val = IBB_FASTER_PFET_OFF;
		rc = qpnp_labibb_masked_write(labibb,
			labibb->ibb_base + REG_IBB_SPARE_CTL,
			IBB_POFF_CTL_MASK, val);
		if (rc) {
			pr_err("qpnp_labibb_masked_write %x failed rc = %d\n",
				REG_IBB_SPARE_CTL, rc);
			return rc;
		}
	}

	if (labibb->standalone) {
		val = 0;
		rc = qpnp_labibb_sec_write(labibb, labibb->ibb_base,
				REG_IBB_PWRUP_PWRDN_CTL_1, &val, 1);
		if (rc) {
			pr_err("qpnp_labibb_sec_write register %x failed rc = %d\n",
				REG_IBB_PWRUP_PWRDN_CTL_1, rc);
			return rc;
		}
		labibb->ibb_vreg.pwrup_dly = 0;
		labibb->ibb_vreg.pwrdn_dly = 0;
	}

	rc = qpnp_labibb_read(labibb, &val,
			labibb->ibb_base + REG_IBB_MODULE_RDY, 1);
	if (rc) {
		pr_err("qpnp_ibb_read read register %x failed rc = %d\n",
			REG_IBB_MODULE_RDY, rc);
		return rc;
	}

	if (!(val & IBB_MODULE_RDY_EN)) {
		val = IBB_MODULE_RDY_EN;

		rc = qpnp_labibb_write(labibb, labibb->ibb_base +
			REG_IBB_MODULE_RDY, &val, 1);

		if (rc) {
			pr_err("qpnp_ibb_dt_init write register %x failed rc = %d\n",
				REG_IBB_MODULE_RDY, rc);
			return rc;
		}
	}

	if (init_data->constraints.name) {
		rdesc			= &(labibb->ibb_vreg.rdesc);
		rdesc->owner		= THIS_MODULE;
		rdesc->type		= REGULATOR_VOLTAGE;
		rdesc->ops		= &qpnp_ibb_ops;
		rdesc->name		= init_data->constraints.name;

		cfg.dev = labibb->dev;
		cfg.init_data = init_data;
		cfg.driver_data = labibb;
		cfg.of_node = of_node;

		if (of_get_property(labibb->dev->of_node, "parent-supply",
				 NULL))
			init_data->supply_regulator = "parent";

		init_data->constraints.valid_ops_mask
				|= REGULATOR_CHANGE_VOLTAGE |
					REGULATOR_CHANGE_STATUS;

		labibb->ibb_vreg.rdev = regulator_register(rdesc, &cfg);
		if (IS_ERR(labibb->ibb_vreg.rdev)) {
			rc = PTR_ERR(labibb->ibb_vreg.rdev);
			labibb->ibb_vreg.rdev = NULL;
			pr_err("unable to get regulator init data for qpnp ibb regulator, rc = %d\n",
				rc);

			return rc;
		}
	} else {
		dev_err(labibb->dev, "qpnp ibb regulator name missing\n");
		return -EINVAL;
	}

	mutex_init(&(labibb->ibb_vreg.ibb_mutex));
	return 0;
}

static int qpnp_lab_register_irq(struct spmi_resource *spmi_resource,
					struct qpnp_labibb *labibb)
{
	if (labibb->skip_2nd_swire_cmd) {
		labibb->lab_vreg.lab_vreg_ok_irq =
					spmi_get_irq_byname(labibb->spmi,
					spmi_resource, "lab-vreg-ok");
		if (labibb->lab_vreg.lab_vreg_ok_irq < 0) {
			pr_err("Invalid lab-vreg-ok irq\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int qpnp_labibb_check_ttw_supported(struct qpnp_labibb *labibb)
{
	int rc = 0;
	u8 val;

	switch (labibb->pmic_rev_id->pmic_subtype) {
	case PMI8996:
		rc = qpnp_labibb_read(labibb, &val,
				labibb->ibb_base + REG_IBB_REVISION4, 1);
		if (rc) {
			pr_err("qpnp_labibb_read register %x failed rc = %d\n",
				REG_IBB_REVISION4, rc);
			return rc;
		}

		/* PMI8996 has revision 1 */
		if (val < 1) {
			pr_err("TTW feature cannot be enabled for revision %d\n",
									val);
			labibb->ttw_en = false;
		}
		/* FORCE_LAB_ON in TTW is not required for PMI8996 */
		labibb->ttw_force_lab_on = false;
		break;
	case PMI8950:
		/* TTW supported for all revisions */
		break;
	default:
		pr_info("TTW mode not supported for PMIC-subtype = %d\n",
					labibb->pmic_rev_id->pmic_subtype);
		labibb->ttw_en = false;
		break;

	}
	return rc;
}

static int qpnp_labibb_regulator_probe(struct spmi_device *spmi)
{
	struct qpnp_labibb *labibb;
	struct resource *resource;
	struct spmi_resource *spmi_resource;
	struct device_node *revid_dev_node;
	const char *mode_name;
	u8 type;
	int rc = 0;

	labibb = devm_kzalloc(&spmi->dev,
			sizeof(struct qpnp_labibb), GFP_KERNEL);
	if (labibb == NULL) {
		pr_err("labibb allocation failed.\n");
		return -ENOMEM;
	}

	labibb->dev = &(spmi->dev);
	labibb->spmi = spmi;

	revid_dev_node = of_parse_phandle(spmi->dev.of_node,
					"qcom,pmic-revid", 0);
	if (!revid_dev_node) {
		pr_err("Missing qcom,pmic-revid property - driver failed\n");
		return -EINVAL;
	}

	labibb->pmic_rev_id = get_revid_data(revid_dev_node);
	if (IS_ERR(labibb->pmic_rev_id)) {
		pr_debug("Unable to get revid data\n");
		return -EPROBE_DEFER;
	}

	rc = of_property_read_string(labibb->dev->of_node,
			"qpnp,qpnp-labibb-mode", &mode_name);
	if (!rc) {
		if (strcmp("lcd", mode_name) == 0) {
			labibb->mode = QPNP_LABIBB_LCD_MODE;
		} else if (strcmp("amoled", mode_name) == 0) {
			labibb->mode = QPNP_LABIBB_AMOLED_MODE;
		} else {
			pr_err("Invalid device property in qpnp,qpnp-labibb-mode: %s\n",
				mode_name);
			return -EINVAL;
		}
	} else {
		pr_err("qpnp_labibb: qpnp,qpnp-labibb-mode is missing.\n");
		return rc;
	}

	labibb->standalone = of_property_read_bool(labibb->dev->of_node,
				"qcom,labibb-standalone");

	labibb->ttw_en = of_property_read_bool(labibb->dev->of_node,
				"qcom,labibb-touch-to-wake-en");
	if (labibb->ttw_en && labibb->mode != QPNP_LABIBB_LCD_MODE) {
		pr_err("Invalid mode for TTW\n");
		return -EINVAL;
	}

	labibb->ttw_force_lab_on = of_property_read_bool(
		labibb->dev->of_node, "qcom,labibb-ttw-force-lab-on");

	labibb->swire_control = of_property_read_bool(labibb->dev->of_node,
							"qpnp,swire-control");
	if (labibb->swire_control && labibb->mode != QPNP_LABIBB_AMOLED_MODE) {
		pr_err("Invalid mode for SWIRE control\n");
		return -EINVAL;
	}
	if (labibb->swire_control) {
		labibb->skip_2nd_swire_cmd =
				of_property_read_bool(labibb->dev->of_node,
				"qcom,skip-2nd-swire-cmd");
		rc = of_property_read_u32(labibb->dev->of_node,
				"qcom,swire-2nd-cmd-delay",
				&labibb->swire_2nd_cmd_delay);
		if (rc)
			labibb->swire_2nd_cmd_delay =
					SWIRE_DEFAULT_2ND_CMD_DLY_MS;

		rc = of_property_read_u32(labibb->dev->of_node,
				"qcom,swire-ibb-ps-enable-delay",
				&labibb->swire_ibb_ps_enable_delay);
		if (rc)
			labibb->swire_ibb_ps_enable_delay =
					SWIRE_DEFAULT_IBB_PS_ENABLE_DLY_MS;
	}

	spmi_for_each_container_dev(spmi_resource, spmi) {
		if (!spmi_resource) {
			pr_err("qpnp_labibb: spmi resource absent\n");
			return -ENXIO;
		}

		resource = spmi_get_resource(spmi, spmi_resource,
						IORESOURCE_MEM, 0);
		if (!(resource && resource->start)) {
			pr_err("node %s IO resource absent!\n",
				spmi->dev.of_node->full_name);
			return -ENXIO;
		}

		rc = qpnp_labibb_read(labibb, &type,
				resource->start + REG_PERPH_TYPE, 1);
		if (rc) {
			pr_err("Peripheral type read failed rc=%d\n", rc);
			goto fail_registration;
		}

		switch (type) {
		case QPNP_LAB_TYPE:
			labibb->lab_base = resource->start;
			rc = qpnp_lab_register_irq(spmi_resource, labibb);
			if (rc) {
				pr_err("Failed to register LAB IRQ rc=%d\n",
							rc);
				goto fail_registration;
			}
			rc = register_qpnp_lab_regulator(labibb,
				spmi_resource->of_node);
			if (rc)
				goto fail_registration;
		break;

		case QPNP_IBB_TYPE:
			labibb->ibb_base = resource->start;
			rc = register_qpnp_ibb_regulator(labibb,
				spmi_resource->of_node);
			if (rc)
				goto fail_registration;
		break;

		default:
			pr_err("qpnp_labibb: unknown peripheral type %x\n",
				type);
			rc = -EINVAL;
			goto fail_registration;
		}
	}

	if (labibb->ttw_en) {
		rc = qpnp_labibb_check_ttw_supported(labibb);
		if (rc) {
			pr_err("pmic revision check failed for TTW rc=%d\n",
									rc);
			goto fail_registration;
		}
	}

	dev_set_drvdata(&spmi->dev, labibb);
	return 0;

fail_registration:
	if (labibb->lab_vreg.rdev)
		regulator_unregister(labibb->lab_vreg.rdev);
	if (labibb->ibb_vreg.rdev)
		regulator_unregister(labibb->ibb_vreg.rdev);

	return rc;
}

static int qpnp_labibb_regulator_remove(struct spmi_device *spmi)
{
	struct qpnp_labibb *labibb = dev_get_drvdata(&spmi->dev);

	if (labibb) {
		if (labibb->lab_vreg.rdev)
			regulator_unregister(labibb->lab_vreg.rdev);
		if (labibb->ibb_vreg.rdev)
			regulator_unregister(labibb->ibb_vreg.rdev);
	}
	return 0;
}

static struct of_device_id spmi_match_table[] = {
	{ .compatible = QPNP_LABIBB_REGULATOR_DRIVER_NAME, },
	{ },
};

static struct spmi_driver qpnp_labibb_regulator_driver = {
	.driver		= {
		.name	= QPNP_LABIBB_REGULATOR_DRIVER_NAME,
		.of_match_table = spmi_match_table,
	},
	.probe		= qpnp_labibb_regulator_probe,
	.remove		= qpnp_labibb_regulator_remove,
};

static int __init qpnp_labibb_regulator_init(void)
{
	return spmi_driver_register(&qpnp_labibb_regulator_driver);
}
arch_initcall(qpnp_labibb_regulator_init);

static void __exit qpnp_labibb_regulator_exit(void)
{
	spmi_driver_unregister(&qpnp_labibb_regulator_driver);
}
module_exit(qpnp_labibb_regulator_exit);

MODULE_DESCRIPTION("QPNP labibb driver");
MODULE_LICENSE("GPL v2");
