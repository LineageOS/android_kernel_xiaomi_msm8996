/*
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
/*Gerbera - WiFi*/
/*
 */


/*========================================================================

  \file  wlan_hdd_main_module.c

  \brief WLAN Host Device Driver module interface implementation

  ========================================================================*/

/*--------------------------------------------------------------------------
  Include Files
  ------------------------------------------------------------------------*/
#include <linux/module.h>
#include "qwlan_version.h"

static char *country_code;
static char *version_string = QWLAN_VERSIONSTR;
static int con_mode;

extern void register_wlan_module_parameters_callback(int con_mode_set,
	char* country_code_set,
	char* version_string_set
);

extern int hdd_driver_init(void);
extern void hdd_driver_exit(void);

static int __init hdd_module_init ( void)
{
	register_wlan_module_parameters_callback(
		con_mode,
		country_code,
		version_string
	);

	return hdd_driver_init();
}

void __exit hdd_module_exit(void)
{
	hdd_driver_exit();

	register_wlan_module_parameters_callback(
		con_mode,
		country_code,
		version_string
	);
}

//Register the module init/exit functions
module_init(hdd_module_init);
module_exit(hdd_module_exit);

MODULE_DESCRIPTION("WLAN HOST DEVICE DRIVER");

#if  defined(QCA_WIFI_FTM)
module_param(con_mode, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#else
module_param_call(con_mode, con_mode_handler, param_get_int, &con_mode,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif

module_param(country_code, charp,
             S_IRUSR | S_IRGRP | S_IROTH);

module_param(version_string, charp,
             S_IRUSR | S_IRGRP | S_IROTH);
