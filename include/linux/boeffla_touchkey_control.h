/*
 * 
 * Boeffla touchkey control OnePlus3/OnePlus2
 * 
 * Author: andip71 (aka Lord Boeffla)
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

#include <linux/leds.h>


/*****************************************/
// Definitions
/*****************************************/

#define	MODE_NORMAL			0
#define MODE_TOUCHKEY_ONLY	1
#define MODE_OFF			2

#define TIMEOUT_DEFAULT		0
#define TIMEOUT_MIN			0
#define TIMEOUT_MAX			30000

#define BRIGHTNESS_DEFAULT	40
#define BRIGHTNESS_OFF		0

#define BTK_CONTROL_VERSION 	"1.2.0"


/*****************************************/
// Function declarations
/*****************************************/

void btkc_touch_start(void);
void btkc_touch_stop(void);
void btkc_touch_button(void);
int btkc_led_set(int val);
void qpnp_boeffla_set_button_backlight(enum led_brightness value);
