 /*
  * Copyright (C) 2015 NXP Semiconductors
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  *      http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

#define P61_MAGIC 0xEA
#define P61_SET_PWR _IOW(P61_MAGIC, 0x01, unsigned int)
#define P61_SET_DBG _IOW(P61_MAGIC, 0x02, unsigned int)
#define P61_SET_POLL _IOW(P61_MAGIC, 0x03, unsigned int)
#define P61_SET_SPM_PWR    _IOW(P61_MAGIC, 0x04, unsigned int)

#define P61_GET_SPM_STATUS    _IOR(P61_MAGIC, 0x05, unsigned int)
#define P61_SET_THROUGHPUT    _IOW(P61_MAGIC, 0x06, unsigned int)
#define P61_GET_ESE_ACCESS    _IOW(P61_MAGIC, 0x07, unsigned int)
#define P61_SET_POWER_SCHEME  _IOW(P61_MAGIC, 0x08, unsigned int)
struct p61_spi_platform_data {
    unsigned int irq_gpio;
    unsigned int rst_gpio;
};
