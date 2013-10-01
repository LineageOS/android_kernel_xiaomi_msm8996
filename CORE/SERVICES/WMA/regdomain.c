/*
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * Previously licensed under the ISC license by Qualcomm Atheros, Inc.
 *
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

/*
 * This file was originally distributed by Qualcomm Atheros, Inc.
 * under proprietary terms before Copyright ownership was assigned
 * to the Linux Foundation.
 */

/*
 * Notifications and licenses are retained for attribution purposes only.
 */
/*
 * Copyright (c) 2002-2006 Sam Leffler, Errno Consulting
 * Copyright (c) 2005-2006 Atheros Communications, Inc.
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the following conditions are met:
 * 1. The materials contained herein are unmodified and are used
 *    unmodified.
 * 2. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following NO
 *    ''WARRANTY'' disclaimer below (''Disclaimer''), without
 *    modification.
 * 3. Redistributions in binary form must reproduce at minimum a
 *    disclaimer similar to the Disclaimer below and any redistribution
 *    must be conditioned upon including a substantially similar
 *    Disclaimer requirement for further binary redistribution.
 * 4. Neither the names of the above-listed copyright holders nor the
 *    names of any contributors may be used to endorse or promote
 *    product derived from this software without specific prior written
 *    permission.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT,
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

#include <adf_os_types.h>
#include "regdomain.h"
#include "regdomain_common.h"

#define N(a) (sizeof(a)/sizeof(a[0]))
/*
 * By default, the regdomain tables reference the common tables
 * from regdomain_common.h.  These default tables can be replaced
 * by calls to populate_regdomain_tables functions.
 */

HAL_REG_DMN_TABLES ol_regdmn_Rdt = {
	ahCmnRegDomainPairs,    /* regDomainPairs */
	ahCmnAllCountries,      /* allCountries */
	N(ahCmnRegDomainPairs),    /* regDomainPairsCt */
	N(ahCmnAllCountries),      /* allCountriesCt */
};

static u_int16_t get_eeprom_rd(u_int16_t rd)
{
	return rd & ~WORLDWIDE_ROAMING_FLAG;
}

/*
 * Return whether or not the regulatory domain/country in EEPROM
 * is acceptable.
 */
static bool regmn_is_eeprom_valid(u_int16_t rd)
{
	int32_t i;

	if (rd & COUNTRY_ERD_FLAG) {
		u_int16_t cc = rd & ~COUNTRY_ERD_FLAG;
		for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++)
			if (ol_regdmn_Rdt.allCountries[i].countryCode == cc)
				return true;
	} else {
		for (i = 0; i < ol_regdmn_Rdt.regDomainPairsCt; i++)
			if (ol_regdmn_Rdt.regDomainPairs[i].regDmnEnum == rd)
				return true;
	}
	/* TODO: Bring it under debug level */
	adf_os_print("%s: invalid regulatory domain/country code 0x%x\n",
		     __func__, rd);
	return false;
}

/*
 * Find the pointer to the country element in the country table
 * corresponding to the country code
 */
static const COUNTRY_CODE_TO_ENUM_RD *find_country(u_int16_t country_code)
{
	int32_t i;

	for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++) {
		if (ol_regdmn_Rdt.allCountries[i].countryCode == country_code)
			return &ol_regdmn_Rdt.allCountries[i];
	}
	return NULL;        /* Not found */
}

static u_int16_t regdmn_get_default_country(u_int16_t rd)
{
	int32_t i;

	if (rd & COUNTRY_ERD_FLAG) {
		const COUNTRY_CODE_TO_ENUM_RD *country = NULL;
		u_int16_t cc = rd & ~COUNTRY_ERD_FLAG;

		country = find_country(cc);
		if (country)
			return cc;
	}

	/*
	 * Check reg domains that have only one country
	 */
	for (i = 0; i < ol_regdmn_Rdt.regDomainPairsCt; i++) {
		if (ol_regdmn_Rdt.regDomainPairs[i].regDmnEnum == rd) {
			if (ol_regdmn_Rdt.regDomainPairs[i].singleCC != 0)
				return ol_regdmn_Rdt.regDomainPairs[i].singleCC;
			else
				i = ol_regdmn_Rdt.regDomainPairsCt;
		}
	}
	return CTRY_DEFAULT;
}

static const REG_DMN_PAIR_MAPPING *get_regdmn_pair(u_int16_t reg_dmn)
{
	int32_t i;

	for (i = 0; i < ol_regdmn_Rdt.regDomainPairsCt; i++) {
		if (ol_regdmn_Rdt.regDomainPairs[i].regDmnEnum == reg_dmn)
			return &ol_regdmn_Rdt.regDomainPairs[i];
	}
	return NULL;
}

static const COUNTRY_CODE_TO_ENUM_RD *get_country_from_rd(u_int16_t regdmn)
{
	int32_t i;

	for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++) {
		if (ol_regdmn_Rdt.allCountries[i].regDmnEnum == regdmn)
			return &ol_regdmn_Rdt.allCountries[i];
	}
	return NULL;        /* Not found */
}

/*
 * Returns country string for the given regulatory domain.
 */
int32_t regdmn_get_country_alpha2(u_int16_t rd, u_int8_t *alpha2)
{
	u_int16_t country_code;
	u_int16_t regdmn;
	const COUNTRY_CODE_TO_ENUM_RD *country = NULL;
	const REG_DMN_PAIR_MAPPING *regpair = NULL;

	regdmn = get_eeprom_rd(rd);

	if (!regmn_is_eeprom_valid(rd))
		return -EINVAL;

	country_code = regdmn_get_default_country(regdmn);
	if (country_code == CTRY_DEFAULT && regdmn == CTRY_DEFAULT) {
		/* Set to CTRY_UNITED_STATES for testing */
		country_code = CTRY_UNITED_STATES;
	}

	if (country_code != CTRY_DEFAULT) {
		country = find_country(country_code);
		if (!country) {
			/* TODO: Bring it under debug level */
			adf_os_print(KERN_ERR "Not a valid country code\n");
			return -EINVAL;
		}
		regdmn = country->regDmnEnum;
	}

	regpair = get_regdmn_pair(regdmn);
	if (!regpair) {
		/* TODO: Bring it under debug level */
		adf_os_print(KERN_ERR "No regpair is found, can not proceeed\n");
		return -EINVAL;
	}

	if (!country)
		country = get_country_from_rd(regdmn);

	if (country) {
		alpha2[0] = country->isoName[0];
		alpha2[1] = country->isoName[1];
	} else {
		alpha2[0] = '0';
		alpha2[1] = '0';
	}

	return 0;
}
