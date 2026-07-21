/*
 * Copyright (C) 2018 Tsvetomir Dimitrov
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "sec_agree.h"

#include <string.h>

#include "../../core/dprint.h"
#include "../../lib/ims/ims_getters.h"
#include "ipsec_alg.h"

extern str ipsec_preferred_alg;
extern str ipsec_preferred_ealg;

int process_sec_agree_param(
		str name, str value, ipsec_t *ipsec, int *alg_found, int *ealg_found)
{

	if(name.len == 3 && strncasecmp(name.s, "alg", 3) == 0) {
		if ((ipsec_preferred_alg.len && STR_EQ(value, ipsec_preferred_alg))
				|| (value.len == 16 && strncasecmp(value.s, "hmac-sha-256-128", 16) == 0)
				|| (value.len == 13 && strncasecmp(value.s, "hmac-sha-1-96", 13) == 0)
				|| (value.len == 12 && strncasecmp(value.s, "hmac-md5-96", 12) == 0)) {

			if(pkg_str_dup(&ipsec->r_alg, &value) < 0) {
				LM_ERR("Failed to allocate memory for r_alg\n");
				return -1;
			}
			*alg_found = 1;
		}

		if(pkg_str_dup(&ipsec->alg, &value) < 0) {
			LM_ERR("Failed to allocate memory for alg\n");
			return -1;
		}
	} else if(name.len == 4 && strncasecmp(name.s, "ealg", 4) == 0) {
		if ((ipsec_preferred_ealg.len && STR_EQ(value, ipsec_preferred_ealg))
				|| (value.len == 7 && strncasecmp(value.s, "aes-gcm", 7) == 0)
				|| (value.len == 11 && strncasecmp(value.s, "aes-256-gcm", 11) == 0)
				|| (value.len == 12 && strncasecmp(value.s, "aes-cbc-128", 12) == 0)
				|| (value.len == 10 && strncasecmp(value.s, "3des-cbc", 10) == 0)
				|| (value.len == 9 && strncasecmp(value.s, "null-ealg", 9) == 0)) {

			if(pkg_str_dup(&ipsec->r_ealg, &value) < 0) {
				LM_ERR("Failed to allocate memory for r_ealg\n");
				return -1;
			}
			*ealg_found = 1;
		}

		if(pkg_str_dup(&ipsec->ealg, &value) < 0) {
			LM_ERR("Failed to allocate memory for ealg\n");
			return -1;
		}
	} else if(name.len == 4 && strncasecmp(name.s, "prot", 4) == 0) {
		if(pkg_str_dup(&ipsec->prot, &value) < 0) {
			LM_ERR("Failed to allocate memory for prot\n");
			return -1;
		}
	} else if(name.len == 3 && strncasecmp(name.s, "mod", 3) == 0) {
		if(pkg_str_dup(&ipsec->mod, &value) < 0) {
			LM_ERR("Failed to allocate memory for mod\n");
			return -1;
		}
	} else if(name.len == 5 && strncasecmp(name.s, "spi-c", 5) == 0) {
		if(str2int(&value, &ipsec->spi_uc) < 0) {
			LM_ERR("Failed to convert spi-c to int\n");
			return -1;
		}
	} else if(name.len == 5 && strncasecmp(name.s, "spi-s", 5) == 0) {
		if(str2int(&value, &ipsec->spi_us) < 0) {
			LM_ERR("Failed to convert spi-s to int\n");
			return -1;
		}
	} else if(name.len == 6 && strncasecmp(name.s, "port-c", 6) == 0) {
		if(str2int(&value, &ipsec->port_uc) < 0) {
			LM_ERR("Failed to convert port-c to int\n");
			return -1;
		}
	} else if(name.len == 6 && strncasecmp(name.s, "port-s", 6) == 0) {
		if(str2int(&value, &ipsec->port_us) < 0) {
			LM_ERR("Failed to convert port-s to int\n");
			return -1;
		}
	}

	return 0;
}
