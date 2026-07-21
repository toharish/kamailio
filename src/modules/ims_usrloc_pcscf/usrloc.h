/*
 * IMS USRLOC PCSCF module
 *
 * Copyright (C) 2012 Smile Communications, jason.penton@smilecoms.com
 * Copyright (C) 2012 Smile Communications, richard.good@smilecoms.com
 * Copyright (C) 2012 Smile Communications, Pty. Ltd.
 *
 * ported/maintained/improved by
 * Jason Penton (jason(dot)penton(at)smilecoms.com and
 * Richard Good (richard(dot)good(at)smilecoms.com) as part of an
 * effort to add full IMS support to Kamailio/SR using a new and
 * improved architecture
 *
 * NB: A lot of this code was originally part of OpenIMSCore,
 * FhG Fokus.
 * Copyright (C) 2004-2006 FhG Fokus
 * Thanks for great work! This is an effort to
 * break apart the various CSCF functions into logically separate
 * components. We hope this will drive wider use. We also feel
 * that in this way the architecture is more complete and thereby easier
 * to manage in the Kamailio/SR environment
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

#ifndef USRLOC_H
#define USRLOC_H

#include "../../core/qvalue.h"
#include "../../core/str.h"
#include "../../core/ip_addr.h"
#include "../../core/locking.h"
#include "../../core/parser/msg_parser.h"
#include "../../core/parser/contact/contact.h"
#include "../../core/globals.h"
#include "../../core/pt.h"
#include "hslot.h"
#include "pcontact.h"
#include "udomain.h"
#include "usrloc_api.h"

#define P_CSCF_UL_DEL_FLAG 1
#define P_CSCF_UL_SAVE_FLAG 2


extern int ul_matching_mode;

int register_p_usrloc_cb(
		struct pcontact *c, int types, p_usrloc_cb f, void *param);


typedef int (*register_ulcb_t)(
		struct pcontact *c, int types, p_usrloc_cb f, void *param);
typedef void (*lock_udomain_t)(
		udomain_t *_d, str *_host, int _port, int _proto);
typedef void (*unlock_udomain_t)(
		udomain_t *_d, str *_host, int _port, int _proto);
typedef int (*get_pcontact_t)(udomain_t *_d, pcontact_info_t *ci,
		struct pcontact **_c, int search_reversed);
typedef int (*update_pcontact_t)(
		udomain_t *_d, pcontact_info_t *ci, struct pcontact *_c);
typedef int (*update_temp_security_t)(udomain_t *_d, security_type _type,
		struct security *_s, struct pcontact *_c);
typedef int (*get_all_ucontacts_t)(
		void *buf, int len, unsigned int flags, int self, int need_ipsec);
typedef int (*get_number_of_contacts_t)();
typedef void (*on_sa_expire_t)(struct pcontact *c, int type, void *param);

typedef struct usrloc_api
{
	register_ulcb_t register_ulcb;
	lock_udomain_t lock_udomain;
	unlock_udomain_t unlock_udomain;
	get_pcontact_t get_pcontact;
	update_pcontact_t update_pcontact;
	update_temp_security_t update_temp_security;
	get_all_ucontacts_t get_all_ucontacts;
	get_number_of_contacts_t get_number_of_contacts;
	on_sa_expire_t on_sa_expire;
} usrloc_api_t;

typedef int (*bind_usrloc_t)(usrloc_api_t *api);

int bind_usrloc(usrloc_api_t *api);

#endif /* USRLOC_H */
