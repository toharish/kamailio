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

#ifndef IMS_IPSEC_PCSCF_IPSEC
#define IMS_IPSEC_PCSCF_IPSEC

#include "../../core/str.h"
#include "../../core/ip_addr.h"

#include <libmnl/libmnl.h>

#include "../../lib/ims/ims_getters.h"

enum ipsec_policy_direction
{
	IPSEC_POLICY_DIRECTION_IN = 0,
	IPSEC_POLICY_DIRECTION_OUT = 1,
	IPSEC_POLICY_DIRECTION_FWD = 2
};

struct delete_sa_data
{
	struct mnl_socket *mnl_socket;
	struct ip_addr dest_ip_addr;
	ipsec_t *ipsec;
};

struct delete_policy_data
{
	struct mnl_socket *mnl_socket;
	struct ip_addr dest_ip_addr;
	ip_addr_t local_ip_addr;
	ipsec_t *ipsec;
};

#ifndef _IPSEC_SPI_LIST_TEST
struct delete_unused_sa_data
{
	struct mnl_socket *mnl_socket;
	struct pcontact *ucontacts;
	int ucontacts_count;
};
#endif

void close_mnl_socket(struct mnl_socket *mnl_socket);
struct mnl_socket *init_mnl_socket();

int add_sa(struct mnl_socket *mnl_socket, const struct ip_addr *src_addr,
		const struct ip_addr *dest_addr, const unsigned short src_port,
		const unsigned short dest_port, const unsigned int spi, const str ck,
		const str ik, const str alg, const str ealg);

int delete_sa(struct mnl_socket *mnl_socket, const struct ip_addr *dest_addr,
		const unsigned int spi);

int add_policy(struct mnl_socket *mnl_socket, const struct ip_addr *src_addr,
		const struct ip_addr *dest_addr, const unsigned short src_port,
		const unsigned short dest_port, const unsigned int spi,
		const enum ipsec_policy_direction dir);

int delete_policy(struct mnl_socket *mnl_socket,
		const struct ip_addr *src_addr, const struct ip_addr *dest_addr,
		const unsigned short src_port, const unsigned short dest_port,
		const enum ipsec_policy_direction dir);

int delete_sa_set(struct mnl_socket *mnl_socket, ip_addr_t *proxy_ip_addr,
		str remote_addr, ipsec_t *s);

int clean_policy(struct mnl_socket *mnl_socket);
int clean_sa(struct mnl_socket *mnl_socket);

int delete_unused_tunnels();

#endif /* IMS_IPSEC_PCSCF_IPSEC */
