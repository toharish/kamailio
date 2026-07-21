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

#include "ipsec.h"

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>

#include "../../core/dprint.h"
#include "../../core/ut.h"
#include "ipsec_alg.h"
#ifndef _IPSEC_SPI_LIST_TEST
#include "../ims_usrloc_pcscf/usrloc.h"

extern usrloc_api_t ul;
extern int ipsec_reuse_server_port;
extern int xfrm_user_selector;

#endif

#ifndef _IPSEC_SPI_LIST_TEST
extern str ipsec_listen_addr;
extern str ipsec_listen_addr6;

extern ip_addr_t ipsec_listen_ip_addr;
extern ip_addr_t ipsec_listen_ip_addr6;
#endif

void close_mnl_socket(struct mnl_socket *mnl_socket)
{
	if(mnl_socket)
		mnl_socket_close(mnl_socket);
}

struct mnl_socket *init_mnl_socket()
{
	struct mnl_socket *nl = mnl_socket_open(NETLINK_XFRM);
	if(!nl) {
		LM_ERR("Failed to open XFRM Netlink socket: %s\n", strerror(errno));
		return NULL;
	}

	if(mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		LM_ERR("Failed to bind XFRM Netlink socket: %s\n", strerror(errno));
		mnl_socket_close(nl);
		return NULL;
	}

	return nl;
}

#ifndef _IPSEC_SPI_LIST_TEST
static int get_algo(const str *alg, char *res)
{
	if(!alg || !res) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	if(alg->len == 13 && strncasecmp(alg->s, "hmac-sha-1-96", 13) == 0) {
		strcpy(res, "sha1");
	} else if(alg->len == 12 && strncasecmp(alg->s, "hmac-md5-96", 12) == 0) {
		strcpy(res, "md5");
	} else if(alg->len == 16 && strncasecmp(alg->s, "hmac-sha-256-128", 16) == 0) {
		strcpy(res, "sha256");
	} else if(alg->len == 9 && strncasecmp(alg->s, "null-auth", 9) == 0) {
		strcpy(res, "digest_null");
	} else {
		LM_ERR("Unknown algo: %.*s\n", alg->len, alg->s);
		return -1;
	}

	return 0;
}

static int get_ealgo(const str *ealg, char *res)
{
	if(!ealg || !res) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	if(ealg->len == 12 && strncasecmp(ealg->s, "aes-cbc-128", 12) == 0) {
		strcpy(res, "cbc(aes)");
	} else if(ealg->len == 10 && strncasecmp(ealg->s, "3des-cbc", 10) == 0) {
		strcpy(res, "cbc(des3_ede)");
	} else if(ealg->len == 9 && strncasecmp(ealg->s, "null-ealg", 9) == 0) {
		strcpy(res, "ecb(cipher_null)");
	} else if(ealg->len == 7 && strncasecmp(ealg->s, "aes-gcm", 7) == 0) {
		strcpy(res, "rfc4106(gcm(aes))");
	} else if(ealg->len == 11 && strncasecmp(ealg->s, "aes-256-gcm", 11) == 0) {
		strcpy(res, "rfc4106(gcm(aes))");
	} else {
		LM_ERR("Unknown ealgo: %.*s\n", ealg->len, ealg->s);
		return -1;
	}

	return 0;
}
#endif

static int hex2byte(const str *hex, unsigned char *byte, const int byte_len)
{
	if(!hex || !byte) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	if(hex->len < byte_len * 2) {
		LM_ERR("Hex string is shorter than required byte length: %d < %d\n",
				hex->len, byte_len * 2);
		return -1;
	}

	int i = 0;
	for(i = 0; i < byte_len; i++) {
		char b[3];
		b[0] = hex->s[i * 2];
		b[1] = hex->s[i * 2 + 1];
		b[2] = 0;

		byte[i] = (unsigned char)strtol(b, NULL, 16);
	}

	return 0;
}

static int add_auth_attr(struct nlmsghdr *nlh, const str *ik, const str *alg)
{
	if(!nlh || !ik || !alg) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	if (is_auth_trunc_alg(alg)) {
		return ipsec_put_auth_trunc_attr(nlh, ik, alg);
	}

	struct xfrm_algo auth_algo;
	memset(&auth_algo, 0, sizeof(auth_algo));

#ifndef _IPSEC_SPI_LIST_TEST
	if(get_algo(alg, auth_algo.alg_name) < 0) {
		return -1;
	}
#endif

	int key_bytes = 0;

	if(alg->len == 13 && strncasecmp(alg->s, "hmac-sha-1-96", 13) == 0) {
		key_bytes = 20;
	} else if(alg->len == 12 && strncasecmp(alg->s, "hmac-md5-96", 12) == 0) {
		key_bytes = 16;
	} else if(alg->len == 9 && strncasecmp(alg->s, "null-auth", 9) == 0) {
		key_bytes = 0;
	} else {
		LM_ERR("Unknown auth algorithm: %.*s\n", alg->len, alg->s);
		return -1;
	}

	auth_algo.alg_key_len = key_bytes * 8;

	if(hex2byte(ik, (unsigned char *)auth_algo.alg_key, key_bytes) < 0) {
		return -1;
	}

	mnl_attr_put(nlh, XFRMA_ALG_AUTH,
			sizeof(struct xfrm_algo) + auth_algo.alg_key_len / 8, &auth_algo);

	return 0;
}

static int add_encr_attr(
		struct nlmsghdr *nlh, const str *ck, const str *ealg, const str *ik)
{
	if(!nlh || !ck || !ealg) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	if (is_aead_alg(ealg)) {
		return ipsec_put_aead_attr(nlh, ck, ik, ealg);
	}

	struct xfrm_algo encr_algo;
	memset(&encr_algo, 0, sizeof(encr_algo));

#ifndef _IPSEC_SPI_LIST_TEST
	if(get_ealgo(ealg, encr_algo.alg_name) < 0) {
		return -1;
	}
#endif

	int key_bytes = 0;

	if(ealg->len == 12 && strncasecmp(ealg->s, "aes-cbc-128", 12) == 0) {
		key_bytes = 16;
	} else if(ealg->len == 10 && strncasecmp(ealg->s, "3des-cbc", 10) == 0) {
		key_bytes = 24;
	} else if(ealg->len == 9 && strncasecmp(ealg->s, "null-ealg", 9) == 0) {
		key_bytes = 0;
	} else {
		LM_ERR("Unknown encryption algorithm: %.*s\n", ealg->len, ealg->s);
		return -1;
	}

	encr_algo.alg_key_len = key_bytes * 8;

	if(hex2byte(ck, (unsigned char *)encr_algo.alg_key, key_bytes) < 0) {
		return -1;
	}

	mnl_attr_put(nlh, XFRMA_ALG_CRYPT,
			sizeof(struct xfrm_algo) + encr_algo.alg_key_len / 8, &encr_algo);

	return 0;
}

#ifndef _IPSEC_SPI_LIST_TEST

static int mnl_talk(struct mnl_socket *nl, struct nlmsghdr *nlh)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret = 0;

	if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("Error sending Netlink message: %s\n", strerror(errno));
		return -1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));

	while(ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_pid(nl), NULL, NULL);

		if(ret <= MNL_CB_STOP)
			break;

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	if(ret < 0) {
		LM_ERR("Error in Netlink answer: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int add_sa(struct mnl_socket *mnl_socket, const struct ip_addr *src_addr,
		const struct ip_addr *dest_addr, const unsigned short src_port,
		const unsigned short dest_port, const unsigned int spi, const str ck,
		const str ik, const str alg, const str ealg)
{
	if(!mnl_socket || !src_addr || !dest_addr) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

	struct xfrm_usersa_info *sa =
			mnl_nlmsg_put_extra_header(nlh, sizeof(struct xfrm_usersa_info));

	sa->family = src_addr->af;

	sa->id.daddr.a4 = dest_addr->u.addr16[0];
	if(sa->family == AF_INET) {
		sa->id.daddr.a4 = dest_addr->u.addr32[0];
	} else if(sa->family == AF_INET6) {
		memcpy(sa->id.daddr.a6, dest_addr->u.addr32, sizeof(sa->id.daddr.a6));
	} else {
		LM_ERR("Unsupported address family: %d\n", sa->family);
		return -1;
	}

	sa->id.spi = htonl(spi);

	sa->id.proto = IPPROTO_ESP;

	sa->saddr.a4 = src_addr->u.addr16[0];
	if(sa->family == AF_INET) {
		sa->saddr.a4 = src_addr->u.addr32[0];
	} else if(sa->family == AF_INET6) {
		memcpy(sa->saddr.a6, src_addr->u.addr32, sizeof(sa->saddr.a6));
	} else {
		LM_ERR("Unsupported address family: %d\n", sa->family);
		return -1;
	}

	sa->lft.soft_byte_limit = XFRM_INF;
	sa->lft.hard_byte_limit = XFRM_INF;
	sa->lft.soft_packet_limit = XFRM_INF;
	sa->lft.hard_packet_limit = XFRM_INF;

	sa->mode = XFRM_MODE_TRANSPORT;

	sa->reqid = xfrm_user_selector;

	if(add_encr_attr(nlh, &ck, &ealg, &ik) < 0) {
		return -1;
	}

	if (!is_aead_alg(&ealg)) {
		if(add_auth_attr(nlh, &ik, &alg) < 0) {
			return -1;
		}
	}

	struct xfrm_encap_tmpl tmpl;
	memset(&tmpl, 0, sizeof(tmpl));

	tmpl.encap_type = UDP_ENCAP_ESPINUDP;
	tmpl.encap_sport = htons(src_port);
	tmpl.encap_dport = htons(dest_port);

	mnl_attr_put(nlh, XFRMA_ENCAP, sizeof(tmpl), &tmpl);

	return mnl_talk(mnl_socket, nlh);
}

int delete_sa(struct mnl_socket *mnl_socket, const struct ip_addr *dest_addr,
		const unsigned int spi)
{
	if(!mnl_socket || !dest_addr) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct xfrm_usersa_id *sa =
			mnl_nlmsg_put_extra_header(nlh, sizeof(struct xfrm_usersa_id));

	sa->family = dest_addr->af;

	if(sa->family == AF_INET) {
		sa->daddr.a4 = dest_addr->u.addr32[0];
	} else if(sa->family == AF_INET6) {
		memcpy(sa->daddr.a6, dest_addr->u.addr32, sizeof(sa->daddr.a6));
	} else {
		LM_ERR("Unsupported address family: %d\n", sa->family);
		return -1;
	}

	sa->spi = htonl(spi);
	sa->proto = IPPROTO_ESP;

	return mnl_talk(mnl_socket, nlh);
}

int add_policy(struct mnl_socket *mnl_socket, const struct ip_addr *src_addr,
		const struct ip_addr *dest_addr, const unsigned short src_port,
		const unsigned short dest_port, const unsigned int spi,
		const enum ipsec_policy_direction dir)
{
	if(!mnl_socket || !src_addr || !dest_addr) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_NEWPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

	struct xfrm_userpolicy_info *pol = mnl_nlmsg_put_extra_header(
			nlh, sizeof(struct xfrm_userpolicy_info));

	pol->sel.family = src_addr->af;

	if(pol->sel.family == AF_INET) {
		pol->sel.saddr.a4 = src_addr->u.addr32[0];
		pol->sel.daddr.a4 = dest_addr->u.addr32[0];
		pol->sel.prefixlen_s = 32;
		pol->sel.prefixlen_d = 32;
	} else if(pol->sel.family == AF_INET6) {
		memcpy(pol->sel.saddr.a6, src_addr->u.addr32,
				sizeof(pol->sel.saddr.a6));
		memcpy(pol->sel.daddr.a6, dest_addr->u.addr32,
				sizeof(pol->sel.daddr.a6));
		pol->sel.prefixlen_s = 128;
		pol->sel.prefixlen_d = 128;
	} else {
		LM_ERR("Unsupported address family: %d\n", pol->sel.family);
		return -1;
	}

	pol->sel.dport = htons(dest_port);

	pol->sel.dport_mask = 0xffff;

	pol->sel.sport = htons(src_port);

	pol->sel.sport_mask = 0xffff;

	pol->sel.proto = IPPROTO_UDP;

	pol->lft.soft_byte_limit = XFRM_INF;
	pol->lft.hard_byte_limit = XFRM_INF;
	pol->lft.soft_packet_limit = XFRM_INF;
	pol->lft.hard_packet_limit = XFRM_INF;

	pol->dir = dir;

	struct xfrm_user_tmpl tmpl;
	memset(&tmpl, 0, sizeof(tmpl));

	tmpl.id.daddr.a4 = dest_addr->u.addr16[0];

	if(pol->sel.family == AF_INET) {
		tmpl.id.daddr.a4 = dest_addr->u.addr32[0];
		tmpl.saddr.a4 = src_addr->u.addr32[0];
	} else if(pol->sel.family == AF_INET6) {
		memcpy(tmpl.id.daddr.a6, dest_addr->u.addr32,
				sizeof(tmpl.id.daddr.a6));
		memcpy(tmpl.saddr.a6, src_addr->u.addr32, sizeof(tmpl.saddr.a6));
	} else {
		LM_ERR("Unsupported address family: %d\n", pol->sel.family);
		return -1;
	}

	tmpl.id.spi = htonl(spi);
	tmpl.id.proto = IPPROTO_ESP;

	tmpl.family = src_addr->af;

	tmpl.mode = XFRM_MODE_TRANSPORT;
	tmpl.reqid = xfrm_user_selector;
	tmpl.aalgos = ~0;
	tmpl.ealgos = ~0;

	mnl_attr_put(nlh, XFRMA_TMPL, sizeof(tmpl), &tmpl);

	return mnl_talk(mnl_socket, nlh);
}

int delete_policy(struct mnl_socket *mnl_socket,
		const struct ip_addr *src_addr, const struct ip_addr *dest_addr,
		const unsigned short src_port, const unsigned short dest_port,
		const enum ipsec_policy_direction dir)
{
	if(!mnl_socket || !src_addr || !dest_addr) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_DELPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct xfrm_userpolicy_id *pol = mnl_nlmsg_put_extra_header(
			nlh, sizeof(struct xfrm_userpolicy_id));

	pol->sel.family = src_addr->af;

	if(pol->sel.family == AF_INET) {
		pol->sel.saddr.a4 = src_addr->u.addr32[0];
		pol->sel.daddr.a4 = dest_addr->u.addr32[0];
		pol->sel.prefixlen_s = 32;
		pol->sel.prefixlen_d = 32;
	} else if(pol->sel.family == AF_INET6) {
		memcpy(pol->sel.saddr.a6, src_addr->u.addr32,
				sizeof(pol->sel.saddr.a6));
		memcpy(pol->sel.daddr.a6, dest_addr->u.addr32,
				sizeof(pol->sel.daddr.a6));
		pol->sel.prefixlen_s = 128;
		pol->sel.prefixlen_d = 128;
	} else {
		LM_ERR("Unsupported address family: %d\n", pol->sel.family);
		return -1;
	}

	pol->sel.dport = htons(dest_port);
	pol->sel.dport_mask = 0xffff;

	pol->sel.sport = htons(src_port);
	pol->sel.sport_mask = 0xffff;

	pol->sel.proto = IPPROTO_UDP;

	pol->dir = dir;

	return mnl_talk(mnl_socket, nlh);
}

static int dump_cb(const struct nlmsghdr *nlh, void *data)
{
	struct xfrm_userpolicy_info *pol = mnl_nlmsg_get_payload(nlh);

	struct mnl_socket *nl = data;

	if(pol->reqid != xfrm_user_selector)
		return MNL_CB_OK;

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *del_nlh = mnl_nlmsg_put_header(buf);
	del_nlh->nlmsg_type = XFRM_MSG_DELPOLICY;
	del_nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct xfrm_userpolicy_id *del_pol = mnl_nlmsg_put_extra_header(
			del_nlh, sizeof(struct xfrm_userpolicy_id));

	del_pol->dir = pol->dir;
	del_pol->index = pol->index;

	mnl_talk(nl, del_nlh);

	return MNL_CB_OK;
}

int clean_policy(struct mnl_socket *mnl_socket)
{
	if(!mnl_socket) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_GETPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	if(mnl_socket_sendto(mnl_socket, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("Error sending Netlink message: %s\n", strerror(errno));
		return -1;
	}

	int ret = mnl_socket_recvfrom(mnl_socket, buf, sizeof(buf));

	while(ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_pid(mnl_socket), dump_cb,
				mnl_socket);

		if(ret <= MNL_CB_STOP)
			break;

		ret = mnl_socket_recvfrom(mnl_socket, buf, sizeof(buf));
	}

	if(ret < 0) {
		LM_ERR("Error in Netlink answer: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int dump_sa_cb(const struct nlmsghdr *nlh, void *data)
{
	struct xfrm_usersa_info *sa = mnl_nlmsg_get_payload(nlh);

	struct mnl_socket *nl = data;

	if(sa->reqid != xfrm_user_selector)
		return MNL_CB_OK;

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *del_nlh = mnl_nlmsg_put_header(buf);
	del_nlh->nlmsg_type = XFRM_MSG_DELSA;
	del_nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct xfrm_usersa_id *del_sa =
			mnl_nlmsg_put_extra_header(del_nlh, sizeof(struct xfrm_usersa_id));

	del_sa->family = sa->family;
	del_sa->daddr = sa->id.daddr;
	del_sa->spi = sa->id.spi;
	del_sa->proto = sa->id.proto;

	mnl_talk(nl, del_nlh);

	return MNL_CB_OK;
}

int clean_sa(struct mnl_socket *mnl_socket)
{
	if(!mnl_socket) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_GETSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	if(mnl_socket_sendto(mnl_socket, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("Error sending Netlink message: %s\n", strerror(errno));
		return -1;
	}

	int ret = mnl_socket_recvfrom(mnl_socket, buf, sizeof(buf));

	while(ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_pid(mnl_socket),
				dump_sa_cb, mnl_socket);

		if(ret <= MNL_CB_STOP)
			break;

		ret = mnl_socket_recvfrom(mnl_socket, buf, sizeof(buf));
	}

	if(ret < 0) {
		LM_ERR("Error in Netlink answer: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int dump_sa_for_delete_cb(const struct nlmsghdr *nlh, void *data)
{
	struct xfrm_usersa_info *sa = mnl_nlmsg_get_payload(nlh);

	struct delete_sa_data *del_data = data;

	LM_DBG("comparing reqid: %d <-> %d, family: %d <-> %d\n", sa->reqid,
			xfrm_user_selector, sa->family, del_data->dest_ip_addr.af);

	if(sa->reqid != xfrm_user_selector)
		return MNL_CB_OK;

	if(sa->family != del_data->dest_ip_addr.af)
		return MNL_CB_OK;

	int daddr_match = 0;
	if(sa->family == AF_INET) {
		if(sa->id.daddr.a4 == del_data->dest_ip_addr.u.addr32[0]) {
			daddr_match = 1;
		}
	} else if(sa->family == AF_INET6) {
		if(memcmp(sa->id.daddr.a6, del_data->dest_ip_addr.u.addr32,
				   sizeof(sa->id.daddr.a6))
				== 0) {
			daddr_match = 1;
		}
	}

	if(!daddr_match)
		return MNL_CB_OK;

	LM_DBG("found SA to delete: daddr_match: %d, spi: %u\n", daddr_match,
			ntohl(sa->id.spi));

	if(ntohl(sa->id.spi) != del_data->ipsec->spi_pc
			&& ntohl(sa->id.spi) != del_data->ipsec->spi_ps
			&& ntohl(sa->id.spi) != del_data->ipsec->spi_uc
			&& ntohl(sa->id.spi) != del_data->ipsec->spi_us) {
		LM_DBG("SA SPI %u doesn't match any of the contact's SPIs: "
			   "spi_pc: %u, spi_ps: %u, spi_uc: %u, spi_us: %u\n",
				ntohl(sa->id.spi), del_data->ipsec->spi_pc,
				del_data->ipsec->spi_ps, del_data->ipsec->spi_uc,
				del_data->ipsec->spi_us);
		return MNL_CB_OK;
	}

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *del_nlh = mnl_nlmsg_put_header(buf);
	del_nlh->nlmsg_type = XFRM_MSG_DELSA;
	del_nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct xfrm_usersa_id *del_sa =
			mnl_nlmsg_put_extra_header(del_nlh, sizeof(struct xfrm_usersa_id));

	del_sa->family = sa->family;
	del_sa->daddr = sa->id.daddr;
	del_sa->spi = sa->id.spi;
	del_sa->proto = sa->id.proto;

	mnl_talk(del_data->mnl_socket, del_nlh);

	return MNL_CB_OK;
}

static int dump_policy_for_delete_cb(const struct nlmsghdr *nlh, void *data)
{
	struct xfrm_userpolicy_info *pol = mnl_nlmsg_get_payload(nlh);

	struct delete_policy_data *del_data = data;

	LM_DBG("comparing reqid: %d <-> %d, family: %d <-> %d, sport: %d, "
		   "dport: %d\n",
			pol->reqid, xfrm_user_selector, pol->sel.family,
			del_data->dest_ip_addr.af, ntohs(pol->sel.sport),
			ntohs(pol->sel.dport));

	if(pol->reqid != xfrm_user_selector)
		return MNL_CB_OK;

	if(pol->sel.family != del_data->dest_ip_addr.af)
		return MNL_CB_OK;

	int match = 0;

	// Check if this policy matches any of the combinations in delete_sa_set
	if(del_data->dest_ip_addr.af == AF_INET) {
		if(pol->sel.saddr.a4 == del_data->local_ip_addr.u.addr32[0]
				&& pol->sel.daddr.a4 == del_data->dest_ip_addr.u.addr32[0]) {
			match = 1;
		} else if(pol->sel.saddr.a4 == del_data->dest_ip_addr.u.addr32[0]
				  && pol->sel.daddr.a4
						  == del_data->local_ip_addr.u.addr32[0]) {
			match = 1;
		}
	} else if(del_data->dest_ip_addr.af == AF_INET6) {
		if(memcmp(pol->sel.saddr.a6, del_data->local_ip_addr.u.addr32,
				   sizeof(pol->sel.saddr.a6))
						== 0
				&& memcmp(pol->sel.daddr.a6, del_data->dest_ip_addr.u.addr32,
						   sizeof(pol->sel.daddr.a6))
						== 0) {
			match = 1;
		} else if(memcmp(pol->sel.saddr.a6, del_data->dest_ip_addr.u.addr32,
						  sizeof(pol->sel.saddr.a6))
						== 0
				&& memcmp(pol->sel.daddr.a6, del_data->local_ip_addr.u.addr32,
						   sizeof(pol->sel.daddr.a6))
						== 0) {
			match = 1;
		}
	}

	if(!match)
		return MNL_CB_OK;

	// Check if the ports match any of the combinations
	unsigned short sport = ntohs(pol->sel.sport);
	unsigned short dport = ntohs(pol->sel.dport);

	match = 0;
	if((sport == del_data->ipsec->port_uc
			   && dport == del_data->ipsec->port_ps)
			|| (sport == del_data->ipsec->port_pc
					&& dport == del_data->ipsec->port_us)
			|| (sport == del_data->ipsec->port_ps
					&& dport == del_data->ipsec->port_uc)
			|| (sport == del_data->ipsec->port_us
					&& dport == del_data->ipsec->port_pc)
			|| (sport == del_data->ipsec->port_uc
					&& dport == del_data->ipsec->port_pc)
			|| (sport == del_data->ipsec->port_pc
					&& dport == del_data->ipsec->port_uc)
			|| (sport == del_data->ipsec->port_ps
					&& dport == del_data->ipsec->port_us)
			|| (sport == del_data->ipsec->port_us
					&& dport == del_data->ipsec->port_ps)) {
		match = 1;
	}

	if(!match)
		return MNL_CB_OK;

	LM_DBG("found policy to delete: match: %d, dir: %d, index: %u\n", match,
			pol->dir, pol->index);

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *del_nlh = mnl_nlmsg_put_header(buf);
	del_nlh->nlmsg_type = XFRM_MSG_DELPOLICY;
	del_nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct xfrm_userpolicy_id *del_pol = mnl_nlmsg_put_extra_header(
			del_nlh, sizeof(struct xfrm_userpolicy_id));

	del_pol->dir = pol->dir;
	del_pol->index = pol->index;

	mnl_talk(del_data->mnl_socket, del_nlh);

	return MNL_CB_OK;
}

int delete_sa_set(struct mnl_socket *mnl_socket, ip_addr_t *proxy_ip_addr,
		str remote_addr, ipsec_t *s)
{

	if(!mnl_socket || !proxy_ip_addr || !s) {
		LM_ERR("Called with NULL ptr\n");
		return -1;
	}

	struct ip_addr dest_ip_addr;
	if(str2ipxbuf(&remote_addr, &dest_ip_addr) < 0) {
		LM_ERR("Error getting AF from remote_addr\n");
		return -1;
	}

	if(dest_ip_addr.af != proxy_ip_addr->af) {
		LM_DBG("Skipping SA delete: dest_ip_addr.af: %d != proxy_ip_addr.af: "
			   "%d\n",
				dest_ip_addr.af, proxy_ip_addr->af);
		return 0;
	}

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_GETSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	if(mnl_socket_sendto(mnl_socket, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("Error sending Netlink message: %s\n", strerror(errno));
		return -1;
	}

	struct delete_sa_data del_sa_data;
	del_sa_data.mnl_socket = mnl_socket;
	del_sa_data.dest_ip_addr = dest_ip_addr;
	del_sa_data.ipsec = s;

	int ret = mnl_socket_recvfrom(mnl_socket, buf, sizeof(buf));

	while(ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_pid(mnl_socket),
				dump_sa_for_delete_cb, &del_sa_data);

		if(ret <= MNL_CB_STOP)
			break;

		ret = mnl_socket_recvfrom(mnl_socket, buf, sizeof(buf));
	}

	if(ret < 0) {
		LM_ERR("Error in Netlink answer: %s\n", strerror(errno));
		return -1;
	}

	// Delete policies
	memset(buf, 0, sizeof(buf));

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_GETPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	if(mnl_socket_sendto(mnl_socket, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("Error sending Netlink message: %s\n", strerror(errno));
		return -1;
	}

	struct delete_policy_data del_pol_data;
	del_pol_data.mnl_socket = mnl_socket;
	del_pol_data.dest_ip_addr = dest_ip_addr;
	del_pol_data.local_ip_addr = *proxy_ip_addr;
	del_pol_data.ipsec = s;

	ret = mnl_socket_recvfrom(mnl_socket, buf, sizeof(buf));

	while(ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_pid(mnl_socket),
				dump_policy_for_delete_cb, &del_pol_data);

		if(ret <= MNL_CB_STOP)
			break;

		ret = mnl_socket_recvfrom(mnl_socket, buf, sizeof(buf));
	}

	if(ret < 0) {
		LM_ERR("Error in Netlink answer: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int delete_unused_sa_cb(const struct nlmsghdr *nlh, void *data)
{
	struct xfrm_usersa_info *sa = mnl_nlmsg_get_payload(nlh);

	struct delete_unused_sa_data *del_data = data;

	if(sa->reqid != xfrm_user_selector)
		return MNL_CB_OK;

	ip_addr_t *proxy_ip_addr = NULL;

	if(sa->family == AF_INET) {
		proxy_ip_addr = &ipsec_listen_ip_addr;
	} else if(sa->family == AF_INET6) {
		proxy_ip_addr = &ipsec_listen_ip_addr6;
	} else {
		LM_ERR("Unsupported address family: %d\n", sa->family);
		return MNL_CB_OK;
	}

	struct ip_addr received_host_addr;

	int match = 0;
	int i = 0;
	for(i = 0; i < del_data->ucontacts_count; i++) {
		str received_host = del_data->ucontacts[i].received_host;
		if(str2ipxbuf(&received_host, &received_host_addr) < 0) {
			LM_ERR("Error getting AF from received_host\n");
			continue;
		}

		if(sa->family != received_host_addr.af)
			continue;

		int daddr_match = 0;
		if(sa->family == AF_INET) {
			if(sa->id.daddr.a4 == received_host_addr.u.addr32[0]) {
				daddr_match = 1;
			}
		} else if(sa->family == AF_INET6) {
			if(memcmp(sa->id.daddr.a6, received_host_addr.u.addr32,
					   sizeof(sa->id.daddr.a6))
					== 0) {
				daddr_match = 1;
			}
		}

		if(!daddr_match)
			continue;

		LM_DBG("found SA: daddr_match: %d, spi: %u\n", daddr_match,
				ntohl(sa->id.spi));

		ipsec_t *s = del_data->ucontacts[i].security_temp->data.ipsec;

		if(ntohl(sa->id.spi) == s->spi_pc || ntohl(sa->id.spi) == s->spi_ps
				|| ntohl(sa->id.spi) == s->spi_uc
				|| ntohl(sa->id.spi) == s->spi_us) {
			LM_DBG("SA SPI %u matches one of the contact's SPIs: spi_pc: %u, "
				   "spi_ps: %u, spi_uc: %u, spi_us: %u\n",
					ntohl(sa->id.spi), s->spi_pc, s->spi_ps, s->spi_uc,
					s->spi_us);
			match = 1;
			break;
		}
	}

	if(match)
		return MNL_CB_OK;

	LM_INFO("Deleting unused SA: spi: %u, daddr: %u\n", ntohl(sa->id.spi),
			sa->id.daddr.a4);

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *del_nlh = mnl_nlmsg_put_header(buf);
	del_nlh->nlmsg_type = XFRM_MSG_DELSA;
	del_nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct xfrm_usersa_id *del_sa =
			mnl_nlmsg_put_extra_header(del_nlh, sizeof(struct xfrm_usersa_id));

	del_sa->family = sa->family;
	del_sa->daddr = sa->id.daddr;
	del_sa->spi = sa->id.spi;
	del_sa->proto = sa->id.proto;

	mnl_talk(del_data->mnl_socket, del_nlh);

	return MNL_CB_OK;
}

static int delete_unused_policy_cb(const struct nlmsghdr *nlh, void *data)
{
	struct xfrm_userpolicy_info *pol = mnl_nlmsg_get_payload(nlh);

	struct delete_unused_sa_data *del_data = data;

	if(pol->reqid != xfrm_user_selector)
		return MNL_CB_OK;

	ip_addr_t *proxy_ip_addr = NULL;

	if(pol->sel.family == AF_INET) {
		proxy_ip_addr = &ipsec_listen_ip_addr;
	} else if(pol->sel.family == AF_INET6) {
		proxy_ip_addr = &ipsec_listen_ip_addr6;
	} else {
		LM_ERR("Unsupported address family: %d\n", pol->sel.family);
		return MNL_CB_OK;
	}

	struct ip_addr received_host_addr;

	int match = 0;
	int i = 0;
	for(i = 0; i < del_data->ucontacts_count; i++) {
		str received_host = del_data->ucontacts[i].received_host;
		if(str2ipxbuf(&received_host, &received_host_addr) < 0) {
			LM_ERR("Error getting AF from received_host\n");
			continue;
		}

		if(pol->sel.family != received_host_addr.af)
			continue;

		int daddr_match = 0;

		if(pol->sel.family == AF_INET) {
			if(pol->sel.saddr.a4 == proxy_ip_addr->u.addr32[0]
					&& pol->sel.daddr.a4 == received_host_addr.u.addr32[0]) {
				daddr_match = 1;
			} else if(pol->sel.saddr.a4 == received_host_addr.u.addr32[0]
					  && pol->sel.daddr.a4 == proxy_ip_addr->u.addr32[0]) {
				daddr_match = 1;
			}
		} else if(pol->sel.family == AF_INET6) {
			if(memcmp(pol->sel.saddr.a6, proxy_ip_addr->u.addr32,
					   sizeof(pol->sel.saddr.a6))
							== 0
					&& memcmp(pol->sel.daddr.a6, received_host_addr.u.addr32,
							   sizeof(pol->sel.daddr.a6))
							== 0) {
				daddr_match = 1;
			} else if(memcmp(pol->sel.saddr.a6, received_host_addr.u.addr32,
							  sizeof(pol->sel.saddr.a6))
							== 0
					&& memcmp(pol->sel.daddr.a6, proxy_ip_addr->u.addr32,
							   sizeof(pol->sel.daddr.a6))
							== 0) {
				daddr_match = 1;
			}
		}

		if(!daddr_match)
			continue;

		// Check if the ports match any of the combinations
		unsigned short sport = ntohs(pol->sel.sport);
		unsigned short dport = ntohs(pol->sel.dport);

		ipsec_t *s = del_data->ucontacts[i].security_temp->data.ipsec;

		if((sport == s->port_uc && dport == s->port_ps)
				|| (sport == s->port_pc && dport == s->port_us)
				|| (sport == s->port_ps && dport == s->port_uc)
				|| (sport == s->port_us && dport == s->port_pc)
				|| (sport == s->port_uc && dport == s->port_pc)
				|| (sport == s->port_pc && dport == s->port_uc)
				|| (sport == s->port_ps && dport == s->port_us)
				|| (sport == s->port_us && dport == s->port_ps)) {
			match = 1;
			break;
		}
	}

	if(match)
		return MNL_CB_OK;

	LM_INFO("Deleting unused Policy: dir: %d, index: %u\n", pol->dir,
			pol->index);

	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *del_nlh = mnl_nlmsg_put_header(buf);
	del_nlh->nlmsg_type = XFRM_MSG_DELPOLICY;
	del_nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct xfrm_userpolicy_id *del_pol = mnl_nlmsg_put_extra_header(
			del_nlh, sizeof(struct xfrm_userpolicy_id));

	del_pol->dir = pol->dir;
	del_pol->index = pol->index;

	mnl_talk(del_data->mnl_socket, del_nlh);

	return MNL_CB_OK;
}

int delete_unused_tunnels()
{
	struct mnl_socket *mnl_socket = init_mnl_socket();
	if(mnl_socket == NULL) {
		return -1;
	}

	int rval = 0;

	// Buffer for ucontacts
	int count = ul.get_number_of_contacts();
	if(count <= 0) {
		LM_DBG("No contacts found in usrloc - skipping delete unused "
			   "tunnels\n");
		close_mnl_socket(mnl_socket);
		return 0;
	}

	int len = count * sizeof(struct pcontact);
	struct pcontact *buf = pkg_malloc(len);
	if(!buf) {
		PKG_MEM_ERROR;
		close_mnl_socket(mnl_socket);
		return -1;
	}
	memset(buf, 0, len);

	rval = ul.get_all_ucontacts(buf, len, 0, 0, 1);
	if(rval < 0) {
		LM_ERR("Error getting all contacts from usrloc: %d\n", rval);
		pkg_free(buf);
		close_mnl_socket(mnl_socket);
		return -1;
	}

	count = rval;

	LM_DBG("Found %d contacts with IPsec parameters in usrloc\n", count);

	char mnl_buf[MNL_SOCKET_BUFFER_SIZE];
	memset(mnl_buf, 0, sizeof(mnl_buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(mnl_buf);
	nlh->nlmsg_type = XFRM_MSG_GETSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	if(mnl_socket_sendto(mnl_socket, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("Error sending Netlink message: %s\n", strerror(errno));
		pkg_free(buf);
		close_mnl_socket(mnl_socket);
		return -1;
	}

	struct delete_unused_sa_data del_unused_sa_data;
	del_unused_sa_data.mnl_socket = mnl_socket;
	del_unused_sa_data.ucontacts = buf;
	del_unused_sa_data.ucontacts_count = count;

	int ret = mnl_socket_recvfrom(mnl_socket, mnl_buf, sizeof(mnl_buf));

	while(ret > 0) {
		ret = mnl_cb_run(mnl_buf, ret, 0, mnl_socket_get_pid(mnl_socket),
				delete_unused_sa_cb, &del_unused_sa_data);

		if(ret <= MNL_CB_STOP)
			break;

		ret = mnl_socket_recvfrom(mnl_socket, mnl_buf, sizeof(mnl_buf));
	}

	if(ret < 0) {
		LM_ERR("Error in Netlink answer: %s\n", strerror(errno));
		pkg_free(buf);
		close_mnl_socket(mnl_socket);
		return -1;
	}

	// Delete unused policies
	memset(mnl_buf, 0, sizeof(mnl_buf));

	nlh = mnl_nlmsg_put_header(mnl_buf);
	nlh->nlmsg_type = XFRM_MSG_GETPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	if(mnl_socket_sendto(mnl_socket, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("Error sending Netlink message: %s\n", strerror(errno));
		pkg_free(buf);
		close_mnl_socket(mnl_socket);
		return -1;
	}

	ret = mnl_socket_recvfrom(mnl_socket, mnl_buf, sizeof(mnl_buf));

	while(ret > 0) {
		ret = mnl_cb_run(mnl_buf, ret, 0, mnl_socket_get_pid(mnl_socket),
				delete_unused_policy_cb, &del_unused_sa_data);

		if(ret <= MNL_CB_STOP)
			break;

		ret = mnl_socket_recvfrom(mnl_socket, mnl_buf, sizeof(mnl_buf));
	}

	if(ret < 0) {
		LM_ERR("Error in Netlink answer: %s\n", strerror(errno));
		pkg_free(buf);
		close_mnl_socket(mnl_socket);
		return -1;
	}

	pkg_free(buf);
	close_mnl_socket(mnl_socket);

	return 0;
}

int ipsec_cleanall()
{
	struct mnl_socket *nlsock = init_mnl_socket();
	if(nlsock == NULL) {
		return -1;
	}

	if(clean_sa(nlsock) != 0) {
		LM_ERR("Error cleaning SAs\n");
		close_mnl_socket(nlsock);
		return -1;
	}

	if(clean_policy(nlsock) != 0) {
		LM_ERR("Error cleaning policies\n");
		close_mnl_socket(nlsock);
		return -1;
	}

	close_mnl_socket(nlsock);

	/* Clean SPI list if contacts are present in usrloc */
	if(ul.get_all_ucontacts == NULL)
		return 0;

	// Buffer for ucontacts
	int count = ul.get_number_of_contacts();
	if(count <= 0) {
		LM_DBG("No contacts found in usrloc - skipping clean SPI list\n");
		return 0;
	}

	int len = count * sizeof(struct pcontact);
	struct pcontact *buf = pkg_malloc(len);
	if(!buf) {
		PKG_MEM_ERROR;
		return -1;
	}
	memset(buf, 0, len);

	int rval = ul.get_all_ucontacts(buf, len, 0, 0, 1);
	if(rval < 0) {
		LM_ERR("Error getting all contacts from usrloc: %d\n", rval);
		pkg_free(buf);
		return -1;
	}

	count = rval;

	int i = 0;
	for(i = 0; i < count; i++) {
		ipsec_t *s = buf[i].security_temp->data.ipsec;

		if(!s)
			continue;

		if(ipsec_listen_ip_addr.af) {
			release_spi(
					s->spi_pc, s->spi_ps, s->port_pc, s->port_ps);
		}
		if(ipsec_listen_ip_addr6.af) {
			release_spi(
					s->spi_pc, s->spi_ps, s->port_pc, s->port_ps);
		}
	}

	pkg_free(buf);

	return 0;
}

#endif
