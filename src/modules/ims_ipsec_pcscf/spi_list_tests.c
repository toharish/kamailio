/*
 * IMS IPSEC PCSCF module - 3GPP Rel-18 SPI List Unit Tests
 *
 * Copyright (C) 2026 Harish S <toharishs@gmail.com>
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "spi_list.h"
#include "ipsec_alg.h"
#include "sec_agree.h"
#include "cmd.h"

str ipsec_preferred_alg = {0, 0};
str ipsec_preferred_ealg = {0, 0};

static void test_spi_list_basic(void) {
	spi_list_t list;
	spi_list_init(&list);
	assert(list.count == 0);

	assert(spi_list_add(&list, 1001) == 0);
	assert(spi_list_contains(&list, 1001) == 1);
	assert(spi_list_contains(&list, 1002) == 0);
	assert(list.count == 1);

	assert(spi_list_add(&list, 1001) == 0);
	assert(list.count == 1);

	assert(spi_list_add(&list, 1002) == 0);
	assert(list.count == 2);

	assert(spi_list_remove(&list, 1001) == 1);
	assert(spi_list_contains(&list, 1001) == 0);
	assert(spi_list_contains(&list, 1002) == 1);
	assert(list.count == 1);

	spi_list_free(&list);
	assert(list.count == 0);
	printf("test_spi_list_basic PASSED\n");
}

static void test_ipsec_alg_detection(void) {
	str s_gcm = {"aes-gcm", 7};
	str s_gcm256 = {"aes-256-gcm", 11};
	str s_cbc = {"aes-cbc-128", 12};

	assert(is_aead_alg(&s_gcm) == 1);
	assert(is_aead_alg(&s_gcm256) == 1);
	assert(is_aead_alg(&s_cbc) == 0);

	str s_sha256 = {"hmac-sha-256-128", 16};
	str s_sha1 = {"hmac-sha-1-96", 13};

	assert(is_auth_trunc_alg(&s_sha256) == 1);
	assert(is_auth_trunc_alg(&s_sha1) == 0);
	printf("test_ipsec_alg_detection PASSED\n");
}

static void test_sec_agree_parsing(void) {
	ipsec_t ipsec;
	memset(&ipsec, 0, sizeof(ipsec));

	int alg_found = 0;
	int ealg_found = 0;

	str name_alg = {"alg", 3};
	str val_sha256 = {"hmac-sha-256-128", 16};

	assert(process_sec_agree_param(name_alg, val_sha256, &ipsec, &alg_found, &ealg_found) == 0);
	assert(alg_found == 1);

	str name_ealg = {"ealg", 4};
	str val_gcm = {"aes-gcm", 7};

	assert(process_sec_agree_param(name_ealg, val_gcm, &ipsec, &alg_found, &ealg_found) == 0);
	assert(ealg_found == 1);

	printf("test_sec_agree_parsing PASSED\n");
}

static void test_sa_params_changed(void) {
	ipsec_t old_sa, new_sa;
	memset(&old_sa, 0, sizeof(old_sa));
	memset(&new_sa, 0, sizeof(new_sa));

	old_sa.r_alg.s = "hmac-sha-256-128";
	old_sa.r_alg.len = 16;
	new_sa.r_alg.s = "hmac-sha-256-128";
	new_sa.r_alg.len = 16;

	old_sa.r_ealg.s = "aes-gcm";
	old_sa.r_ealg.len = 7;
	new_sa.r_ealg.s = "aes-gcm";
	new_sa.r_ealg.len = 7;

	assert(ipsec_sa_params_changed(&old_sa, &new_sa) == 0);

	new_sa.r_ealg.s = "aes-256-gcm";
	new_sa.r_ealg.len = 11;
	assert(ipsec_sa_params_changed(&old_sa, &new_sa) == 1);

	printf("test_sa_params_changed PASSED\n");
}

int main(void) {
	printf("Running ims_ipsec_pcscf 3GPP Rel-18 tests...\n");
	test_spi_list_basic();
	test_ipsec_alg_detection();
	test_sec_agree_parsing();
	test_sa_params_changed();
	printf("ALL TESTS PASSED!\n");
	return 0;
}
