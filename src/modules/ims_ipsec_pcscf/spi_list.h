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

#ifndef IMS_IPSEC_PCSCF_SPI_LIST
#define IMS_IPSEC_PCSCF_SPI_LIST

#include <stdint.h>
#include <stddef.h>

#define SPI_LIST_INITIAL_CAPACITY 64

typedef struct {
	uint32_t *spis;
	size_t count;
	size_t capacity;
} spi_list_t;

static inline void spi_list_init(spi_list_t *list) {
	list->spis = NULL;
	list->count = 0;
	list->capacity = 0;
}

static inline void spi_list_free(spi_list_t *list) {
	if (list->spis) {
		free(list->spis);
		list->spis = NULL;
	}
	list->count = 0;
	list->capacity = 0;
}

static inline int spi_list_contains(const spi_list_t *list, uint32_t spi) {
	if (!list || !list->spis) return 0;
	for (size_t i = 0; i < list->count; i++) {
		if (list->spis[i] == spi) return 1;
	}
	return 0;
}

static inline int spi_list_add(spi_list_t *list, uint32_t spi) {
	if (!list) return -1;
	if (spi_list_contains(list, spi)) return 0;
	if (list->count >= list->capacity) {
		size_t new_cap = (list->capacity == 0) ? SPI_LIST_INITIAL_CAPACITY : list->capacity * 2;
		uint32_t *new_spis = (uint32_t *)realloc(list->spis, new_cap * sizeof(uint32_t));
		if (!new_spis) return -1;
		list->spis = new_spis;
		list->capacity = new_cap;
	}
	list->spis[list->count++] = spi;
	return 0;
}

static inline int spi_list_remove(spi_list_t *list, uint32_t spi) {
	if (!list || !list->spis) return 0;
	for (size_t i = 0; i < list->count; i++) {
		if (list->spis[i] == spi) {
			list->spis[i] = list->spis[--list->count];
			return 1;
		}
	}
	return 0;
}

#endif /* IMS_IPSEC_PCSCF_SPI_LIST */
