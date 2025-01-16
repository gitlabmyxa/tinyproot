/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#ifndef TRACEE_MEM_H
#define TRACEE_MEM_H

#include <limits.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/uio.h>
#include <errno.h>

#include "arch.h"
#include "tracee/tracee.h"

extern int write_data(Tracee *tracee, word_t dst_tracee, const void *src_tracer, word_t size);
extern int writev_data(Tracee *tracee, word_t dst_tracee, const struct iovec *src_tracer, int src_tracer_count);
extern int read_data(const Tracee *tracee, void *dst_tracer, word_t src_tracee, word_t size);
extern int read_string(const Tracee *tracee, char *dst_tracer, word_t src_tracee, word_t max_size);
extern int read_pointer_array(const Tracee *tracee, word_t **dst_tracer, word_t src_tracee);
extern word_t peek_word(const Tracee *tracee, word_t address);
extern void poke_word(const Tracee *tracee, word_t address, word_t value);
extern word_t alloc_mem(Tracee *tracee, ssize_t size);

static inline int read_path(const Tracee *tracee, char dst_tracer[PATH_MAX], word_t src_tracee) {
	int status;

	status = read_string(tracee, dst_tracer, src_tracee, PATH_MAX);
	if (status < 0)
		return status;
	if (status >= PATH_MAX)
		return -ENAMETOOLONG;

	return status;
}

#define GENERATE_peek(type)							\
static inline type ## _t peek_ ## type(const Tracee *tracee, word_t address) { 	\
	type ## _t result;							\
	errno = -read_data(tracee, &result, address, sizeof(type ## _t));	\
	return result;								\
}

GENERATE_peek(uint8);
GENERATE_peek(uint16);
GENERATE_peek(uint32);
GENERATE_peek(uint64);

GENERATE_peek(int8);
GENERATE_peek(int16);
GENERATE_peek(int32);
GENERATE_peek(int64);

#undef GENERATE_peek

#define GENERATE_poke(type)							\
static inline void poke_ ## type(Tracee *tracee, word_t address, type ## _t value) { \
	errno = -write_data(tracee, address, &value, sizeof(type ## _t));	\
}

GENERATE_poke(uint8);
GENERATE_poke(uint16);
GENERATE_poke(uint32);
GENERATE_poke(uint64);

GENERATE_poke(int8);
GENERATE_poke(int16);
GENERATE_poke(int32);
GENERATE_poke(int64);

#undef GENERATE_poke

#endif /* TRACEE_MEM_H */
