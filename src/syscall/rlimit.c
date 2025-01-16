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

#include <stdbool.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "tinyproot.h"

int translate_setrlimit_exit(const Tracee *tracee, bool is_prlimit) {
	struct rlimit64 limit_stack;
	word_t resource;
	word_t address;
	word_t tracee_stack_limit;
	Reg sysarg;
	int status;

	sysarg = (is_prlimit ? SYSARG_2 : SYSARG_1);

	resource = peek_reg(tracee, ORIGINAL, sysarg);
	address  = peek_reg(tracee, ORIGINAL, sysarg + 1);

	if (resource != RLIMIT_STACK)
		return 0;

	if (is_prlimit) {
		if (address == 0)
			return 0;

		tracee_stack_limit = peek_uint64(tracee, address);
	}
	else {
		tracee_stack_limit = peek_word(tracee, address);

		if (tracee->is_aarch32 && tracee_stack_limit == (uint32_t) -1)
			tracee_stack_limit = RLIM_INFINITY;
	}

	if (errno != 0)
		return -errno;

	status = prlimit64(0, RLIMIT_STACK, NULL, &limit_stack);
	if (status < 0) {
		VERBOSE(tracee, 1, "can't get stack limit.");
		return 0;
	}

	if (limit_stack.rlim_cur >= tracee_stack_limit)
		return 0;

    limit_stack.rlim_cur = tracee_stack_limit;

	status = prlimit64(0, RLIMIT_STACK, &limit_stack, NULL);
	if (status < 0)
		VERBOSE(tracee, 1, "can't set stack limit.");
	return 0;
}
