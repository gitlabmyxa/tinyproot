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

#include <assert.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

#include "syscall/syscall.h"
#include "syscall/chain.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tinyproot.h"

int get_sysarg_path(const Tracee *tracee, char path[PATH_MAX], Reg reg) {
	int size;
	word_t src;

	src = peek_reg(tracee, CURRENT, reg);

	if (src == 0) {
		path[0] = '\0';
		return 0;
	}

	size = read_path(tracee, path, src);
	if (size < 0)
		return size;

	path[size] = '\0';
	return size;
}

int set_sysarg_data(Tracee *tracee, const void *tracer_ptr, word_t size, Reg reg) {
	word_t tracee_ptr;
	int status;

	tracee_ptr = alloc_mem(tracee, size);
	if (tracee_ptr == 0)
		return -EFAULT;

	status = write_data(tracee, tracee_ptr, tracer_ptr, size);
	if (status < 0)
		return status;

	poke_reg(tracee, reg, tracee_ptr);

	return 0;
}

int set_sysarg_path(Tracee *tracee, const char path[PATH_MAX], Reg reg) {
	return set_sysarg_data(tracee, path, strlen(path) + 1, reg);
}

void translate_syscall(Tracee *tracee) {
	const bool is_enter_stage = IS_IN_SYSENTER(tracee);
	int status;

	assert(tracee->exe != NULL);

	status = fetch_regs(tracee);
	if (status < 0)
		return;

	if (is_enter_stage) {
		tracee->restore_original_regs = false;

		if (tracee->chain.syscalls == NULL) {
			save_current_regs(tracee, ORIGINAL);
			status = translate_syscall_enter(tracee);
			save_current_regs(tracee, MODIFIED);
		}
		else {
			if (tracee->chain.sysnum_workaround_state != SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL)
				status = 0;
			tracee->restart_how = PTRACE_SYSCALL;
		}

		if (status < 0) {
			set_sysnum(tracee, PR_void);
			poke_reg(tracee, SYSARG_RESULT, (word_t) status);
			tracee->status = status;
		}
		else
			tracee->status = 1;

		if (tracee->restart_how == PTRACE_CONT) {
			tracee->status = 0;
			poke_reg(tracee, STACK_POINTER, peek_reg(tracee, ORIGINAL, STACK_POINTER));
		}
	}
	else {
		tracee->restore_original_regs = true;

		if (tracee->chain.syscalls == NULL || tracee->chain.sysnum_workaround_state == SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL) {
			tracee->chain.sysnum_workaround_state = SYSNUM_WORKAROUND_INACTIVE;
			translate_syscall_exit(tracee);
		}
		else if (tracee->chain.sysnum_workaround_state == SYSNUM_WORKAROUND_PROCESS_FAULTY_CALL) {
			tracee->chain.sysnum_workaround_state = SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL;
		}

		tracee->status = 0;

		if (tracee->chain.syscalls != NULL)
			chain_next_syscall(tracee);
	}

	push_specific_regs(tracee, is_enter_stage && tracee->chain.syscalls == NULL);
}
