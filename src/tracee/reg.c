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

#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <sys/uio.h>

#include "arch.h"

#include <linux/elf.h>

#include "syscall/sysnum.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "tinyproot.h"

#define USER_REGS_OFFSET(reg_name)			\
	(offsetof(struct user, regs)			\
	 + offsetof(struct user_regs_struct, reg_name))

#define REG(tracee, version, index)			\
	(*(word_t*) (((uint8_t *) &tracee->_regs[version]) + reg_offset[index]))

    #undef  USER_REGS_OFFSET
    #define USER_REGS_OFFSET(reg_name) offsetof(struct user_regs_struct, reg_name)
    #define USER_REGS_OFFSET_32(reg_number) ((reg_number) * 4)

    static off_t reg_offset[] = {
        [SYSARG_NUM]    = USER_REGS_OFFSET(regs[8]),
        [SYSARG_1]      = USER_REGS_OFFSET(regs[0]),
        [SYSARG_2]      = USER_REGS_OFFSET(regs[1]),
        [SYSARG_3]      = USER_REGS_OFFSET(regs[2]),
        [SYSARG_4]      = USER_REGS_OFFSET(regs[3]),
        [SYSARG_5]      = USER_REGS_OFFSET(regs[4]),
        [SYSARG_6]      = USER_REGS_OFFSET(regs[5]),
        [SYSARG_RESULT] = USER_REGS_OFFSET(regs[0]),
        [STACK_POINTER] = USER_REGS_OFFSET(sp),
        [INSTR_POINTER] = USER_REGS_OFFSET(pc),
        [USERARG_1]     = USER_REGS_OFFSET(regs[0]),
    };

    static off_t reg_offset_armeabi[] = {
        [SYSARG_NUM]    = USER_REGS_OFFSET_32(7),
        [SYSARG_1]      = USER_REGS_OFFSET_32(0),
        [SYSARG_2]      = USER_REGS_OFFSET_32(1),
        [SYSARG_3]      = USER_REGS_OFFSET_32(2),
        [SYSARG_4]      = USER_REGS_OFFSET_32(3),
        [SYSARG_5]      = USER_REGS_OFFSET_32(4),
        [SYSARG_6]      = USER_REGS_OFFSET_32(5),
        [SYSARG_RESULT] = USER_REGS_OFFSET_32(0),
        [STACK_POINTER] = USER_REGS_OFFSET_32(13),
        [INSTR_POINTER] = USER_REGS_OFFSET_32(15),
        [USERARG_1]     = USER_REGS_OFFSET_32(0),
    };

    #undef  REG
    #define REG(tracee, version, index)					\
	(*(word_t*) (tracee->is_aarch32									\
		? (((uint8_t *) &tracee->uregs[version]) + reg_offset_armeabi[index]) \
		: (((uint8_t *) &tracee->uregs[version]) + reg_offset[index])))

word_t peek_reg(const Tracee *tracee, RegVersion version, Reg reg) {
	word_t result;

	assert(version < NB_REG_VERSION);

	result = REG(tracee, version, reg);

	if (tracee->is_aarch32)
		result &= 0xFFFFFFFF;

	return result;
}

void poke_reg(Tracee *tracee, Reg reg, word_t value) {
	if (peek_reg(tracee, CURRENT, reg) == value)
		return;

	if (tracee->is_aarch32) {
		*(uint32_t *) &REG(tracee, CURRENT, reg) = value;
	}
    else
	    REG(tracee, CURRENT, reg) = value;

	tracee->uregs_were_changed = true;
}

void save_current_regs(Tracee *tracee, RegVersion version) {
	if (version == ORIGINAL)
		tracee->uregs_were_changed = false;

	memcpy(&tracee->uregs[version], &tracee->uregs[CURRENT], sizeof(tracee->uregs[CURRENT]));
}

int fetch_regs(Tracee *tracee) {
	int status;
	struct iovec regs;

	regs.iov_base = &tracee->uregs[CURRENT];
	regs.iov_len  = sizeof(tracee->uregs[CURRENT]);

	status = ptrace(PTRACE_GETREGSET, tracee->pid, NT_PRSTATUS, &regs);
	if (status < 0)
		return status;

	return 0;
}

int push_specific_regs(Tracee *tracee, bool including_sysnum) {
	int status;

	if (tracee->uregs_were_changed || (tracee->restore_original_regs && tracee->restore_original_regs_after_seccomp_event)) {
		if (tracee->restore_original_regs) {
			RegVersion restore_from = ORIGINAL;
			if (tracee->restore_original_regs_after_seccomp_event) {
				restore_from = ORIGINAL_SECCOMP_REWRITE;
				tracee->restore_original_regs_after_seccomp_event = false;
			}

#define	RESTORE(sysarg) (void) (reg_offset[SYSARG_RESULT] != reg_offset[sysarg] && \
				(REG(tracee, CURRENT, sysarg) = REG(tracee, restore_from, sysarg)))

			RESTORE(SYSARG_NUM);
			RESTORE(SYSARG_1);
			RESTORE(SYSARG_2);
			RESTORE(SYSARG_3);
			RESTORE(SYSARG_4);
			RESTORE(SYSARG_5);
			RESTORE(SYSARG_6);
			RESTORE(STACK_POINTER);
		}

		struct iovec regs;
		word_t current_sysnum = REG(tracee, CURRENT, SYSARG_NUM);

		if (including_sysnum && current_sysnum != REG(tracee, ORIGINAL, SYSARG_NUM)) {
			regs.iov_base = &current_sysnum;
			regs.iov_len = sizeof(current_sysnum);
			status = ptrace(PTRACE_SETREGSET, tracee->pid, NT_ARM_SYSTEM_CALL, &regs);
			if (status < 0)
				return status;
		}

		regs.iov_base = &tracee->uregs[CURRENT];
		regs.iov_len  = sizeof(tracee->uregs[CURRENT]);

		status = ptrace(PTRACE_SETREGSET, tracee->pid, NT_PRSTATUS, &regs);
		if (status < 0)
			return status;
	}

	return 0;
}

int push_regs(Tracee *tracee) {
	return push_specific_regs(tracee, true);
}

word_t get_systrap_size(Tracee *tracee) {
	if (tracee->is_aarch32 && (((unsigned char *) &tracee->uregs[CURRENT])[0x40] & 0x20) != 0)
		return 2;

	return SYSTRAP_SIZE;
}
