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

#include <linux/auxvec.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "execve/execve.h"
#include "execve/elf.h"
#include "loader/script.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "tinyproot.h"

static void *transcript_mappings(void *cursor, const Mapping *mappings, int num_mappings) {
	size_t i;

	for (i = 0; i < num_mappings; i++) {
		LoadStatement *statement = cursor;

		if ((mappings[i].flags & MAP_ANONYMOUS) != 0)
			statement->action = LOAD_ACTION_MMAP_ANON;
		else
			statement->action = LOAD_ACTION_MMAP_FILE;

		statement->mmap.addr   = mappings[i].addr;
		statement->mmap.length = mappings[i].length;
		statement->mmap.prot   = mappings[i].prot;
		statement->mmap.offset = mappings[i].offset;
		statement->mmap.clear_length = mappings[i].clear_length;

		cursor += LOAD_STATEMENT_SIZE(*statement, mmap);
	}

	return cursor;
}

static int transfer_load_script(Tracee *tracee) {
	const word_t stack_pointer = peek_reg(tracee, CURRENT, STACK_POINTER);
	static word_t page_size = 0;
	static word_t page_mask = 0;

	word_t entry_point;

	size_t script_size;
	size_t strings_size;
	size_t string1_size;
	size_t string2_size;
	size_t padding_size;

	word_t string1_address;
	word_t string2_address;

	void *buffer;
	size_t buffer_size;

	bool needs_executable_stack;
	LoadStatement *statement;
	void *cursor;
	int status = 0;

	if (page_size == 0) {
		page_size = sysconf(_SC_PAGE_SIZE);
		if ((int) page_size <= 0)
			page_size = 0x1000;
		page_mask = ~(page_size - 1);
	}

	needs_executable_stack = (tracee->load_info->needs_executable_stack
                       || (   tracee->load_info->interp != NULL
                           && tracee->load_info->interp->needs_executable_stack));

	string1_size = strlen(tracee->load_info->user_path) + 1;

	string2_size = (tracee->load_info->interp == NULL ? 0
		   : strlen(tracee->load_info->interp->user_path) + 1);

	padding_size = (stack_pointer - string1_size - string2_size) % STACK_ALIGNMENT;

	strings_size = string1_size + string2_size + padding_size;
	string1_address = stack_pointer - strings_size;
	string2_address = stack_pointer - strings_size + string1_size;

	script_size =
		LOAD_STATEMENT_SIZE(*statement, open)
		+ (LOAD_STATEMENT_SIZE(*statement, mmap)
			* tracee->load_info->num_mappings)
		+ (tracee->load_info->interp == NULL ? 0
			: LOAD_STATEMENT_SIZE(*statement, open)
			+ (LOAD_STATEMENT_SIZE(*statement, mmap)
				* tracee->load_info->interp->num_mappings))
		+ (needs_executable_stack ? LOAD_STATEMENT_SIZE(*statement, make_stack_exec) : 0)
		+ LOAD_STATEMENT_SIZE(*statement, start);

	buffer_size = script_size + strings_size;
	buffer = calloc(buffer_size, 1);
	if (buffer == NULL)
		return -ENOMEM;

	cursor = buffer;

	statement = cursor;
	statement->action = LOAD_ACTION_OPEN;
	statement->open.string_address = string1_address;

	cursor += LOAD_STATEMENT_SIZE(*statement, open);

	cursor = transcript_mappings(cursor, tracee->load_info->mappings, tracee->load_info->num_mappings);

	if (tracee->load_info->interp != NULL) {
		statement = cursor;
		statement->action = LOAD_ACTION_OPEN_NEXT;
		statement->open.string_address = string2_address;

		cursor += LOAD_STATEMENT_SIZE(*statement, open);
		cursor = transcript_mappings(cursor, tracee->load_info->interp->mappings, tracee->load_info->interp->num_mappings);

		entry_point = ELF_FIELD(tracee->load_info->interp->elf_header, entry);
	}
	else
		entry_point = ELF_FIELD(tracee->load_info->elf_header, entry);

	if (needs_executable_stack) {
		statement = cursor;

		statement->action = LOAD_ACTION_MAKE_STACK_EXEC;
		statement->make_stack_exec.start = stack_pointer & page_mask;

		cursor += LOAD_STATEMENT_SIZE(*statement, make_stack_exec);
	}

	statement = cursor;

	if (tracee->as_ptracee.ptracer != NULL)
		statement->action = LOAD_ACTION_START_TRACED;
	else
		statement->action = LOAD_ACTION_START;

	statement->start.stack_pointer = stack_pointer;
	statement->start.entry_point   = entry_point;
	statement->start.at_phent = ELF_FIELD(tracee->load_info->elf_header, phentsize);
	statement->start.at_phnum = ELF_FIELD(tracee->load_info->elf_header, phnum);
	statement->start.at_entry = ELF_FIELD(tracee->load_info->elf_header, entry);
	statement->start.at_phdr  = ELF_FIELD(tracee->load_info->elf_header, phoff)
				                        + tracee->load_info->mappings[0].addr;
	statement->start.at_execfn = string1_address;

	cursor += LOAD_STATEMENT_SIZE(*statement, start);

	assert((uintptr_t) cursor - (uintptr_t) buffer == script_size);

	if (tracee->is_aarch32) {
		int i;
		for (i = 0; buffer + i * sizeof(uint64_t) < cursor; i++)
			((uint32_t *) buffer)[i] = ((uint64_t *) buffer)[i];
	}

	memcpy(cursor, tracee->load_info->user_path, string1_size);
	cursor += string1_size;

	if (string2_size != 0) {
		memcpy(cursor, tracee->load_info->interp->user_path, string2_size);
		cursor += string2_size;
	}

	cursor += padding_size;
	assert((uintptr_t) cursor - (uintptr_t) buffer == buffer_size);

	poke_reg(tracee, STACK_POINTER, stack_pointer - buffer_size);
	poke_reg(tracee, USERARG_1, stack_pointer - buffer_size);

	status = write_data(tracee, stack_pointer - buffer_size, buffer, buffer_size);
	if (status < 0)
        goto end;

	save_current_regs(tracee, ORIGINAL);
	tracee->uregs_were_changed = true;

end:
    MEMFREE(buffer);
	return status;
}

void translate_execve_exit(Tracee *tracee) {
	word_t syscall_result;
	int status;

	if (IS_NOTIFICATION_PTRACED_LOAD_DONE(tracee)) {
		poke_reg(tracee, SYSARG_RESULT, 0);
		set_sysnum(tracee, PR_execve);

		poke_reg(tracee, STACK_POINTER, peek_reg(tracee, ORIGINAL, SYSARG_2));
		poke_reg(tracee, INSTR_POINTER, peek_reg(tracee, ORIGINAL, SYSARG_3));
		poke_reg(tracee, RTLD_FINI, 0);
		poke_reg(tracee, STATE_FLAGS, 0);

		save_current_regs(tracee, ORIGINAL);
		tracee->uregs_were_changed = true;

		if ((tracee->as_ptracee.options & PTRACE_O_TRACEEXEC) == 0)
			kill(tracee->pid, SIGTRAP);

		return;
	}

	tracee->is_aarch32 = IS_CLASS32(tracee->load_info->elf_header);

	syscall_result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) syscall_result < 0)
		return;

	status = transfer_load_script(tracee);
	if (status < 0)
		note(tracee, ERROR, "can't transfer load script: %s", strerror(-status));
}
