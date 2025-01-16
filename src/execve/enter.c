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
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "execve/execve.h"
#include "execve/elf.h"
#include "path/path.h"
#include "tracee/tracee.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "arch.h"
#include "tinyproot.h"

#define P(a) PROGRAM_FIELD(load_info->elf_header, *program_header, a)

static int add_mapping(const Tracee *tracee, LoadInfo *load_info,
		               const ProgramHeader *program_header) {
	size_t index;
	word_t start_address;
	word_t end_address;
	static word_t page_size = 0;
	static word_t page_mask = 0;

	if (page_size == 0) {
		page_size = sysconf(_SC_PAGE_SIZE);
		if ((int) page_size <= 0)
			page_size = 0x1000;
		page_mask = ~(page_size - 1);
	}

	if (load_info->mappings == NULL)
		index = 0;
	else
        index = load_info->num_mappings;

	load_info->mappings = realloc(load_info->mappings, (index + 1) * sizeof(Mapping));
	if (load_info->mappings == NULL)
		return -ENOMEM;

    load_info->num_mappings = index + 1;

	start_address = P(vaddr) & page_mask;
	end_address   = (P(vaddr) + P(filesz) + page_size) & page_mask;

	load_info->mappings[index].fd     = -1;
	load_info->mappings[index].offset = P(offset) & page_mask;
	load_info->mappings[index].addr   = start_address;
	load_info->mappings[index].length = end_address - start_address;
	load_info->mappings[index].flags  = MAP_PRIVATE | MAP_FIXED;
	load_info->mappings[index].prot   =  ( (P(flags) & PF_R ? PROT_READ  : 0)
					| (P(flags) & PF_W ? PROT_WRITE : 0)
					| (P(flags) & PF_X ? PROT_EXEC  : 0));

	if (P(memsz) > P(filesz)) {
		load_info->mappings[index].clear_length = end_address - P(vaddr) - P(filesz);

		start_address = end_address;
		end_address   = (P(vaddr) + P(memsz) + page_size) & page_mask;
		if (end_address > start_address) {
			index++;
			load_info->mappings = realloc(load_info->mappings, (index + 1) * sizeof(Mapping));
			if (load_info->mappings == NULL)
				return -ENOMEM;
            load_info->num_mappings = index + 1;

			load_info->mappings[index].fd     = -1;
			load_info->mappings[index].offset =  0;
			load_info->mappings[index].addr   = start_address;
			load_info->mappings[index].length = end_address - start_address;
			load_info->mappings[index].clear_length = 0;
			load_info->mappings[index].flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
			load_info->mappings[index].prot   = load_info->mappings[index - 1].prot;
		}
	}
	else
		load_info->mappings[index].clear_length = 0;

	return 0;
}

int translate_and_check_exec(Tracee *tracee, char host_path[PATH_MAX], const char *user_path) {
	struct stat statl;
	int status;

	if (user_path[0] == '\0')
		return -ENOEXEC;

	status = translate_path(tracee, host_path, AT_FDCWD, user_path);
	if (status < 0)
		return status;

	status = access(host_path, F_OK);
	if (status < 0)
		return -ENOENT;

	status = access(host_path, X_OK);
	if (status < 0)
		return -EACCES;

	status = lstat(host_path, &statl);
	if (status < 0)
		return -EPERM;

	return 0;
}

static int add_interp(Tracee *tracee, int fd, LoadInfo *load_info,
		              const ProgramHeader *program_header) {
    const int user_path_len = P(filesz);
	char host_path[PATH_MAX];
	char user_path[user_path_len + 1];
	int status;

	if (load_info->interp != NULL)
		return -EINVAL;

	load_info->interp = calloc(1, sizeof(LoadInfo));
	if (load_info->interp == NULL)
		return -ENOMEM;

	status = pread(fd, user_path, user_path_len, P(offset));
	if ((size_t) status != user_path_len)
		status = -EACCES;

	if (status < 0)
		return status;

	user_path[user_path_len] = '\0';

	status = translate_and_check_exec(tracee, host_path, user_path);
	if (status < 0)
		return status;

	load_info->interp->host_path = strdup(host_path);
	if (load_info->interp->host_path == NULL)
		return -ENOMEM;

	load_info->interp->user_path = strdup(user_path);
	if (load_info->interp->user_path == NULL)
		return -ENOMEM;

	return 0;
}

#undef P

struct add_load_info_data {
	LoadInfo *load_info;
	Tracee *tracee;
	int fd;
};

static int add_load_info(const ElfHeader *elf_header,
			             const ProgramHeader *program_header, void *data_) {
	struct add_load_info_data *data = data_;
	int status;

    switch (PROGRAM_FIELD(*elf_header, *program_header, type)) {
        case PT_LOAD:
            status = add_mapping(data->tracee, data->load_info, program_header);
            if (status < 0)
                return status;
            break;

        case PT_INTERP:
            status = add_interp(data->tracee, data->fd, data->load_info, program_header);
            if (status < 0)
                return status;
            break;

        case PT_GNU_STACK:
            data->load_info->needs_executable_stack |=
                    ((PROGRAM_FIELD(*elf_header, *program_header, flags) & PF_X) != 0);
            break;

        default:
            break;
    }

	return 0;
}

static int extract_load_info(Tracee *tracee, LoadInfo *load_info) {
	struct add_load_info_data data;
	int fd;
	int status;

	assert(load_info != NULL);
	assert(load_info->host_path != NULL);

	fd = open_elf(load_info->host_path, &load_info->elf_header);
	if (fd < 0)
		return fd;

    switch (ELF_FIELD(load_info->elf_header, type)) {
        case ET_EXEC:
        case ET_DYN:
            break;

        default:
            status = -EINVAL;
            goto end;
    }

	data.load_info = load_info;
	data.tracee    = tracee;
	data.fd        = fd;

	status = iterate_program_headers(tracee, fd, &load_info->elf_header, add_load_info, &data);

end:
    close(fd);
	return status;
}

static void add_load_base(LoadInfo *load_info, word_t load_base) {
	size_t i;

	for (i = 0; i < load_info->num_mappings; i++)
		load_info->mappings[i].addr += load_base;

	if (IS_CLASS64(load_info->elf_header))
		load_info->elf_header.class64.e_entry += load_base;
	else
		load_info->elf_header.class32.e_entry += load_base;
}

static void compute_load_addresses(Tracee *tracee) {
	if (IS_POSITION_INDENPENDANT(tracee->load_info->elf_header)
	    && tracee->load_info->mappings[0].addr == 0) {
		if (IS_CLASS32(tracee->load_info->elf_header))
			add_load_base(tracee->load_info, EXEC_PIC_ADDRESS_32);
		else
		    add_load_base(tracee->load_info, EXEC_PIC_ADDRESS);
	}

	if (tracee->load_info->interp == NULL)
		return;

	if (IS_POSITION_INDENPENDANT(tracee->load_info->interp->elf_header)
	    && tracee->load_info->interp->mappings[0].addr == 0) {
		if (IS_CLASS32(tracee->load_info->elf_header))
			add_load_base(tracee->load_info->interp, INTERP_PIC_ADDRESS_32);
		else
		    add_load_base(tracee->load_info->interp, INTERP_PIC_ADDRESS);
	}
}

int translate_execve_enter(Tracee *tracee) {
	char user_path[PATH_MAX];
	char host_path[PATH_MAX];
	const char *loader_path;
	int status;

	if (IS_NOTIFICATION_PTRACED_LOAD_DONE(tracee)) {
		tracee->as_ptracee.ignore_loader_syscalls = false;

		set_sysnum(tracee, PR_void);
		return 0;
	}

	status = get_sysarg_path(tracee, user_path, SYSARG_1);
	if (status < 0)
		return status;

    status = translate_and_check_exec(tracee, host_path, user_path);
    if (status < 0)
        return status;

    MEMFREE(tracee->exe);
    tracee->exe = strdup(user_path);

	MEMFREE(tracee->load_info);

	tracee->load_info = calloc(1, sizeof(LoadInfo));
	if (tracee->load_info == NULL)
		return -ENOMEM;

	tracee->load_info->host_path = strdup(host_path);
	if (tracee->load_info->host_path == NULL)
		return -ENOMEM;

	tracee->load_info->user_path = strdup(user_path);
	if (tracee->load_info->user_path == NULL)
		return -ENOMEM;

	status = extract_load_info(tracee, tracee->load_info);
	if (status < 0)
		return status;

	if (tracee->load_info->interp != NULL) {
		status = extract_load_info(tracee, tracee->load_info->interp);
		if (status < 0)
			return status;

		if (tracee->load_info->interp->interp != NULL) {
			MEMFREE(tracee->load_info->interp->interp);
			return -EINVAL;
		}
	}

	compute_load_addresses(tracee);

	loader_path = getenv("TINYPROOT_LOADER");
	if (loader_path == NULL)
		return -ENOENT;

	status = set_sysarg_path(tracee, loader_path, SYSARG_1);
	if (status < 0)
		return status;

	tracee->as_ptracee.ignore_loader_syscalls = true;

	return 0;
}
