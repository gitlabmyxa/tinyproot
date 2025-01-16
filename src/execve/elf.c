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

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "execve/elf.h"
#include "tracee/tracee.h"
#include "tinyproot.h"
#include "arch.h"

int open_elf(const char *t_path, ElfHeader *elf_header) {
	int fd;
	int status;

	fd = open(t_path, O_RDONLY);
	if (fd < 0)
		return -errno;

	status = read(fd, elf_header, sizeof(ElfHeader));
	if (status < 0) {
		status = -errno;
		goto end;
	}

	if ((size_t) status < sizeof(ElfHeader)
	    || ELF_IDENT(*elf_header, 0) != 0x7f
	    || ELF_IDENT(*elf_header, 1) != 'E'
	    || ELF_IDENT(*elf_header, 2) != 'L'
	    || ELF_IDENT(*elf_header, 3) != 'F') {
		status = -ENOEXEC;
		goto end;
	}

	if (   !IS_CLASS32(*elf_header)
	    && !IS_CLASS64(*elf_header)) {
		status = -ENOEXEC;
		goto end;
	}

	status = 0;
end:
	if (status < 0) {
		close(fd);
		return status;
	}

	return fd;
}

int iterate_program_headers(const Tracee *tracee, int fd, const ElfHeader *elf_header,
			                program_headers_iterator_t callback, void *data) {
	ProgramHeader program_header;

	uint64_t elf_phoff;
	uint16_t elf_phentsize;
	uint16_t elf_phnum;

	int status;
	int i;

	elf_phnum     = ELF_FIELD(*elf_header, phnum);
	elf_phentsize = ELF_FIELD(*elf_header, phentsize);
	elf_phoff     = ELF_FIELD(*elf_header, phoff);

	if (elf_phnum >= 0xffff) {
		note(tracee, WARNING, "%d: big PH tables are not yet supported.", fd);
		return -ENOTSUP;
	}

	if (!KNOWN_PHENTSIZE(*elf_header, elf_phentsize)) {
		note(tracee, WARNING, "%d: unsupported size of program header.", fd);
		return -ENOTSUP;
	}

	status = (int) lseek(fd, elf_phoff, SEEK_SET);
	if (status < 0)
		return -errno;

	for (i = 0; i < elf_phnum; i++) {
		status = read(fd, &program_header, elf_phentsize);
		if (status != elf_phentsize)
			return (status < 0 ? -errno : -ENOTSUP);

		status = callback(elf_header, &program_header, data);
		if (status != 0)
			return status;
	}

	return 0;
}
