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
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <linux/prctl.h>

#define NO_LIBC_HEADER
#include "loader/script.h"
#include "arch.h"

#include "loader/assembly-arm64.h"

#ifndef MMAP_OFFSET_SHIFT
    #define MMAP_OFFSET_SHIFT 0
#endif

#define FATAL() do {						\
		SYSCALL(EXIT, 1, 182);				\
		__builtin_unreachable();			\
	} while (0)

#define unlikely(expr) __builtin_expect(!!(expr), 0)

static inline void clear(word_t start, word_t end) {
	byte_t *start_misaligned;
	byte_t *end_misaligned;

	word_t *start_aligned;
	word_t *end_aligned;

	word_t start_bytes = start % sizeof(word_t);
	word_t end_bytes   = end % sizeof(word_t);

	start_aligned = (word_t *) (start_bytes ? start + sizeof(word_t) - start_bytes : start);
	end_aligned   = (word_t *) (end - end_bytes);

	start_misaligned = (byte_t *) start;
	while (start_misaligned < (byte_t *) start_aligned)
		*start_misaligned++ = 0;

	while (start_aligned < end_aligned)
		*start_aligned++ = 0;

	end_misaligned = (byte_t *) end_aligned;
	while (end_misaligned < (byte_t *) end)
		*end_misaligned++ = 0;
}

static inline word_t basename(word_t string_) {
	byte_t *string = (byte_t *) string_;
	byte_t *cursor;

	for (cursor = string; *cursor != 0; cursor++);

	for (; *cursor != (byte_t) '/' && cursor > string; cursor--);

	if (cursor != string)
		cursor++;

	return (word_t) cursor;
}

void _start(void *cursor) {
	bool traced = false;
	bool reset_at_base = true;
	word_t at_base = 0;

	word_t fd = -1;
	word_t status;

	while (1) {
		LoadStatement *stmt = cursor;

        switch (stmt->action) {
            case LOAD_ACTION_OPEN_NEXT:
                status = SYSCALL(CLOSE, 1, fd);
                if (unlikely((int) status < 0))
                    FATAL();

            case LOAD_ACTION_OPEN:
                fd = SYSCALL(OPENAT, 4, AT_FDCWD, stmt->open.string_address, O_RDONLY, 0);

                if (unlikely((int) fd < 0))
                    FATAL();

                reset_at_base = true;

                cursor += LOAD_STATEMENT_SIZE(*stmt, open);
                break;

            case LOAD_ACTION_MMAP_FILE:
                status = SYSCALL(MMAP, 6, stmt->mmap.addr, stmt->mmap.length,
                                 stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED, fd,
                                 stmt->mmap.offset >> MMAP_OFFSET_SHIFT);
                if (unlikely(status != stmt->mmap.addr))
                    FATAL();

                if (stmt->mmap.clear_length != 0)
                    clear(stmt->mmap.addr + stmt->mmap.length - stmt->mmap.clear_length,
                          stmt->mmap.addr + stmt->mmap.length);

                if (reset_at_base) {
                    at_base = stmt->mmap.addr;
                    reset_at_base = false;
                }

                cursor += LOAD_STATEMENT_SIZE(*stmt, mmap);
                break;

            case LOAD_ACTION_MMAP_ANON:
                status = SYSCALL(MMAP, 6, stmt->mmap.addr, stmt->mmap.length,
                                 stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
                if (unlikely(status != stmt->mmap.addr))
                    FATAL();

                cursor += LOAD_STATEMENT_SIZE(*stmt, mmap);
                break;

            case LOAD_ACTION_MAKE_STACK_EXEC:
                SYSCALL(MPROTECT, 3,
                        stmt->make_stack_exec.start, 1,
                        PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN);

                cursor += LOAD_STATEMENT_SIZE(*stmt, make_stack_exec);
                break;

            case LOAD_ACTION_START_TRACED:
                traced = true;

            case LOAD_ACTION_START: {
                word_t *cursor2 = (word_t *) stmt->start.stack_pointer;
                const word_t argc = cursor2[0];
                const word_t at_execfn = cursor2[1];
                word_t name;

                status = SYSCALL(CLOSE, 1, fd);
                if (unlikely((int) status < 0))
                    FATAL();

                cursor2 += argc + 1;

                do cursor2++; while (cursor2[0] != 0);
                cursor2++;

                do {
                    switch (cursor2[0]) {
                        case AT_PHDR:
                            cursor2[1] = stmt->start.at_phdr;
                            break;
                        case AT_PHENT:
                            cursor2[1] = stmt->start.at_phent;
                            break;
                        case AT_PHNUM:
                            cursor2[1] = stmt->start.at_phnum;
                            break;
                        case AT_ENTRY:
                            cursor2[1] = stmt->start.at_entry;
                            break;
                        case AT_BASE:
                            cursor2[1] = at_base;
                            break;
                        case AT_EXECFN:
                            cursor2[1] = at_execfn;
                            break;
                        default:
                            break;
                    }
                    cursor2 += 2;
                }
                while (cursor2[0] != AT_NULL);

                name = basename(stmt->start.at_execfn);
                SYSCALL(PRCTL, 3, PR_SET_NAME, name, 0);

                if (unlikely(traced))
                    SYSCALL(EXECVE, 6, 1,
                            stmt->start.stack_pointer,
                            stmt->start.entry_point, 2, 3, 4);
                else
                    BRANCH(stmt->start.stack_pointer, stmt->start.entry_point);
                FATAL();
            }

            default:
                FATAL();
        }
	}

	FATAL();
}
