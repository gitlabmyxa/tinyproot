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

#include <sys/ptrace.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/user.h>
#include <errno.h>
#include <assert.h>
#include <sys/wait.h>
#include <string.h>
#include <stdint.h>

#define __USE_GNU
#include <sys/uio.h>
#include <unistd.h>
#include <sys/mman.h>

#include "tracee/mem.h"
#include "tracee/abi.h"
#include "arch.h"
#include "tinyproot.h"

int write_data(Tracee *tracee, word_t dst_tracee, const void *src_tracer, word_t size) {
	word_t *src = (word_t *)src_tracer;
	word_t *dst = (word_t *)dst_tracee;

	int ret;

	struct iovec local;
	struct iovec remote;

	local.iov_base = src;
	local.iov_len  = size;

	remote.iov_base = dst;
	remote.iov_len  = size;

    ret = process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0);
	if ((size_t) ret == size)
		return 0;

    return -EFAULT;
}

int writev_data(Tracee *tracee, word_t dst_tracee, const struct iovec *src_tracer, int src_tracer_count) {
	size_t size;
	int ret;
	int i;

	struct iovec remote;

	for (i = 0, size = 0; i < src_tracer_count; i++)
		size += src_tracer[i].iov_len;

	remote.iov_base = (word_t *)dst_tracee;
	remote.iov_len  = size;

    ret = process_vm_writev(tracee->pid, src_tracer, src_tracer_count, &remote, 1, 0);
	if ((size_t) ret == size)
		return 0;

	for (i = 0, size = 0; i < src_tracer_count; i++) {
        ret = write_data(tracee, dst_tracee + size,
                            src_tracer[i].iov_base, src_tracer[i].iov_len);
		if (ret < 0)
			return ret;

		size += src_tracer[i].iov_len;
	}

	return 0;
}

int read_data(const Tracee *tracee, void *dst_tracer, word_t src_tracee, word_t size) {
	word_t *src  = (word_t *)src_tracee;
	word_t *dst = (word_t *)dst_tracer;

	int ret;
	struct iovec local;
	struct iovec remote;

	local.iov_base = dst;
	local.iov_len  = size;

	remote.iov_base = src;
	remote.iov_len  = size;

    ret = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
	if ((size_t) ret == size)
		return 0;

    return -EFAULT;
}

int read_string(const Tracee *tracee, char *dst_tracer, word_t src_tracee, word_t max_size) {
	word_t *src = (word_t *)src_tracee;
	word_t *dst = (word_t *)dst_tracer;

	int ret;
	size_t size;
	size_t offset;
	struct iovec local;
	struct iovec remote;

	static size_t chunk_size = 0;
	static uintptr_t chunk_mask;

	if (chunk_size == 0) {
		chunk_size = sysconf(_SC_PAGE_SIZE);
		chunk_size = (chunk_size > 0 && chunk_size < 1024 ? chunk_size : 1024);
		chunk_mask = ~(chunk_size - 1);
	}

	offset = 0;
	do {
		uintptr_t current_chunk = (src_tracee + offset) & chunk_mask;
		uintptr_t next_chunk    = current_chunk + chunk_size;

		size = next_chunk - (src_tracee + offset);
		size = (size < max_size - offset ? size : max_size - offset);

		local.iov_base = (uint8_t *)dst + offset;
		local.iov_len  = size;

		remote.iov_base = (uint8_t *)src + offset;
		remote.iov_len  = size;

        ret = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
		if ((size_t) ret != size)
            return -EFAULT;

        ret = strnlen(local.iov_base, size);
		if ((size_t) ret < size) {
			size = offset + ret + 1;
			assert(size <= max_size);
			return size;
		}

		offset += size;
	}
    while (offset < max_size);

    return -EFAULT;
}

int read_pointer_array(const Tracee *tracee, word_t **dst_tracer, word_t src_tracee) {
	word_t pointer;
	word_t *array = NULL;
    int len = 0;
    int index = 0;

	*dst_tracer = NULL;

    do {
        pointer = peek_word(tracee, src_tracee + index * sizeof_word(tracee));
        if (errno != 0)
            return -errno;

        if (pointer != 0) {
            index = len++;
            array = realloc(array, len * sizeof_word(tracee));
            if (array == NULL)
                return -ENOMEM;
            array[index] = pointer;
        }
    }
    while (pointer != 0);

	*dst_tracer = array;
	return len;
}

word_t peek_word(const Tracee *tracee, word_t address) {
	word_t result = 0;

	int ret;
	struct iovec local;
	struct iovec remote;

	local.iov_base = &result;
	local.iov_len  = sizeof_word(tracee);

	remote.iov_base = (void *)address;
	remote.iov_len  = sizeof_word(tracee);

	errno = 0;
    ret = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
	if (ret > 0)
		return result;

	errno = EFAULT;

    if (tracee->is_aarch32)
        result &= 0xFFFFFFFF;

	return result;
}

void poke_word(const Tracee *tracee, word_t address, word_t value) {
    int ret;

	struct iovec local;
	struct iovec remote;

	local.iov_base = &value;
	local.iov_len  = sizeof_word(tracee);

	remote.iov_base = (void *)address;
	remote.iov_len  = sizeof_word(tracee);

    errno = 0;
    ret = process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0);
    if (ret > 0)
        return;

    errno = EFAULT;
}

word_t alloc_mem(Tracee *tracee, ssize_t size) {
	word_t stack_pointer;

	assert(IS_IN_SYSENTER(tracee));

	stack_pointer = peek_reg(tracee, CURRENT, STACK_POINTER);

	if (stack_pointer == peek_reg(tracee, ORIGINAL, STACK_POINTER))
		size += RED_ZONE_SIZE;

	if (   (size > 0 && stack_pointer <= (word_t) size)
	    || (size < 0 && stack_pointer >= ULONG_MAX + size)) {
		note(tracee, WARNING, "integer under/overflow detected in %s",
			__FUNCTION__);
		return 0;
	}

	stack_pointer -= size;

	poke_reg(tracee, STACK_POINTER, stack_pointer);
	return stack_pointer;
}
