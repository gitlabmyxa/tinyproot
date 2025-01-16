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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "path/proc.h"
#include "tracee/tracee.h"
#include "path/path.h"
#include "tinyproot.h"

int readlink_proc(const Tracee *tracee, char result[PATH_MAX],
	 	          const char base[PATH_MAX], const char component[NAME_MAX]) {
	const Tracee *known_tracee;
	char proc_path[64];
	int status;
	pid_t pid;
    Comparison comparison;

	pid = atoi(base + strlen("/proc/"));
	if (pid == 0)
		return 0;

	status = snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
	if (status < 0 || (size_t) status >= sizeof(proc_path))
		return -EPERM;

	comparison = compare_paths(proc_path, base);
    switch (comparison) {
        case PATHS_ARE_EQUAL:
            known_tracee = get_tracee(tracee, pid, false);
            if (known_tracee == NULL)
                return 0;

#define SUBSTITUTE(name, string)                \
    do {                        \
        if (strcmp(component, #name) != 0)    \
            break;                \
                            \
        status = strlen(string);        \
        if (status >= PATH_MAX)            \
            return -EPERM;            \
                            \
        strncpy(result, string, status + 1);    \
        return 0;            \
    }                                 \
    while (0)

            SUBSTITUTE(exe, known_tracee->exe);
            SUBSTITUTE(cwd, known_tracee->cwd);
            SUBSTITUTE(root, root_path);
#undef SUBSTITUTE
            return 0;

        case PATH1_IS_PREFIX:
            break;

        default:
            return 0;
    }

	status = snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd", pid);
	if (status < 0 || (size_t) status >= sizeof(proc_path))
		return -EPERM;

	comparison = compare_paths(proc_path, base);
    if (comparison == PATHS_ARE_EQUAL) {
        char *end_ptr;

        errno = 0;
        (void) strtol(component, &end_ptr, 10);
        if (errno != 0 || end_ptr == component)
            return -EPERM;

        status = snprintf(result, PATH_MAX, "%s/%s", base, component);
        if (status < 0 || status >= PATH_MAX)
            return -EPERM;
    }

	return 0;
}

int readlink_proc2(const Tracee *tracee, char result[PATH_MAX], const char referer[PATH_MAX]) {
	char base[PATH_MAX];
	char *component;

	strcpy(base, referer);
	component = strrchr(base, '/');

	assert(component != NULL && component != base);

	component[0] = '\0';
	component++;
	if (component[0] == '\0')
		return 0;

	return readlink_proc(tracee, result, base, component);
}
