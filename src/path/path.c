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

#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>

#include "path/path.h"
#include "path/proc.h"
#include "tinyproot.h"

static bool is_proc_path(const char *path) {
    if (path[0] != '/' || path[1] != 'p' || path[2] != 'r' || path[3] != 'o' || path[4] != 'c')
        return false;
    return true;
}

static bool is_sys_path(const char *path) {
    if (path[0] != '/' || path[1] != 's' || path[2] != 'y' || path[3] != 's')
        return false;
    return true;
}

static bool is_android_storage_path(const char *path) {
    if (path[0] != '/' || path[1] != 's' || path[2] != 't' || path[3] != 'o' || path[4] != 'r' || path[5] != 'a' || path[6] != 'g' || path[7] != 'e')
        return false;
    return true;
}

static bool is_android_data_path(const char *path) {
    if (path[0] != '/' || path[1] != 'd' || path[2] != 'a' || path[3] != 't' || path[4] != 'a')
        return false;
    return true;
}

static bool is_dev_path(const char *path) {
    if (path[0] != '/' || path[1] != 'd' || path[2] != 'e' || path[3] != 'v')
        return false;
    return true;
}

static bool is_dev_shm_path(const char *path) {
    if (path[0] != '/' || path[1] != 'd' || path[2] != 'e' || path[3] != 'v' ||
        path[4] != '/' || path[5] != 's' || path[6] != 'h' || path[7] != 'm')
        return false;
    return true;
}

void join_paths(char result[PATH_MAX], const char *path1, const char *path2) {
	size_t length = path1 == root_path ? root_path_len : strlen(path1);
    strcpy(result, path1);

    if (length > 0 && result[length - 1] != '/' && path2[0] != '/') {
        strcat(result + length, "/");
        strcat(result + length, path2);
    }
    else if (length > 0 && result[length - 1] == '/' && path2[0] == '/') {
        strcat(result + length, path2 + 1);
    }
    else
        strcat(result + length, path2);
}

void chop_finality(char *path) {
	size_t length = strlen(path);

	if (path[length - 1] == '.') {
		assert(length >= 2);
		if (length == 2)
			path[length - 1] = '\0';
		else
			path[length - 2] = '\0';
	}
	else if (path[length - 1] == '/') {
		if (length > 1)
			path[length - 1] = '\0';
	}
}

int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX]) {
	char link[32];
	int status;

	status = snprintf(link, sizeof(link), "/proc/%d/fd/%d",	pid, fd);
	if (status < 0)
		return -EBADF;
	if ((size_t) status >= sizeof(link))
		return -EBADF;

	status = readlink(link, path, PATH_MAX);
	if (status < 0)
		return -EBADF;
	if (status >= PATH_MAX)
		return -ENAMETOOLONG;
	path[status] = '\0';

	return 0;
}

int translate_path(Tracee *tracee, char result[PATH_MAX], int dir_fd, const char *user_path) {
    int status;

	if (user_path[0] == '/') {
        if (is_proc_path(user_path) || is_sys_path(user_path) || is_android_storage_path(user_path) ||
            is_android_data_path(user_path)) {
            strcpy(result, user_path);
        }
        else if (is_dev_path(user_path)) {
            if (is_dev_shm_path(user_path)) {
                char path[PATH_MAX];

                strcpy(path, user_path);
                path[1] = 't';
                path[2] = 'm';
                path[3] = 'p';
                join_paths(result, root_path, path);
            }
            else
                strcpy(result, user_path);
        }
        else
            join_paths(result, root_path, user_path);

        return 0;
	}
	else if (dir_fd != AT_FDCWD) {
        char path[PATH_MAX];

		status = readlink_proc_pid_fd(tracee->pid, dir_fd, path);
		if (status < 0)
			return status;

		if (path[0] != '/')
			return -ENOTDIR;

        join_paths(result, path, user_path);
        return 0;
	}
	else {
        if (is_android_storage_path(tracee->cwd) || is_android_data_path(tracee->cwd)) {
            join_paths(result, tracee->cwd, user_path);
        }
        else {
            char path[PATH_MAX];

            join_paths(path, tracee->cwd, user_path);
            join_paths(result, root_path, path);
        }
        return 0;
    }
}

int detranslate_path(Tracee *tracee, char path[PATH_MAX], const char referrer[PATH_MAX]) {
	ssize_t new_length;

	if (path[0] != '/')
		return 0;

	if (referrer != NULL && is_proc_path(referrer)) {
        char proc_path[PATH_MAX];
        strcpy(proc_path, path);
        new_length = readlink_proc2(tracee, proc_path, referrer);

        if (new_length < 0)
            return new_length;
    }

    switch (compare_paths(root_path, path)) {
        case PATH1_IS_PREFIX:
            new_length = strlen(path) - root_path_len;
            memmove(path, path + root_path_len, new_length);

            path[new_length] = '\0';
            break;
        case PATHS_ARE_EQUAL:
            new_length = 1;
            strcpy(path, "/");
            break;
        default:
            return 0;
    }

	return new_length + 1;
}

Comparison compare_paths2(const char *path1, size_t length1, const char *path2, size_t length2) {
	size_t length_min;
	bool is_prefix;
	char sentinel;

	if (!length1 || !length2)
		return PATHS_ARE_NOT_COMPARABLE;

	if (path1[length1 - 1] == '/')
		length1--;

	if (path2[length2 - 1] == '/')
		length2--;

	if (length1 < length2) {
		length_min = length1;
		sentinel = path2[length_min];
	}
	else {
		length_min = length2;
		sentinel = path1[length_min];
	}

	if (sentinel != '/' && sentinel != '\0')
		return PATHS_ARE_NOT_COMPARABLE;

	is_prefix = (strncmp(path1, path2, length_min) == 0);

	if (!is_prefix)
		return PATHS_ARE_NOT_COMPARABLE;

	if (length1 == length2)
		return PATHS_ARE_EQUAL;
	else if (length1 < length2)
		return PATH1_IS_PREFIX;
	else if (length1 > length2)
		return PATH2_IS_PREFIX;

	return PATHS_ARE_NOT_COMPARABLE;
}

Comparison compare_paths(const char *path1, const char *path2) {
	return compare_paths2(path1, strlen(path1), path2, strlen(path2));
}

size_t substitute_path_prefix(char path[PATH_MAX], size_t old_prefix_length,
			                  const char *new_prefix, size_t new_prefix_length) {
	size_t path_length;
	size_t new_length;

	path_length = strlen(path);

	assert(old_prefix_length < PATH_MAX);
	assert(new_prefix_length < PATH_MAX);

	if (new_prefix_length == 1) {
		new_length = path_length - old_prefix_length;
		if (new_length != 0)
			memmove(path, path + old_prefix_length, new_length);
		else {
			path[0] = '/';
			new_length = 1;
		}
	}
	else if (old_prefix_length == 1) {
		new_length = new_prefix_length + path_length;
		if (new_length >= PATH_MAX)
			return -ENAMETOOLONG;

		if (path_length > 1) {
			memmove(path + new_prefix_length, path, path_length);
			memcpy(path, new_prefix, new_prefix_length);
		}
		else {
			memcpy(path, new_prefix, new_prefix_length);
			new_length = new_prefix_length;
		}
	}
	else {
		new_length = path_length - old_prefix_length + new_prefix_length;
		if (new_length >= PATH_MAX)
			return -ENAMETOOLONG;

		memmove(path + new_prefix_length,
			    path + old_prefix_length,
			    path_length - old_prefix_length);
		memcpy(path, new_prefix, new_prefix_length);
	}

	assert(new_length < PATH_MAX);
	path[new_length] = '\0';

	return new_length;
}
