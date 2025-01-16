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

#include <errno.h>
#include <sys/utsname.h>
#include <linux/net.h>
#include <string.h>

#include "tinyproot.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/socket.h"
#include "syscall/chain.h"
#include "syscall/rlimit.h"
#include "execve/execve.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "tracee/seccomp.h"
#include "path/path.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "arch.h"

void translate_syscall_exit(Tracee *tracee) {
	word_t syscall_number;
	word_t syscall_result;
	int status = 0;

	if (tracee->status < 0) {
		poke_reg(tracee, SYSARG_RESULT, (word_t) tracee->status);
		return;
	}

	if (peek_reg(tracee, MODIFIED, SYSARG_NUM) == SYSCALL_AVOIDER &&
			peek_reg(tracee, ORIGINAL, SYSARG_NUM) != SYSCALL_AVOIDER) {
		poke_reg(tracee, SYSARG_RESULT, peek_reg(tracee, MODIFIED, SYSARG_RESULT));
	}

	syscall_number = get_sysnum(tracee, ORIGINAL);
	syscall_result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
    switch (syscall_number) {
        case PR_getcwd: {
            char path[PATH_MAX];
            size_t new_size;
            size_t size;
            word_t output;

            size = (size_t) peek_reg(tracee, ORIGINAL, SYSARG_2);
            if (size == 0) {
                status = -EINVAL;
                break;
            }

            status = translate_path(tracee, path, AT_FDCWD, ".");
            if (status < 0)
                break;

            new_size = strlen(tracee->cwd) + 1;
            if (size < new_size) {
                status = -ERANGE;
                break;
            }

            output = peek_reg(tracee, ORIGINAL, SYSARG_1);
            status = write_data(tracee, output, tracee->cwd, new_size);
            if (status < 0)
                break;

            status = new_size;
            break;
        }

        case PR_accept:
        case PR_accept4:
            if (peek_reg(tracee, ORIGINAL, SYSARG_2) == 0)
                return;
        case PR_getsockname:
        case PR_getpeername: {
            word_t sock_addr;
            word_t size_addr;
            word_t max_size;

            if ((int) syscall_result < 0)
                return;

            sock_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
            size_addr = peek_reg(tracee, MODIFIED, SYSARG_3);
            max_size = peek_reg(tracee, MODIFIED, SYSARG_6);

            status = translate_socketcall_exit(tracee, sock_addr, size_addr, max_size);
            if (status < 0)
                break;

            return;
        }

#define SYSARG_ADDR(n) (args_addr + ((n) - 1) * sizeof_word(tracee))

#define POKE_WORD(addr, value)            \
    poke_word(tracee, addr, value);        \
    if (errno != 0)    {            \
        status = -errno;        \
        break;                \
    }

#define PEEK_WORD(addr)                \
    peek_word(tracee, addr);        \
    if (errno != 0) {            \
        status = -errno;        \
        break;                \
    }

#undef SYSARG_ADDR
#undef PEEK_WORD
#undef POKE_WORD

        case PR_fchdir:
        case PR_chdir:
            status = 0;
            break;

        case PR_rename:
        case PR_renameat: {
            char old_path[PATH_MAX];
            char new_path[PATH_MAX];
            ssize_t old_length;
            ssize_t new_length;
            Comparison comparison;
            Reg old_reg;
            Reg new_reg;
            char *tmp;

            if ((int) syscall_result < 0)
                return;

            if (syscall_number == PR_rename) {
                old_reg = SYSARG_1;
                new_reg = SYSARG_2;
            }
            else {
                old_reg = SYSARG_2;
                new_reg = SYSARG_4;
            }

            status = read_path(tracee, old_path, peek_reg(tracee, MODIFIED, old_reg));
            if (status < 0)
                break;

            status = detranslate_path(tracee, old_path, NULL);
            if (status < 0)
                break;
            old_length = (status > 0 ? status - 1 : (ssize_t) strlen(old_path));

            comparison = compare_paths(old_path, tracee->cwd);
            if (comparison != PATH1_IS_PREFIX && comparison != PATHS_ARE_EQUAL) {
                status = 0;
                break;
            }

            status = read_path(tracee, new_path, peek_reg(tracee, MODIFIED, new_reg));
            if (status < 0)
                break;

            status = detranslate_path(tracee, new_path, NULL);
            if (status < 0)
                break;
            new_length = (status > 0 ? status - 1 : (ssize_t) strlen(new_path));

            if (strlen(tracee->cwd) >= PATH_MAX) {
                status = 0;
                break;
            }
            strcpy(old_path, tracee->cwd);

            substitute_path_prefix(old_path, old_length, new_path, new_length);

            tmp = strdup(old_path);
            if (tmp == NULL) {
                status = -ENOMEM;
                break;
            }

            MEMFREE(tracee->cwd);
            tracee->cwd = tmp;

            status = 0;
            break;
        }

        case PR_readlink:
        case PR_readlinkat: {
            char referee[PATH_MAX];
            char referer[PATH_MAX];
            size_t old_size;
            size_t new_size;
            size_t max_size;
            word_t input;
            word_t output;

            if ((int) syscall_result < 0)
                return;

            old_size = syscall_result;

            if (syscall_number == PR_readlink) {
                output = peek_reg(tracee, ORIGINAL, SYSARG_2);
                max_size = peek_reg(tracee, ORIGINAL, SYSARG_3);
                input = peek_reg(tracee, MODIFIED, SYSARG_1);
            }
            else {
                output = peek_reg(tracee, ORIGINAL, SYSARG_3);
                max_size = peek_reg(tracee, ORIGINAL, SYSARG_4);
                input = peek_reg(tracee, MODIFIED, SYSARG_2);
            }

            if (max_size > PATH_MAX)
                max_size = PATH_MAX;

            if (max_size == 0) {
                status = -EINVAL;
                break;
            }

            status = read_data(tracee, referee, output, old_size);
            if (status < 0)
                break;
            referee[old_size] = '\0';

            status = read_path(tracee, referer, input);
            if (status < 0)
                break;

            if (status >= PATH_MAX) {
                status = -ENAMETOOLONG;
                break;
            }

            if (status == 1) {
                word_t dirfd = peek_reg(tracee, ORIGINAL, SYSARG_1);
                if (syscall_number == PR_readlink || dirfd < 0) {
                    status = -EBADF;
                    break;
                }
                status = readlink_proc_pid_fd(tracee->pid, dirfd, referer);
                if (status < 0)
                    break;
            }

            status = detranslate_path(tracee, referee, referer);
            if (status < 0)
                break;

            if (status == 0)
                return;

            if ((size_t) status < max_size) {
                new_size = status - 1;
                status = write_data(tracee, output, referee, status);
            }
            else {
                new_size = max_size;
                status = write_data(tracee, output, referee, max_size);
            }

            if (status < 0)
                break;

            status = new_size;
            break;
        }

        case PR_execve:
            translate_execve_exit(tracee);
            return;

        case PR_ptrace:
            status = translate_ptrace_exit(tracee);
            break;

        case PR_wait4:
        case PR_waitpid:
            if (tracee->as_ptracer.waits_in != WAITS_IN_PROOT)
                return;

            status = translate_wait_exit(tracee);
            break;

        case PR_setrlimit:
        case PR_prlimit64:
            if ((int) syscall_result < 0)
                return;

            status = translate_setrlimit_exit(tracee, syscall_number == PR_prlimit64);
            if (status < 0)
                break;

            return;

        case PR_utime:
            if ((int) syscall_result == -ENOSYS)
                fix_and_restart_enosys_syscall(tracee);
            return;

        case PR_statfs:
        case PR_statfs64: {
            static const char tmpfs_magic[] = {0x94, 0x19, 0x02, 0x01};
            char tmpshm_path[PATH_MAX];
            char statfs_path[PATH_MAX];

            if (syscall_result != 0)
                return;

            join_paths(tmpshm_path, root_path, "/tmp/shm");

            if (read_path(tracee, statfs_path, peek_reg(tracee, MODIFIED, SYSARG_1)) < 0) {
                VERBOSE(tracee, 5, "statfs() exit couldn't read statfs_path");
                return;
            }

            Comparison comparison = compare_paths(tmpshm_path, statfs_path);
            if (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX) {
                VERBOSE(tracee, 5, "Updating statfs() result to fake tmpfs /dev/shm");

                word_t stat_addr = peek_reg(tracee, ORIGINAL,
                                            syscall_number == PR_statfs64 ? SYSARG_3 : SYSARG_2);
                int write_status = write_data(tracee, stat_addr, tmpfs_magic, 4);
                if (write_status < 0)
                    VERBOSE(tracee, 5, "Updating statfs() result failed");
            }

            return;
        }

        default:
            return;
    }

	poke_reg(tracee, SYSARG_RESULT, (word_t) status);
}
