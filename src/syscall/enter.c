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
#include <sys/un.h>
#include <linux/net.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/prctl.h>
#include <termios.h>

#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/socket.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "execve/execve.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "path/path.h"
#include "arch.h"

static int translate_path2(Tracee *tracee, int dir_fd, char path[PATH_MAX], Reg reg) {
	char new_path[PATH_MAX];
	int status;

	if (path[0] == '\0')
		return 0;

	status = translate_path(tracee, new_path, dir_fd, path);
	if (status < 0)
		return status;

	return set_sysarg_path(tracee, new_path, reg);
}

static int translate_sysarg(Tracee *tracee, Reg reg) {
	char old_path[PATH_MAX];
	int status;

	status = get_sysarg_path(tracee, old_path, reg);
	if (status < 0)
		return status;

	return translate_path2(tracee, AT_FDCWD, old_path, reg);
}

int translate_syscall_enter(Tracee *tracee) {
	int dir_fd;
	int old_dir_fd;

	char path[PATH_MAX];
	char old_path[PATH_MAX];

    int status = 0;
	word_t syscall_number;
	bool special = false;

	syscall_number = get_sysnum(tracee, ORIGINAL);
    switch (syscall_number) {
        case PR_execve:
            status = translate_execve_enter(tracee);
            break;

        case PR_ptrace:
            status = translate_ptrace_enter(tracee);
            break;

        case PR_wait4:
        case PR_waitpid:
            translate_wait_enter(tracee);
            status = 0;
            break;

        case PR_getcwd:
            set_sysnum(tracee, PR_void);
            status = 0;
            break;

        case PR_fchdir:
        case PR_chdir: {
            struct stat statl;
            char *cwd;

            if (syscall_number == PR_chdir) {
                status = get_sysarg_path(tracee, old_path, SYSARG_1);
                if (status < 0)
                    break;

                dir_fd = AT_FDCWD;
            }
            else {
                strcpy(old_path, ".");
                dir_fd = peek_reg(tracee, CURRENT, SYSARG_1);
            }

            status = translate_path(tracee, path, dir_fd, old_path);
            if (status < 0)
                break;

            status = lstat(path, &statl);
            if (status < 0)
                return -ENOENT;

            if ((statl.st_mode & S_IXUSR) == 0)
                return -EACCES;

            if (dir_fd != AT_FDCWD) {
                status = detranslate_path(tracee, path, NULL);
                if (status < 0)
                    break;
                chop_finality(path);

                cwd = strdup(path);
            }
            else
                cwd = strdup(old_path);

            if (cwd == NULL) {
                status = -ENOMEM;
                break;
            }

            MEMFREE(tracee->cwd);
            tracee->cwd = cwd;

            set_sysnum(tracee, PR_void);
            status = 0;
            break;
        }

        case PR_bind:
        case PR_connect: {
            word_t address;
            word_t size;

            address = peek_reg(tracee, CURRENT, SYSARG_2);
            size = peek_reg(tracee, CURRENT, SYSARG_3);

            status = translate_socketcall_enter(tracee, &address, size);
            if (status <= 0)
                break;

            poke_reg(tracee, SYSARG_2, address);
            poke_reg(tracee, SYSARG_3, sizeof(struct sockaddr_un));

            status = 0;
            break;
        }

#define SYSARG_ADDR(n) (args_addr + ((n) - 1) * sizeof_word(tracee))

#define PEEK_WORD(addr, forced_errno)        \
    peek_word(tracee, addr);        \
    if (errno != 0) {            \
        status = forced_errno ?: -errno; \
        break;                \
    }

#define POKE_WORD(addr, value)            \
    poke_word(tracee, addr, value);        \
    if (errno != 0) {            \
        status = -errno;        \
        break;                \
    }

        case PR_accept:
        case PR_accept4:
            if (peek_reg(tracee, ORIGINAL, SYSARG_2) == 0) {
                status = 0;
                break;
            }
            special = true;
        case PR_getsockname:
        case PR_getpeername: {
            int size;

            size = (int) PEEK_WORD(peek_reg(tracee, ORIGINAL, SYSARG_3), special ? -EINVAL : 0);

            poke_reg(tracee, SYSARG_6, size);

            status = 0;
            break;
        }

#undef SYSARG_ADDR
#undef PEEK_WORD
#undef POKE_WORD

        case PR_access:
        case PR_chmod:
        case PR_chown:
        case PR_chown32:
        case PR_getxattr:
        case PR_listxattr:
        case PR_mknod:
        case PR_removexattr:
        case PR_setxattr:
        case PR_stat:
        case PR_stat64:
        case PR_statfs:
        case PR_statfs64:
        case PR_truncate:
        case PR_truncate64:
        case PR_utime:
        case PR_utimes:
            status = translate_sysarg(tracee, SYSARG_1);
            break;

        case PR_open:
            status = translate_sysarg(tracee, SYSARG_1);
            break;

        case PR_fchownat:
        case PR_fstatat64:
        case PR_newfstatat:
        case PR_utimensat:
        case PR_name_to_handle_at:
            dir_fd = peek_reg(tracee, CURRENT, SYSARG_1);

            status = get_sysarg_path(tracee, path, SYSARG_2);
            if (status < 0)
                break;

            status = translate_path2(tracee, dir_fd, path, SYSARG_2);
            break;

        case PR_fchmodat:
        case PR_faccessat:
        case PR_faccessat2:
        case PR_futimesat:
        case PR_mknodat:
            dir_fd = peek_reg(tracee, CURRENT, SYSARG_1);

            status = get_sysarg_path(tracee, path, SYSARG_2);
            if (status < 0)
                break;

            status = translate_path2(tracee, dir_fd, path, SYSARG_2);
            break;

        case PR_inotify_add_watch:
            status = translate_sysarg(tracee, SYSARG_2);
            break;

        case PR_readlink:
        case PR_lchown:
        case PR_lchown32:
        case PR_lgetxattr:
        case PR_llistxattr:
        case PR_lremovexattr:
        case PR_lsetxattr:
        case PR_lstat:
        case PR_lstat64:
        case PR_unlink:
        case PR_rmdir:
        case PR_mkdir:
            status = translate_sysarg(tracee, SYSARG_1);
            break;

        case PR_linkat:
            old_dir_fd = peek_reg(tracee, CURRENT, SYSARG_1);
            dir_fd = peek_reg(tracee, CURRENT, SYSARG_3);

            status = get_sysarg_path(tracee, old_path, SYSARG_2);
            if (status < 0)
                break;

            status = get_sysarg_path(tracee, path, SYSARG_4);
            if (status < 0)
                break;

            status = translate_path2(tracee, old_dir_fd, old_path, SYSARG_2);
            if (status < 0)
                break;

            status = translate_path2(tracee, dir_fd, path, SYSARG_4);
            break;

        case PR_openat:
            dir_fd = peek_reg(tracee, CURRENT, SYSARG_1);

            status = get_sysarg_path(tracee, path, SYSARG_2);
            if (status < 0)
                break;

            status = translate_path2(tracee, dir_fd, path, SYSARG_2);
            break;

        case PR_readlinkat:
        case PR_unlinkat:
        case PR_mkdirat:
            dir_fd = peek_reg(tracee, CURRENT, SYSARG_1);

            status = get_sysarg_path(tracee, path, SYSARG_2);
            if (status < 0)
                break;

            translate_path2(tracee, dir_fd, path, SYSARG_2);
            break;

        case PR_link:
        case PR_rename:
            status = translate_sysarg(tracee, SYSARG_1);
            if (status < 0)
                break;

            status = translate_sysarg(tracee, SYSARG_2);
            break;

        case PR_renameat:
        case PR_renameat2:
            old_dir_fd = peek_reg(tracee, CURRENT, SYSARG_1);
            dir_fd = peek_reg(tracee, CURRENT, SYSARG_3);

            status = get_sysarg_path(tracee, old_path, SYSARG_2);
            if (status < 0)
                break;

            status = get_sysarg_path(tracee, path, SYSARG_4);
            if (status < 0)
                break;

            status = translate_path2(tracee, old_dir_fd, old_path, SYSARG_2);
            if (status < 0)
                break;

            status = translate_path2(tracee, dir_fd, path, SYSARG_4);
            break;

        case PR_symlink:
            status = translate_sysarg(tracee, SYSARG_2);
            break;

        case PR_symlinkat:
            dir_fd = peek_reg(tracee, CURRENT, SYSARG_2);

            status = get_sysarg_path(tracee, path, SYSARG_3);
            if (status < 0)
                break;

            status = translate_path2(tracee, dir_fd, path, SYSARG_3);
            break;

        case PR_prctl:
            if (peek_reg(tracee, CURRENT, SYSARG_1) == PR_SET_DUMPABLE) {
                set_sysnum(tracee, PR_void);
                status = 0;
            }
            break;
    }

	return status;
}

