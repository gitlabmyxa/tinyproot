#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <utime.h>
#include <stdio.h>
#include <sys/vfs.h>
#include <string.h>
#include <linux/net.h>
#include <assert.h>
#include <time.h>

#include "tinyproot.h"
#include "syscall/chain.h"
#include "syscall/syscall.h"
#include "tracee/seccomp.h"
#include "tracee/mem.h"
#include "path/path.h"

static int handle_seccomp_event_common(Tracee *tracee);

void restart_syscall_after_seccomp(Tracee* tracee) {
	word_t instr_pointer;

	tracee->restore_original_regs_after_seccomp_event = true;
	tracee->restart_how = PTRACE_SYSCALL;

	instr_pointer = peek_reg(tracee, CURRENT, INSTR_POINTER);
	poke_reg(tracee, INSTR_POINTER, instr_pointer - get_systrap_size(tracee));

	push_specific_regs(tracee, false);
}

void set_result_after_seccomp(Tracee *tracee, word_t result) {
	VERBOSE(tracee, 3, "Setting result after SIGSYS to 0x%lx", result);
	poke_reg(tracee, SYSARG_RESULT, result);
	push_specific_regs(tracee, false);
}

int handle_seccomp_event(Tracee* tracee) {
	int ret;

	tracee->status = 0;
	tracee->restore_original_regs = false;

	ret = fetch_regs(tracee);
	if (ret != 0) {
		VERBOSE(tracee, 1, "Couldn't fetch regs on seccomp SIGSYS");
		return SIGSYS;
	}

	save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);

	return handle_seccomp_event_common(tracee);
}

void fix_and_restart_enosys_syscall(Tracee* tracee) {
	tracee->status = 0;
	tracee->restore_original_regs = false;

	memcpy(&tracee->uregs[CURRENT], &tracee->uregs[ORIGINAL], sizeof(tracee->uregs[CURRENT]));
	save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);

	handle_seccomp_event_common(tracee);
}

static int handle_seccomp_event_common(Tracee *tracee) {
	int ret;
	Sysnum sysnum;

	sysnum = get_sysnum(tracee, CURRENT);

    switch (sysnum) {
        case PR_open:
            set_sysnum(tracee, PR_openat);
            poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_3));
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_accept:
            set_sysnum(tracee, PR_accept4);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_setgroups:
        case PR_setgroups32:
            set_result_after_seccomp(tracee, 0);
            break;

        case PR_getpgrp:
            set_result_after_seccomp(tracee, getpgid(tracee->pid));
            break;

        case PR_symlink:
            set_sysnum(tracee, PR_symlinkat);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, AT_FDCWD);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_link:
            set_sysnum(tracee, PR_linkat);
            poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_3, AT_FDCWD);
            poke_reg(tracee, SYSARG_5, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_chmod:
            set_sysnum(tracee, PR_fchmodat);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_chown:
        case PR_lchown:
        case PR_chown32:
        case PR_lchown32:
            set_sysnum(tracee, PR_fchownat);
            poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_3));
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            if (sysnum == PR_lchown || sysnum == PR_lchown32) {
                poke_reg(tracee, SYSARG_5, AT_SYMLINK_NOFOLLOW);
            }
            else {
                poke_reg(tracee, SYSARG_5, 0);
            }
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_unlink:
        case PR_rmdir:
            set_sysnum(tracee, PR_unlinkat);
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_3, sysnum == PR_rmdir ? AT_REMOVEDIR : 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_send:
            set_sysnum(tracee, PR_sendto);
            poke_reg(tracee, SYSARG_5, 0);
            poke_reg(tracee, SYSARG_6, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_recv:
            set_sysnum(tracee, PR_recvfrom);
            poke_reg(tracee, SYSARG_5, 0);
            poke_reg(tracee, SYSARG_6, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_waitpid:
            set_sysnum(tracee, PR_wait4);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_utimes: {
            struct timeval times[2];
            struct timespec timens[2];

            set_sysnum(tracee, PR_utimensat);
            if (peek_reg(tracee, CURRENT, SYSARG_2) != 0) {
                ret = read_data(tracee, times, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(times));
                if (ret < 0) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
                timens[0].tv_sec = (time_t) times[0].tv_sec;
                timens[0].tv_nsec = (long) times[0].tv_usec * 1000;
                timens[1].tv_sec = (time_t) times[1].tv_sec;
                timens[1].tv_nsec = (long) times[1].tv_usec * 1000;
                ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
                if (ret < 0) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
            }
            poke_reg(tracee, SYSARG_4, 0);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_utime: {
            struct utimbuf times;
            struct timespec timens[2];

            set_sysnum(tracee, PR_utimensat);
            if (peek_reg(tracee, CURRENT, SYSARG_2) != 0) {
                ret = read_data(tracee, &times, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(times));
                if (ret < 0) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
                timens[0].tv_sec = (time_t) times.actime;
                timens[0].tv_nsec = 0;
                timens[1].tv_sec = (time_t) times.modtime;
                timens[1].tv_nsec = 0;
                ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
                if (ret < 0) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
            }
            poke_reg(tracee, SYSARG_4, 0);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_stat:
        case PR_lstat:
            set_sysnum(tracee, PR_newfstatat);
            poke_reg(tracee, SYSARG_4, sysnum == PR_lstat ? AT_SYMLINK_NOFOLLOW : 0);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_pipe:
            set_sysnum(tracee, PR_pipe2);
            poke_reg(tracee, SYSARG_2, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_dup2:
            set_sysnum(tracee, PR_dup3);
            poke_reg(tracee, SYSARG_3, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_access:
            set_sysnum(tracee, PR_faccessat);
            poke_reg(tracee, SYSARG_4, 0);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_mkdir:
            set_sysnum(tracee, PR_mkdirat);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_rename:
            set_sysnum(tracee, PR_renameat);
            poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_3, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_select: {
            word_t timeval_arg = peek_reg(tracee, CURRENT, SYSARG_5);
            word_t timespec_arg = 0;
            if (timeval_arg != 0) {
                struct timeval tv = {0};
                if (read_data(tracee, &tv, timeval_arg, sizeof(tv))) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
                if (tv.tv_usec >= 1000000 || tv.tv_usec < 0) {
                    set_result_after_seccomp(tracee, -EINVAL);
                    break;
                }
                struct timespec ts = {
                    .tv_sec = tv.tv_sec,
                    .tv_nsec = tv.tv_usec * 1000
                };
                timespec_arg = alloc_mem(tracee, sizeof(ts));
                if (write_data(tracee, timespec_arg, &ts, sizeof(ts))) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
            }
            set_sysnum(tracee, PR_pselect6);
            poke_reg(tracee, SYSARG_5, timespec_arg);
            poke_reg(tracee, SYSARG_6, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_poll: {
            int ms_arg = (int) peek_reg(tracee, CURRENT, SYSARG_3);
            word_t timespec_arg = 0;
            if (ms_arg >= 0) {
                struct timespec ts = {
                    .tv_sec = ms_arg / 1000,
                    .tv_nsec = (ms_arg % 1000) * 1000000
                };
                timespec_arg = alloc_mem(tracee, sizeof(ts));
                if (write_data(tracee, timespec_arg, &ts, sizeof(ts))) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
            }
            set_sysnum(tracee, PR_ppoll);
            poke_reg(tracee, SYSARG_3, timespec_arg);
            poke_reg(tracee, SYSARG_4, 0);
            poke_reg(tracee, SYSARG_5, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_time: {
            time_t t = time(NULL);
            word_t addr = peek_reg(tracee, CURRENT, SYSARG_1);
            errno = 0;
            if (addr != 0) {
                poke_word(tracee, addr, t);
            }
            set_result_after_seccomp(tracee, errno ? -EFAULT : t);
            break;
        }

        case PR_ftruncate: {
            if (detranslate_sysnum(get_abi(tracee), PR_ftruncate64) == SYSCALL_AVOIDER) {
                set_result_after_seccomp(tracee, -ENOSYS);
                break;
            }
            set_sysnum(tracee, PR_ftruncate64);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, 0);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_setresuid:
        case PR_setresgid: {
            gid_t rxid, exid, sxid, rxid_, exid_, sxid_;
            rxid = peek_reg(tracee, CURRENT, SYSARG_1);
            exid = peek_reg(tracee, CURRENT, SYSARG_2);
            sxid = peek_reg(tracee, CURRENT, SYSARG_3);
            if (sysnum == PR_setresuid)
                ret = getresuid(&rxid_, &exid_, &sxid_);
            else if (sysnum == PR_setresgid)
                ret = getresgid(&rxid_, &exid_, &sxid_);
            if (ret) {
                set_result_after_seccomp(tracee, -EPERM);
                break;
            }
            ret = 0;
            if (rxid != rxid_ && rxid != -1)
                ret = -EPERM;
            if (exid != exid_ && exid != -1)
                ret = -EPERM;
            if (sxid != sxid_ && sxid != -1)
                ret = -EPERM;
            set_result_after_seccomp(tracee, ret);
            break;
        }

        case PR_set_robust_list:
        default:
            set_result_after_seccomp(tracee, -ENOSYS);
    }

	return 0;
}
