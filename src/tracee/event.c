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

#include <sched.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <strings.h>

#include "tracee/event.h"
#include "tracee/seccomp.h"
#include "tracee/mem.h"
#include "ptrace/ptrace.h"
#include "tinyproot.h"
#include "path/path.h"
#include "syscall/syscall.h"
#include "syscall/seccomp.h"
#include "ptrace/wait.h"
#include "execve/elf.h"

static bool seccomp_after_ptrace_enter = true;
static int last_exit_status = -1;

int launch_process(Tracee *tracee, char *const argv[]) {
	long status;
	pid_t pid;

	pid = fork();
    switch (pid) {
        case -1:
            note(tracee, ERROR, "fork()");
            return -errno;

        case 0: // child
            status = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            if (status < 0) {
                note(tracee, ERROR, "ptrace(TRACEME)");
                return -errno;
            }

            kill(getpid(), SIGSTOP);

            enable_syscall_filtering();

            execvp(tracee->exe, argv);
            return -errno;

        default: // parent
            tracee->pid = pid;
            return 0;
    }
}

static void kill_all_tracees2(int signum, siginfo_t *siginfo, void *ucontext) {
	note(NULL, WARNING, "signal %d received from process %d",
		 signum, siginfo->si_pid);
	kill_all_tracees();

	if (signum != SIGQUIT)
		_exit(EXIT_FAILURE);
}

int event_loop() {
	struct sigaction signal_action;
	long status;
	int signum;

	status = atexit(kill_all_tracees);
	if (status != 0)
		note(NULL, WARNING, "atexit() failed");

	bzero(&signal_action, sizeof(signal_action));
	signal_action.sa_flags = SA_SIGINFO | SA_RESTART;
	status = sigfillset(&signal_action.sa_mask);
	if (status < 0)
		note(NULL, WARNING, "sigfillset()");

	for (signum = 0; signum < SIGRTMAX; signum++) {
        switch (signum) {
            case SIGQUIT:
            case SIGILL:
            case SIGABRT:
            case SIGFPE:
            case SIGSEGV:
                signal_action.sa_sigaction = kill_all_tracees2;
                break;

            case SIGUSR1:
            case SIGUSR2:
            case SIGCHLD:
            case SIGCONT:
            case SIGSTOP:
            case SIGTSTP:
            case SIGTTIN:
            case SIGTTOU:
                continue;

            default:
                signal_action.sa_sigaction = (void *) SIG_IGN;
                break;
        }

		status = sigaction(signum, &signal_action, NULL);
		if (status < 0 && errno != EINVAL)
			note(NULL, WARNING, "sigaction(%d)", signum);
	}

	while (1) {
		int tracee_status;
		Tracee *tracee;
		int signal;
		pid_t pid;

		free_terminated_tracees();

		pid = waitpid(-1, &tracee_status, __WALL);
		if (pid < 0) {
			if (errno != ECHILD) {
				note(NULL, ERROR, "waitpid()");
				return EXIT_FAILURE;
			}
			break;
		}

		tracee = get_tracee(NULL, pid, true);
		assert(tracee != NULL);

		tracee->running = false;

		if (tracee->as_ptracee.ptracer != NULL) {
			bool keep_stopped = handle_ptracee_event(tracee, tracee_status);
			if (keep_stopped)
				continue;
		}

		signal = handle_tracee_event(tracee, tracee_status);
		(void) restart_tracee(tracee, signal);
	}

	return last_exit_status;
}

int handle_tracee_event(Tracee *tracee, int tracee_status) {
	static bool seccomp_detected = false;
	long status;
	int signal;
	bool sysexit_necessary;

	sysexit_necessary = tracee->sysexit_pending
				|| tracee->chain.syscalls != NULL
				|| tracee->restore_original_regs_after_seccomp_event;
	if (tracee->restart_how == 0) {
		if (tracee->seccomp == ENABLED && !sysexit_necessary)
			tracee->restart_how = PTRACE_CONT;
		else
			tracee->restart_how = PTRACE_SYSCALL;
	}

	signal = 0;

	if (WIFEXITED(tracee_status)) {
		last_exit_status = WEXITSTATUS(tracee_status);
		VERBOSE(tracee, 1, "pid %d: exited with status %d", tracee->pid, last_exit_status);
		terminate_tracee(tracee);
	}
	else if (WIFSIGNALED(tracee_status)) {
		VERBOSE(tracee, (int) (tracee->pid != 1), "pid %d: terminated with signal %d", tracee->pid, WTERMSIG(tracee_status));
		terminate_tracee(tracee);
	}
	else if (WIFSTOPPED(tracee_status)) {
		signal = (tracee_status & 0xfff00) >> 8;

        switch (signal) {
            static bool deliver_sigtrap = false;

            case SIGTRAP: {
                const unsigned long default_ptrace_options = (
                    PTRACE_O_TRACESYSGOOD |
                    PTRACE_O_TRACEFORK |
                    PTRACE_O_TRACEVFORK |
                    PTRACE_O_TRACEVFORKDONE |
                    PTRACE_O_TRACEEXEC |
                    PTRACE_O_TRACECLONE |
                    PTRACE_O_TRACEEXIT
                );

                if (deliver_sigtrap)
                    break;

                deliver_sigtrap = true;

                status = ptrace(PTRACE_SETOPTIONS, tracee->pid, NULL,
                                default_ptrace_options | PTRACE_O_TRACESECCOMP);
                if (status < 0) {
                    status = ptrace(PTRACE_SETOPTIONS, tracee->pid, NULL,
                                    default_ptrace_options);
                    if (status < 0) {
                        note(tracee, ERROR, "ptrace(PTRACE_SETOPTIONS)");
                        exit(EXIT_FAILURE);
                    }
                }
            }

            case SIGTRAP | 0x80:
                signal = 0;

                if (tracee->exe == NULL) {
                    tracee->restart_how = PTRACE_CONT;
                    return 0;
                }

                switch (tracee->seccomp) {
                    case ENABLED:
                        if (IS_IN_SYSENTER(tracee)) {
                            tracee->restart_how = PTRACE_SYSCALL;
                            tracee->sysexit_pending = true;
                        }
                        else {
                            tracee->restart_how = PTRACE_CONT;
                            tracee->sysexit_pending = false;
                        }
                    case DISABLED:
                        if (!tracee->seccomp_already_handled_enter) {
                            bool was_sysenter = IS_IN_SYSENTER(tracee);

                            translate_syscall(tracee);

                            if (was_sysenter) {
                                tracee->skip_next_seccomp_signal = (
                                        seccomp_after_ptrace_enter &&
                                        get_sysnum(tracee, CURRENT) == PR_void);
                            }

                            if (tracee->chain.suppressed_signal && tracee->chain.syscalls == NULL) {
                                signal = tracee->chain.suppressed_signal;
                                tracee->chain.suppressed_signal = 0;
                                VERBOSE(tracee, 6, "pid %d: redelivering suppressed signal %d",
                                        tracee->pid, signal);
                            }
                        }
                        else {
                            VERBOSE(tracee, 6, "skipping SIGTRAP for already handled sysenter");
                            assert(!IS_IN_SYSENTER(tracee));
                            assert(!seccomp_after_ptrace_enter);
                            tracee->seccomp_already_handled_enter = false;
                            tracee->restart_how = PTRACE_SYSCALL;
                        }

                        if (tracee->seccomp == DISABLING) {
                            tracee->restart_how = PTRACE_SYSCALL;
                            tracee->seccomp = DISABLED;
                        }

                        break;

                    case DISABLING:
                        tracee->seccomp = DISABLED;
                        if (IS_IN_SYSENTER(tracee))
                            tracee->status = 1;
                        break;
                }
                break;

            case SIGTRAP | PTRACE_EVENT_SECCOMP2 << 8:
            case SIGTRAP | PTRACE_EVENT_SECCOMP << 8: {
                unsigned long flags = 0;

                signal = 0;

                if (!seccomp_detected) {
                    tracee->seccomp = ENABLED;
                    seccomp_detected = true;
                    seccomp_after_ptrace_enter = !IS_IN_SYSENTER(tracee);
                    VERBOSE(tracee, 1,
                            "ptrace acceleration (seccomp mode 2, %s syscall order) enabled",
                            seccomp_after_ptrace_enter ? "new" : "old");
                }

                tracee->skip_next_seccomp_signal = false;

                if (seccomp_after_ptrace_enter && !IS_IN_SYSENTER(tracee)) {
                    tracee->restart_how = tracee->last_restart_how;
                    VERBOSE(tracee, 6,
                            "skipping PTRACE_EVENT_SECCOMP for already handled sysenter");

                    assert(tracee->restart_how != PTRACE_CONT);
                    break;
                }

                assert(IS_IN_SYSENTER(tracee));

                if (tracee->seccomp != ENABLED)
                    break;

                status = ptrace(PTRACE_GETEVENTMSG, tracee->pid, NULL, &flags);
                if (status < 0)
                    break;

                if ((flags & FILTER_SYSEXIT) != 0 || sysexit_necessary) {
                    if (seccomp_after_ptrace_enter) {
                        tracee->restart_how = PTRACE_SYSCALL;
                        translate_syscall(tracee);
                    }
                    tracee->restart_how = PTRACE_SYSCALL;
                    break;
                }

                tracee->restart_how = PTRACE_CONT;
                translate_syscall(tracee);

                if (tracee->seccomp == DISABLING)
                    tracee->restart_how = PTRACE_SYSCALL;

                if (!seccomp_after_ptrace_enter && tracee->restart_how == PTRACE_SYSCALL)
                    tracee->seccomp_already_handled_enter = true;
                break;
            }

            case SIGTRAP | PTRACE_EVENT_VFORK << 8:
                signal = 0;
                (void) new_child(tracee, CLONE_VFORK);
                break;

            case SIGTRAP | PTRACE_EVENT_FORK << 8:
            case SIGTRAP | PTRACE_EVENT_CLONE << 8:
                signal = 0;
                (void) new_child(tracee, 0);
                break;

            case SIGTRAP | PTRACE_EVENT_VFORK_DONE << 8:
            case SIGTRAP | PTRACE_EVENT_EXEC << 8:
            case SIGTRAP | PTRACE_EVENT_EXIT << 8:
                signal = 0;
                if (tracee->last_restart_how) {
                    tracee->restart_how = tracee->last_restart_how;
                }
                break;

            case SIGSTOP:
                if (tracee->exe == NULL) {
                    tracee->sigstop = SIGSTOP_PENDING;
                    signal = -1;
                }

                if (tracee->sigstop == SIGSTOP_IGNORED) {
                    tracee->sigstop = SIGSTOP_ALLOWED;
                    signal = 0;
                }
                break;

            case SIGSYS: {
                siginfo_t siginfo = {0};
                ptrace(PTRACE_GETSIGINFO, tracee->pid, NULL, &siginfo);
                if (siginfo.si_code == SYS_SECCOMP) {
                    if (!IS_IN_SYSENTER(tracee)) {
                        VERBOSE(tracee, 1, "Handling syscall exit from SIGSYS");
                        translate_syscall(tracee);
                    }

                    if (tracee->skip_next_seccomp_signal ||
                        (seccomp_after_ptrace_enter && siginfo.si_syscall == SYSCALL_AVOIDER)) {
                        VERBOSE(tracee, 4, "suppressed SIGSYS after void syscall");
                        tracee->skip_next_seccomp_signal = false;
                        signal = 0;
                    }
                    else
                        signal = handle_seccomp_event(tracee);
                }
                else
                    VERBOSE(tracee, 1, "non-seccomp SIGSYS");
                break;
            }

            default:
                if (tracee->chain.syscalls != NULL) {
                    VERBOSE(tracee, 5,
                            "pid %d: suppressing signal during chain signal=%d, prev suppressed_signal=%d",
                            tracee->pid, signal, tracee->chain.suppressed_signal);
                    tracee->chain.suppressed_signal = signal;
                    signal = 0;
                }
                break;
        }
	}

	tracee->as_ptracee.event4.proot.pending = false;

	return signal;
}

bool restart_tracee(Tracee *tracee, int signal) {
	int status;

	if (tracee->as_ptracer.wait_pid != 0 || signal == -1)
		return false;

	assert(tracee->restart_how != 0);
	status = ptrace(tracee->restart_how, tracee->pid, NULL, signal);
	if (status < 0)
		return false;

	tracee->last_restart_how = tracee->restart_how;
	tracee->restart_how = 0;
	tracee->running = true;

	return true;
}
