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
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <string.h>
#include <strings.h>

#include "ptrace/ptrace.h"
#include "tracee/tracee.h"
#include "syscall/sysnum.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "tracee/event.h"
#include "tinyproot.h"
#include "arch.h"

int translate_ptrace_enter(Tracee *tracee) {
	set_sysnum(tracee, PR_void);
	return 0;
}

void attach_to_ptracer(Tracee *ptracee, Tracee *ptracer) {
	bzero(&(PTRACEE), sizeof(PTRACEE));
	PTRACEE.ptracer = ptracer;

	PTRACER.nb_ptracees++;
}

void detach_from_ptracer(Tracee *ptracee) {
	Tracee *ptracer = PTRACEE.ptracer;

	PTRACEE.ptracer = NULL;

	assert(PTRACER.nb_ptracees > 0);
	PTRACER.nb_ptracees--;
}

int translate_ptrace_exit(Tracee *tracee) {
	word_t request, pid, address, data, result;
	Tracee *ptracee, *ptracer;
	int forced_signal = -1;
	int signal;
	int status;

	request = peek_reg(tracee, ORIGINAL, SYSARG_1);
	pid     = peek_reg(tracee, ORIGINAL, SYSARG_2);
	address = peek_reg(tracee, ORIGINAL, SYSARG_3);
	data    = peek_reg(tracee, ORIGINAL, SYSARG_4);

	if (tracee->is_aarch32 && pid == 0xFFFFFFFF)
		pid = (word_t) -1;

	if (request == PTRACE_TRACEME) {
		ptracer = tracee->parent;
		ptracee = tracee;

		if (PTRACEE.ptracer != NULL || ptracee == ptracer)
			return -EPERM;

		attach_to_ptracer(ptracee, ptracer);

		if (PTRACER.waits_in == WAITS_IN_KERNEL) {
			status = kill(ptracer->pid, SIGSTOP);
			if (status < 0)
				note(tracee, WARNING, "can't wake ptracer %d", ptracer->pid);
			else {
				ptracer->sigstop = SIGSTOP_IGNORED;
				PTRACER.waits_in = WAITS_IN_PROOT;
			}
		}

		if (tracee->seccomp == ENABLED)
			tracee->seccomp = DISABLING;

		return 0;
	}

	if (request == PTRACE_ATTACH) {
		ptracer = tracee;
		ptracee = get_tracee(ptracer, pid, false);
		if (ptracee == NULL)
			return -ESRCH;

		if (PTRACEE.ptracer != NULL || ptracee == ptracer)
			return -EPERM;

		attach_to_ptracer(ptracee, ptracer);

		kill(pid, SIGSTOP);

		return 0;
	}

	ptracer = tracee;
	ptracee = get_stopped_ptracee(ptracer, pid, false, __WALL);
	if (ptracee == NULL) {
		static bool warned = false;

		ptracee = get_tracee(tracee, pid, false);
		if (ptracee != NULL && ptracee->exe == NULL && !warned) {
			warned = true;
			note(ptracer, WARNING, "ptrace request to an unexpected ptracee");
		}

		return -ESRCH;
	}

	if (   PTRACEE.is_zombie
	    || PTRACEE.ptracer != ptracer
	    || pid == (word_t) -1)
		return -ESRCH;

    switch (request) {
        case PTRACE_CONT:
            PTRACEE.ignore_syscalls = true;
            forced_signal = (int) data;
            status = 0;
            break;

        case PTRACE_SINGLESTEP:
            ptracee->restart_how = PTRACE_SINGLESTEP;
            forced_signal = (int) data;
            status = 0;
            break;

        case PTRACE_DETACH:
            detach_from_ptracer(ptracee);
            status = 0;
            break;

        case PTRACE_PEEKUSER:
            if (ptracer->is_aarch32 && address == (word_t) -1)
                return -EIO;
        case PTRACE_PEEKTEXT:
        case PTRACE_PEEKDATA:
            errno = 0;
            result = (word_t) ptrace(request, pid, address, NULL);
            if (errno != 0)
                return -errno;

            poke_word(ptracer, data, result);
            if (errno != 0)
                return -errno;

            return 0;

        case PTRACE_POKEUSER:
            if (ptracer->is_aarch32) {
                if (address == (word_t) -1)
                    return -EIO;
            }

            status = ptrace(request, pid, address, data);
            if (status < 0)
                return -errno;

            return 0;

        case PTRACE_POKETEXT:
        case PTRACE_POKEDATA:
            if (ptracer->is_aarch32) {
                word_t tmp;

                errno = 0;
                tmp = (word_t) ptrace(PTRACE_PEEKDATA, ptracee->pid, address, NULL);
                if (errno != 0)
                    return -errno;

                data |= (tmp & 0xFFFFFFFF00000000ULL);
            }

            status = ptrace(request, pid, address, data);
            if (status < 0)
                return -errno;

            return 0;

        default:
            note(ptracer, WARNING, "ptrace request %d not supported yet", request);
            return -ENOTSUP;
    }

	signal = PTRACEE.event4.proot.pending
		? handle_tracee_event(ptracee, PTRACEE.event4.proot.value)
		: PTRACEE.event4.proot.value;

	if (forced_signal != -1)
		signal = forced_signal;

	(void) restart_tracee(ptracee, signal);

	return status;
}
