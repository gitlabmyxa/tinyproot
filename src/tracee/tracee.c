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
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <inttypes.h>
#include <strings.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "syscall/sysnum.h"
#include "tracee/event.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "tinyproot.h"
#include "execve/execve.h"

static Tracees tracees;

static void free_load_info(LoadInfo *load_info) {
    if (!load_info)
        return;

    MEMFREE(load_info->user_path);
    MEMFREE(load_info->host_path);
    MEMFREE(load_info->mappings);
    load_info->num_mappings = 0;

    LoadInfo *interp = load_info->interp;
    while (interp) {
        free_load_info(interp);
        interp = interp->interp;
    }

    MEMFREE(load_info->interp);
}

static Tracee *new_tracee(pid_t pid) {
    Tracee *tracee;

    tracee = calloc(1, sizeof(Tracee));
    if (tracee == NULL)
        return NULL;

    tracee->pid = pid;

    LIST_INSERT_HEAD(&tracees, tracee, link);

    return tracee;
}

static void free_tracee(Tracee *tracee) {
    MEMFREE(tracee->cwd);
    MEMFREE(tracee->exe);
    MEMFREE(tracee->chain.syscalls);

    free_load_info(tracee->load_info);
    MEMFREE(tracee->load_info);
}

void remove_zombie(Tracee *zombie) {
    free_tracee(zombie);

    LIST_REMOVE(zombie, link);
}

void remove_tracee(Tracee *tracee) {
	Tracee *relative;
	Tracee *ptracer;
	int event;

    free_tracee(tracee);

	LIST_REMOVE(tracee, link);

	LIST_FOREACH(relative, &tracees, link) {
		if (relative->parent == tracee)
			relative->parent = NULL;

		if (relative->as_ptracee.ptracer == tracee) {
			relative->as_ptracee.ptracer = NULL;

			if (relative->as_ptracee.event4.proot.pending) {
				event = handle_tracee_event(relative, relative->as_ptracee.event4.proot.value);
				(void) restart_tracee(relative, event);
			}
			else if (relative->as_ptracee.event4.ptracer.pending) {
				event = relative->as_ptracee.event4.proot.value;
				(void) restart_tracee(relative, event);
			}

			bzero(&relative->as_ptracee, sizeof(relative->as_ptracee));
		}
	}

	ptracer = tracee->as_ptracee.ptracer;
	if (ptracer == NULL)
		return;

	event = tracee->as_ptracee.event4.ptracer.value;
	if (tracee->as_ptracee.event4.ptracer.pending
	    && (WIFEXITED(event) || WIFSIGNALED(event))) {
		Tracee *zombie;

		zombie = calloc(1, sizeof(Tracee));
		if (zombie != NULL) {
			LIST_INSERT_HEAD(&PTRACER.zombies, zombie, link);

			zombie->parent = tracee->parent;
			zombie->clone = tracee->clone;
			zombie->pid = tracee->pid;

			detach_from_ptracer(tracee);
			attach_to_ptracer(zombie, ptracer);

			zombie->as_ptracee.event4.ptracer.pending = true;
			zombie->as_ptracee.event4.ptracer.value = event;
			zombie->as_ptracee.is_zombie = true;

			return;
		}
	}

	detach_from_ptracer(tracee);

	if (PTRACER.nb_ptracees == 0 && PTRACER.wait_pid != 0) {
		poke_reg(ptracer, SYSARG_RESULT, -ECHILD);

		(void) push_regs(ptracer);

		PTRACER.wait_pid = 0;
		(void) restart_tracee(ptracer, 0);
	}
}

static Tracee *get_ptracee(const Tracee *ptracer, pid_t pid, bool only_stopped,
			               bool only_with_pevent, word_t wait_options) {
	Tracee *ptracee;

	LIST_FOREACH(ptracee, &PTRACER.zombies, link) {
		if (pid != ptracee->pid && pid != -1)
			continue;

		if (!EXPECTED_WAIT_CLONE(wait_options, ptracee))
			continue;

		return ptracee;
	}

	LIST_FOREACH(ptracee, &tracees, link) {
		if (PTRACEE.ptracer != ptracer)
			continue;

		if (pid != ptracee->pid && pid != -1)
			continue;

		if (!EXPECTED_WAIT_CLONE(wait_options, ptracee))
			continue;

		if (!only_stopped)
			return ptracee;

		if (ptracee->running)
			continue;

		if (PTRACEE.event4.ptracer.pending || !only_with_pevent)
			return ptracee;

		if (pid == ptracee->pid)
			return NULL;
	}

	return NULL;
}

Tracee *get_stopped_ptracee(const Tracee *ptracer, pid_t pid,
			                bool only_with_pevent, word_t wait_options) {
	return get_ptracee(ptracer, pid, true, only_with_pevent, wait_options);
}

bool has_ptracees(const Tracee *ptracer, pid_t pid, word_t wait_options) {
	return (get_ptracee(ptracer, pid, false, false, wait_options) != NULL);
}

Tracee *get_tracee(const Tracee *current_tracee, pid_t pid, bool create) {
	Tracee *tracee;

	if (current_tracee != NULL && current_tracee->pid == pid)
		return (Tracee *)current_tracee;

	LIST_FOREACH(tracee, &tracees, link) {
		if (tracee->pid == pid)
			return tracee;
	}

	return (create ? new_tracee(pid) : NULL);
}

void terminate_tracee(Tracee *tracee) {
	tracee->terminated = true;

	if (tracee->killall_on_exit) {
		VERBOSE(tracee, 1, "terminating all tracees on exit");
		kill_all_tracees();
	}
}

void free_terminated_tracees() {
	Tracee *next;

	next = tracees.lh_first;
	while (next != NULL) {
		Tracee *tracee = next;
		next = tracee->link.le_next;

		if (tracee->terminated)
			remove_tracee(tracee);
	}
}

int new_child(Tracee *parent, word_t clone_flags) {
	int ptrace_options;
	unsigned long pid;
	Tracee *child;
	int status;

	status = fetch_regs(parent);
	if (status >= 0 && get_sysnum(parent, CURRENT) == PR_clone)
		clone_flags = peek_reg(parent, CURRENT, SYSARG_1);

	status = ptrace(PTRACE_GETEVENTMSG, parent->pid, NULL, &pid);
	if (status < 0 || pid == 0) {
		note(parent, WARNING, "ptrace(GETEVENTMSG)");
		return status;
	}

	child = get_tracee(parent, (pid_t) pid, true);
	if (child == NULL) {
		note(parent, WARNING, "running out of memory");
		return -ENOMEM;
	}

	child->seccomp = parent->seccomp;
	child->sysexit_pending = parent->sysexit_pending;
	child->is_aarch32 = parent->is_aarch32;

    free_load_info(child->load_info);
    MEMFREE(child->load_info);

	if ((clone_flags & CLONE_PARENT) != 0)
		child->parent = parent->parent;
	else
		child->parent = parent;

	child->clone = ((clone_flags & CLONE_THREAD) != 0);

	ptrace_options = ( clone_flags == 0			? PTRACE_O_TRACEFORK
			: (clone_flags & 0xFF) == SIGCHLD	? PTRACE_O_TRACEFORK
			: (clone_flags & CLONE_VFORK) != 0	? PTRACE_O_TRACEVFORK
			: 					  PTRACE_O_TRACECLONE);
	if (parent->as_ptracee.ptracer != NULL
	    && (   (ptrace_options & parent->as_ptracee.options) != 0
		|| (clone_flags & CLONE_PTRACE) != 0)) {
		attach_to_ptracer(child, parent->as_ptracee.ptracer);

		child->as_ptracee.options |= (parent->as_ptracee.options
					      & ( PTRACE_O_TRACECLONE
						| PTRACE_O_TRACEEXEC
						| PTRACE_O_TRACEEXIT
						| PTRACE_O_TRACEFORK
						| PTRACE_O_TRACESYSGOOD
						| PTRACE_O_TRACEVFORK
						| PTRACE_O_TRACEVFORKDONE));
	}

    MEMFREE(child->cwd);
    child->cwd = strdup(parent->cwd);
    if (child->cwd == NULL)
        return -ENOMEM;

    MEMFREE(child->exe);
	child->exe = strdup(parent->exe);

	if (child->sigstop == SIGSTOP_PENDING) {
		bool keep_stopped = false;

		child->sigstop = SIGSTOP_ALLOWED;

		if (child->as_ptracee.ptracer != NULL) {
			assert(!child->as_ptracee.tracing_started);

#ifndef __W_STOPCODE
	#define __W_STOPCODE(sig) ((sig) << 8 | 0x7f)
#endif
			keep_stopped = handle_ptracee_event(child, __W_STOPCODE(SIGSTOP));

			child->as_ptracee.event4.proot.pending = false;
			child->as_ptracee.event4.proot.value   = 0;
		}

		if (!keep_stopped)
			(void) restart_tracee(child, 0);
	}

	VERBOSE(child, 1, "new child pid=%d exe=%s", child->pid, child->exe);

	return 0;
}

void kill_all_tracees() {
	Tracee *tracee;

	LIST_FOREACH(tracee, &tracees, link)
		kill(tracee->pid, SIGKILL);
}

Tracees *get_tracees_list_head() {
	return &tracees;
}
