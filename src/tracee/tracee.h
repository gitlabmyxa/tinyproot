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

#ifndef TRACEE_H
#define TRACEE_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/ptrace.h>
#include <stdint.h>
#include <stdio.h>
#include <malloc.h>

#include "arch.h"

typedef enum {
	CURRENT  = 0,
	ORIGINAL = 1,
	MODIFIED = 2,
	ORIGINAL_SECCOMP_REWRITE = 3,
	NB_REG_VERSION
} RegVersion;

struct load_info;
struct chained_syscalls;

typedef struct tracee {
	LIST_ENTRY(tracee) link;

	pid_t pid;
	bool running;
	bool terminated;
	bool killall_on_exit;
	struct tracee *parent;
	bool clone;

	struct {
		size_t nb_ptracees;
		LIST_HEAD(zombies, tracee) zombies;

		pid_t wait_pid;
		word_t wait_options;

		enum {
			DOESNT_WAIT = 0,
			WAITS_IN_KERNEL,
			WAITS_IN_PROOT
		} waits_in;
	} as_ptracer;

	struct {
		struct tracee *ptracer;

		struct {
			#define STRUCT_EVENT struct { int value; bool pending; }

			STRUCT_EVENT proot;
			STRUCT_EVENT ptracer;
		} event4;

		bool tracing_started;
		bool ignore_loader_syscalls;
		bool ignore_syscalls;
		word_t options;
		bool is_zombie;
	} as_ptracee;

	int status;

#define IS_IN_SYSENTER(tracee) ((tracee)->status == 0)

	int restart_how, last_restart_how;

	struct user_regs_struct uregs[NB_REG_VERSION];
	bool uregs_were_changed;
	bool restore_original_regs;
	bool restore_original_regs_after_seccomp_event;

	enum {
		SIGSTOP_IGNORED = 0,
		SIGSTOP_ALLOWED,
		SIGSTOP_PENDING,
	} sigstop;

	bool skip_next_seccomp_signal;

	struct {
		struct chained_syscalls *syscalls;
		bool force_final_result;
		word_t final_result;
		enum {
			SYSNUM_WORKAROUND_INACTIVE,
			SYSNUM_WORKAROUND_PROCESS_FAULTY_CALL,
			SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL
		} sysnum_workaround_state;
		int suppressed_signal;
	} chain;

	struct load_info *load_info;

	bool is_aarch32;

	enum { DISABLED = 0, DISABLING, ENABLED } seccomp;

	bool sysexit_pending;
	bool seccomp_already_handled_enter;
	char *exe;
	char *cwd;

} Tracee;

extern Tracee *get_tracee(const Tracee *tracee, pid_t pid, bool create);
extern void remove_zombie(Tracee *zombie);
extern void remove_tracee(Tracee *tracee);
extern Tracee *get_stopped_ptracee(const Tracee *ptracer, pid_t pid,
								   bool only_with_pevent, word_t wait_options);
extern bool has_ptracees(const Tracee *ptracer, pid_t pid, word_t wait_options);
extern int new_child(Tracee *parent, word_t clone_flags);
extern void terminate_tracee(Tracee *tracee);
extern void free_terminated_tracees();
extern void kill_all_tracees();

typedef LIST_HEAD(tracees, tracee) Tracees;
extern Tracees *get_tracees_list_head();

#endif /* TRACEE_H */
