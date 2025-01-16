#include <stdio.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "tinyproot.h"
#include "tracee/event.h"
#include "path/path.h"

int global_verbose_level = -1;
char *root_path = NULL;
int root_path_len = 0;

void note(const Tracee *tracee, Severity severity, const char *message, ...) {
    va_list extra_params;

    if (global_verbose_level < 0 && severity != ERROR)
        return;

    switch (severity) {
        case WARNING:
            fprintf(stderr, "proot:warn: ");
            break;

        case ERROR:
            fprintf(stderr, "proot:err: ");
            break;

        case INFO:
        default:
            fprintf(stderr, "proot:info: ");
            break;
    }

    va_start(extra_params, message);
    vfprintf(stderr, message, extra_params);
    va_end(extra_params);

    fprintf(stderr, "\n");
}

int parse_argv(Tracee *tracee, size_t argc, char *const argv[]) {
    int i, argc_offset;
    char *rootfs = NULL;
    char *cwd = NULL;

    if (argc == 1)
        return -1;

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (arg[0] != '-') {
            argc_offset = i;
            break;
        }

        if (arg[1] == '-') {
            char key[16];
            char *value;
            int pos;
            arg += 2;

            value = strstr(arg, "=");
            if (value != NULL) {
                value++;
                pos = value - arg - 1;

                memset(key, 0, 16);
                strncpy(key, arg, pos);

                if (strcmp(key, "rootfs") == 0) {
                    rootfs = strdup(value);
                }
                else if (strcmp(key, "cwd") == 0) {
                    cwd = strdup(value);
                }
            }
        }
    }

    if (rootfs) {
        root_path = rootfs;
        root_path_len = strlen(rootfs);
    }

    if (cwd) {
        tracee->cwd = cwd;
        if (tracee->cwd == NULL)
            return -1;
    }

    if (argc_offset > 0) {
        tracee->exe = strdup(argv[argc_offset]);
        if (tracee->exe == NULL)
            return -1;
    }

    return argc_offset;
}

int main(int argc, char *const argv[]) {
    Tracee *tracee;
    int status;

    tracee = get_tracee(NULL, 0, true);
    if (tracee == NULL)
        goto error;

    tracee->pid = getpid();
    tracee->killall_on_exit = true;

    const char *verbose_env = getenv("TINYPROOT_VERBOSE");
    if (verbose_env != NULL)
        global_verbose_level = strtol(verbose_env, NULL, 10);

    status = parse_argv(tracee, argc, argv);
    if (status < 0)
        goto error;

    status = launch_process(tracee, &argv[status]);
    if (status < 0)
        goto error;

    status = event_loop();

    MEMFREE(root_path);
    exit(status);

error:
    MEMFREE(root_path);
    remove_tracee(tracee);
    exit(EXIT_FAILURE);
}