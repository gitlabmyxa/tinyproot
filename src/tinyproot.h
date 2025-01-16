#ifndef TINYPROOT_H
#define TINYPROOT_H

#include <stddef.h>
#include "tracee/tracee.h"

typedef enum {
    ERROR,
    WARNING,
    INFO,
} Severity;

#define VERBOSE(tracee, level, message, args...) do {			\
    if (tracee == NULL || global_verbose_level >= (level))	\
        note(tracee, INFO, (message), ## args); \
} while (0)

#define MEMFREE(x) do { \
    if (x != NULL) {    \
        free(x);        \
        x = NULL;       \
    }                   \
} while(0)

extern void note(const Tracee *tracee, Severity severity, const char *message, ...);

extern int global_verbose_level;
extern char *root_path;
extern int root_path_len;

#endif //TINYPROOT_H
