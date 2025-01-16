#include "tracee/tracee.h"
#include "sys/vfs.h"

void restart_syscall_after_seccomp(Tracee* tracee);
void set_result_after_seccomp(Tracee *tracee, word_t result);
int handle_seccomp_event(Tracee* tracee);
void fix_and_restart_enosys_syscall(Tracee* tracee);
