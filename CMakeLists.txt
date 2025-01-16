cmake_minimum_required(VERSION 3.22.1)

project(TinyPRoot)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wno-unused-function -Wimplicit-function-declaration -DNDEBUG")

include_directories(src)

add_executable(libtinyproot.so
               src/tinyproot.c
               src/execve/enter.c
               src/execve/exit.c
               src/execve/elf.c
               src/path/path.c
               src/path/proc.c
               src/syscall/seccomp.c
               src/syscall/syscall.c
               src/syscall/chain.c
               src/syscall/enter.c
               src/syscall/exit.c
               src/syscall/sysnum.c
               src/syscall/socket.c
               src/syscall/rlimit.c
               src/tracee/tracee.c
               src/tracee/mem.c
               src/tracee/reg.c
               src/tracee/event.c
               src/tracee/seccomp.c
               src/ptrace/ptrace.c
               src/ptrace/wait.c)

add_library(tinyproot-loader SHARED
            src/loader/loader.c)