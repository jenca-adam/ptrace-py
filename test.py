import ptrace
import os
import signal
import time


def tracee():
    ptrace.ptrace(ptrace.PtraceRequest.TRACEME)

    print("EXEC")
    os.execve("/usr/bin/xterm", ["xterm", "-e", "mc"], os.environ)


def tracer(pid):
    os.waitpid(pid, 0)
    while True:

        ptrace.ptrace(ptrace.PtraceRequest.SYSCALL, pid)
        _, stat = os.waitpid(pid, 0)
        if os.WIFEXITED(stat):
            break
        elif os.WIFSTOPPED(stat):

            orig_eax = ptrace.ptrace(ptrace.PtraceRequest.PEEKUSR, pid, 8 * 15)
            print(orig_eax)


def main():
    pid = os.fork()
    if pid:
        tracer(pid)
    else:
        tracee()


if __name__ == "__main__":
    main()
