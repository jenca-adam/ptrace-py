import ctypes
import os
import platform
from .const import *

try:
    libc_dll = ctypes.CDLL("libc.so.6", use_errno=True)
    _ptrace = libc_dll.ptrace
except (OSError, AttributeError) as e:
    raise OSError("ptrace not supported on your system.") from e


def ptrace_errcheck(result, func, args):
    if result == -1:
        errno = ctypes.get_errno()
        if not errno:
            return result
        raise OSError(errno, os.strerror(errno))
    return result


### linux/ptrace.h


class PeeksiginfoArgs(ctypes.Structure):
    _fields_ = [
        ("off", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("nr", ctypes.c_int32),
    ]


class SeccompMetadata(ctypes.Structure):
    _fields_ = [("filter_off", ctypes.c_uint64), ("flags", ctypes.c_uint64)]


class SyscallInfo(ctypes.Structure):

    class SyscallInfoUnion(ctypes.Union):
        class SyscallInfoEntry(ctypes.Structure):
            _fields_ = [("nr", ctypes.c_uint64), ("args", ctypes.c_uint64 * 6)]

        class SyscallInfoExit(ctypes.Structure):
            _fields_ = [("rval", ctypes.c_int64), ("is_error", ctypes.c_uint8)]

        class SyscallInfoSeccomp(ctypes.Structure):
            _fields_ = [
                ("nr", ctypes.c_uint64),
                ("args", ctypes.c_uint64 * 6),
                ("ret_data", ctypes.c_uint32),
            ]

        _fields_ = [
            ("entry", SyscallInfoEntry),
            ("exit", SyscallInfoExit),
            ("seccomp", SyscallInfoSeccomp),
        ]

    _fields_ = [
        ("op", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("stack_pointer", ctypes.c_uint64),
        ("_union", SyscallInfoUnion),
    ]

    @property
    def entry(self):
        return self._union.entry

    @property
    def exit(self):
        return self._union.exit

    @property
    def seccomp(self):
        return self._union.seccomp


class RseqConfiguration(ctypes.Structure):
    _fields_ = [
        ("rseq_abi_pointer", ctypes.c_uint64),
        ("rseq_abi_size", ctypes.c_uint32),
        ("signature", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("pad", ctypes.c_uint32),
    ]


class SudConfig(ctypes.Structure):
    _fields_ = [
        ("mode", ctypes.c_uint64),
        ("selector", ctypes.c_uint64),
        ("offset", ctypes.c_uint64),
        ("len", ctypes.c_uint64),
    ]


## sys/user.h


class _UserFpregsStruct_x86_64(ctypes.Structure):
    _fields_ = [
        ("cwd", ctypes.c_ushort),
        ("swd", ctypes.c_ushort),
        ("ftw", ctypes.c_ushort),
        ("fop", ctypes.c_ushort),
        ("rip", ctypes.c_ulonglong),
        ("rdp", ctypes.c_ulonglong),
        ("mxscr", ctypes.c_uint),
        ("mxcr_mask", ctypes.c_uint),
        ("st_space", ctypes.c_uint * 32),
        ("xmm_space", ctypes.c_uint * 64),
        ("padding", ctypes.c_uint * 24),
    ]


class _UserRegsStruct_x86_64(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


class _User_x86_64(ctypes.Structure):
    class UAr0Union(ctypes.Union):
        _fields_ = [
            ("u_ar0", ctypes.POINTER(_UserRegsStruct_x86_64)),
            (
                "__u_ar0_word",
                ctypes.c_ulonglong,
            ),
        ]

    class UFpstateUnion(ctypes.Union):
        _fields_ = [
            ("u_fpstate", ctypes.POINTER(_UserFpregsStruct_x86_64)),
            ("__u_fpstate_word", ctypes.c_ulonglong),
        ]

    _fields_ = [
        ("regs", _UserRegsStruct_x86_64),
        ("u_fpvalid", ctypes.c_int),
        ("i387", _UserFpregsStruct_x86_64),
        ("u_tsize", ctypes.c_ulonglong),
        ("u_dsize", ctypes.c_ulonglong),
        ("u_ssize", ctypes.c_ulonglong),
        ("start_code", ctypes.c_ulonglong),
        ("start_stack", ctypes.c_ulonglong),
        ("signal", ctypes.c_longlong),
        ("reserved", ctypes.c_int),
        ("_u_ar0_union", UAr0Union),
        ("_u_fpstate_union", UFpstateUnion),
        ("magic", ctypes.c_ulonglong),
        ("u_comm", ctypes.c_char * 32),
        ("u_debugreg", ctypes.c_ulonglong * 8),
    ]

    @property
    def u_ar0(self):
        return self._u_ar0_union.u_ar0

    @property
    def u_ar0_word(self):
        return self._u_ar0_union.__u_ar0_word

    @property
    def u_fpstate(self):
        return self._u_fpstate_union.u_fpstate

    @property
    def u_fpstate_word(self):
        return self._u_fpstate_union.__u_fpstate_word


class _UserFpRegsStruct_i386(ctypes.Structure):
    _fields_ = [
        ("cwd", ctypes.c_long),
        ("swd", ctypes.c_long),
        ("twd", ctypes.c_long),
        ("fip", ctypes.c_long),
        ("fcs", ctypes.c_long),
        ("foo", ctypes.c_long),
        ("fos", ctypes.c_long),
        ("st_space", ctypes.c_long * 20),
    ]


class _UserFpxRegsStruct_i386(ctypes.Structure):
    _fields_ = [
        ("cwd", ctypes.c_ushort),
        ("swd", ctypes.c_ushort),
        ("twd", ctypes.c_ushort),
        ("fop", ctypes.c_ushort),
        ("fip", ctypes.c_long),
        ("fcs", ctypes.c_long),
        ("foo", ctypes.c_long),
        ("fos", ctypes.c_long),
        ("mxcsr", ctypes.c_long),
        ("reserved", ctypes.c_long),
        ("st_space", ctypes.c_long * 32),
        ("xmm_space", ctypes.c_long * 32),
        ("padding", ctypes.c_long * 56),
    ]


class _UserRegsStruct_i386(ctypes.Structure):
    _fields_ = [
        ("ebx", ctypes.c_long),
        ("ecx", ctypes.c_long),
        ("edx", ctypes.c_long),
        ("esi", ctypes.c_long),
        ("edi", ctypes.c_long),
        ("ebp", ctypes.c_long),
        ("eax", ctypes.c_long),
        ("xds", ctypes.c_long),
        ("xes", ctypes.c_long),
        ("xfs", ctypes.c_long),
        ("xgs", ctypes.c_long),
        ("orig_eax", ctypes.c_long),
        ("eip", ctypes.c_long),
        ("xcs", ctypes.c_long),
        ("eflags", ctypes.c_long),
        ("esp", ctypes.c_long),
        ("xss", ctypes.c_long),
    ]


class _User_i386(ctypes.Structure):
    _fields_ = [
        ("regs", _UserRegsStruct_i386),
        ("u_fpvalid", ctypes.c_int),
        ("i387", _UserFpRegsStruct_i386),
        ("u_tsize", ctypes.c_ulong),
        ("u_dsize", ctypes.c_ulong),
        ("u_ssize", ctypes.c_ulong),
        ("start_code", ctypes.c_ulong),
        ("start_stack", ctypes.c_ulong),
        ("signal", ctypes.c_long),
        ("reserved", ctypes.c_int),
        ("u_ar0", ctypes.POINTER(_UserRegsStruct_i386)),
        ("u_fpstate", ctypes.POINTER(_UserFpRegsStruct_i386)),
        ("magic", ctypes.c_ulong),
        ("u_comm", ctypes.c_char * 32),
        ("u_debugreg", ctypes.c_int * 8),
    ]

if platform.machine() == "x86_64":
    User = _User_x86_64
    UserFpregsStruct = _UserFpregsStruct_x86_64
    UserRegsStruct = _UserRegsStruct_x86_64
    UserFpxregsStruct = None
elif platform.machine() in ("i386", "i686"):
    User = _User_i386
    UserFpregsStruct = _UserFpRegsStruct_i386
    UserRegsStruct = _UserRegsStruct_i386
    UserFpxregsStruct = _UserFpxRegsStruct_i386
    
_ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
_ptrace.restype = ctypes.c_long
_ptrace.errcheck = ptrace_errcheck


def ptrace(trace_request, pid=0, addr=0, data=0):
    return _ptrace(trace_request.value, pid, addr, data)
