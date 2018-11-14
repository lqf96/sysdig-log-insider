from __future__ import unicode_literals, division, print_function
from namedlist import namedlist

# Log line data
LogLine = namedlist("LogLine", [
    "evt_num",
    "evt_time",
    "evt_cpu",
    "proc_name",
    "thread_tid",
    "evt_dir",
    "evt_type",
    "evt_args"
])

# Optional argument
OptArg = namedlist("OptArg", [
    "value",
    "options"
])

# System call error argument
SyscallErrorArg = namedlist("SyscallErrorArg", [
    "value",
    "name"
])

# File descriptor argument
FdArg = namedlist("FdArg", [
    "fd_val",
    "fd_type",
    "location"
])
