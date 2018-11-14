from __future__ import unicode_literals, division, print_function
import re

from .types import LogLine, OptArg, SyscallErrorArg, FdArg
from .processing import simple_pass

# Line string regular expression
_LINE_REGEX = re.compile(r"(\d+) ([\d\.:]+) (\d+) ([^\(]+) \((\d+)\) ([\<\>]) ([^ ]+) ?(.*)?")
# Time string regular expression
_TIME_REGEX = re.compile(r"(\d+):(\d+):(\d+).(\d+)")
# Argument name regular expression
_ARG_NAME_REGEX = re.compile(r"(\w+)(=| )(.*)")

# Argument with extra information regular expression
_ARG_WITH_EXTRA_INFO_REGEX = re.compile(r"(\-?\d+)(?:\(([^\)]+)\))?")
# File descriptor inner regular expression
_FD_INNER_REGEX = re.compile(r"\<(\w+)\>(.*)")

def _parse_time(time_str):
    """ Parse time string in Sysdig log. """
    # Parse time string with regular expression
    time_match = _TIME_REGEX.match(time_str)
    if not time_match:
        raise SyntaxError("Unrecognized time format")
    h, m, s, ns = [int(item) for item in time_match.groups()]
    # Construct time in nano seconds
    return (h*3600+m*60+s)*(10**9)+ns

@simple_pass
def parse_line(raw_line):
    """ Parse log line in Sysdig log. """
    # Parse log line with regular expression
    line_match = _LINE_REGEX.match(raw_line)
    if not line_match:
        raise SyntaxError("Unrecognized log line: {}".format(raw_line))
    evt_num, evt_time, evt_cpu, proc_name, thread_tid, evt_dir, evt_type, evt_args \
        = line_match.groups()
    # Parse each part
    return LogLine(
        evt_num=int(evt_num),
        evt_time=_parse_time(evt_time),
        evt_cpu=int(evt_cpu),
        proc_name=proc_name,
        thread_tid=int(thread_tid),
        evt_dir=evt_dir,
        evt_type=evt_type,
        evt_args=evt_args
    )

def extract_arg_default(arg_str):
    """ Default strategy for extracting raw argument value. """
    args_str_split = arg_str.split(" ", 1)
    if len(args_str_split)==1:
        args_str_split.append("")
    return args_str_split

def extract_arg_until_line_end(args_str):
    """ Extract arguments by reading until line end. """
    return args_str, ""

# Argument with extra information regular expression
_EXTRACT_ARG_WITH_EXTRA_INFO_REGEX = re.compile(r"(\-?\w+(?:\([^\)]*\))?) ?(.*)")
def extract_arg_with_extra_info(args_str):
    """ Extract arguments with flags. """
    return _EXTRACT_ARG_WITH_EXTRA_INFO_REGEX.match(args_str).groups()

# Argument extractors preset
ARG_EXTRACTORS_PRESET = {
    "data": extract_arg_until_line_end,
    "fds": extract_arg_until_line_end,
    "args": extract_arg_until_line_end,
    "tuple": extract_arg_until_line_end,
    "fd": extract_arg_with_extra_info,
    "exe": extract_arg_until_line_end,
    "msg": extract_arg_until_line_end,
    "res": extract_arg_with_extra_info,
    "name": extract_arg_until_line_end,
}

@simple_pass
def parse_args_str(line, strict_parsing=False, arg_extractors=ARG_EXTRACTORS_PRESET):
    """ Parse log line arguments string in Sysdig log. """
    # Arguments string and dictionary
    args_str = line.evt_args
    args_dict = {}
    # Parse arguments string until it is empty
    while args_str:
        # Parse argument name
        next_arg_match = _ARG_NAME_REGEX.match(args_str)
        if not next_arg_match:
            if strict_parsing:
                # Raise parsing error
                raise SyntaxError("Unrecognized arguments string format: {}".format(args_str))
            else:
                # Ignore remaining line
                break
        arg_name, delimiter, args_str = next_arg_match.groups()
        # Parse argument raw value
        if delimiter=="=":
            arg_extractor = arg_extractors.get(arg_name, extract_arg_default)
            arg_raw_val, args_str = arg_extractor(args_str)
        else:
            arg_raw_val = None
        # Record argument name and raw value
        args_dict[arg_name] = arg_raw_val
    # Replace arguments string by dictionary
    line.evt_args = args_dict
    return line

@simple_pass
def parse_option_args(line, event_opt_args={}):
    """ Parse option arguments for log line. """
    opt_args = event_opt_args.get(line.evt_type)
    # Not event with optional arguments
    if not opt_args:
        return line
    # Process each argument in line
    opt_args_dict = {}
    for arg_name, arg_raw_val in line.evt_args.items():
        # Not optional argument
        if arg_name not in opt_args:
            continue
        # Parse optional argument
        opt_arg_match = _ARG_WITH_EXTRA_INFO_REGEX.match(arg_raw_val)
        if not opt_arg_match:
            raise SyntaxError("Unrecognized optional argument format: {}".format(arg_raw_val))
        arg_val, arg_opts_str = opt_arg_match.groups()
        # Record parsed argument
        opt_args_dict[arg_name] = OptArg(
            value=int(arg_val),
            options=arg_opts_str.split("|")
        )
    # Replace optional arguments
    line.evt_args.update(opt_args_dict)
    return line

@simple_pass
def parse_fd_args(line):
    """ Parse file descriptor arguments for log line. """
    arg_raw_val = line.evt_args.get("fd")
    # No file descriptor argument
    if not arg_raw_val:
        return line
    # Parse as argument with extra information
    fd_outer_match = _ARG_WITH_EXTRA_INFO_REGEX.match(arg_raw_val)
    if not fd_outer_match:
        raise SyntaxError("Unrecognized file descriptor argument format: {}".format(arg_raw_val))
    fd_val, fd_inner = fd_outer_match.groups()
    fd_val = int(fd_val)
    # System call error
    if fd_val<0:
        fd_arg = SyscallErrorArg(value=fd_val, name=fd_inner)
    # File descriptor
    else:
        # Non-null inner part
        if fd_inner is not None:
            fd_inner_match = _FD_INNER_REGEX.match(fd_inner)
            if not fd_inner_match:
                raise SyntaxError("Unrecognized file descriptor inner format: {}".format(fd_inner))
            # File descriptor type and location
            fd_type, location = fd_inner_match.groups()
        # Null inner part
        else:
            fd_type = location = ""
        fd_arg = FdArg(fd_val=fd_val, fd_type=fd_type, location=location)
    # Update file descriptor argument
    line.evt_args["fd"] = fd_arg
    return line
