from __future__ import unicode_literals, division
import os, re, functools, logging
from six import iteritems
from six.moves import map
import numpy as np

from .types import FdArg

# Logger
_logger = logging.getLogger(__name__)

def log_pipeline(source, *passes):
    """ Log processing pipeline. """
    composed_iter = source
    # Apply previous generator to next pass
    for pass_func in passes:
        composed_iter = pass_func(composed_iter)
    # Collect into a list
    return list(composed_iter)

def simple_pass(pass_functor):
    """ Convert a functor to a simple pass function. """
    @functools.wraps(pass_functor)
    def pass_func(*args, **kwargs):
        return lambda stream: map(
            functools.partial(pass_functor, *args, **kwargs),
            stream
        )
    return pass_func

@simple_pass
def inspect_line(data):
    """ Inspect line in the streamline. """
    _logger.debug("[Line Inspection] %s", data)
    # Do nothing to data except printing
    return data

def lines_from_file(log_file):
    """ Read and yield lines from log file. """
    with open(log_file) as f:
        for line in f:
            # Remove trailing characters
            line = line.rstrip()
            # Yield line if it is non-empty
            if line:
                yield line

def remove_events(*evt_names):
    """ Remove events from log line stream. """
    event_names = set(evt_names)
    # Pass generator function
    def remove_events_pass(lines):
        for line in lines:
            # Filter lines by event type
            if line.evt_type not in event_names:
                yield line
    return remove_events_pass

def opt_arg_features(evt_opts_map={}):
    """ Extract option argument features from line. """
    def feature_generator(line):
        opt_args = evt_opts_map.get(line.evt_type)
        # No option arguments
        if not opt_args:
            return []
        # Features array
        features = []
        # Try each option argument for this event
        for opt_arg in opt_args:
            opt_arg_val = line.evt_args.get(opt_arg)
            # Option argument exists for line
            if opt_arg_val:
                features += [(opt_arg, option) for option in opt_arg_val.options]
        # Generated features
        return features
    return feature_generator

def fd_features(path_patterns=[]):
    """ Extract file descriptor features from line """
    # Compile each pattern into regular expression
    path_patterns = [re.compile(pattern_str) for pattern_str in path_patterns]
    def feature_generator(line):
        features = []
        fd_arg = line.evt_args.get("fd")
        # No file descriptor option or file descriptor option is error
        if not isinstance(fd_arg, FdArg):
            return features
        # File descriptor type feature
        fd_type = fd_arg.fd_type
        features = [("fd_type", fd_type)]
        # Not a file or unix socket
        if fd_arg.fd_type!="f" and fd_arg.fd_type!="u":
            return features
        # Match path against given path patterns
        location = fd_arg.location
        for pattern in path_patterns:
            if pattern.match(location):
                features.append(("fd_path_pattern", pattern.pattern))
        # Final features
        return features
    return feature_generator

class FreqCounter(object):
    def __init__(self, processes=set(), evt_feature_tuples=set(), feature_generators=[]):
        """ Initialize feature frequency counter. """
        ## Processes set
        self.processes = processes
        ## Event-feature tuples set
        self.evt_feature_tuples = evt_feature_tuples
        ## Discrete feature generators
        self.feature_generators = feature_generators
    def _process_lines_impl(self, lines, training):
        # Process-event-feature count
        proc_evt_feature_count = {}
        # Lines count
        lines_count = 0
        for line in lines:
            # Update lines count
            lines_count += 1
            # Process and event name
            process_name = line.proc_name
            event_name = line.evt_type
            # Build event-discrete feature tuples
            # (Format: (event_name, feature_name, feature_value))
            evt_feature_tuples = []
            for generator in self.feature_generators:
                evt_feature_tuples += [
                    (event_name, feature_name, feature_value)
                    for feature_name, feature_value in generator(line)
                ]
            # No tuples built, default to process name only    
            if not evt_feature_tuples:
                evt_feature_tuples.append((event_name,))
            # Process each tuple
            for evt_feature_tuple in evt_feature_tuples:
                # Add process name and event-feature tuple
                if training:
                    self.processes.add(process_name)
                    self.evt_feature_tuples.add(evt_feature_tuple)
                # Update process-event-feature count
                count = proc_evt_feature_count.get((process_name, evt_feature_tuple), 0)
                count += 1
                proc_evt_feature_count[(process_name, evt_feature_tuple)] = count
        # Return process-event-feature count and lines count
        yield proc_evt_feature_count, lines_count
    def process_lines(self, training=False):
        return functools.partial(self._process_lines_impl, training=training)
    def count_freq(self, log_file_datum):
        # Process and event-feature reverse look-up table
        proc_rev = dict((
            (proc, i) for (i, proc) in enumerate(sorted(self.processes))
        ))
        evt_feature_rev = dict((
            (evt_opt, i) for (i, evt_opt) in enumerate(sorted(self.evt_feature_tuples))
        ))
        # Amount of total processes and event-feature tuples
        n_proc = len(proc_rev)
        n_evt_opt = len(evt_feature_rev)
        # Process each log file
        for proc_evt_feature_count, lines_count in log_file_datum:
            # Frequency matrix
            freq_matrix = np.zeros((n_proc+1, n_evt_opt+1))
            # Process each pair
            for (process_name, evt_feature_tuple), count in iteritems(proc_evt_feature_count):
                # Look for index in matrix
                proc_index = proc_rev.get(process_name, n_proc)
                evt_opt_index = evt_feature_rev.get(evt_feature_tuple, n_evt_opt)
                # Update matrix
                freq_matrix[proc_index][evt_opt_index] += count
            # Divide by lines count
            freq_matrix /= lines_count
            yield freq_matrix
