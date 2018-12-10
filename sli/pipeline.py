#! /usr/bin/env python
from __future__ import unicode_literals, division
import os, functools, logging
import numpy as np
from scipy.sparse import csr_matrix
from six import iterkeys, iteritems
from six.moves import range

from sli.parser import parse_line, parse_args_str, parse_option_args, parse_fd_args
from sli.processing import FreqCounter, inspect_line, log_pipeline, lines_from_file, \
    remove_events, opt_arg_features, fd_features

# Logger
_logger = logging.getLogger(__name__)

# Option arguments
_OPT_ARGS_MAP = {
    "mmap": ["prot", "flags"],
    "futex": ["op"],
    "access": ["mode"],
    "open": ["flags"],
    "fcntl": ["cmd"],
    "lseek": ["whence"],
    "clone": ["flags"]
}
# File descriptor path patterns
_FD_PATH_PATTERNS = [
    # Top-level directories
    r"^\/bin",
    r"^\/dev",
    r"^\/etc",
    r"^\/home",
    r"^\/lib",
    r"^\/proc",
    r"^\/run",
    r"^\/sbin",
    r"^\/sys",
    r"^\/tmp",
    r"^\/usr",
    r"^\/var"
]

# Log feature passes and generators
_LOG_FEATURE_MAP = {
    # Option arguments
    "option-arg": (
        (lambda: parse_option_args(event_opt_args=_OPT_ARGS_MAP)),
        (lambda: opt_arg_features(_OPT_ARGS_MAP))
    ),
    # File descriptor arguements
    "fd": (
        parse_fd_args,
        (lambda: fd_features(_FD_PATH_PATTERNS))
    )
}

def run_pipeline(file_path, freq_counter, *passes, **kwargs):
    """ Helper function for constructing and running pipelines. """
    # Build all passes for the pipeline
    all_passes = [
        lines_from_file(file_path),
        # Parse line
        parse_line(),
        # Remove given events
        remove_events("switch"),
        # Parse arguments string
        parse_args_str()
    ]
    # Supplied passes
    all_passes += passes
    # Process lines with frequence counter
    all_passes += [
        # Process lines with frequency counter
        freq_counter.process_lines(training=kwargs.get("training", False))
    ]
    return log_pipeline(*all_passes)

def log_dataset_path(dataset_root, dataset_name, i):
    """ Helper function for assembling file path in log dataset. """
    return os.path.join(
        dataset_root,
        dataset_name,
        "{}log-{}.txt".format(dataset_name, i)
    )

def gen_training_dataset_part(dataset_root, idx_map, freq_counter, *passes, **kwargs):
    """ Generate training, validation or testing part of the training dataset. """
    # Temporary result and labels
    x_tmp = []
    labels = []
    # Dataset names
    dataset_names = sorted(iterkeys(idx_map))
    # Process all training set
    for label, dataset_name in enumerate(dataset_names):
        idx_array = idx_map[dataset_name]
        idx_size = len(idx_array)
        # Process logs
        for i, idx in enumerate(idx_array):
            _logger.debug(
                "[Training] Processing %s log #%d (%d/%d)",
                dataset_name, idx+1, i+1, idx_size
            )
            # Run pipeline for each log
            x_tmp += run_pipeline(
                log_dataset_path(dataset_root, dataset_name, idx+1),
                freq_counter,
                *passes,
                training=kwargs.get("training", False)
            )
        # Append labels
        labels = np.concatenate([labels, np.repeat(label, idx_size)])
    # Count frequency on each log
    x = log_pipeline(x_tmp, freq_counter.count_freq)
    # Reshape matrix into vector
    x = np.reshape(x, (len(x), -1))
    return x, labels

def passes_features(log_features):
    """ Additional passes and feature generators for log features. """
    # Additional pipeline passes
    passes = [_LOG_FEATURE_MAP[feature][0]() for feature in log_features]
    # Additional feature generators
    feature_generators = [_LOG_FEATURE_MAP[feature][1]() for feature in log_features]
    return passes, feature_generators

def gen_training_dataset(dataset_root, dataset_size_map, log_features=[]):
    """ Process logs and generate full training dataset with training, validation and testing data. """
    # Pipeline passes and feature generators
    passes, feature_generators = passes_features(log_features)
    # Frequency counter
    freq_counter = FreqCounter(feature_generators=feature_generators)
    # Training, validation and testing set indexes
    train_idx_map = {}
    validate_idx_map = {}
    test_idx_map = {}
    # Dataset names
    dataset_names = sorted(iterkeys(dataset_size_map))
    # Generate indexes
    for dataset_name, size in iteritems(dataset_size_map):
        rand_idx = np.random.permutation(size)
        # Training, validation and test set range
        train_max = int(size*0.6)
        validate_max = train_max+int(size*0.2)
        # Set indexes
        train_idx_map[dataset_name] = rand_idx[:train_max]
        validate_idx_map[dataset_name] = rand_idx[train_max:validate_max]
        test_idx_map[dataset_name] = rand_idx[validate_max:]
    # Training, validation and testing data
    _logger.debug("[Training] Processing training set")
    x_train, labels_train = gen_training_dataset_part(
        dataset_root, train_idx_map, freq_counter, *passes, training=True
    )
    _logger.debug("[Training] Processing validation set")
    x_validate, labels_validate = gen_training_dataset_part(
        dataset_root, validate_idx_map, freq_counter, *passes
    )
    _logger.debug("[Training] Processing testing set")
    x_test, labels_test = gen_training_dataset_part(
        dataset_root, test_idx_map, freq_counter, *passes
    )
    # Compress feature data for smaller file size
    return csr_matrix(x_train), \
        labels_train, \
        csr_matrix(x_validate), \
        labels_validate, \
        csr_matrix(x_test), \
        labels_test, \
        dataset_names, \
        sorted(freq_counter.processes), \
        sorted(freq_counter.evt_feature_tuples), \
        log_features

def gen_detection_dataset(dataset_path, processes, evt_feature_tuples, n_logs=0, log_features=[]):
    """ Process logs and generate detection dataset. """
    # Pipeline passes and feature generators
    passes, feature_generators = passes_features(log_features)
    # Frequency counter
    freq_counter = FreqCounter(
        processes=processes,
        evt_feature_tuples=evt_feature_tuples,
        feature_generators=feature_generators
    )
    # Single log
    if n_logs==0:
        log_names = [dataset_path]   
    # Multiple logs
    else:
        dataset_name = os.path.basename(dataset_path)
        dataset_parent = os.path.dirname(dataset_path)
        log_names = (log_dataset_path(dataset_parent, dataset_name, i+1) for i in range(n_logs))
    # Temporary result
    x_tmp = []
    # Process logs
    for i, log_name in enumerate(log_names):
        # Prompt progress
        if n_logs>0:
            _logger.debug(
                "[Detection] Processing %s log (%d/%d)",
                dataset_name, i+1, n_logs
            )
        else:
            _logger.debug("[Detection] Processing log %s", dataset_path)
        # Run pipeline for each log
        x_tmp += run_pipeline(log_name, freq_counter, *passes)
    # Count frequency on each log
    x = log_pipeline(x_tmp, freq_counter.count_freq)
    # Reshape matrix into vector
    x = np.reshape(x, (len(x), -1))
    return csr_matrix(x)
