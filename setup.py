#! /usr/bin/env python
from __future__ import unicode_literals, division, print_function
from setuptools import setup

setup(
    name="sysdig-log-insider",
    version="0.1.0",
    descriptor="Sysdig system call log processor and analyzer.",
    author="Qifan Lu",
    author_email="lqf96@uw.edu",
    url="https://github.com/lqf96/sysdig-log-insider",
    packages=["sli"],
    scripts=[
        "sli-gen-training",
        "sli-gen-detection"
    ],
    install_requires=[
        "numpy",
        "scipy",
        "six",
        "namedlist"
    ]
)
