#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name="are",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "frida-tools",
        "click",
        "rich",
        "prompt_toolkit",
        "hexdump",
    ],
    entry_points={
        'console_scripts': [
            'are=are.cli:main',
        ],
    },
    python_requires='>=3.6',
    package_data={
        'are': [
            'resources/*',
            'scripts/*.ts',
            'scripts/modules/*.ts',
        ],
    },
)