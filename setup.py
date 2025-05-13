#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# setup.py
from setuptools import setup, find_packages

# 读取README
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="are",
    version="0.1",
    description="Android Reverse Engineering Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Tensor",
    author_email="zhizhongemail@gmail.com",
    url="https://github.com/TensorFu/Are",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "frida-tools",
        "click",
        "rich",
        "prompt_toolkit",
        "hexdump",
        "androguard"
    ],
    entry_points={ # 入口
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
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)