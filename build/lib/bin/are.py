#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os

# 确保包能被导入
script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, script_dir)

from are.cli import main

if __name__ == "__main__":
    main()