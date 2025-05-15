#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os

# 将当前目录添加到路径
sys.path.insert(0, os.path.abspath("."))

# 尝试导入CLI并运行
from are.cli import main

if __name__ == "__main__":
    main()
