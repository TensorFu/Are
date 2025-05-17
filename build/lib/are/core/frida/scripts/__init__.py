#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/frida/scripts/__init__.py
# 此文件确保scripts目录被识别为Python包

# 确保src和dist目录存在
import os
from pathlib import Path

# 创建目录
script_dir = Path(__file__).parent
src_dir = script_dir / "src"
dist_dir = script_dir / "dist"

# 确保目录存在
src_dir.mkdir(exist_ok=True)
dist_dir.mkdir(exist_ok=True)
