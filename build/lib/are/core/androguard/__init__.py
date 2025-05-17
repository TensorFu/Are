#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/androguard/__init__.py
"""
androguard 相关功能模块，用于解析APK文件和AndroidManifest.xml。
"""

from typing import Dict, List, Any, Optional

# 检查是否安装了androguard
try:
    import androguard
except ImportError:
    androguard = None

def is_androguard_available() -> bool:
    """
    检查是否安装了androguard
    
    返回:
        是否可用
    """
    return androguard is not None
