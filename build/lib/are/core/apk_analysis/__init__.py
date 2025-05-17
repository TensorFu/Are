#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/apk_analysis/__init__.py
"""
APK分析相关功能模块，用于解析APK文件和AndroidManifest.xml。
"""

from typing import Dict, List, Any, Optional

# 检查是否安装了androguard
try:
    import androguard
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

def is_androguard_available() -> bool:
    """
    检查是否安装了androguard
    
    返回:
        是否可用
    """
    global ANDROGUARD_AVAILABLE
    
    if not ANDROGUARD_AVAILABLE:
        return False
        
    # 检查是否可以导入核心组件
    try:
        import androguard.core
        import androguard.core.bytecodes
        from androguard.core.bytecodes.apk import APK
        return True
    except ImportError:
        return False
