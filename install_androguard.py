#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
安装 androguard 的简单脚本，不指定版本要求
"""
import sys
import subprocess

print("正在安装 androguard...")
try:
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-cache-dir", "androguard"],
        check=True
    )
    print("安装 androguard 成功！")
except Exception as e:
    print(f"安装 androguard 时出错: {e}")
    sys.exit(1)

print("\n尝试导入 androguard...")
try:
    import androguard
    print(f"导入 androguard 成功，版本: {getattr(androguard, '__version__', '未知')}")
    
    import androguard.core
    print("导入 androguard.core 成功")
    
    import androguard.core.bytecodes
    print("导入 androguard.core.bytecodes 成功")
    
    from androguard.core.bytecodes.apk import APK
    print("导入 androguard.core.bytecodes.apk 成功")
    
    print("\n恭喜！androguard 已成功安装和导入，现在应该可以正常工作了。")
except Exception as e:
    print(f"导入 androguard 时出错: {e}")
    sys.exit(1)
