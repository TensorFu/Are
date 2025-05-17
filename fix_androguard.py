#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
修复 androguard 安装问题的脚本 - 专门安装 3.4.0 版本
"""

import sys
import subprocess
import importlib
import shutil
import os
import site

print(f"Python 版本: {sys.version}")
print(f"Python 路径: {sys.executable}")

# 尝试卸载当前版本
print("\n尝试卸载当前版本...")
try:
    subprocess.run(
        [sys.executable, "-m", "pip", "uninstall", "-y", "androguard"],
        check=True
    )
    print("卸载成功")
except Exception as e:
    print(f"卸载时出错: {e}")

# 清除可能存在的残留文件
print("\n清除残留文件...")
for site_dir in site.getsitepackages():
    androguard_dir = os.path.join(site_dir, "androguard")
    if os.path.exists(androguard_dir):
        print(f"删除目录: {androguard_dir}")
        try:
            shutil.rmtree(androguard_dir)
            print(f"成功删除 {androguard_dir}")
        except Exception as e:
            print(f"删除 {androguard_dir} 时出错: {e}")

# 安装 androguard 3.4.0 版本
print("\n安装 androguard 3.4.0 版本...")
try:
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-cache-dir", "androguard==3.4.0"],
        check=True
    )
    print("安装 androguard 3.4.0 成功")
except Exception as e:
    print(f"安装 androguard 3.4.0 时出错: {e}")
    
    # 如果安装失败，尝试其他方法
    print("\n尝试使用其他方法安装...")
    try:
        # 尝试从 GitHub 安装
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-cache-dir", "git+https://github.com/androguard/androguard.git@v3.4.0"],
            check=True
        )
        print("从 GitHub 安装 androguard 3.4.0 成功")
    except Exception as e:
        print(f"从 GitHub 安装 androguard 3.4.0 时出错: {e}")
        
        # 如果仍然失败，尝试安装最新版本
        print("\n尝试安装最新版本的 androguard...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--force-reinstall", "androguard"],
                check=True
            )
            print("安装最新版本成功")
        except Exception as e:
            print(f"安装最新版本时出错: {e}")

# 重新加载模块
print("\n重新加载模块...")
importlib.invalidate_caches()

# 清除所有 androguard 模块
for key in list(sys.modules.keys()):
    if key.startswith('androguard'):
        del sys.modules[key]

# 尝试导入
print("\n尝试导入 androguard...")
try:
    import androguard
    print(f"导入 androguard 成功，版本: {getattr(androguard, '__version__', 'Unknown')}")
    
    # 检查 core 模块
    print("\n尝试导入 androguard.core...")
    import androguard.core
    print("导入 androguard.core 成功")
    
    # 检查 bytecodes 模块
    print("\n尝试导入 androguard.core.bytecodes...")
    import androguard.core.bytecodes
    print("导入 androguard.core.bytecodes 成功")
    
    # 检查 apk 模块
    print("\n尝试导入 androguard.core.bytecodes.apk...")
    from androguard.core.bytecodes.apk import APK
    print("导入 androguard.core.bytecodes.apk 成功")
    
    print("\n恭喜！androguard 已成功安装和导入，现在应该可以正常工作了。")
except ImportError as e:
    print(f"\n导入失败: {e}")
    print("\n似乎安装仍然存在问题。这可能是由于以下原因:")
    print("1. Python 3.12 可能与 androguard 不兼容")
    print("2. 操作系统的特定依赖缺失")
    print("3. 安装过程中的权限问题")
    
    print("\n您可以尝试以下解决方案:")
    print("1. 降级到 Python 3.9 或 3.10 并重新安装 androguard")
    print("2. 使用替代实现 (alternative_explore.py)")
    print("3. 手动从源代码安装:")
    print("   git clone https://github.com/androguard/androguard.git")
    print("   cd androguard")
    print("   pip install -e .")
    
except Exception as e:
    print(f"\n出现意外错误: {e}")
