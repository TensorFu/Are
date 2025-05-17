#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
诊断 androguard 库的安装和导入问题
"""

import sys
import os
import importlib
import subprocess
import traceback
import inspect

print(f"Python 版本: {sys.version}")
print(f"Python 路径: {sys.executable}")
print(f"系统路径: {sys.path}")

try:
    print("\n尝试导入 androguard 模块...")
    import androguard
    print(f"androguard 版本: {getattr(androguard, '__version__', 'Unknown')}")
    print(f"androguard 位置: {inspect.getfile(androguard)}")
    
    print("\nandroguard 包含的子模块:")
    for loader, name, ispkg in pkgutil.iter_modules(androguard.__path__, androguard.__name__ + '.'):
        print(f"- {name} ({'包' if ispkg else '模块'})")
    
    try:
        print("\n尝试导入 androguard.core...")
        import androguard.core
        print("导入 androguard.core 成功")
        print(f"androguard.core 位置: {inspect.getfile(androguard.core)}")
        
        try:
            print("\n尝试导入 androguard.core.bytecodes...")
            import androguard.core.bytecodes
            print("导入 androguard.core.bytecodes 成功")
            print(f"androguard.core.bytecodes 位置: {inspect.getfile(androguard.core.bytecodes)}")
            
            try:
                print("\n尝试导入 androguard.core.bytecodes.apk...")
                from androguard.core.bytecodes.apk import APK
                print("导入 androguard.core.bytecodes.apk 成功")
                print(f"APK 类位置: {inspect.getfile(APK)}")
            except ImportError as e:
                print(f"导入 androguard.core.bytecodes.apk 失败: {e}")
                print(traceback.format_exc())
        except ImportError as e:
            print(f"导入 androguard.core.bytecodes 失败: {e}")
            print(traceback.format_exc())
    except ImportError as e:
        print(f"导入 androguard.core 失败: {e}")
        print(traceback.format_exc())
except ImportError as e:
    print(f"导入 androguard 失败: {e}")
    print(traceback.format_exc())
    
    print("\n尝试使用 pip 获取 androguard 信息...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", "androguard"],
            capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            print("pip 显示 androguard 已安装:")
            print(result.stdout)
        else:
            print("androguard 未通过 pip 安装:")
            print(result.stderr)
    except Exception as e:
        print(f"运行 pip show 命令时出错: {e}")

print("\n尝试检查 site-packages 目录...")
import site
for site_dir in site.getsitepackages():
    print(f"检查 {site_dir}:")
    androguard_dir = os.path.join(site_dir, "androguard")
    if os.path.exists(androguard_dir):
        print(f"- androguard 目录存在: {androguard_dir}")
        
        # 检查子目录
        core_dir = os.path.join(androguard_dir, "core")
        if os.path.exists(core_dir):
            print(f"  - core 目录存在: {core_dir}")
            
            bytecodes_dir = os.path.join(core_dir, "bytecodes")
            if os.path.exists(bytecodes_dir):
                print(f"    - bytecodes 目录存在: {bytecodes_dir}")
                
                apk_file = os.path.join(bytecodes_dir, "apk.py")
                if os.path.exists(apk_file):
                    print(f"      - apk.py 文件存在: {apk_file}")
                else:
                    print(f"      - apk.py 文件不存在")
            else:
                print(f"    - bytecodes 目录不存在")
        else:
            print(f"  - core 目录不存在")
    else:
        print(f"- androguard 目录不存在")

# 检查是否有安装文件但没有成功导入
print("\n寻找所有 androguard 相关文件...")
for site_dir in site.getsitepackages():
    for root, dirs, files in os.walk(site_dir):
        for name in files + dirs:
            if "androguard" in name.lower():
                print(f"找到: {os.path.join(root, name)}")

# 尝试运行系统安装的 androguard
print("\n尝试运行 androguard 命令行工具...")
try:
    result = subprocess.run(
        ["androguard", "version"],
        capture_output=True, text=True, check=False
    )
    if result.returncode == 0:
        print(f"androguard 命令行工具可用: {result.stdout.strip()}")
    else:
        print(f"androguard 命令行工具出错: {result.stderr}")
except FileNotFoundError:
    print("androguard 命令行工具不可用")
except Exception as e:
    print(f"运行 androguard 命令时出错: {e}")

# 最后 - 尝试重新安装
print("\n尝试重新安装 androguard...")
try:
    import pip
    print("执行: pip uninstall -y androguard")
    pip.main(["uninstall", "-y", "androguard"])
    
    print("执行: pip install androguard")
    pip.main(["install", "androguard"])
    
    # 尝试再次导入
    print("\n尝试再次导入 androguard...")
    importlib.invalidate_caches()
    
    # 清除可能存在的旧模块
    for key in list(sys.modules.keys()):
        if key.startswith('androguard'):
            del sys.modules[key]
    
    import androguard
    print(f"导入成功，版本: {getattr(androguard, '__version__', 'Unknown')}")
    
    # 尝试导入问题模块
    from androguard.core.bytecodes.apk import APK
    print("成功导入 androguard.core.bytecodes.apk.APK")
    
except Exception as e:
    print(f"重新安装和导入失败: {e}")
    print(traceback.format_exc())
