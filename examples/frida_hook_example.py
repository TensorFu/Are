#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# examples/frida_hook_example.py
"""
Frida Hook 示例

该示例演示如何使用 ARE 的 Frida Hook 功能来监控应用程序方法调用
"""

import os
import sys
import time

# 将项目根目录添加到路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from are.core.theme.ui import AreConsole
from are.core.frida import (
    FridaHook, 
    check_frida_server_running,
    restart_frida_server
)

# 创建控制台
console = AreConsole()

def main():
    """主函数"""
    console.banner("Frida Hook 示例")
    
    # 检查 Frida 服务器是否在运行
    if not check_frida_server_running():
        console.warning("Frida 服务器未运行，尝试启动...")
        if not restart_frida_server():
            console.error("无法启动 Frida 服务器，请确保已正确安装")
            return
    
    # 目标进程和方法
    process_name = "com.android.chrome"
    method_signature = "java.net.URL.openConnection"
    
    console.info(f"目标进程: {process_name}")
    console.info(f"目标方法: {method_signature}")
    console.info("选项: 显示参数，显示返回值，不显示回溯")
    
    # 创建 Frida Hook 实例
    hook = FridaHook()
    
    try:
        # 运行 Hook
        hook.run_hook(
            process_name=process_name,
            method_signature=method_signature,
            include_args=True,
            include_return_value=True,
            include_backtrace=False
        )
    except KeyboardInterrupt:
        console.info("用户中断，退出...")
    except Exception as e:
        console.error(f"Hook 时出错: {str(e)}")
        import traceback
        console.debug(traceback.format_exc())

if __name__ == "__main__":
    main()
