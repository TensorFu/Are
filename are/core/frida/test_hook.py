#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/frida/test_hook.py
# 用于测试Frida Hook功能是否正常工作

import os
import sys
from pathlib import Path
from are.core.theme.ui import AreConsole
from are.core.frida import FridaHook, restart_frida_server, check_frida_server_running

# 控制台实例
console = AreConsole()

def test_compilation():
    """测试TypeScript编译"""
    console.banner("测试Frida Hook TypeScript编译")
    
    hook = FridaHook()
    result = hook.compile_typescript()
    
    if result:
        console.success("✅ TypeScript编译成功！")
    else:
        console.error("❌ TypeScript编译失败！")
    
    # 检查编译后的文件是否存在
    js_path = hook.dist_path / "hook.js"
    if js_path.exists():
        console.success(f"✅ 编译后的JavaScript文件存在: {js_path}")
        
        # 显示文件大小
        file_size = os.path.getsize(js_path)
        console.info(f"文件大小: {file_size} 字节")
        
        # 显示文件前几行
        with open(js_path, 'r') as f:
            lines = f.readlines()[:5]
            console.info("文件前几行内容:")
            for line in lines:
                console.print(f"  {line.strip()}")
    else:
        console.error(f"❌ 编译后的JavaScript文件不存在: {js_path}")

def main():
    """主函数"""
    console.banner("Frida Hook 测试工具")
    
    # 测试TypeScript编译
    test_compilation()
    
    # 检查Frida服务器
    console.info("\n检查Frida服务器状态...")
    if check_frida_server_running():
        console.success("✅ Frida服务器正在运行")
    else:
        console.warning("⚠️ Frida服务器未运行")
        restart = input("是否尝试启动Frida服务器？(y/n): ")
        if restart.lower() == 'y':
            if restart_frida_server():
                console.success("✅ Frida服务器启动成功")
            else:
                console.error("❌ Frida服务器启动失败")
                return
    
    # 是否要运行hook测试
    run_hook_test = input("\n是否要运行实际的Hook测试？(y/n): ")
    if run_hook_test.lower() != 'y':
        console.info("跳过Hook测试")
        return
    
    # 获取测试目标
    console.info("\n请选择Hook测试目标:")
    console.info("1. com.android.settings - Settings应用(Java方法)")
    console.info("2. com.android.chrome - Chrome浏览器(Java方法)")
    console.info("3. 自定义目标")
    
    choice = input("请输入选择(1-3): ")
    
    if choice == '1':
        process_name = "com.android.settings"
        method_signature = "android.os.Bundle.getString"
    elif choice == '2':
        process_name = "com.android.chrome"
        method_signature = "java.net.URL.openConnection"
    elif choice == '3':
        process_name = input("请输入进程名称: ")
        method_signature = input("请输入方法签名: ")
    else:
        console.error("无效的选择")
        return
    
    # 运行Hook测试
    console.info(f"\n开始Hook测试: {process_name} - {method_signature}")
    console.info("按Ctrl+C可以停止测试")
    
    hook = FridaHook()
    try:
        hook.run_hook(
            process_name=process_name,
            method_signature=method_signature,
            include_args=True,
            include_return_value=True,
            include_backtrace=False
        )
    except KeyboardInterrupt:
        console.info("用户中断，测试结束")
    except Exception as e:
        console.error(f"Hook测试出错: {str(e)}")
        import traceback
        console.debug(traceback.format_exc())

if __name__ == "__main__":
    main()
