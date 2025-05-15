#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/hook.py

from typing import List, Any, Set
from prompt_toolkit.completion import Completion
from are.commands.base import CommandBase
from are.core.theme.ui import AreConsole
from are.core.frida import FridaHook, restart_frida_server, check_frida_server_running

# 控制台实例
console = AreConsole()


class HookCommand(CommandBase):
    """方法钩子命令"""

    name = "hook"
    help_short = "Hook methods and functions"
    help_text = "Hook Java/Objective-C methods or native functions to view their parameters and return values"
    usage = "hook <method_signature> [--args] [--return] [--backtrace]"
    examples = [
        "hook com.example.app.MainActivity.onCreate",
        "hook java.net.URL.openConnection --args --return",
        "hook com.company.app.Api.login --args --return --backtrace",
        "hook libnative.so!decrypt --args --return"
    ]

    def execute(self, context: Any, args: str):
        """
        执行命令

        参数:
            context: ARE实例
            args: 命令参数
        """
        if not context.current_session:
            console.error("No active session!")
            return

        parts = args.strip().split()
        if not parts:
            console.error("Usage: hook <method_signature> [--args] [--return] [--backtrace]")
            return

        method_signature = parts[0]
        options = set(part.lower() for part in parts[1:])
        
        # 默认行为：显示参数和返回值，但不显示回溯
        show_args = "--args" in options or not options
        show_return = "--return" in options or not options
        show_backtrace = "--backtrace" in options

        # 检查 Frida 服务器是否在运行
        if not check_frida_server_running():
            console.warning("Frida服务器未运行，尝试启动...")
            if not restart_frida_server():
                console.error("无法启动Frida服务器，请确保已正确安装")
                return

        console.info(f"目标方法: {method_signature}")
        console.info(f"选项: " + 
                   f"{'参数 ' if show_args else ''}" +
                   f"{'返回值 ' if show_return else ''}" +
                   f"{'回溯' if show_backtrace else ''}")

        try:
            # 创建Frida Hook实例
            frida_hook = FridaHook()
            
            # 在两层会话模式下hook方法
            if hasattr(context, 'frida_session') and context.frida_session:
                console.info(f"在现有会话中hook方法: {method_signature}")
                
                # 使用已有会话进行hook
                script = frida_hook.hook_method(
                    session=context.frida_session,
                    method_signature=method_signature,
                    include_args=show_args,
                    include_return_value=show_return,
                    include_backtrace=show_backtrace
                )
                
                if script:
                    # 保存脚本引用，以便在需要时可以卸载
                    if not hasattr(context, 'frida_scripts'):
                        context.frida_scripts = []
                    context.frida_scripts.append(script)
                    
                    console.success(f"成功hook方法: {method_signature}")
                    console.info("方法被调用时将自动显示信息")
                else:
                    console.error(f"Hook方法失败: {method_signature}")
            else:
                # 如果没有现有会话，则创建新会话
                if hasattr(context, 'current_process') and context.current_process:
                    process_name = context.current_process
                    console.info(f"使用当前进程: {process_name}")
                    
                    # 执行Hook
                    frida_hook.run_hook(
                        process_name=process_name,
                        method_signature=method_signature,
                        include_args=show_args,
                        include_return_value=show_return,
                        include_backtrace=show_backtrace
                    )
                else:
                    console.error("未指定目标进程，请先使用 'watch <process_name>' 命令指定进程")
                    return
            
        except Exception as e:
            console.error(f"Hook方法时出错: {str(e)}")
            import traceback
            console.debug(traceback.format_exc())

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        if len(args) == 0 or (len(args) == 1 and not document.text.endswith(' ')):
            # 类/方法名补全
            common_classes = [
                "com.android.app.Activity", 
                "java.net.URL",
                "android.webkit.WebView",
                "java.security.MessageDigest",
                "javax.crypto.Cipher",
                "libart.so!ExecuteSwitch",
                "libssl.so!SSL_read"
            ]
            
            word = args[0] if args else ""
            for cls in common_classes:
                if cls.startswith(word):
                    yield Completion(cls, start_position=-len(word),
                                   display=cls, display_meta="class/method")
            return
            
        if len(args) >= 1 and document.text.endswith(' '):
            # 选项补全
            options = ["--args", "--return", "--backtrace"]
            used_options = set(arg.lower() for arg in args[1:])
            
            for option in options:
                if option not in used_options:
                    yield Completion(option, start_position=0,
                                   display=option, display_meta="hook option")
