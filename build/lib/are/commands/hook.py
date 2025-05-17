#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/hook.py

from typing import List, Any, Set
from prompt_toolkit.completion import Completion
import frida
import time
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
        # 调试日志：打印上下文信息
        console.debug("执行hook命令...")
        if hasattr(context, 'frida_session'):
            console.debug("context.frida_session存在")
        else:
            console.debug("context.frida_session不存在")
            
        if hasattr(context, 'current_process'):
            console.debug(f"当前进程: {context.current_process}")
        else:
            console.debug("当前进程未定义")
            
        # 解析命令参数
        parts = args.strip().split()
        if not parts:
            console.error("Usage: hook <method_signature> [--args] [--return] [--backtrace]")
            return

        method_signature = parts[0]
        options = set(part.lower() for part in parts[1:])
        
        # 默认行为：显示参数和返回值，以及回溯信息
        show_args = "--args" in options or not options
        show_return = "--return" in options or not options
        show_backtrace = "--backtrace" in options or True  # 默认显示回溯信息

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

        # 创建Frida Hook实例
        frida_hook = FridaHook()
        
        # 重要：检查Frida会话状态，并在必要时恢复会话
        self._ensure_frida_session_available(context)
        
        # 检查会话是否可用
        if hasattr(context, 'frida_session') and context.frida_session and hasattr(context, 'current_process') and context.current_process:
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
            console.error("未指定目标进程，请先使用 'watching <process_name>' 或 'watch <process_name>' 命令指定进程")

    def _ensure_frida_session_available(self, context):
        """
        确保Frida会话信息在当前上下文中可用
        如果会话不存在，尝试从工作空间元数据恢复
        
        参数:
            context: ARE实例
        """
        # 如果当前上下文已经有Frida会话信息，则无需处理
        if hasattr(context, 'frida_session') and context.frida_session:
            console.debug("Frida会话已存在于上下文中")
            return
        
        # 获取当前工作空间
        current_workspace = None
        if hasattr(context, 'workspace_manager'):
            current_workspace = context.workspace_manager.get_current_workspace()
        
        if not current_workspace or current_workspace.type.name != "PROCESS":
            console.debug("当前不在进程工作空间中，无法恢复Frida会话")
            return
        
        # 从工作空间元数据中获取任务ID
        task_id = current_workspace.metadata.get("task_id")
        if not task_id:
            console.debug("工作空间元数据中没有任务ID")
            return
        
        # 获取任务
        task = None
        if hasattr(context, 'task_manager'):
            task = next((t for t in context.task_manager.get_all_tasks() if t.id == task_id), None)
        
        if not task:
            console.debug(f"找不到任务ID: {task_id}")
            return
        
        # 从任务获取进程信息
        pid = task.pid
        process_name = task.process_name
        console.debug(f"从任务中获取到进程信息: {process_name} (PID: {pid})")
        
        # 尝试重新附加到进程
        try:
            # 尝试连接到设备
            device = None
            try:
                if hasattr(context, 'device'):
                    device = context.device
                else:
                    device = frida.get_usb_device(1)  # 1秒超时
            except Exception:
                try:
                    device = frida.get_local_device()
                except Exception as e:
                    console.debug(f"无法获取设备: {str(e)}")
                    return
            
            if not device:
                console.debug("无法获取设备")
                return
            
            # 尝试附加到进程
            try:
                console.debug(f"尝试附加到进程: {process_name} (PID: {pid})")
                session = device.attach(pid)
                
                # 验证是否附加到了正确的进程
                try:
                    # 使用简单的测试脚本检查进程
                    test_script = session.create_script("""
                    try {
                        if (Java.available) {
                            Java.perform(function() {
                                send({
                                    status: "success",
                                    process: Java.androidClassName || "unknown"
                                });
                            });
                        } else {
                            send({
                                status: "error",
                                error: "Java VM not available"
                            });
                        }
                    } catch(e) {
                        send({
                            status: "error",
                            error: e.toString()
                        });
                    }
                    """)
                    
                    process_verified = [False]  # 使用列表包装布尔值以便在闭包中修改
                    
                    def on_test_message(message, data):
                        if message['type'] == 'send':
                            payload = message.get('payload', {})
                            if payload.get('status') == 'success':
                                process_class = payload.get('process', 'unknown')
                                console.debug(f"检测到进程类: {process_class}")
                                actual_process_name = session.get_process_name()
                                if process_name in process_class or process_name in actual_process_name:
                                    process_verified[0] = True
                                    console.debug(f"进程验证成功: {process_name} 在 {actual_process_name} 或 {process_class} 中")
                                else:
                                    console.warning(f"进程验证失败: 期望 {process_name}，但连接到了 {actual_process_name}/{process_class}")
                            else:
                                console.warning(f"进程检查失败: {payload.get('error', 'unknown error')}")
                    
                    test_script.on('message', on_test_message)
                    test_script.load()
                    
                    # 给脚本一点时间执行
                    time.sleep(0.5)
                    
                    # 卸载测试脚本
                    test_script.unload()
                    
                    # 如果验证失败，尝试用包名重新查找正确的进程
                    if not process_verified[0]:
                        console.warning("尝试重新查找正确的进程...")
                        
                        # 尝试使用模糊匹配找到最接近的进程
                        matching_processes = []
                        for process in device.enumerate_processes():
                            if process_name.lower() in process.name.lower():
                                matching_processes.append({
                                    'name': process.name,
                                    'pid': process.pid
                                })
                        
                        if matching_processes:
                            best_match = matching_processes[0]
                            console.info(f"找到可能匹配的进程: {best_match['name']} (PID: {best_match['pid']})")
                            session.detach()
                            pid = best_match['pid']
                            process_name = best_match['name']
                            session = device.attach(pid)
                        else:
                            console.warning(f"无法找到匹配 {process_name} 的进程，将继续使用当前会话")
                except Exception as e:
                    console.warning(f"验证进程时出错 (非致命): {str(e)}")
                
                # 更新上下文中的会话信息
                context.frida_session = session
                context.current_process = process_name
                context.frida_device = device
                context.frida_pid = pid
                
                console.debug(f"成功恢复Frida会话: {process_name} (PID: {pid})")
            except Exception as e:
                console.debug(f"附加到进程时出错: {str(e)}")
        except Exception as e:
            console.debug(f"恢复Frida会话时出错: {str(e)}")

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
