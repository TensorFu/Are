#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/watch.py

from typing import List, Any
from prompt_toolkit.completion import Completion
import frida
import time
from are.commands.base import CommandBase
from are.core.theme.ui import AreConsole
from are.core.frida import restart_frida_server, check_frida_server_running

# 控制台实例
console = AreConsole()


class WatchCommand(CommandBase):
    """进程观察命令"""

    name = "watch"
    help_short = "Watch and attach to a process"
    help_text = "Watch and attach to a process to establish a Frida session for hooking"
    usage = "watch <process_name>"
    examples = [
        "watch com.android.browser",
        "watch com.example.app"
    ]

    def execute(self, context: Any, args: str):
        """
        执行命令

        参数:
            context: ARE实例
            args: 命令参数
        """
        parts = args.strip().split()
        if not parts:
            console.error("Usage: watch <process_name>")
            return

        process_name = parts[0]

        # 检查 Frida 服务器是否在运行
        if not check_frida_server_running():
            console.warning("Frida服务器未运行，尝试启动...")
            if not restart_frida_server():
                console.error("无法启动Frida服务器，请确保已正确安装")
                return

        console.info(f"尝试连接到进程: {process_name}")

        try:
            # 尝试连接到设备
            try:
                device = frida.get_usb_device(1)  # 1秒超时
            except Exception as e:
                console.warning(f"无法连接到USB设备: {str(e)}")
                console.info("尝试连接到本地设备...")
                device = frida.get_local_device()
            
            console.info(f"已连接到设备: {device.name}")
            
            # 查找匹配进程
            matching_processes = []
            
            # 1. 首先尝试使用Frida API
            try:
                # 尝试直接查找进程
                try:
                    pid = device.get_process(process_name).pid
                    matching_processes.append({
                        'name': process_name,
                        'pid': pid,
                        'source': 'frida-direct'
                    })
                except:
                    # 如果直接查找失败，则枚举所有进程
                    for process in device.enumerate_processes():
                        if process_name.lower() in process.name.lower():
                            matching_processes.append({
                                'name': process.name,
                                'pid': process.pid,
                                'source': 'frida-enum'
                            })
            except Exception as e:
                console.warning(f"使用Frida API查找进程失败: {str(e)}")
            
            # 2. 如果还没找到进程，或者特别是Chrome，尝试使用adb命令
            if not matching_processes or process_name.lower() == "com.android.chrome":
                try:
                    import subprocess
                    import re
                    
                    console.info("尝试使用adb命令查找进程...")
                    
                    # 使用adb shell ps命令查找进程
                    cmd = ["adb", "shell", "ps | grep " + process_name]
                    
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                    if result.returncode == 0 or result.returncode == 1:  # grep返回1表示没有匹配
                        lines = result.stdout.strip().split('\n')
                        for line in lines:
                            if line.strip() and process_name in line:
                                parts = line.strip().split()
                                if len(parts) >= 2:
                                    for i, part in enumerate(parts):
                                        if part.isdigit() and i < len(parts) - 1:
                                            pid = int(part)
                                            name = parts[-1]
                                            if not any(p['pid'] == pid for p in matching_processes):
                                                matching_processes.append({
                                                    'name': name,
                                                    'pid': pid,
                                                    'source': 'adb'
                                                })
                                            break
                except Exception as e:
                    console.warning(f"使用adb查找进程失败: {str(e)}")
            
            # 3. 处理查找结果
            if not matching_processes:
                console.error(f"找不到进程: {process_name}")
                return
            
            # 如果有多个匹配的进程，让用户选择
            selected_process = None
            if len(matching_processes) > 1:
                console.info(f"找到 {len(matching_processes)} 个匹配进程:")
                for i, proc in enumerate(matching_processes):
                    console.print(f"[{i}] {proc['name']} (PID: {proc['pid']})")
                
                # 获取用户选择
                try:
                    selection = input("请选择进程 (0): ")
                    if not selection.strip():
                        selection = "0"
                    index = int(selection)
                    if 0 <= index < len(matching_processes):
                        selected_process = matching_processes[index]
                    else:
                        console.error("无效的选择")
                        return
                except ValueError:
                    console.error("无效的选择，请输入数字")
                    return
            else:
                # 只有一个匹配
                selected_process = matching_processes[0]
            
            # 4. 附加到选择的进程
            pid = selected_process['pid']
            process_name = selected_process['name']
            
            try:
                # 尝试附加到进程
                session = device.attach(pid)
                console.success(f"已附加到进程 {process_name} (PID: {pid})")
            except Exception as e:
                # 如果附加失败，尝试spawn启动
                console.info(f"附加失败，尝试spawn启动: {str(e)}")
                try:
                    pid = device.spawn([process_name])
                    session = device.attach(pid)
                    console.success(f"已启动并附加到进程 {process_name} (PID: {pid})")
                    
                    # 恢复进程执行
                    device.resume(pid)
                    console.info("进程已恢复执行")
                except Exception as spawn_e:
                    console.error(f"无法启动进程: {str(spawn_e)}")
                    return
            
            # 保存会话和进程信息到上下文
            context.frida_session = session
            context.current_process = process_name
            context.frida_device = device
            context.frida_pid = pid
            
            # 添加一个简单的监听脚本，以确保会话保持活跃
            monitor_script = session.create_script("""
            console.log("[*] 会话监控已启动");
            
            // 定期发送心跳以保持会话活跃
            setInterval(function() {
                send("heartbeat");
            }, 10000);
            
            // 监听系统事件
            Process.setExceptionHandler(function(exception) {
                console.log("[!] 进程异常: " + JSON.stringify(exception));
                return false;
            });
            """)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    if message.get('payload') == 'heartbeat':
                        # 忽略心跳消息
                        pass
                    else:
                        console.info(f"[Monitor] {message.get('payload', '')}")
                elif message['type'] == 'error':
                    console.error(f"[Monitor Error] {message.get('description', '未知错误')}")
            
            monitor_script.on('message', on_message)
            monitor_script.load()
            
            # 保存监控脚本到上下文
            context.frida_monitor = monitor_script
            
            console.success(f"成功建立会话: {process_name}")
            console.info("现在您可以使用 'hook <method_signature>' 命令来hook特定方法")
            
        except frida.ProcessNotFoundError:
            console.error(f"找不到进程: {process_name}")
        except frida.ServerNotRunningError:
            console.error("Frida 服务器未运行，请确保已启动 frida-server")
        except Exception as e:
            console.error(f"连接到进程时出错: {str(e)}")
            import traceback
            console.debug(traceback.format_exc())

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        if len(args) == 0 or (len(args) == 1 and not document.text.endswith(' ')):
            # 进程名补全
            common_processes = [
                "com.android.browser", 
                "com.android.settings",
                "com.google.android.apps.maps",
                "com.android.chrome",
                "com.android.vending",
                "com.android.launcher",
                "com.android.systemui",
                "com.google.android.gms",
                "com.google.android.gms.persistent",
                "com.google.android.gms.unstable",
                "com.google.android.googlequicksearchbox",
                "com.google.process.gapps",
                "system_server",
                "media.codec",
                "media.swcodec",
                "surfaceflinger"
            ]
            
            word = args[0] if args else ""
            for proc in common_processes:
                if word.lower() in proc.lower() or proc.lower().startswith(word.lower()):
                    yield Completion(proc, start_position=-len(word),
                                   display=proc, display_meta="process")
