#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/watch.py

from typing import List, Any
from prompt_toolkit.completion import Completion
import frida
import time
import re
from are.commands.base import CommandBase
from are.core.theme.ui import AreConsole
from are.core.frida import restart_frida_server, check_frida_server_running
from are.core.frida import FridaHook
from are.core.tasks import Task

# 控制台实例
console = AreConsole()


class WatchCommand(CommandBase):
    """进程观察命令"""

    name = "watching"
    help_short = "Watch and attach to a process"
    help_text = """Watch and attach to a process to establish a Frida session for hooking
    
    使用方式:
    1. watching processName - 使用attach方式hook进程，在第二层会话可以直接使用hook命令
    2. watching packageName with "hook 方法路径" - 使用spawn方式启动并hook指定方法
    """
    usage = """watching <process_name> - 使用attach方式
watching <package_name> with "hook 方法路径" - 使用spawn方式"""
    examples = [
        "watching com.android.browser",
        "watching com.example.app",
        "watching com.example.app with \"hook com.example.app.MainActivity.onCreate\""
    ]

    def execute(self, context: Any, args: str):
        """
        执行命令

        参数:
            context: ARE实例
            args: 命令参数
        """
        # 解析参数
        if "with" in args:
            # 使用spawn方式
            self._execute_spawn_mode(context, args)
        else:
            # 使用attach方式
            self._execute_attach_mode(context, args.strip())

    def _execute_attach_mode(self, context: Any, process_name: str):
        """
        使用attach方式执行
        
        参数:
            context: ARE实例
            process_name: 进程名称
        """
        if not process_name:
            console.error("用法: watching <process_name>")
            return

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
                
                # 创建任务
                task = context.task_manager.create_task(
                    pid=pid, 
                    process_name=process_name,
                    description=f"Attach to {process_name}",
                    is_spawned=False
                )
                
                # 在全局上下文和任务元数据中保存会话信息
                context.frida_session = session
                context.current_process = process_name
                context.frida_device = device
                context.frida_pid = pid
                
                # 更新任务元数据
                task.metadata["device_name"] = device.name
                task.metadata["connection_type"] = "attach"
                
                # 创建进程监视工作空间
                workspace = context.workspace_manager.create_workspace(
                    name=f"Process: {process_name}",
                    type=context.core.tasks.WorkspaceType.PROCESS,
                    metadata={
                        "task_id": task.id,
                        "device_name": device.name,
                        "process_name": process_name,
                        "pid": pid,
                        "connection_type": "attach"
                    },
                    command_handler=lambda cmd: self._process_workspace_command(context, cmd)
                )
                
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
                
                # 切换到新创建的工作空间
                context.workspace_manager.switch_to_workspace(workspace.id)
                
                console.success(f"成功建立会话: {process_name}")
                console.info("进入到进程工作空间, 现在可以直接输入 hook <method_signature> 命令来hook特定方法")
                
                # 启动新的控制台会话
                context._start_console()
                
            except frida.ProcessNotFoundError:
                console.error(f"找不到进程: {process_name}")
            except frida.ServerNotRunningError:
                console.error("Frida 服务器未运行，请确保已启动 frida-server")
            except Exception as e:
                console.error(f"连接到进程时出错: {str(e)}")
                import traceback
                console.debug(traceback.format_exc())
            
        except frida.ProcessNotFoundError:
            console.error(f"找不到进程: {process_name}")
        except frida.ServerNotRunningError:
            console.error("Frida 服务器未运行，请确保已启动 frida-server")
        except Exception as e:
            console.error(f"连接到进程时出错: {str(e)}")
            import traceback
            console.debug(traceback.format_exc())

    def _execute_spawn_mode(self, context: Any, args: str):
        """
        使用spawn方式执行
        
        参数:
            context: ARE实例
            args: 命令参数
        """
        # 解析参数 - 支持多个命令，以逗号分隔
        match = re.match(r'(.*?)\s+with\s+"(.*?)"', args)
        if not match:
            console.error('用法: watching <package_name> with "hook 方法路径1, hook 方法路径2, ..."')
            return
        
        package_name = match.group(1).strip()
        commands_str = match.group(2).strip()
        
        if not package_name or not commands_str:
            console.error('用法: watching <package_name> with "hook 方法路径1, hook 方法路径2, ..."')
            return
            
        # 解析命令列表
        commands = [cmd.strip() for cmd in commands_str.split(',')]
        
        # 检查命令格式
        method_signatures = []
        for cmd in commands:
            if cmd.startswith("hook "):
                method_signatures.append(cmd[5:].strip())
            else:
                console.warning(f"不支持的命令: {cmd}，目前仅支持 hook 命令")
        
        if not method_signatures:
            console.error('无有效命令，用法: watching <package_name> with "hook 方法路径1, hook 方法路径2, ..."')
            return
        
        # 检查 Frida 服务器是否在运行
        if not check_frida_server_running():
            console.warning("Frida服务器未运行，尝试启动...")
            if not restart_frida_server():
                console.error("无法启动Frida服务器，请确保已正确安装")
                return
        
        console.info(f"尝试使用Spawn方式启动并hook包: {package_name}")
        console.info(f"目标方法: {method_signature}")
        
        try:
            # 创建Frida Hook实例
            frida_hook = FridaHook()
            
            # 尝试连接到设备
            try:
                device = frida.get_usb_device(1)  # 1秒超时
            except Exception as e:
                console.warning(f"无法连接到USB设备: {str(e)}")
                console.info("尝试连接到本地设备...")
                device = frida.get_local_device()
            
            console.info(f"已连接到设备: {device.name}")
            
            # 尝试使用spawn启动进程
            console.info(f"尝试spawn启动进程: {package_name}")
            try:
                # 尝试使用 spawn 方式
                try:
                    pid = device.spawn([package_name])
                    console.success(f"进程已启动，PID: {pid}")
                except frida.Error as e:
                    # 检查是否是内存分配错误
                    if "unexpected crash while trying to allocate memory" in str(e):
                        console.warning("Spawn 模式内存分配失败，尝试使用替代方法...")
                        
                        # 尝试使用不同的注入方法
                        # 首先尝试直接附加到已运行的进程
                        try:
                            matching_processes = []
                            for process in device.enumerate_processes():
                                if package_name.lower() in process.name.lower():
                                    matching_processes.append({
                                        'name': process.name,
                                        'pid': process.pid
                                    })
                            
                            if matching_processes:
                                # 找到了匹配的进程，尝试附加
                                selected_process = matching_processes[0]
                                pid = selected_process['pid']
                                
                                console.info(f"尝试附加到已运行的进程: {selected_process['name']} (PID: {pid})")
                                session = device.attach(pid)
                                console.success(f"已附加到进程 {selected_process['name']} (PID: {pid})")
                                
                                # 更新运行模式为 attach
                                is_spawned = False
                            else:
                                # 如果没有运行中的进程，尝试先启动应用然后再附加
                                console.info(f"未找到运行中的 {package_name} 进程，尝试先启动应用...")
                                
                                # 使用 adb 命令启动应用
                                import subprocess
                                cmd = ["adb", "shell", f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1"]
                                subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                                
                                # 等待应用启动
                                console.info("等待应用启动...")
                                time.sleep(2)
                                
                                # 查找新启动的进程
                                for i in range(5):  # 尝试5次
                                    try:
                                        pid = device.get_process(package_name).pid
                                        console.success(f"应用已启动，PID: {pid}")
                                        break
                                    except:
                                        if i < 4:  # 最后一次尝试不打印
                                            console.info(f"尝试 {i+1}/5，未找到进程，继续等待...")
                                        time.sleep(1)
                                
                                if 'pid' not in locals():
                                    raise frida.ProcessNotFoundError(f"无法找到进程: {package_name}")
                                
                                # 附加到进程
                                session = device.attach(pid)
                                console.success(f"已附加到进程 {package_name} (PID: {pid})")
                                
                                # 更新运行模式为 attach
                                is_spawned = False
                        except Exception as inner_e:
                            # 如果替代方法也失败了，抛出原始错误
                            console.error(f"替代方法也失败: {str(inner_e)}")
                            raise e
                    else:
                        # 不是内存分配错误，直接抛出
                        raise
                
                # 附加到进程
                session = device.attach(pid)
                console.success(f"已附加到进程 {package_name} (PID: {pid})")
                
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
                    
                    def on_test_message(message, data):
                        if message['type'] == 'send':
                            payload = message.get('payload', {})
                            if payload.get('status') == 'success':
                                process_class = payload.get('process', 'unknown')
                                console.debug(f"检测到进程类: {process_class}")
                                if package_name not in process_class and package_name not in session.get_process_name():
                                    console.warning(f"警告: 可能连接到了错误的进程，当前进程不包含 {package_name}")
                            else:
                                console.warning(f"进程检查失败: {payload.get('error', 'unknown error')}")
                    
                    test_script.on('message', on_test_message)
                    test_script.load()
                    
                    # 给脚本一点时间执行
                    time.sleep(0.5)
                    
                    # 卸载测试脚本
                    test_script.unload()
                except Exception as e:
                    console.warning(f"验证进程时出错 (非致命): {str(e)}")
                
                # 创建任务
                task = context.task_manager.create_task(
                    pid=pid, 
                    process_name=package_name,
                    description=f"{'Spawn' if 'is_spawned' not in locals() or is_spawned else 'Attach'} and hook {package_name}",
                    is_spawned='is_spawned' not in locals() or is_spawned
                )
                
                # 保存会话和进程信息到上下文和任务元数据
                context.frida_session = session
                context.current_process = package_name
                context.frida_device = device
                context.frida_pid = pid
                
                # 更新任务元数据
                task.metadata["device_name"] = device.name
                task.metadata["connection_type"] = "spawn" if 'is_spawned' not in locals() or is_spawned else "attach"
                task.metadata["hooked_method"] = method_signature
                
                # 创建进程监视工作空间
                workspace = context.workspace_manager.create_workspace(
                    name=f"Process: {package_name}",
                    type=context.core.tasks.WorkspaceType.PROCESS,
                    metadata={
                        "task_id": task.id,
                        "device_name": device.name,
                        "process_name": package_name,
                        "pid": pid,
                        "connection_type": "spawn" if 'is_spawned' not in locals() or is_spawned else "attach",
                        "hooked_method": method_signature
                    },
                    command_handler=lambda cmd: self._process_workspace_command(context, cmd)
                )
                
                # 设置选项
                show_args = True
                show_return = True
                show_backtrace = True
                
                # 切换到新创建的工作空间
                context.workspace_manager.switch_to_workspace(workspace.id)
                
                # 在这里遍历执行所有hook方法
                console.info(f"将执行 {len(method_signatures)} 个hook命令")
                
                for method_signature in method_signatures:
                    console.info(f"正在hook方法: {method_signature}")
                    script = frida_hook.hook_method(
                        session=session,
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
                    else:
                        console.error(f"Hook方法失败: {method_signature}")
                
                # 恢复进程执行（只在spawn模式下需要）
                if 'is_spawned' not in locals() or is_spawned:
                    device.resume(pid)
                    console.info("进程已恢复执行")
                
                console.info("方法被调用时将自动显示信息")
                console.info("进入到进程工作空间, 现在可以直接输入 hook <method_signature> 命令来hook更多方法")
                
                # 启动新的控制台会话
                context._start_console()
            except Exception as e:
                console.error(f"无法启动或hook进程: {str(e)}")
                import traceback
                console.debug(traceback.format_exc())
                # 清理资源
                try:
                    if 'session' in locals():
                        session.detach()
                    if 'pid' in locals():
                        device.kill(pid)
                except:
                    pass
                
        except Exception as e:
            console.error(f"执行spawn模式时出错: {str(e)}")
            import traceback
            console.debug(traceback.format_exc())

    def _process_workspace_command(self, context, command):
        """
        处理进程工作空间命令
        
        参数:
            context: ARE实例
            command: 命令字符串
            
        返回:
            是否处理了命令
        """
        # 先确保Frida会话信息在当前上下文中可用
        self._ensure_frida_session_available(context)
        
        # 如果命令是纯hook指令，则自动执行hook命令
        if command.strip().startswith("hook "):
            # 已经处理过了前缀，直接传递剩余部分给hook命令
            method_signature = command.strip()[5:].strip()
            
            # 直接执行hook命令，确保上下文中的frida_session等信息是可用的
            console.debug(f"执行hook命令: {method_signature}")
            
            # 输出调试信息，检查会话状态
            if hasattr(context, 'frida_session') and context.frida_session:
                console.debug("Frida会话已存在")
            else:
                console.debug("Frida会话不存在")
                
            if hasattr(context, 'current_process') and context.current_process:
                console.debug(f"当前进程: {context.current_process}")
            else:
                console.debug("当前进程未定义")
            
            # 使用hook命令对象直接执行
            from are.commands.hook import HookCommand
            hook_cmd = HookCommand()
            hook_cmd.execute(context, method_signature)
            
            return True
            
        # 显示当前的hook状态
        if command.strip() in ["status", "hooks", "list"]:
            self._show_hook_status(context)
            return True
        
        # 如果是返回主工作空间的命令
        if command.strip() in ["back", "exit", "quit", "return"]:
            # 查找主工作空间
            main_workspaces = [
                ws for ws in context.workspace_manager.get_all_workspaces() 
                if ws.type.name == "MAIN"
            ]
            
            if main_workspaces:
                # 切换到主工作空间
                context.workspace_manager.switch_to_workspace(main_workspaces[0].id)
                console.success("已返回主工作空间")
                
                # 启动新的控制台会话
                context._start_console()
            else:
                console.error("找不到主工作空间")
            
            return True
            
        # 默认返回False，表示未处理命令
        return False
        
    def _show_hook_status(self, context):
        """
        显示当前的hook状态
        
        参数:
            context: ARE实例
        """
        # 检查是否有frida_scripts
        if not hasattr(context, 'frida_scripts') or not context.frida_scripts:
            console.info("当前没有活动的hook")
            return
            
        # 获取当前进程名称
        process_name = context.current_process if hasattr(context, 'current_process') else "Unknown"
        pid = context.frida_pid if hasattr(context, 'frida_pid') else "Unknown"
        
        # 显示hook信息
        console.info(f"当前进程: {process_name} (PID: {pid})")
        console.info(f"活动的hook数量: {len(context.frida_scripts)}")
        
        # 由于frida_scripts中只存储了脚本对象，没有方法签名信息
        # 所以这里只能显示脚本数量，不能显示具体的方法签名
        console.info("注意: 要添加新的hook，直接输入 'hook <method_signature>'")
        
    def _ensure_frida_session_available(self, context):
        """
        确保Frida会话信息在当前上下文中可用
        
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
                
                # 更新上下文中的会话信息
                context.frida_session = session
                context.current_process = process_name
                context.frida_device = device
                context.frida_pid = pid
                
                console.debug(f"成功恢复Frida会话: {process_name} (PID: {pid})")
            except Exception as e:
                console.debug(f"附加到进程时出错: {str(e)}")
        except Exception as e:
            console.debug(f"确保Frida会话可用时出错: {str(e)}")

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        # 检查当前是否在进程工作空间中
        in_process_workspace = False
        if hasattr(document, 'context') and document.context:
            current_workspace = document.context.workspace_manager.get_current_workspace()
            in_process_workspace = current_workspace and current_workspace.type.name == "PROCESS"
        
        # 在进程工作空间中的命令补全
        if in_process_workspace:
            word = args[0] if args else ""
            commands = [
                "hook",      # hook命令
                "status",    # 显示当前hook状态
                "hooks",     # 显示当前hook状态（别名）
                "list",      # 显示当前hook状态（别名）
                "back",      # 返回主工作空间
                "exit",      # 返回主工作空间（别名）
                "quit",      # 返回主工作空间（别名）
                "return"     # 返回主工作空间（别名）
            ]
            
            for cmd in commands:
                if cmd.startswith(word):
                    yield Completion(cmd, start_position=-len(word),
                                   display=cmd, display_meta="command")
            return
        
        # 正常模式下的补全
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
                                   
        elif len(args) >= 1 and document.text.endswith(' ') and "with" not in document.text:
            # with关键字补全
            yield Completion("with", start_position=0,
                           display="with", display_meta="keyword")
                           
        elif "with" in document.text and not any(arg.startswith("\"hook") or arg.endswith("\"") for arg in args):
            # hook命令补全
            yield Completion("\"hook ", start_position=0,
                           display="\"hook ", display_meta="command")
