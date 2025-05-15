#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/are.py
import os
import subprocess
import time
import frida
from typing import Optional, Dict, Any, List
from rich.prompt import Prompt
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from are.core import AreConsole, utils
from are.core.workspace_manager import WorkspaceManager, WorkspaceType, Workspace
from are.core.task_manager import TaskManager, Task
from are.commands import get_all_commands
import threading
import time
from rich.text import Text



class AreCompleter(Completer):
    """ARE控制台的命令补全器"""

    def __init__(self, are_instance):
        self.are_instance = are_instance
        self.commands = get_all_commands()

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor.lstrip()

        # 分割文本为命令和参数
        parts = text.split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:] if len(parts) > 1 else []

        # 获取当前工作空间
        current_workspace = self.are_instance.workspace_manager.get_current_workspace()
        if not current_workspace:
            return  # 没有工作空间

        # 根据工作空间类型提供不同的补全
        if current_workspace.type == WorkspaceType.MAIN:  # 在第一个工作空间
            # 提供第一级会话的命令补全
            if not text or not cmd:
                # 显示所有第一级命令
                for cmd_name in ["ps", "watching", "tasks", "help", "q", "quit", "exit"]:
                    yield Completion(
                        cmd_name,
                        start_position=-len(text),
                        display=cmd_name,
                        display_meta=self._get_first_level_cmd_help(cmd_name)
                    )
                return

            # 如果是部分命令，补全它
            if len(parts) == 1:
                for cmd_name in ["ps", "watching", "tasks", "help", "q", "quit", "exit"]:
                    if cmd_name.startswith(cmd):
                        yield Completion(
                            cmd_name,
                            start_position=-len(cmd),
                            display=cmd_name,
                            display_meta=self._get_first_level_cmd_help(cmd_name)
                        )
                return

            # 如果是带参数的命令，提供参数补全
            if cmd == "watching" and len(args) == 0:
                # 提供进程ID和进程名补全
                try:
                    processes = self.are_instance.device.enumerate_processes()
                    
                    # 创建进程名到PID的映射，以便过滤掉重复的进程名
                    name_to_pid = {}
                    for process in processes:
                        if process.name not in name_to_pid:
                            name_to_pid[process.name] = []
                        name_to_pid[process.name].append(process.pid)
                    
                    # 首先提供PID补全（仅提供前20个进程，避免列表过长）
                    for i, process in enumerate(processes):
                        if i >= 20:
                            break
                        yield Completion(
                            str(process.pid),
                            start_position=0,
                            display=f"{process.pid}",
                            display_meta=f"PID: {process.name}"
                        )
                    
                    # 然后提供一些常见的Android进程名称补全
                    common_processes = [
                        name for name in name_to_pid.keys() 
                        if name.startswith(("com.android.", "android.", "system.", "com.google."))
                    ]
                    
                    # 限制显示数量，避免列表过长
                    for name in sorted(common_processes)[:15]:
                        pids = name_to_pid[name]
                        pid_str = f"PID: {pids[0]}" if len(pids) == 1 else f"PIDs: {len(pids)}个"
                        yield Completion(
                            name,
                            start_position=0,
                            display=name,
                            display_meta=pid_str
                        )
                        
                except Exception as e:
                    # 在出错时不中断
                    pass
                return

            if cmd == "tasks" and len(args) == 0:
                # 提供任务命令补全
                for task_cmd in ["list", "switch", "delete", "info"]:
                    yield Completion(
                        task_cmd,
                        start_position=0,
                        display=task_cmd,
                        display_meta=f"任务{task_cmd}操作"
                    )
                return

            if cmd == "help" and len(args) == 0:
                # 提供帮助主题补全
                for help_topic in ["ps", "watching", "tasks", "q"]:
                    yield Completion(
                        help_topic,
                        start_position=0,
                        display=help_topic,
                        display_meta=f"显示 {help_topic} 帮助"
                    )
                return
        else:  # 在进程会话中
            # 提供进程会话的命令补全
            if not text or not cmd:
                # 显示所有进程会话命令
                for cmd_name in ["q", "quit", "exit", "help"]:
                    yield Completion(
                        cmd_name,
                        start_position=-len(text),
                        display=cmd_name,
                        display_meta=self._get_process_cmd_help(cmd_name)
                    )
                # 显示所有命令对象
                for name, cmd_obj in self.commands.items():
                    yield Completion(
                        name,
                        start_position=-len(text),
                        display=name,
                        display_meta=cmd_obj.help_short
                    )
                return

            # 如果是部分命令，补全它
            if len(parts) == 1:
                for cmd_name in ["q", "quit", "exit", "help"]:
                    if cmd_name.startswith(cmd):
                        yield Completion(
                            cmd_name,
                            start_position=-len(cmd),
                            display=cmd_name,
                            display_meta=self._get_process_cmd_help(cmd_name)
                        )
                for name, cmd_obj in self.commands.items():
                    if name.startswith(cmd):
                        yield Completion(
                            name,
                            start_position=-len(cmd),
                            display=name,
                            display_meta=cmd_obj.help_short
                        )
                return

            # 如果是带参数的命令，委托给命令的补全器
            if cmd in self.commands:
                cmd_obj = self.commands[cmd]
                yield from cmd_obj.get_completions(document, args)
                return

            if cmd == "help" and len(args) == 0:
                # 提供帮助主题补全
                for help_topic in ["q"] + list(self.commands.keys()):
                    yield Completion(
                        help_topic,
                        start_position=0,
                        display=help_topic,
                        display_meta=f"显示 {help_topic} 帮助"
                    )
                return

    def _get_first_level_cmd_help(self, cmd_name):
        """获取第一级命令的帮助描述"""
        if cmd_name == "ps":
            return "列出设备上的所有进程"
        elif cmd_name == "watching":
            return "附加到指定的进程（支持进程ID或名称，支持spawn模式）"
        elif cmd_name == "tasks":
            return "管理和查看进程监视任务"
        elif cmd_name in ["q", "quit", "exit"]:
            return "退出程序并停止frida-server进程"
        elif cmd_name == "help":
            return "显示帮助信息"
        return ""

    def _get_process_cmd_help(self, cmd_name):
        """获取进程会话命令的帮助描述"""
        if cmd_name in ["q", "quit", "exit"]:
            return "返回到顶级会话"
        elif cmd_name == "help":
            return "显示帮助信息"
        return ""


class Are:
    """Main ARE class"""

    def __init__(self, device_id: Optional[str] = None):
        """
        Initialize ARE

        Args:
            device_id: frida device ID
        """
        self.console = AreConsole()
        self.device_id = device_id
        self.device = None
        self.script = None
        self.session = None
        self.process = None
        self.current_session = None
        self.commands = get_all_commands()
        self.running = False
        self.device_name = "Unknown Device"
        self.process_name = None
        self._device_disconnected = False
        self._exiting = False  # 新增: 标记是否正在退出

        # 初始化工作空间管理器
        self.workspace_manager = WorkspaceManager()
        
        # 初始化任务管理器
        self.task_manager = TaskManager()

        # 后台线程状态
        self._bg_thread = None
        self._thread_running = False

        # Try to get the device
        self._get_device()

        # 启动设备监控线程
        self._start_device_monitor()
        
        # 创建主工作空间
        self._create_main_workspace()

    def _create_main_workspace(self):
        """创建主工作空间"""
        self.workspace_manager.create_workspace(
            name="Main",
            type=WorkspaceType.MAIN,
            metadata={
                "device_name": self.device_name,
                "device_id": self.device_id,
            },
            command_handler=self._process_command
        )

    def _get_device(self):
        """Get the frida device"""
        try:
            # 重置断开连接标志
            old_disconnected_state = self._device_disconnected
            self._device_disconnected = False

            # Get all devices
            devices = frida.enumerate_devices()

            if not devices:
                self.console.error("No devices found")
                self._device_disconnected = True  # 设置断开标志
                return False

            # If device_id is specified, find that device
            if self.device_id:
                for device in devices:
                    if device.id == self.device_id:
                        self.device = device
                        self.device_name = device.name

                        # 如果之前断开连接，现在重新连接
                        if old_disconnected_state:
                            self.console.success(f"设备 {self.device_name} 已重新连接")

                        return True

                self.console.error(f"Device with ID {self.device_id} not found")
                self._device_disconnected = True  # 设置断开标志
                return False

            # Otherwise, use the first USB device
            for device in devices:
                if device.type == "usb":
                    self.device = device
                    self.device_name = device.name

                    # 如果之前断开连接，现在重新连接
                    if old_disconnected_state:
                        self.console.success(f"设备 {self.device_name} 已重新连接")

                    return True

            # If no USB device, use the first device
            self.device = devices[0]
            self.device_name = self.device.name

            # 如果之前断开连接，现在重新连接
            if old_disconnected_state:
                self.console.success(f"设备 {self.device_name} 已重新连接")

            return True

        except Exception as e:
            self.console.error(f"Error getting device: {str(e)}")
            self._device_disconnected = True  # 设置断开标志
            return False

    def attach(self, process_name: str, cmd: Optional[str] = None):
        """
        Attach to a process and create a new session

        Args:
            process_name: Name or PID of the process
            cmd: Optional command to execute after attaching
        """
        try:
            # 先尝试作为PID解析
            try:
                pid = int(process_name)
                is_pid = True
            except ValueError:
                is_pid = False
                
            if is_pid:
                # 使用PID附加
                # 尝试查找进程名
                process_name_str = None
                for p in self.device.enumerate_processes():
                    if p.pid == pid:
                        process_name_str = p.name
                        break
                        
                if process_name_str:
                    self.console.info(f"正在附加到进程 {process_name_str} (PID: {pid})...")
                else:
                    self.console.warning(f"找不到PID为 {pid} 的进程名称，但仍将尝试附加")
                    process_name_str = f"PID-{pid}"
                    
                self.session = self.device.attach(pid)
                self.process_name = process_name_str
                
                # 创建任务
                task = self.task_manager.create_task(
                    pid=pid,
                    process_name=process_name_str
                )
                
                # 创建进程工作空间
                process_workspace = self.workspace_manager.create_workspace(
                    name=process_name_str,
                    type=WorkspaceType.PROCESS,
                    metadata={
                        "process_name": process_name_str,
                        "pid": pid,
                        "device_name": self.device_name,
                        "connection_type": "usb" if self.device.type == "usb" else "remote",
                        "task_id": task.id
                    },
                    command_handler=self._process_command
                )
                
                # 切换到新工作空间
                self.workspace_manager.switch_to_workspace(process_workspace.id)
                
                # 执行命令如果提供
                if cmd:
                    script = self.session.create_script(cmd)
                    script.load()
                
                # 更新会话信息
                self.current_session = {
                    "device": self.device,
                    "session": self.session,
                    "process_name": self.process_name,
                    "workspace_id": process_workspace.id,
                    "task_id": task.id
                }
                
                return True
            else:
                # 使用进程名称附加
                # ... existing code ...
                # 注意: 需要保持一致地更新工作空间和任务
                return True
                
        except frida.ProcessNotFoundError:
            self.console.error(f"找不到进程: {process_name}")
            return False
        except Exception as e:
            self.console.error(f"附加到进程时出错: {str(e)}")
            return False

    def _start_console(self):
        """启动交互式控制台"""
        # 设置历史记录
        history_file = os.path.expanduser("~/.are_history")

        # 设置提示样式
        style = Style.from_dict({
            'prompt': 'green bold',
            'process_name': 'bold #88C0D0',  # 北欧风格的浅蓝色
            'device_name': 'bold #A3BE8C',  # 北欧风格的浅绿色
            'connection_type': 'bold #D8DEE9'  # 北欧风格的灰色
        })

        # 设置会话
        session = PromptSession(
            history=FileHistory(history_file),
            auto_suggest=AutoSuggestFromHistory(),
            completer=AreCompleter(self),
            style=style
        )

        self.running = True

        # 获取当前工作空间
        current_workspace = self.workspace_manager.get_current_workspace()
        if not current_workspace:
            self.console.error("没有可用的工作空间")
            return
            
        # 在开始控制台之前，显示欢迎消息
        if current_workspace.type == WorkspaceType.MAIN:
            # 在主ARE会话中
            self.console.info("输入 'ps' 查看所有进程")
        else:
            # 在进程特定的会话中
            process_name = current_workspace.metadata.get("process_name", "Unknown")
            self.console.success(f"已附加到进程: {process_name}")
            self.console.info("现在您可以执行命令，如 'hook com.example.Class.method'")
            
        # 获取工作空间的提示符
        prompt_text = current_workspace.get_prompt()

        while self.running:
            try:
                # 获取输入
                command = session.prompt(prompt_text)

                # 跳过空命令
                if not command.strip():
                    continue

                # 处理命令
                current_workspace = self.workspace_manager.get_current_workspace()
                if current_workspace:
                    current_workspace.handle_command(command)
                else:
                    self.console.error("没有活动的工作空间")
                    break

            except KeyboardInterrupt:
                # 捕获Ctrl+C
                self.console.print("\n使用 'exit'、'quit' 或 'q' 退出")
            except EOFError:
                # 捕获Ctrl+D
                self._exiting = True
                self.running = False
                self._stop_device_monitor()
                self.console.print("\n再见！")
            except Exception as e:
                if not self._device_disconnected:
                    self.console.error(f"错误: {str(e)}")

    def _process_command(self, command: str):
        """
        处理命令

        参数:
            command: 命令字符串
        """
        # 分割命令和参数
        parts = command.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        # 总是允许退出命令，即使设备断开
        if cmd in ["exit", "quit", "q"]:
            # 获取当前工作空间
            current_workspace = self.workspace_manager.get_current_workspace()
            
            if current_workspace and current_workspace.type == WorkspaceType.PROCESS:
                # 如果在进程工作空间，返回主工作空间
                self._detach_process()
                return True
            else:
                # 如果在主工作空间，退出程序
                self._exiting = True  # 标记正在退出
                self.running = False
                self._stop_device_monitor()  # 停止监控线程
                
                # 停止frida-server进程
                from are.core.utils import kill_frida_server
                kill_frida_server()
                
                self.console.info("再见！")
                return True

        # 检查设备连接状态
        device_connected = utils.check_device_connection()

        # 如果设备已连接但状态为断开，尝试重新初始化
        if device_connected and self._device_disconnected:
            self.console.success("检测到设备已重新连接，正在恢复环境...")
            self._device_disconnected = False
            self._get_device()

            # 检查并重启Frida服务器
            self._restart_frida_server_after_reconnect()

        # 如果设备已断开，只允许执行特定命令
        if self._device_disconnected and cmd not in ["help"]:
            self.console.error("设备已断开连接，无法执行此命令")
            self.console.info("请重新连接设备或输入 'q' 退出程序")
            return False

        # 获取当前工作空间
        current_workspace = self.workspace_manager.get_current_workspace()
        
        # 根据工作空间类型处理命令
        if current_workspace.type == WorkspaceType.MAIN:  # 在第一个工作空间
            # 处理内置命令
            if cmd == "help":
                self._show_help(args)
            elif cmd == "ps":
                self._list_processes()
            elif cmd == "watching":
                self._watch_process(args)
            elif cmd == "tasks":
                # 使用任务命令处理任务管理
                if "tasks" in self.commands:
                    try:
                        self.commands["tasks"].execute(self, args)
                    except Exception as e:
                        self.console.error(f"执行任务命令时出错: {str(e)}")
                else:
                    self.console.error("任务命令不可用")
            else:
                self.console.error(f"未知命令: {cmd}")
                self.console.info("输入 'help' 查看可用命令")
        else:  # 在进程工作空间
            # 处理进程会话的命令
            if cmd == "help":
                self._show_process_help(args)
            # 处理其他进程会话的命令
            elif cmd in self.commands:
                try:
                    self.commands[cmd].execute(self, args)
                except Exception as e:
                    self.console.error(f"执行命令时出错: {str(e)}")
            else:
                self.console.error(f"未知命令: {cmd}")
                self.console.info("输入 'help' 查看可用命令")
                
        return True

    def _show_help(self, args: str):
        """
        显示命令帮助

        参数:
            args: 要显示帮助的命令
        """
        # 获取当前工作空间
        current_workspace = self.workspace_manager.get_current_workspace()
        
        if current_workspace and current_workspace.type == WorkspaceType.MAIN:
            if args:
                # 显示特定命令的帮助
                cmd = args.strip().lower()
                if cmd == "ps":
                    self.console.panel(
                        "列出设备上的所有进程，以树形结构展示进程层次关系。\n\n用法：ps\n\n这将显示所有进程的PID、父进程ID和名称。",
                        title="ps 命令帮助",
                        style="info"
                    )
                elif cmd == "watching":
                    self.console.panel(
                        "附加到指定进程，并可以选择性地执行初始命令。支持通过进程ID或进程名称附加。\n\n用法：\n  watching <pid或进程名>\n  watching <进程名> with \"command1, command2, ...\"\n\n示例：\n  watching 1234\n  watching com.android.settings\n  watching chrome\n  watching 1234 with \"hook java.lang.String.substring, info class java.lang.String\"\n  watching com.android.settings with \"\"\n\n注意：\n  - 使用 'with' 语法时，将启用spawn模式启动进程（仅适用于进程名，不适用于PID）\n  - spawn模式会在启动进程前先暂停进程，执行完命令后再恢复进程执行",
                        title="watching 命令帮助",
                        style="info"
                    )
                elif cmd == "tasks":
                    self.console.panel(
                        "管理和查看进程监视任务。\n\n用法：\n  tasks\n  tasks list\n  tasks switch\n  tasks delete\n  tasks info\n\n示例：\n  tasks          - 显示任务列表并允许切换\n  tasks list     - 仅显示任务列表\n  tasks switch   - 交互式切换任务\n  tasks delete   - 交互式删除任务\n  tasks info     - 显示当前任务的详细信息",
                        title="tasks 命令帮助",
                        style="info"
                    )
                elif cmd == "q":
                    self.console.panel(
                        "退出程序或返回上一级会话。\n\n用法：q\n\n在顶级会话中，此命令将退出程序并停止frida-server进程。\n在进程会话中，此命令将返回到顶级会话。",
                        title="q 命令帮助",
                        style="info"
                    )
                else:
                    self.console.error(f"未知命令: {cmd}")
                    self.console.info("在主工作空间可用的命令: ps, watching, tasks, q/quit/exit, help")
            else:
                # 只有当用户输入help命令时才显示一般帮助
                self.console.panel(
                    "\n".join([
                        "ps          - 列出设备上的所有进程",
                        "watching    - 附加到指定的进程（支持进程ID或名称，支持spawn模式）",
                        "tasks       - 管理和查看进程监视任务",
                        "q/quit/exit - 退出程序并停止frida-server进程",
                        "help        - 显示帮助信息"
                    ]),
                    title="主工作空间可用命令",
                    style="info"
                )
                self.console.info("输入 'help <命令>' 获取特定命令的详细信息")
        else:  # 在进程会话中
            self._show_process_help(args)

    def _list_processes(self):
        """列出设备上的所有进程，以树形结构展示"""
        if not self.device:
            self.console.error("未连接到设备")
            return

        try:
            self.console.info(f"列出 {self.device_name} 上的进程...")

            # 使用adb命令获取进程列表
            import subprocess

            # 获取设备 ID
            device_id = self.device_id or self.device.id

            # 构建adb命令
            if device_id and device_id != "local":
                ps_cmd = ["adb", "-s", device_id, "shell", "ps", "-e", "-o", "PID,PPID,NAME"]
            else:
                ps_cmd = ["adb", "shell", "ps", "-e", "-o", "PID,PPID,NAME"]

            # 执行命令
            result = subprocess.run(ps_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                self.console.error(f"执行adb命令失败: {result.stderr}")
                return

            # 解析输出
            lines = result.stdout.strip().split('\n')
            
            # 跳过标题行
            header = lines[0].strip().split()
            processes = []
            
            # 收集所有进程信息
            for line in lines[1:]:
                if not line.strip():
                    continue
                    
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    pid, ppid, name = parts
                    processes.append({
                        'pid': int(pid),
                        'ppid': int(ppid),
                        'name': name
                    })
            
            # 构建进程树
            process_map = {proc['pid']: proc for proc in processes}
            tree = {}
            
            # 把每个进程添加到其父进程的子进程列表中
            for proc in processes:
                proc['children'] = []
                
                # 添加到父进程
                parent_pid = proc['ppid']
                if parent_pid in process_map and parent_pid != proc['pid']:  # 避免自引用
                    if 'children' not in process_map[parent_pid]:
                        process_map[parent_pid]['children'] = []
                    process_map[parent_pid]['children'].append(proc)
                else:
                    # 如果没有父进程或父进程不在列表中，添加到根
                    if parent_pid not in tree:
                        tree[parent_pid] = []
                    tree[parent_pid].append(proc)
            
            # 打印进程树
            from rich.tree import Tree as RichTree
            from rich.text import Text
            
            root_tree = RichTree("进程树")
            
            # 首先处理init进程（PID 1）
            if 1 in process_map:
                init_proc = process_map[1]
                self._add_process_to_tree(root_tree, init_proc)
            
            # 然后处理其他根进程
            for ppid, procs in tree.items():
                if ppid == 1:  # 已经处理过init
                    continue
                for proc in procs:
                    if proc['pid'] != 1:  # 避免重复处理init
                        self._add_process_to_tree(root_tree, proc)
            
            # 打印树
            self.console.print_tree(root_tree)
            self.console.info(f"使用 'watching <pid>' 附加到进程或 'watching <process_name> with \"\"' 使用spawn模式启动进程")

        except Exception as e:
            self.console.error(f"列出进程时出错: {str(e)}")
            import traceback
            self.console.debug(traceback.format_exc())
    
    def _add_process_to_tree(self, parent_node, process, depth=0, max_depth=3):
        """递归添加进程到树形结构
        
        参数:
            parent_node: 父节点
            process: 进程信息
            depth: 当前深度
            max_depth: 最大展示深度
        """
        if depth > max_depth:
            # 超过最大深度，显示省略号
            parent_node.add("...")
            return
            
        # 创建当前进程节点
        proc_text = Text(f"{process['pid']}: {process['name']}")
        proc_text.stylize(f"bold green" if process['name'].startswith("com.android") else "bold blue")
        proc_node = parent_node.add(proc_text)
        
        # 递归添加子进程
        if 'children' in process and process['children']:
            for child in sorted(process['children'], key=lambda p: p['pid']):
                self._add_process_to_tree(proc_node, child, depth + 1, max_depth)

    def _watch_process(self, args: str):
        """
        附加到进程，支持通过PID或进程名自动识别
        使用 'with' 语法时启用spawn模式

        参数:
            args: 命令参数 - 可能是 "<pid>" 或 "<process_name>" 或 "<pid/process_name> with command1, command2, ..."
        """
        if not self.device:
            self.console.error("未连接到设备")
            return

        # 调试信息
        self.console.info(f"处理 watching 命令，参数: '{args}'")

        # 解析命令行
        parts = args.strip().split(" with ", 1)
        process_spec = parts[0].strip()
        commands = None
        spawn_mode = len(parts) > 1  # 如果有 'with' 部分，则启用spawn模式

        # 调试信息
        self.console.info(f"解析后的进程标识符: '{process_spec}'")

        if len(parts) > 1:
            commands = [cmd.strip() for cmd in parts[1].split(",")]
            self.console.info(f"解析后的命令: {commands}")
            self.console.info("启用spawn模式")

        # 验证进程标识符
        if not process_spec:
            self.console.error("未提供进程ID或进程名")
            self.console.info("正确用法: watching <pid或进程名> [with 命令1, 命令2, ...]")
            return
            
        # 尝试识别进程标识符是PID还是进程名
        is_pid = process_spec.isdigit()
        
        if is_pid:
            # 处理进程ID的情况
            pid = int(process_spec)
            
            # 使用spawn模式还是attach模式
            if spawn_mode:
                self.console.error("无法使用spawn模式附加到已运行的进程ID，spawn模式只适用于进程名")
                self.console.info("请使用 'watching <进程名> with ...' 来使用spawn模式")
                return
                
            self.console.info(f"按进程ID识别，尝试附加到PID: {pid}")
            
            if self.attach(str(pid)):
                # 如果有命令，执行它们
                if commands:
                    self._execute_commands_in_current_workspace(commands)
                # 启动新的控制台
                self._start_console()
            else:
                self.console.error(f"无法附加到PID为 {pid} 的进程")
        else:
            # 处理进程名的情况
            process_name = process_spec
            
            if spawn_mode:
                self.console.info(f"使用spawn模式启动进程: {process_name}")
                self._spawn_process(process_name, commands)
                return
                
            self.console.info(f"按进程名识别，尝试查找和附加到进程: {process_name}")
            
            # 查找匹配的进程
            matching_processes = []
            try:
                for process in self.device.enumerate_processes():
                    if process_name.lower() in process.name.lower():
                        matching_processes.append(process)
            except Exception as e:
                self.console.error(f"查找进程时出错: {str(e)}")
                return
                
            # 处理查找结果
            if not matching_processes:
                self.console.error(f"找不到匹配 '{process_name}' 的进程")
                return
                
            # 如果有多个匹配项，让用户选择
            selected_process = None
            if len(matching_processes) > 1:
                self.console.info(f"找到 {len(matching_processes)} 个匹配进程:")
                for i, process in enumerate(matching_processes):
                    self.console.print(f"[{i}] {process.name} (PID: {process.pid})")
                    
                # 获取用户选择
                from rich.prompt import Prompt
                selection = Prompt.ask("请选择进程", default="0")
                try:
                    index = int(selection)
                    if 0 <= index < len(matching_processes):
                        selected_process = matching_processes[index]
                    else:
                        self.console.error("无效的选择")
                        return
                except ValueError:
                    self.console.error("无效的选择，请输入数字")
                    return
            else:
                # 只有一个匹配项
                selected_process = matching_processes[0]
                
            # 附加到选定的进程
            if selected_process:
                self.console.info(f"正在附加到进程: {selected_process.name} (PID: {selected_process.pid})")
                
                if self.attach(str(selected_process.pid)):
                    # 如果有命令，执行它们
                    if commands:
                        self._execute_commands_in_current_workspace(commands)
                    # 启动新的控制台
                    self._start_console()
                else:
                    self.console.error(f"无法附加到进程: {selected_process.name} (PID: {selected_process.pid})")
                    
    def _spawn_process(self, process_name: str, commands=None):
        """使用spawn模式启动并附加到进程
        
        参数:
            process_name: 进程名称
            commands: 要执行的命令列表
        """
        try:
            self.console.info(f"尝试spawn模式启动进程: {process_name}")
            
            # 使用spawn模式启动进程
            pid = self.device.spawn([process_name])
            self.console.success(f"已启动进程: {process_name}，PID: {pid}")
            
            # 附加到进程
            self.session = self.device.attach(pid)
            self.process_name = process_name
            
            # 创建任务
            task = self.task_manager.create_task(
                pid=pid,
                process_name=process_name,
                is_spawned=True  # 标记为spawned模式
            )
            
            # 创建进程工作空间
            process_workspace = self.workspace_manager.create_workspace(
                name=process_name,
                type=WorkspaceType.PROCESS,
                metadata={
                    "process_name": process_name,
                    "pid": pid,
                    "device_name": self.device_name,
                    "connection_type": "usb" if self.device.type == "usb" else "remote",
                    "task_id": task.id,
                    "is_spawned": True  # 标记为spawned模式
                },
                command_handler=self._process_command
            )
            
            # 切换到新工作空间
            self.workspace_manager.switch_to_workspace(process_workspace.id)
            
            # 如果有命令，执行它们
            if commands:
                self._execute_commands_in_current_workspace(commands)
                
            # 恢复进程执行
            self.device.resume(pid)
            self.console.success(f"已恢复进程执行: {process_name}")
            
            # 更新会话信息
            self.current_session = {
                "device": self.device,
                "session": self.session,
                "process_name": self.process_name,
                "workspace_id": process_workspace.id,
                "task_id": task.id,
                "is_spawned": True
            }
            
            # 启动新的控制台
            self._start_console()
            return True
        except frida.ProcessNotFoundError:
            self.console.error(f"找不到进程: {process_name}")
            return False
        except Exception as e:
            self.console.error(f"使用spawn模式启动进程时出错: {str(e)}")
            return False

    def _execute_commands_in_current_workspace(self, commands):
        """在当前工作空间中执行命令列表
        
        参数:
            commands: 命令列表
        """
        self.console.info("执行指定的命令...")
        for cmd in commands:
            self.console.status(f"执行: {cmd}")
            try:
                current_workspace = self.workspace_manager.get_current_workspace()
                if current_workspace:
                    current_workspace.handle_command(cmd)
            except Exception as e:
                self.console.error(f"执行命令 '{cmd}' 时出错: {str(e)}")

    def _detach_process(self):
        """从当前进程分离，返回到第一级会话"""
        # 获取当前工作空间
        current_workspace = self.workspace_manager.get_current_workspace()
        
        if not current_workspace or current_workspace.type != WorkspaceType.PROCESS:
            return False
            
        # 获取进程信息
        process_name = current_workspace.metadata.get("process_name", "Unknown")
        
        try:
            # 关闭当前会话
            if self.session:
                self.session.detach()
                self.session = None
                
            # 重置状态
            self.process_name = None
            self.current_session = None
            
            # 切换回主工作空间
            for workspace in self.workspace_manager.get_all_workspaces():
                if workspace.type == WorkspaceType.MAIN:
                    self.workspace_manager.switch_to_workspace(workspace.id)
                    break
            
            self.console.success(f"已从进程 {process_name} 分离")
            
            # 重启控制台
            self._start_console()
            return True
        except Exception as e:
            self.console.error(f"从进程分离时出错: {str(e)}")
            return False

    def _show_process_help(self, args: str):
        """
        在进程会话中显示命令帮助

        参数:
            args: 要显示帮助的命令
        """
        if args:
            # 显示特定命令的帮助
            cmd = args.strip().lower()
            if cmd == "q":
                self.console.panel(
                    "返回到顶级会话。\n\n用法：q\n\n这将从当前进程分离，并返回到主ARE会话。",
                    title="q 命令帮助",
                    style="info"
                )
            elif cmd in self.commands:
                cmd_obj = self.commands[cmd]
                self.console.panel(
                    f"{cmd_obj.help_text}\n\n用法: {cmd_obj.usage}\n\n示例:\n" +
                    "\n".join([f"  {ex}" for ex in cmd_obj.examples]),
                    title=f"'{cmd}' 命令帮助",
                    style="info"
                )
            else:
                self.console.error(f"未知命令: {cmd}")
        else:
            # 显示一般帮助
            # 首先显示内置命令
            built_in_commands = [
                "q/quit/exit - 返回到顶级会话",
                "help        - 显示帮助信息"
            ]

            # 然后显示进程特定的命令
            process_commands = [f"{name.ljust(15)} - {cmd.help_short}" for name, cmd in self.commands.items()]

            self.console.panel(
                "\n".join(built_in_commands + ["\n进程特定命令:"] + process_commands),
                title="可用命令",
                style="info"
            )
            self.console.info("输入 'help <命令>' 获取特定命令的详细信息")

    def _check_device_connection(self):
        """检查设备是否仍然连接

        这个方法保留用于向后兼容，主要逻辑移到监控线程中
        """
        if not self.device:
            return False

        # 如果设备已断开但_exiting标志为True，则允许退出
        if self._device_disconnected and self._exiting:
            return True

        return not self._device_disconnected

    def _start_device_monitor(self):
        """启动设备监控线程"""
        if self._bg_thread is not None:
            return  # 已经启动

        self._thread_running = True
        self._bg_thread = threading.Thread(target=self._device_monitor_thread, daemon=True)
        self._bg_thread.start()

    def _device_monitor_thread(self):
        """设备监控线程函数"""
        last_connection_state = None  # 记录上一次的连接状态

        while self._thread_running and not self._exiting:
            current_connection_state = False

            # 检查设备连接状态
            try:
                # 使用utils中的函数检查设备连接
                current_connection_state = utils.check_device_connection()

                # 如果设备状态从断开变为连接
                if current_connection_state and last_connection_state is False:
                    self.console.print("\n" + "═" * 50, style="success")
                    self.console.print("🎉 [success bold]设备已重新连接！[/success bold] 🎉")
                    self.console.print("═" * 50 + "\n", style="success")
                    self._device_disconnected = False

                    # 尝试重新初始化设备连接
                    self._get_device()

                    # 设备重新连接后，重启Frida服务器
                    self._restart_frida_server_after_reconnect()

                # 如果设备状态从连接变为断开
                elif not current_connection_state and last_connection_state is True:
                    self.console.print("\n" + "⚠️" * 17, style="error")
                    self.console.print("🔌 [error bold]设备已断开连接！[/error bold] 🔌")
                    self.console.print("⚠️" * 17, style="error")
                    self.console.print("📱 请重新连接设备并继续，或输入 'q' 退出程序\n")
                    self._device_disconnected = True

            except Exception:
                # 忽略线程中的所有异常
                pass

            # 更新上一次的连接状态
            last_connection_state = current_connection_state

            # 短暂休眠以减少CPU使用
            time.sleep(0.5)  # 缩短检查间隔，使响应更快

    def _stop_device_monitor(self):
        """停止设备监控线程"""
        self._thread_running = False
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=1.0)  # 等待线程结束，最多1秒

    def _restart_frida_server_after_reconnect(self):
        """在重新连接后重启Frida服务器"""
        self.console.info("🔄 检查并重启Frida服务器...")

        # 使用utils模块中的函数重启Frida服务器
        restart_success = utils.restart_frida_server()

        # 如果重启成功，尝试恢复会话
        if restart_success and self.process_name:
            try:
                # 等待Frida服务器完全启动
                time.sleep(2)

                # 尝试找到之前的进程
                self.console.info(f"🔍 正在查找之前的进程: {self.process_name}...")

                for process in self.device.enumerate_processes():
                    if process.name == self.process_name:
                        # 重新附加到进程
                        self.console.info(f"🔄 尝试重新附加到进程: {self.process_name}")
                        self.session = self.device.attach(process.pid)
                        self.current_session = {
                            "device": self.device,
                            "session": self.session,
                            "process_name": self.process_name
                        }
                        self.console.success(f"✅ 已重新附加到进程: {self.process_name}")
                        break
                else:
                    self.console.warning(f"⚠️ 无法找到之前的进程: {self.process_name}")
            except Exception as e:
                self.console.error(f"❌ 重新附加到进程时出错: {str(e)}")

    def __del__(self):
        self._stop_device_monitor()
        
        # 确保在程序意外终止时停止frida-server
        if self._exiting:  # 只有在正常退出时才停止frida-server
            try:
                from are.core.utils import kill_frida_server
                kill_frida_server()
            except:
                pass  # 忽略任何错误，确保清理过程继续