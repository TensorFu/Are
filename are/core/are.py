#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/are.py
import os
import time
import frida
from typing import Optional
from rich.prompt import Prompt
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from are.core import AreConsole
from are.commands import get_all_commands


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

        # 根据当前会话类型提供不同的补全
        if not self.are_instance.process_name:  # 在第一个工作空间
            # 提供第一级会话的命令补全
            if not text or not cmd:
                # 显示所有第一级命令
                for cmd_name in ["ps", "watching", "help", "q", "quit", "exit"]:
                    yield Completion(
                        cmd_name,
                        start_position=-len(text),
                        display=cmd_name,
                        display_meta=self._get_first_level_cmd_help(cmd_name)
                    )
                return

            # 如果是部分命令，补全它
            if len(parts) == 1:
                for cmd_name in ["ps", "watching", "help", "q", "quit", "exit"]:
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
                # 提供进程ID补全
                try:
                    processes = self.are_instance.device.enumerate_processes()
                    for process in processes:
                        yield Completion(
                            str(process.pid),
                            start_position=0,
                            display=f"{process.pid}",
                            display_meta=process.name
                        )
                except Exception:
                    pass
                return

            if cmd == "help" and len(args) == 0:
                # 提供帮助主题补全
                for help_topic in ["ps", "watching", "q"]:
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
            return "附加到指定的进程"
        elif cmd_name in ["q", "quit", "exit"]:
            return "退出程序"
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

        # Try to get the device
        self._get_device()

    def _get_device(self):
        """Get the frida device"""
        try:
            # Get all devices
            devices = frida.enumerate_devices()

            if not devices:
                self.console.error("No devices found")
                return False

            # If device_id is specified, find that device
            if self.device_id:
                for device in devices:
                    if device.id == self.device_id:
                        self.device = device
                        self.device_name = device.name
                        return True

                self.console.error(f"Device with ID {self.device_id} not found")
                return False

            # Otherwise, use the first USB device
            for device in devices:
                if device.type == "usb":
                    self.device = device
                    self.device_name = device.name
                    return True

            # If no USB device, use the first device
            self.device = devices[0]
            self.device_name = self.device.name
            return True

        except Exception as e:
            self.console.error(f"Error getting device: {str(e)}")
            return False

    def attach(self, process_name: str, cmd: Optional[str] = None):
        """
        Attach to a process

        Args:
            process_name: Process name or PID
            cmd: JavaScript command to execute
            
        Returns:
            bool: Whether the attachment was successful
        """
        try:
            # Try to get the device first
            if not self.device and not self._get_device():
                return False

            # Try to attach to the process
            try:
                # Check if process_name is a PID
                if process_name.isdigit():
                    pid = int(process_name)
                    self.session = self.device.attach(pid)
                    # Get process name from PID
                    for process in self.device.enumerate_processes():
                        if process.pid == pid:
                            self.process_name = process.name
                            break
                else:
                    # Find processes matching the name
                    processes = [p for p in self.device.enumerate_processes() if process_name.lower() in p.name.lower()]

                    if not processes:
                        self.console.error(f"No process matching '{process_name}' found")
                        return False

                    # If multiple matches, show them and ask user to select
                    if len(processes) > 1:
                        self.console.info(f"Found {len(processes)} processes matching '{process_name}':")
                        for i, p in enumerate(processes):
                            self.console.print(f"[{i}] {p.name} (PID: {p.pid})")

                        index = Prompt.ask("Select process", default="0")
                        try:
                            index = int(index)
                            if index < 0 or index >= len(processes):
                                self.console.error("Invalid selection")
                                return False
                        except ValueError:
                            self.console.error("Invalid selection")
                            return False

                        process = processes[index]
                    else:
                        process = processes[0]

                    self.process_name = process.name
                    self.session = self.device.attach(process.pid)

                self.current_session = {
                    "device": self.device,
                    "session": self.session,
                    "process_name": self.process_name
                }

                # Execute the command if specified
                if cmd:
                    script = self.session.create_script(cmd)
                    script.load()

                # Start the console
                self._start_console()
                return True

            except frida.ProcessNotFoundError:
                self.console.error(f"Process '{process_name}' not found")
                return False
            except Exception as e:
                self.console.error(f"Error attaching to process: {str(e)}")
                return False

        except Exception as e:
            self.console.error(f"Error: {str(e)}")
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

        # 在开始控制台之前，显示欢迎消息
        if not self.process_name:
            # 在主ARE会话中
            prompt_text = f"are is running on {self.device_name} -> "
            self.console.success(f"ARE 正在运行在 {self.device_name}")
            self.console.info("输入 'ps' 查看所有进程")
            self.console.info("输入 'watching <pid>' 附加到进程")
            self.console.info("输入 'help' 查看所有可用命令")
        else:
            # 在进程特定的会话中
            connection_type = "usb" if self.device.type == "usb" else "remote"
            # 按照所需格式格式化提示
            device_name = self.device_name if self.device_name else "Unknown"
            prompt_text = f"[process_name]{self.process_name}[/] on ([device_name]{device_name}[/]) [[connection_type]{connection_type}[/]] # "
            self.console.success(f"已附加到进程: {self.process_name}")
            self.console.info("现在您可以执行命令，如 'hook com.example.Class.method'")

        while self.running:
            try:
                # 检查设备是否仍然连接
                if not self._check_device_connection():
                    time.sleep(1)  # 避免过于频繁的检查
                    continue

                # 获取输入
                command = session.prompt(prompt_text)

                # 跳过空命令
                if not command.strip():
                    continue

                # 处理命令
                self._process_command(command)

            except KeyboardInterrupt:
                # 捕获Ctrl+C
                self.console.print("\n使用 'exit'、'quit' 或 'q' 退出")
            except EOFError:
                # 捕获Ctrl+D
                self.running = False
                self.console.print("\n再见！")
            except Exception as e:
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

        # 处理第一级会话的命令
        if not self.process_name:  # 在第一个工作空间
            # 处理内置命令
            if cmd in ["exit", "quit", "q"]:
                self.running = False
                return
            elif cmd == "help":
                self._show_help(args)
                return
            elif cmd == "ps":
                self._list_processes()
                return
            elif cmd == "watching":
                self._watch_process(args)
                return
            else:
                self.console.error(f"未知命令: {cmd}")
                self.console.info("输入 'help' 查看可用命令")
        else:  # 在第二个工作空间（已附加到进程）
            # 处理进程会话的命令
            if cmd in ["exit", "quit", "q"]:
                # 返回到第一个工作空间
                self._detach_process()
                return
            elif cmd == "help":
                self._show_process_help(args)
                return
            # 处理其他进程会话的命令
            elif cmd in self.commands:
                try:
                    self.commands[cmd].execute(self, args)
                except Exception as e:
                    self.console.error(f"执行命令时出错: {str(e)}")
            else:
                self.console.error(f"未知命令: {cmd}")
                self.console.info("输入 'help' 查看可用命令")

    def _show_help(self, args: str):
        """
        显示命令帮助

        参数:
            args: 要显示帮助的命令
        """
        if not self.process_name:  # 在第一个工作空间
            if args:
                # 显示特定命令的帮助
                cmd = args.strip().lower()
                if cmd == "ps":
                    self.console.panel(
                        "列出设备上的所有进程。\n\n用法：ps\n\n这将显示所有进程的PID、名称和所有者（如果可用）。",
                        title="ps 命令帮助",
                        style="info"
                    )
                elif cmd == "watching":
                    self.console.panel(
                        "附加到指定进程，并可以选择性地执行初始命令。\n\n用法：\n  watching <pid>\n  watching <pid> with \"command1, command2, ...\"\n\n示例：\n  watching 1234\n  watching 1234 with \"hook java.lang.String.substring, info class java.lang.String\"\n\n这将附加到指定PID的进程，并可选择性地执行随后的命令。",
                        title="watching 命令帮助",
                        style="info"
                    )
                elif cmd == "q":
                    self.console.panel(
                        "退出程序或返回上一级会话。\n\n用法：q\n\n在顶级会话中，此命令将退出程序。\n在进程会话中，此命令将返回到顶级会话。",
                        title="q 命令帮助",
                        style="info"
                    )
                else:
                    self.console.error(f"未知命令: {cmd}")
            else:
                # 显示一般帮助
                self.console.panel(
                    "\n".join([
                        "ps          - 列出设备上的所有进程",
                        "watching    - 附加到指定的进程",
                        "q/quit/exit - 退出程序",
                        "help        - 显示帮助信息"
                    ]),
                    title="可用命令",
                    style="info"
                )
                self.console.info("输入 'help <命令>' 获取特定命令的详细信息")
        else:  # 在进程会话中
            self._show_process_help(args)

    def _list_processes(self):
        """列出设备上的所有进程"""
        if not self.device:
            self.console.error("未连接到设备")
            return

        try:
            self.console.info(f"列出 {self.device_name} 上的进程...")

            # 使用 adb 命令获取进程列表
            import subprocess

            # 获取设备 ID，如果是 USB 设备，通常是设备序列号
            device_id = self.device_id or self.device.id

            # 执行 adb 命令
            if device_id and device_id != "local":
                cmd = ["adb", "-s", device_id, "shell", "ps", "-A"]
            else:
                cmd = ["adb", "shell", "ps", "-A"]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                self.console.error(f"执行 adb 命令失败: {result.stderr}")
                return

            # 解析输出
            lines = result.stdout.strip().split('\n')
            header = lines[0]
            processes = lines[1:]

            # 创建表格
            table = self.console.table(title="进程列表")
            table.add_column("PID", style="dim")
            table.add_column("名称", style="green")
            table.add_column("用户", style="cyan")

            # 添加数据
            for line in processes:
                parts = line.split()
                if len(parts) >= 9:  # 标准输出格式有至少9列
                    user = parts[0]
                    pid = parts[1]
                    name = parts[8]  # 通常进程名在第9列
                    table.add_row(pid, name, user)

            # 打印表格
            self.console.console.print(table)
            self.console.info("使用 'watching <pid>' 附加到进程")

        except Exception as e:
            self.console.error(f"列出进程时出错: {str(e)}")
            import traceback
            self.console.debug(traceback.format_exc())

    def _watch_process(self, args: str):
        """
        附加到进程

        参数:
            args: 命令参数 - 可能是 "<pid>" 或 "<pid> with command1, command2, ..."
        """
        if not self.device:
            self.console.error("未连接到设备")
            return

        # 解析命令行
        parts = args.strip().split(" with ", 1)
        process_id = parts[0].strip()
        commands = None

        if len(parts) > 1:
            commands = [cmd.strip() for cmd in parts[1].split(",")]

        # 验证进程ID
        if not process_id.isdigit():
            self.console.error(f"无效的进程ID: {process_id}")
            return

        # 尝试附加到进程
        try:
            pid = int(process_id)

            # 尝试查找进程名
            process_name = None
            for process in self.device.enumerate_processes():
                if process.pid == pid:
                    process_name = process.name
                    break

            if not process_name:
                self.console.warning(f"找不到PID为 {pid} 的进程，但仍将尝试附加")
                process_name = f"PID-{pid}"

            self.console.info(f"正在附加到进程 {process_name} (PID: {pid})...")

            # 附加到进程
            self.session = self.device.attach(pid)
            self.process_name = process_name

            self.current_session = {
                "device": self.device,
                "session": self.session,
                "process_name": self.process_name
            }

            self.console.success(f"已附加到进程: {process_name}")

            # 如果有命令，执行它们
            if commands:
                self.console.info("执行指定的命令...")
                for cmd in commands:
                    self.console.status(f"执行: {cmd}")
                    try:
                        self._process_command(cmd)
                    except Exception as e:
                        self.console.error(f"执行命令 '{cmd}' 时出错: {str(e)}")

            # 启动新的控制台
            self._start_console()

        except frida.ProcessNotFoundError:
            self.console.error(f"找不到PID为 {process_id} 的进程")
        except Exception as e:
            self.console.error(f"附加到进程时出错: {str(e)}")

    def _detach_process(self):
        """从当前进程分离，返回到第一级会话"""
        if not self.session:
            return

        try:
            process_name = self.process_name
            self.session.detach()
            self.session = None
            self.process_name = None
            self.current_session = None

            self.console.success(f"已从进程 {process_name} 分离")

            # 重启控制台
            self._start_console()
        except Exception as e:
            self.console.error(f"从进程分离时出错: {str(e)}")

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
        """检查设备是否仍然连接"""
        if not self.device:
            return False

        try:
            # 尝试列出进程以验证连接
            self.device.enumerate_processes()

            # 如果之前设备已断开连接，现在已重新连接，显示消息并重置标志
            if hasattr(self, '_device_disconnected') and self._device_disconnected:
                self.console.success("设备已重新连接！继续执行操作。")
                self._device_disconnected = False

            return True
        except frida.InvalidOperationError:
            # 设备已断开连接
            if not hasattr(self, '_device_disconnected') or not self._device_disconnected:
                self.console.error("设备已断开连接！请重新连接设备以继续。")
                self._device_disconnected = True
            return False
        except Exception as e:
            self.console.error(f"检查设备连接时出错: {str(e)}")
            return False

    