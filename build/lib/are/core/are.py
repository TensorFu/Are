#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import frida
from typing import Dict, Optional
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.styles import Style
from are.core.ui import AreConsole, ProgressSpinner
from are.core.session import Session
from are.commands import get_commands, CommandBase

# 控制台实例
console = AreConsole()


class AreCompleter(Completer):
    """命令补全器"""

    def __init__(self, commands: Dict[str, CommandBase]):
        self.commands = commands

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor

        # 空输入时提供所有命令
        if not text.strip():
            for name in sorted(self.commands.keys()):
                yield Completion(name, start_position=0, display=name,
                                 display_meta=self.commands[name].help_short)
            return

        # 解析命令
        parts = text.strip().split()

        # 首个词的补全
        if len(parts) == 1 and not text.endswith(' '):
            word = parts[0]
            for name in sorted(self.commands.keys()):
                if name.startswith(word):
                    yield Completion(name, start_position=-len(word), display=name,
                                     display_meta=self.commands[name].help_short)
            return

        # 子命令补全
        if len(parts) >= 1:
            command = parts[0]
            if command in self.commands:
                # 获取命令对象
                cmd_obj = self.commands[command]

                # 调用命令的补全方法
                if hasattr(cmd_obj, 'get_completions'):
                    for comp in cmd_obj.get_completions(document, parts[1:]):
                        yield comp


class Are:
    def __init__(self, device_id: Optional[str] = None):
        """
        初始化ARE实例

        参数:
            device_id: 设备ID，None表示使用本地设备
        """
        # 获取设备
        if device_id:
            try:
                self.device = frida.get_device(device_id)
            except frida.InvalidArgumentError:
                console.error(f"Device {device_id} not found!")
                sys.exit(1)
        else:
            try:
                self.device = frida.get_local_device()
            except frida.InvalidArgumentError:
                console.error("No local device available!")
                sys.exit(1)

        # 会话管理
        self.sessions: Dict[str, Session] = {}
        self.current_session: Optional[Session] = None

        # 命令注册
        self.commands = get_commands()

        # 提示会话
        history_file = os.path.expanduser("~/.are_history")
        self.history = FileHistory(history_file)
        self.completer = AreCompleter(self.commands)
        self.session = PromptSession(
            history=self.history,
            auto_suggest=AutoSuggestFromHistory(),
            completer=self.completer,
            style=Style.from_dict({
                'prompt': 'ansicyan bold',
                'rprompt': 'ansigreen',
            })
        )

        # 显示横幅
        self._show_banner()

    def _show_banner(self):
        """显示ARE标题"""
        # 从文件加载ASCII艺术标题
        banner_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'resources',
            'banner.txt'
        )

        try:
            with open(banner_path, 'r') as f:
                banner = f.read()
                console.banner(banner)
        except FileNotFoundError:
            # 如果文件不存在，显示简单标题
            console.banner("ARE - Android Reverse Engineering")

        console.info("A Frida-based instrumentation toolkit")
        console.info("Type 'help' for available commands")
        console.newline()

    def attach(self, process_name: str, initial_command: Optional[str] = None) -> bool:
        """
        附加到现有进程

        参数:
            process_name: 目标进程名
            initial_command: 附加后要执行的初始命令

        返回:
            是否成功
        """
        with ProgressSpinner(f"Attaching to {process_name}") as spinner:
            try:
                # 查找进程
                target = None
                for process in self.device.enumerate_processes():
                    if process.name == process_name:
                        target = process
                        break

                if not target:
                    console.error(f"Process {process_name} not found!")
                    return False

                # 创建会话
                frida_session = self.device.attach(target.pid)
                session = Session(frida_session, target, self.device)
                self.sessions[process_name] = session
                self.current_session = session

                # 加载基本脚本
                session.load_typescript("base")

                # 显示会话信息
                console.success(f"Attached to {process_name} (PID: {target.pid})")

                # 启动交互式会话
                self._interactive_session(initial_command)
                return True

            except frida.ProcessNotFoundError:
                console.error(f"Process {process_name} not found!")
                return False
            except Exception as e:
                console.error(f"Error attaching to process: {str(e)}")
                return False

    def spawn_and_attach(self, process_name: str, initial_command: Optional[str] = None) -> bool:
        """
        生成并附加到新进程

        参数:
            process_name: 目标进程名
            initial_command: 附加后要执行的初始命令

        返回:
            是否成功
        """
        with ProgressSpinner(f"Spawning {process_name}") as spinner:
            try:
                # 生成进程
                pid = self.device.spawn(process_name)

                # 附加到进程
                frida_session = self.device.attach(pid)

                # 获取进程信息
                target = None
                for process in self.device.enumerate_processes():
                    if process.pid == pid:
                        target = process
                        break

                if not target:
                    console.error(f"Spawned process not found!")
                    return False

                # 创建会话
                session = Session(frida_session, target, self.device)
                self.sessions[process_name] = session
                self.current_session = session

                # 加载基本脚本
                session.load_typescript("base")

                # 恢复进程执行
                self.device.resume(pid)

                # 显示会话信息
                console.success(f"Spawned and attached to {process_name} (PID: {target.pid})")

                # 启动交互式会话
                self._interactive_session(initial_command)
                return True

            except Exception as e:
                console.error(f"Error spawning process: {str(e)}")
                return False

    def _interactive_session(self, initial_command: Optional[str] = None):
        """
        启动交互式会话

        参数:
            initial_command: 要执行的初始命令
        """
        if not self.current_session:
            console.error("No active session!")
            return

        # 如果有初始命令，首先执行它
        if initial_command:
            # 检查是否使用 'with' 关键字
            if initial_command.startswith('with '):
                initial_command = initial_command[5:]  # 去掉 'with ' 前缀

            self._execute_command(initial_command)

        # 交互循环
        try:
            while self.current_session and self.current_session.is_active():
                # 构建提示符
                prompt = self._build_prompt()

                # 获取用户输入
                try:
                    command = self.session.prompt(prompt)
                except KeyboardInterrupt:
                    console.newline()
                    continue

                # 执行命令
                if command.strip():
                    self._execute_command(command)

        except KeyboardInterrupt:
            console.warning("\nExiting session...")
        except Exception as e:
            console.error(f"Error in interactive session: {str(e)}")
        finally:
            # 如果会话仍在活动，尝试清理
            if self.current_session and self.current_session.is_active():
                try:
                    self.current_session.detach()
                except Exception as e:
                    console.error(f"Error detaching session: {str(e)}")

            self.current_session = None

    def _build_prompt(self) -> str:
        """构建交互式提示符"""
        if not self.current_session:
            return "are > "

        target = self.current_session.target
        device = self.current_session.device

        # 获取设备信息
        device_info = []
        if hasattr(device, 'name') and device.name:
            device_info.append(device.name)

        if hasattr(device, 'id') and device.id:
            id_parts = device.id.split(':')
            if len(id_parts) > 1:
                device_info.append(id_parts[0])

        # 设备类型
        device_type = "usb"
        if hasattr(device, 'type'):
            device_type = device.type

        # 构建提示符
        device_str = ": ".join(device_info) if device_info else "device"
        return f"{target.name} on ({device_str}) [{device_type}] # "

    def _execute_command(self, command_line: str):
        """
        执行命令

        参数:
            command_line: 命令行文本
        """
        parts = command_line.strip().split(maxsplit=1)
        if not parts:
            return

        command_name = parts[0]
        args = parts[1] if len(parts) > 1 else ""

        # 检查是否为内置命令
        if command_name == "exit" or command_name == "quit":
            if self.current_session:
                self.current_session.detach()
                self.current_session = None
            return

        # 查找命令
        if command_name in self.commands:
            cmd = self.commands[command_name]
            try:
                cmd.execute(self, args)
            except Exception as e:
                console.error(f"Error executing command: {str(e)}")
        else:
            console.error(f"Unknown command: {command_name}")
            console.info("Type 'help' for a list of available commands")