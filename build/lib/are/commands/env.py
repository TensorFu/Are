#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/env.py
from typing import List, Any
from prompt_toolkit.completion import Completion
from are.commands.base import CommandBase
from are.core import AreConsole

# 控制台实例
console = AreConsole()


class EnvCommand(CommandBase):
    """环境信息命令"""

    name = "env"
    help_short = "Show environment information"
    help_text = "Show information about the target environment"
    usage = "env [system|process|frida]"
    examples = [
        "env",
        "env system",
        "env process",
        "env frida"
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

        subcommand = args.strip().lower() if args.strip() else "all"

        if subcommand == "all":
            self._show_all_info(context)
        elif subcommand == "system":
            self._show_system_info(context)
        elif subcommand == "process":
            self._show_process_info(context)
        elif subcommand == "frida":
            self._show_frida_info(context)
        else:
            console.error(f"Unknown subcommand: {subcommand}")
            console.info("Available options: system, process, frida")

    def _show_all_info(self, context: Any):
        """显示所有信息"""
        self._show_system_info(context)
        console.print()
        self._show_process_info(context)
        console.print()
        self._show_frida_info(context)

    def _show_system_info(self, context: Any):
        """显示系统信息"""
        console.panel(
            """OS: iOS 15.0
Device: iPhone 12
Architecture: arm64
Memory: 4GB""",
            title="System Information",
            style="info"
        )

    def _show_process_info(self, context: Any):
        """显示进程信息"""
        console.panel(
            """Process Name: Example App
PID: 1234
Path: /var/containers/Bundle/Application/...
Memory Usage: 45MB""",
            title="Process Information",
            style="info"
        )

    def _show_frida_info(self, context: Any):
        """显示Frida信息"""
        console.panel(
            """Frida Version: 15.1.17
Script Runtime: v8
Certificates: Pinning bypassed
Protections: Disabled""",
            title="Frida Information",
            style="info"
        )

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        if len(args) == 0 or (len(args) == 1 and not document.text.endswith(' ')):
            word = args[0] if args else ""
            for option in ["system", "process", "frida"]:
                if option.startswith(word):
                    yield Completion(option, start_position=-len(word),
                                    display=option, display_meta=f"Show {option} info")