#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Any
from prompt_toolkit.completion import Completion
from are.commands.base import CommandBase
from are.core import AreConsole

# 控制台实例
console = AreConsole()


class HelpCommand(CommandBase):
    """帮助命令"""

    name = "help"
    help_short = "Display help information"
    help_text = "Display help information for ARE commands"
    usage = "help [command]"
    examples = [
        "help",
        "help memory",
        "help classes"
    ]

    def execute(self, context: Any, args: str):
        """
        执行命令

        参数:
            context: ARE实例
            args: 命令参数
        """
        if not args:
            # 显示所有命令
            console.show_help(context.commands)
        else:
            # 显示特定命令帮助
            command_name = args.strip()
            if command_name in context.commands:
                cmd = context.commands[command_name]
                console.show_command_help(
                    cmd.name,
                    cmd.help_text,
                    cmd.usage,
                    cmd.examples
                )
            else:
                console.error(f"Unknown command: {command_name}")
                console.info("Type 'help' for a list of available commands")

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        from are.core import Are

        # 确保上下文是ARE实例
        if not isinstance(document.app.session.context, Are):
            return []

        are = document.app.session.context

        # 提供命令名称补全
        if len(args) == 0 or (len(args) == 1 and not document.text.endswith(' ')):
            word = args[0] if args else ""
            for name in sorted(are.commands.keys()):
                if name.startswith(word):
                    yield Completion(name, start_position=-len(word),
                                     display=name, display_meta=are.commands[name].help_short)