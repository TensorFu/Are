#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/documentation.py
from typing import List, Any
from are.commands.base import CommandBase

class DocumentationCommand(CommandBase):
    """文档命令"""

    name = "doc"
    help_short = "Show documentation"
    help_text = "Show documentation for ARE or specific features"
    usage = "doc [topic]"
    examples = [
        "doc",
        "doc frida",
        "doc hook"
    ]

    def execute(self, context: Any, args: str):
        """
        执行命令

        参数:
            context: ARE实例
            args: 命令参数
        """
        # 简单地调用help命令
        if hasattr(context, 'commands') and 'help' in context.commands:
            context.commands['help'].execute(context, args)
        else:
            print("Documentation command is just a placeholder. Use 'help' instead.")
            
    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        yield from []
