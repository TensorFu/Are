#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/ui.py
import sys
import time
from typing import Optional, List, Any, Dict
from rich.console import Console
from rich.theme import Theme
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.style import Style

# 定义主题
are_theme = Theme({
    "banner": "magenta bold",
    "info": "cyan",
    "success": "green bold",
    "warning": "yellow",
    "error": "red bold",
    "status": "blue",
    "debug": "dim",
    "prompt": "cyan bold",
    "highlight": "magenta",
    "code": "green",
    "command": "yellow bold"
})


class AreConsole:
    """自定义控制台输出"""

    def __init__(self):
        """初始化控制台"""
        self.console = Console(theme=are_theme)

    def banner(self, text: str):
        """显示横幅文本"""
        self.console.print(text, style="banner")

    def info(self, text: str):
        """显示信息文本"""
        self.console.print(f"[info][[*]] {text}[/info]")

    def success(self, text: str):
        """显示成功文本"""
        self.console.print(f"[success][[+]] {text}[/success]")

    def warning(self, text: str):
        """显示警告文本"""
        self.console.print(f"[warning][[!]] {text}[/warning]")

    def error(self, text: str):
        """显示错误文本"""
        self.console.print(f"[error][[x]] {text}[/error]")

    def status(self, text: str):
        """显示状态文本"""
        self.console.print(f"[status][[>]] {text}[/status]")

    def debug(self, text: str):
        """显示调试文本"""
        self.console.print(f"[debug][[~]] {text}[/debug]")

    def newline(self):
        """显示空行"""
        self.console.print()

    def print(self, text: str, style: Optional[str] = None):
        """显示自定义样式文本"""
        self.console.print(text, style=style)

    def syntax(self, code: str, lexer: str = "python"):
        """显示语法高亮代码"""
        self.console.print(Syntax(code, lexer, theme="monokai"))

    def markdown(self, text: str):
        """显示Markdown文本"""
        self.console.print(Markdown(text))

    def panel(self, text: str, title: Optional[str] = None, style: Optional[str] = None):
        """显示面板"""
        self.console.print(Panel(text, title=title, style=style or "info"))

    def table(self, title: Optional[str] = None) -> Table:
        """创建表格"""
        return Table(title=title, box=True)

    def show_help(self, commands: Dict[str, Any]):
        """显示帮助信息"""
        table = self.table("Available Commands")

        table.add_column("Command", style="command")
        table.add_column("Description", style="info")

        for name, cmd in sorted(commands.items()):
            table.add_row(name, cmd.help_short)

        self.console.print(table)

    def show_command_help(self, command: str, description: str,
                          usage: str, examples: Optional[List[str]] = None):
        """显示命令帮助信息"""
        self.console.print(f"[command]{command}[/command]", style="bold")
        self.console.print(f"{description}\n")

        self.console.print("[bold]Usage:[/bold]")
        self.console.print(f"  {usage}")

        if examples:
            self.console.print("\n[bold]Examples:[/bold]")
            for example in examples:
                self.console.print(f"  {example}")


class ProgressSpinner:
    """进度旋转器上下文管理器"""

    def __init__(self, text: str):
        """
        初始化进度旋转器

        参数:
            text: 显示文本
        """
        self.text = text
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[status]{task.description}[/status]")
        )
        self.task_id = None

    def __enter__(self):
        """进入上下文"""
        self.progress.start()
        self.task_id = self.progress.add_task(self.text, total=None)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文"""
        self.progress.stop()