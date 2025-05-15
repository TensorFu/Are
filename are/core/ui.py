#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rich import box
# are/core/ui.py
from rich.theme import Theme
from rich.progress import  SpinnerColumn
from typing import Optional, Dict, List, Any
from rich.console import Console
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.tree import Tree

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

    def print_table(self, table: Table):
        """打印表格"""
        self.console.print(table)

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
        return Table(title=title, box=box.SIMPLE)

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

    def progress(self):
        """创建一个进度条实例"""
        return Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=self.console
        )

    def device_disconnected_alert(self):
        """设备断开连接警报"""
        self.console.print("\n" + "!" * 50, style="error")
        self.console.print("[error bold]设备已断开连接！[/error bold]", highlight=True)
        self.console.print("!" * 50, style="error")
        self.console.print("请重新连接设备并继续，或输入 'q' 退出程序\n")

    def device_reconnected_alert(self):
        """设备重新连接警报"""
        self.console.print("\n" + "=" * 50, style="success")
        self.console.print("[success bold]设备已重新连接！[/success bold]", highlight=True)
        self.console.print("=" * 50, style="success")
        self.console.print("正在重新初始化环境...\n")

    def print_tree(self, data, title: Optional[str] = None):
        """显示树形数据结构或直接打印已经构建好的Rich Tree

        Args:
            data: 要显示的数据结构，可以是字典、列表、树对象或其他嵌套结构
            title: 可选的树形图标题
        """
        # 如果data已经是一个Tree对象，直接打印
        if isinstance(data, Tree):
            self.console.print(data)
            return

        # 否则，创建一个树形控件
        tree = Tree(f"[bold]{title or '数据结构'}[/bold]")

        # 递归构建树
        def _build_tree(node, data):
            if isinstance(data, dict):
                # 处理字典类型
                for key, value in data.items():
                    if isinstance(value, (dict, list)) and value:
                        # 复杂类型递归处理
                        branch = node.add(f"[yellow]{key}[/yellow]")
                        _build_tree(branch, value)
                    else:
                        # 简单类型直接显示
                        node.add(f"[yellow]{key}[/yellow]: [green]{value}[/green]")
            elif isinstance(data, list):
                # 处理列表类型
                for i, item in enumerate(data):
                    if isinstance(item, (dict, list)) and item:
                        # 复杂类型递归处理
                        branch = node.add(f"[blue][{i}][/blue]")
                        _build_tree(branch, item)
                    else:
                        # 简单类型直接显示
                        node.add(f"[blue][{i}][/blue]: [green]{item}[/green]")
            else:
                # 其他类型直接显示
                node.add(f"[green]{data}[/green]")

        # 开始构建树
        _build_tree(tree, data)

        # 打印树
        self.console.print(tree)


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