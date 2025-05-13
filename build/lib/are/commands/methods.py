#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Any
from prompt_toolkit.completion import Completion
from are.commands.base import CommandBase
from are.core import AreConsole

# 控制台实例
console = AreConsole()


class MethodsCommand(CommandBase):
    """方法列表命令"""

    name = "methods"
    help_short = "List methods of a class"
    help_text = "List all methods of a specified class"
    usage = "methods <class_name> [filter]"
    examples = [
        "methods UIViewController",
        "methods NSString init*",
        "methods MyClass *privateMethod*"
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

        parts = args.strip().split(maxsplit=1)
        if not parts:
            console.error("Usage: methods <class_name> [filter]")
            return

        class_name = parts[0]
        filter_text = parts[1] if len(parts) > 1 else ""

        console.info(
            f"Listing methods for class '{class_name}'{' (filter: ' + filter_text + ')' if filter_text else ''}...")

        try:
            # 这里应该调用实际的Frida脚本来获取方法列表
            # 示例实现
            method_list = [
                "- initWithFrame:",
                "- setNeedsDisplay",
                "+ alloc",
                "- dealloc"
                # 应从Frida脚本获取实际方法列表
            ]

            # 应用过滤器
            if filter_text:
                import fnmatch
                method_list = [method for method in method_list if fnmatch.fnmatch(method, f"*{filter_text}*")]

            if method_list:
                console.success(f"Found {len(method_list)} methods")
                for i, method_name in enumerate(sorted(method_list)):
                    console.print(f"[{i}] {method_name}")
            else:
                console.warning(f"No methods found for class '{class_name}'")

        except Exception as e:
            console.error(f"Error listing methods: {str(e)}")

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        from are.core import Are

        # 确保上下文是ARE实例
        if not isinstance(document.app.session.context, Are):
            return []

        # 如果还没有输入类名，可以提供类名补全
        if len(args) == 0 or (len(args) == 1 and not document.text.endswith(' ')):
            # 这里应该获取可用的类名列表
            class_list = ["UIView", "UIViewController", "NSString", "NSArray"]
            word = args[0] if args else ""
            for cls in class_list:
                if cls.startswith(word):
                    yield Completion(cls, start_position=-len(word),
                                     display=cls, display_meta="class")
