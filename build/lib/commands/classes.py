#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Any
from are.commands import CommandBase
from are.core import AreConsole

# 控制台实例
console = AreConsole()


class ClassesCommand(CommandBase):
    """类列表命令"""

    name = "classes"
    help_short = "List all classes in the target"
    help_text = "List all classes/namespaces in the target application"
    usage = "classes [filter]"
    examples = [
        "classes",
        "classes UIKit",
        "classes *View*"
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

        filter_text = args.strip()
        console.info(f"Listing classes{' (filter: ' + filter_text + ')' if filter_text else ''}...")

        try:
            # 这里应该调用实际的Frida脚本来获取类列表
            # 示例实现
            class_list = [
                "SampleClass1",
                "SampleClass2",
                "UIView",
                "UIViewController"
                # 应从Frida脚本获取实际类列表
            ]

            # 应用过滤器
            if filter_text:
                import fnmatch
                class_list = [cls for cls in class_list if fnmatch.fnmatch(cls, filter_text)]

            if class_list:
                console.success(f"Found {len(class_list)} classes")
                for i, cls_name in enumerate(sorted(class_list)):
                    console.print(f"[{i}] {cls_name}")
            else:
                console.warning("No classes found")

        except Exception as e:
            console.error(f"Error listing classes: {str(e)}")

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        # 这里可以提供之前找到的类名作为补全
        return []