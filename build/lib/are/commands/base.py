#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional


class CommandBase(ABC):
    """命令基类"""

    # 命令名称
    name = "base"

    # 简短帮助
    help_short = "Base command"

    # 详细帮助
    help_text = "Base command that should be subclassed"

    # 用法示例
    usage = "base [arguments]"

    # 示例命令
    examples = []

    @abstractmethod
    def execute(self, context: Any, args: str):
        """
        执行命令

        参数:
            context: 命令上下文（ARE实例）
            args: 命令参数
        """
        pass

    def get_completions(self, document, args: List[str]):
        """
        获取命令补全

        参数:
            document: 文档对象
            args: 参数列表

        返回:
            补全生成器
        """
        return []