#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/__init__.py
from typing import Dict
from are.commands.base import CommandBase
from are.commands.help import HelpCommand
from are.commands.memory import MemoryCommand
from are.commands.classes import ClassesCommand
from are.commands.env import EnvCommand
from are.commands.methods import MethodsCommand
from are.commands.info import InfoCommand
from are.commands.hook import HookCommand


def get_all_commands() -> Dict[str, CommandBase]:
    """
    获取所有可用命令

    返回:
        命令字典
    """
    commands = {}

    # 注册命令
    for command_class in [
        HelpCommand,
        MemoryCommand,
        ClassesCommand,
        EnvCommand,
        MethodsCommand,
        InfoCommand,
        HookCommand,
        # 添加更多命令...
    ]:
        cmd = command_class()
        commands[cmd.name] = cmd

    return commands


# 定义对外提供的函数作为模块API
__all__ = ['get_all_commands']