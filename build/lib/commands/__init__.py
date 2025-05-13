#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict
from are.commands import CommandBase
from are.commands import HelpCommand
from are.commands import MemoryCommand
from are.commands import ClassesCommand
from are.commands import EnvCommand
from are.commands import MethodsCommand
from are.commands import InfoCommand


def get_commands() -> Dict[str, CommandBase]:
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
        # 添加更多命令...
    ]:
        cmd = command_class()
        commands[cmd.name] = cmd

    return commands