#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any
from commands.base import CommandBase
from commands.help import HelpCommand
from commands.memory import MemoryCommand
from commands.classes import ClassesCommand
from commands.env import EnvCommand
from commands.methods import MethodsCommand
from commands.info import InfoCommand


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