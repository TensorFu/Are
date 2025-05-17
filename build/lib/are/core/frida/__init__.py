#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/frida/__init__.py
from are.core.frida.server import (
    check_frida_server,
    check_frida_server_running,
    start_frida_server,
    kill_frida_server,
    restart_frida_server,
    get_pid_by_port,
    check_root_access
)

from are.core.frida.device import (
    list_devices,
    run_frida_command
)

from are.core.frida.hook import FridaHook

# 确保Frida Hook的脚本目录结构存在
import os
from pathlib import Path

# 创建必要的目录
script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
dist_dir = script_dir / "scripts" / "dist"
dist_dir.mkdir(parents=True, exist_ok=True)

# 不再尝试在导入时编译TypeScript，改为在实际使用时检查

__all__ = [
    'check_frida_server',
    'check_frida_server_running',
    'start_frida_server',
    'kill_frida_server',
    'restart_frida_server',
    'get_pid_by_port',
    'check_root_access',
    'list_devices',
    'run_frida_command',
    'FridaHook'
]
