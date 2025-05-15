#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/frida/device.py

import frida
import json
from typing import Optional, List, Dict, Any
from are.core.ui import AreConsole

# 控制台实例
console = AreConsole()

def check_device_connection():
    """检查是否有Android设备通过ADB连接"""
    try:
        import subprocess
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            check=False
        )

        # 解析输出以检查已连接的设备
        lines = result.stdout.strip().split('\n')
        # 跳过第一行，它是标题"List of devices attached"
        device_lines = [line for line in lines[1:] if line.strip()]

        return len(device_lines) > 0
    except Exception as e:
        console.error(f"检查设备连接时出错: {str(e)}")
        return False

def list_devices():
    """列出可用设备"""
    try:
        devices = frida.enumerate_devices()

        if not devices:
            console.warning("No devices found")
            return

        console.info("Available devices:")

        for device in devices:
            if device.type == "local":
                console.print(f"► Local device (type: {device.type})")
            elif device.type == "usb":
                console.print(f"► {device.name} (id: {device.id}, type: {device.type})")
            elif device.type == "remote":
                console.print(f"► Remote device {device.id} (type: {device.type})")
            else:
                console.print(f"► {device.name} (id: {device.id}, type: {device.type})")
    except Exception as e:
        console.error(f"Error listing devices: {str(e)}")

def run_frida_command(device: frida.core.Device, command: List[str]) -> Optional[Dict[str, Any]]:
    """
    运行Frida命令

    参数:
        device: Frida设备对象
        command: 命令参数列表

    返回:
        命令结果或None
    """
    try:
        result = device.execute_command(" ".join(command))
        return json.loads(result)
    except Exception as e:
        console.error(f"Error executing Frida command: {str(e)}")
        return None 