#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import frida
import json
import subprocess
import tempfile
from typing import Optional, List, Dict, Any
from core.ui import AreConsole

# 控制台实例
console = AreConsole()


def get_version() -> str:
    """获取当前版本"""
    # 可以从配置文件或包元数据中获取
    return "0.1.0"


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


def get_script_path(script_name: str) -> str:
    """
    获取脚本文件路径

    参数:
        script_name: 脚本名称

    返回:
        脚本文件路径
    """
    # 检查是否包含文件扩展名
    if not script_name.endswith(".ts"):
        script_name = f"{script_name}.ts"

    # 尝试在模块目录中查找
    if '/' in script_name or '\\' in script_name:
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'scripts',
            script_name
        )
    else:
        # 尝试在根脚本目录查找
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'scripts',
            script_name
        )

        # 如果不存在，尝试在模块目录查找
        if not os.path.exists(script_path):
            script_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'scripts',
                'modules',
                script_name
            )

    return script_path


def load_typescript_script(script_name: str) -> Optional[str]:
    """
    加载TypeScript脚本内容

    参数:
        script_name: 脚本名称

    返回:
        脚本内容或None
    """
    script_path = get_script_path(script_name)

    try:
        with open(script_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        console.error(f"Script file not found: {script_path}")
        return None
    except Exception as e:
        console.error(f"Error loading script: {str(e)}")
        return None


def compile_typescript(script_name: str) -> Optional[str]:
    """
    编译TypeScript脚本为JavaScript

    参数:
        script_name: 脚本名称

    返回:
        编译后的JavaScript代码或None
    """
    # 获取脚本路径
    script_path = get_script_path(script_name)

    if not os.path.exists(script_path):
        console.error(f"Script not found: {script_path}")
        return None

    try:
        # 检查是否安装了TypeScript编译器
        try:
            subprocess.run(["tsc", "--version"], check=True, capture_output=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            console.error("TypeScript compiler (tsc) not found. Please install it with 'npm install -g typescript'")
            return None

        # 创建临时目录用于编译
        with tempfile.TemporaryDirectory() as temp_dir:
            # 临时tsconfig.json
            tsconfig = {
                "compilerOptions": {
                    "target": "ES2020",
                    "module": "commonjs",
                    "outDir": temp_dir,
                    "strict": True,
                    "esModuleInterop": True,
                    "lib": ["ES2020"],
                    "types": ["frida-gum"]
                },
                "include": [script_path]
            }

            # 写入临时tsconfig.json
            tsconfig_path = os.path.join(temp_dir, "tsconfig.json")
            with open(tsconfig_path, "w") as f:
                json.dump(tsconfig, f, indent=2)

            # 运行TypeScript编译器
            result = subprocess.run(
                ["tsc", "-p", tsconfig_path],
                check=False,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                console.error(f"TypeScript compilation failed:")
                console.error(result.stderr)
                return None

            # 确定输出文件路径
            output_file = os.path.join(
                temp_dir,
                os.path.basename(script_path).replace(".ts", ".js")
            )

            # 如果输出文件不存在，可能是存储在子目录中
            if not os.path.exists(output_file):
                # 尝试在temp_dir的子目录中查找
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        if file.endswith(".js"):
                            output_file = os.path.join(root, file)
                            break

            # 读取编译后的JavaScript
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    return f.read()
            else:
                console.error(f"Compiled output not found")
                return None

    except Exception as e:
        console.error(f"Error compiling TypeScript: {str(e)}")
        return None


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