#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/cli.py
import os
import subprocess
import sys
import click
import time
from pathlib import Path
from typing import Optional, Tuple

from rich.console import Console
from are.core import AreConsole
from are.core.are import Are
from are.core.frida import (
    check_frida_server,
    check_frida_server_running,
    start_frida_server,
    list_devices as frida_list_devices,
    check_root_access
)
from are.core.frida.device import check_device_connection

# 初始化控制台
console = AreConsole()


class AreCLI:
    """ARE命令行界面类，处理CLI相关逻辑"""

    def __init__(self):
        self.banner_path = Path(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / 'are' / 'resources' / 'banner.txt'
        self.rich_console = Console()

    def get_device_info(self) -> str:
        """获取连接设备信息"""
        try:
            result = subprocess.run(
                ["adb", "shell", "getprop ro.product.model"],
                capture_output=True,
                text=True,
                check=False
            )
            return result.stdout.strip() or "Unknown Device"
        except Exception as e:
            console.warning(f"获取设备信息失败: {e}")
            return "Unknown Device"

    def display_banner(self) -> None:
        """显示ARE banner"""
        device_info = self.get_device_info()

        self.rich_console.print(f"\n使用USB设备 `{device_info}`")
        self.rich_console.print("Agent已注入并正常响应！\n")

        # 读取banner文件
        try:
            with open(self.banner_path, 'r') as f:
                banner = f.read()
        except Exception:
            # 读取失败时使用默认banner
            banner = """
█████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝
███████║██████╔╝█████╗
██╔══██║██╔══██╗██╔══╝
██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

Android Reverse Engineering
"""

        self.rich_console.print(banner)
        self.rich_console.print("\nRuntime Mobile Exploration")
        self.rich_console.print("输入 'help' 查看可用命令\n")

    def prompt_for_frida_server(self) -> Optional[str]:
        """提示用户提供frida-server路径，直到找到有效路径或用户退出"""
        while True:
            console.warning("在 /data/local/tmp 中未找到 frida-server 或 fs")
            console.info("请提供您的 frida-server 路径或输入 'exit' 退出:")
            console.info("  示例: /data/local/tmp/frida-server-16.0.8")
            console.info("  或者您可以通过以下步骤安装:")
            console.info("  1. 从 https://github.com/frida/frida/releases 下载 frida-server")
            console.info("  2. 推送到设备: adb push frida-server /data/local/tmp/")
            console.info("  3. 设置可执行权限: adb shell chmod 755 /data/local/tmp/frida-server")

            try:
                user_input = input("输入路径 (或 'exit' 退出): ")

                if user_input.lower() in ['exit', 'quit', 'q']:
                    console.info("操作已被用户取消")
                    return None

                # 如果用户直接按Enter，再次检查默认路径
                if not user_input.strip():
                    server_path = check_frida_server()
                    if server_path:
                        return server_path
                    continue

                # 检查用户提供的路径是否存在
                server_path = check_frida_server(user_input)
                if server_path:
                    return server_path
                else:
                    console.error(f"在 {user_input} 找不到 frida-server")
                    # 继续循环重新提示
            except KeyboardInterrupt:
                console.info("操作已被用户取消")
                return None

    def setup_frida_server(self) -> Tuple[bool, Optional[str]]:
        """设置并启动frida-server"""
        # 检查frida-server是否已在运行
        if check_frida_server_running():
            console.success("Frida服务器已经在运行")
            return True, None

        # 检查frida-server
        server_path = check_frida_server()
        if not server_path:
            # 提示用户输入frida-server路径
            server_path = self.prompt_for_frida_server()
            if not server_path:  # 用户取消了操作
                return False, None

        # 尝试使用找到的路径启动frida-server
        start_success = start_frida_server(server_path)

        if start_success:
            # 给服务器一点启动时间
            time.sleep(1)
            return True, server_path
        else:
            # 检查root权限
            if not check_root_access():
                console.warning("没有root权限")
                console.info("没有root权限，某些功能可能无法使用")
                console.info("如果您的设备已root，请授予ADB root权限")

            console.warning("无法自动启动frida-server")
            console.info("请手动启动:")
            console.info(f"  adb shell \"su -c '{server_path} &'\"")

            return False, server_path

    def run_are_session(self) -> None:
        """运行ARE会话"""
        try:
            are = Are()
            are.start_console()
        except Exception as e:
            console.error(f"启动ARE会话时出错: {e}")
            sys.exit(1)


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """ARE - 基于Frida的进程检测工具"""
    # 如果没有子命令
    if ctx.invoked_subcommand is None:
        are_cli = AreCLI()

        # 检查设备连接
        if not check_device_connection():
            console.error("未连接Android设备")
            console.info("请通过USB连接您的Android设备并启用USB调试")
            console.info("然后运行 'adb devices' 验证连接")
            return

        console.success("Android设备已连接")

        # 设置frida-server
        setup_success, server_path = are_cli.setup_frida_server()

        if setup_success:
            # 显示banner
            are_cli.display_banner()
            # 启动ARE会话
            are_cli.run_are_session()
        else:
            if server_path:  # 有server_path但启动失败
                # 等待用户输入
                console.print("\n按Enter继续或Ctrl+C退出...", style="prompt")
                try:
                    input()
                    # 即使无法启动frida-server，也尝试运行ARE
                    are_cli.run_are_session()
                except KeyboardInterrupt:
                    console.info("操作已被用户取消")
                    return
            else:  # 没有server_path（用户取消了操作）
                return

        # 显示帮助
        click.echo(ctx.get_help())


def process_arguments() -> None:
    """处理命令行参数"""
    # 检查命令行参数
    if len(sys.argv) > 1:
        # 如果第一个参数不是子命令或选项，假设它是一个处理规范
        first_arg = sys.argv[1]
        if first_arg not in ['version', 'devices', '--help', '-h'] and not first_arg.startswith('-'):
            process_spec = first_arg
            sys.argv.pop(1)
            sys.argv.insert(1, 'watching')
            sys.argv.insert(2, process_spec)


def main():
    """命令行主入口点"""
    try:
        process_arguments()
        cli()
        # 正常退出，不显示帮助信息
        sys.exit(0)
    except KeyboardInterrupt:
        click.echo("\n操作已被用户取消")
    except Exception as e:
        click.echo(f"错误: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()