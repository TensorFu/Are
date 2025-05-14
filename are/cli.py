#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/cli.py
import os
import subprocess
import sys
import click
import re
from are.core import AreConsole, utils
from are.core.are import Are
import time
from rich.console import Console
from rich.panel import Panel

# Initialize console
console = AreConsole()

def prompt_for_frida_server():
    """Repeatedly prompt for frida-server path until a valid one is found or user exits"""
    while True:
        console.warning("Could not find frida-server or fs in /data/local/tmp")
        console.info("Please provide the path to your frida-server or type 'exit' to quit:")
        console.info("  Example: /data/local/tmp/frida-server-16.0.8")
        console.info("  Or you can install it by running:")
        console.info("  1. Download frida-server from https://github.com/frida/frida/releases")
        console.info("  2. Push it to your device: adb push frida-server /data/local/tmp/")
        console.info("  3. Make it executable: adb shell chmod 755 /data/local/tmp/frida-server")

        try:
            user_input = input("Enter path (or 'exit' to quit): ")

            if user_input.lower() in ['exit', 'quit', 'q']:
                console.info("Operation cancelled by user")
                sys.exit(0)

            # If user just presses Enter, check default paths again
            if not user_input.strip():
                server_path = utils.check_frida_server()
                if server_path:
                    return server_path
                continue

            # Check if the user-provided path exists
            server_path = utils.check_frida_server(user_input)
            if server_path:
                return server_path
            else:
                console.error(f"Could not find frida-server at: {user_input}")
                # Continue loop to prompt again
        except KeyboardInterrupt:
            console.info("Operation cancelled by user")
            sys.exit(0)

def display_are_banner():
    """Display the ARE banner"""
    device_info = subprocess.run(
        ["adb", "shell", "getprop ro.product.model"],
        capture_output=True,
        text=True,
        check=False
    ).stdout.strip()
    
    console = Console()
    console.print(f"\nUsing USB device `{device_info}`")
    console.print("Agent injected and responds ok!\n")
    
    # 从banner.txt文件中读取banner内容
    banner_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                              'are', 'resources', 'banner.txt')
    try:
        with open(banner_path, 'r') as f:
            banner = f.read()
    except:
        # 如果读取失败，使用默认banner
        banner = """
█████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝
███████║██████╔╝█████╗
██╔══██║██╔══██╗██╔══╝
██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

Android Reverse Engineering
"""
    
    console.print(banner)
    console.print("\nRuntime Mobile Exploration")
    console.print("Type 'help' for available commands\n")

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """ARE - A Frida-based process instrumentation tool"""
    # If no subcommand, show help
    if ctx.invoked_subcommand is None:
        # Check if device is connected
        if not utils.check_device_connection():
            console.error("No Android device connected")
            console.info("Please connect your Android device via USB and enable USB debugging")
            console.info("Then run 'adb devices' to verify the connection")
            return

        console.success("Android device connected")

        # Check if frida-server is already running
        if utils.check_frida_server_running():
            console.success("Frida server is already running")
            # Display the banner and continue
            display_are_banner()
            
            # Create and run the main ARE session
            are = Are()
            are._start_console()
            return

        # Check for frida-server
        server_path = utils.check_frida_server()
        if not server_path:
            # Prompt user for frida-server path until valid or exit
            server_path = prompt_for_frida_server()

        # Try to start frida-server with the found path
        start_success = utils.start_frida_server(server_path)
        
        if start_success:
            # Give the server a moment to start
            time.sleep(1)
            
            # Display the banner
            display_are_banner()
            
            # Create and run the main ARE session
            are = Are()
            are._start_console()
        else:
            # Check root access
            if not utils.check_root_access():
                console.warning("Root access not available")
                console.info("Some features may not work without root access")
                console.info("If your device is rooted, please grant root permissions to ADB")

            console.warning("Failed to start frida-server automatically")
            console.info("Please start it manually with:")
            console.info(f"  adb shell \"su -c '{server_path} &'\"")

            # Wait for user input
            console.print("\nPress Enter to continue anyway or Ctrl+C to exit...", style="prompt")
            try:
                input()
                # Even if we couldn't start frida-server, try to run ARE
                are = Are()
                are._start_console()
            except KeyboardInterrupt:
                console.info("Operation cancelled by user")
                return

        # Display help
        click.echo(ctx.get_help())


@cli.command()
def version():
    """Display the current version"""
    from are import __version__
    click.echo(f"ARE version {__version__}")

@cli.command()
def devices():
    """List available devices"""
    utils.list_devices()

def main():
    """命令行主入口点"""
    try:
        # 检查命令行参数
        if len(sys.argv) > 1:
            # 如果第一个参数不是子命令或选项，假设它是一个处理规范
            if sys.argv[1] not in ['version', 'devices', '--help', '-h'] and not sys.argv[
                1].startswith('-'):
                process_spec = sys.argv[1]
                sys.argv.pop(1)
                sys.argv.insert(1, 'watching')
                sys.argv.insert(2, process_spec)

        cli()
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user")
    except Exception as e:
        click.echo(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()