#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/cli.py
import os
import subprocess
import sys
import click
import re
from are.core import AreConsole
from are.core.are import Are
from are.core.utils import list_devices
import time
from rich.console import Console
from rich.panel import Panel


# Initialize console
console = AreConsole()

def check_device_connection():
    """Check if any Android device is connected via ADB"""
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            check=False
        )

        # Parse the output to check for connected devices
        lines = result.stdout.strip().split('\n')
        # Skip the first line which is the header "List of devices attached"
        device_lines = [line for line in lines[1:] if line.strip()]

        return len(device_lines) > 0
    except Exception as e:
        console.error(f"Error checking device connection: {str(e)}")
        return False

def check_root_access():
    """Check if we have root access on the device"""
    try:
        result = subprocess.run(
            ["adb", "shell", "su", "-c", "id"],
            capture_output=True,
            text=True,
            check=False
        )

        # If the command was successful and contains "uid=0", we have root access
        return result.returncode == 0 and "uid=0" in result.stdout
    except Exception as e:
        console.error(f"Error checking root access: {str(e)}")
        return False

def check_frida_server(custom_path=None):
    """Check if frida-server exists at the specified path or default locations"""
    try:
        paths_to_check = []

        # Add custom path if provided
        if custom_path:
            paths_to_check.append(custom_path)

        # Add default paths
        paths_to_check.extend(["/data/local/tmp/frida-server", "/data/local/tmp/fs"])

        for path in paths_to_check:
            result = subprocess.run(
                ["adb", "shell", f"[ -f {path} ]"],
                capture_output=True,
                check=False
            )
            if result.returncode == 0:
                return path  # Return the path of the found server

        return None  # Return None if no server found
    except Exception as e:
        console.error(f"Error checking frida-server: {str(e)}")
        return None

def check_frida_server_running():
    """Check if frida-server is already running"""
    try:
        # Try two different methods to check if frida-server is running
        # Method 1: Check using ps command
        ps_result = subprocess.run(
            ["adb", "shell", "ps | grep frida-server"],
            capture_output=True,
            text=True,
            check=False
        )
        
        # Method 2: Check if port 27042 is in use (default frida-server port)
        port_result = subprocess.run(
            ["adb", "shell", "netstat -tlnp | grep 27042"],
            capture_output=True,
            text=True,
            check=False
        )
        
        # Either method can confirm frida-server is running
        return "frida-server" in ps_result.stdout or "27042" in port_result.stdout
    except Exception as e:
        console.error(f"Error checking if frida-server is running: {str(e)}")
        return False


def start_frida_server(server_path):
    """Try to start the frida-server at the specified path"""
    try:
        if server_path:
            # Check if frida-server is already running
            if check_frida_server_running():
                console.success("Frida server is already running")
                return True

            # Try to get root access (max 5 attempts)
            root_access = False
            with console.progress() as progress:
                task = progress.add_task("[yellow]Requesting root access...", total=5)

                for i in range(5):
                    # Update progress bar
                    progress.update(task, completed=i,
                                    description=f"[yellow]Requesting root access... Attempt {i + 1}/5")

                    # Try to request root
                    subprocess.run(["adb", "shell", "su", "-c", "echo 'Requesting root'"], check=False)

                    # Check if root access granted
                    if check_root_access():
                        root_access = True
                        progress.update(task, completed=5, description="[green]Root access granted")
                        break

                    time.sleep(1)

            if root_access:
                # Kill any existing frida-server instances
                subprocess.run(
                    ["adb", "shell", "su", "-c", "killall frida-server 2>/dev/null"],
                    check=False
                )

                # Check file permissions
                is_executable = False
                with console.progress() as progress:
                    task = progress.add_task("[yellow]Checking file permissions...", total=5)

                    for i in range(5):
                        # Update progress bar
                        progress.update(task, completed=i,
                                        description=f"[yellow]Checking file permissions... Attempt {i + 1}/5")

                        # Check if file is executable
                        check_exec = subprocess.run(
                            ["adb", "shell", "su", "-c", f"[ -x {server_path} ] && echo 'executable'"],
                            capture_output=True,
                            text=True,
                            check=False
                        )

                        if "executable" in check_exec.stdout:
                            is_executable = True
                            progress.update(task, completed=5, description="[green]File is executable")
                            break

                        # Grant executable permissions
                        subprocess.run(
                            ["adb", "shell", "su", "-c", f"chmod 755 {server_path}"],
                            check=False
                        )

                        time.sleep(1)

                if not is_executable:
                    raise Exception("Failed to set executable permissions after 5 attempts")

                # Start frida-server with nohup to prevent hanging
                console.status("Starting Frida server...")

                try:
                    # Method 1: Use nohup to ensure process runs in background
                    subprocess.run(
                        ["adb", "shell", "su", "-c", f"nohup {server_path} > /dev/null 2>&1 &"],
                        check=False,
                        timeout=3  # Add timeout to prevent hanging
                    )
                except subprocess.TimeoutExpired:
                    # If timeout occurs, this might be normal - server may be starting in background
                    pass

                # Check if frida-server started successfully
                server_running = False
                with console.progress() as progress:
                    task = progress.add_task("[yellow]Waiting for Frida server to start...", total=5)

                    for i in range(5):
                        # Update progress bar
                        progress.update(task, completed=i,
                                        description=f"[yellow]Waiting for Frida server... Attempt {i + 1}/5")
                        time.sleep(1)

                        if check_frida_server_running():
                            server_running = True
                            progress.update(task, completed=5, description="[green]Frida server started successfully")
                            break

                if server_running:
                    console.success(f"Started {os.path.basename(server_path)} with root privileges")
                    return True

                # If first method failed, try alternative method
                console.status("First method failed, trying alternative method...")
                try:
                    # Method 2: Use subprocess.Popen with new session
                    subprocess.Popen(
                        ["adb", "shell", "su", "-c", f"{server_path}"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True
                    )
                except Exception as e:
                    console.error(f"Alternative method error: {str(e)}")

                # Check again if server started
                server_running = False
                with console.progress() as progress:
                    task = progress.add_task("[yellow]Checking alternative method...", total=5)

                    for i in range(5):
                        progress.update(task, completed=i,
                                        description=f"[yellow]Checking alternative method... Attempt {i + 1}/5")
                        time.sleep(1)

                        if check_frida_server_running():
                            server_running = True
                            progress.update(task, completed=5, description="[green]Frida server started successfully")
                            break

                if server_running:
                    console.success(
                        f"Started {os.path.basename(server_path)} with root privileges (alternative method)")
                    return True

                raise Exception("Failed to start frida-server with root privileges after all attempts")
            else:
                # Try without root
                console.warning("Failed to get root access, trying without root...")

                # Check file permissions
                is_executable = False
                with console.progress() as progress:
                    task = progress.add_task("[yellow]Checking file permissions (non-root)...", total=5)

                    for i in range(5):
                        # Update progress bar
                        progress.update(task, completed=i,
                                        description=f"[yellow]Checking permissions (non-root)... Attempt {i + 1}/5")

                        # Check if file is executable
                        check_exec = subprocess.run(
                            ["adb", "shell", f"[ -x {server_path} ] && echo 'executable'"],
                            capture_output=True,
                            text=True,
                            check=False
                        )

                        if "executable" in check_exec.stdout:
                            is_executable = True
                            progress.update(task, completed=5, description="[green]File is executable")
                            break

                        # Grant executable permissions
                        subprocess.run(
                            ["adb", "shell", f"chmod 755 {server_path}"],
                            check=False
                        )

                        time.sleep(1)

                if not is_executable:
                    raise Exception("Failed to set executable permissions (non-root) after 5 attempts")

                # Start frida-server with nohup
                console.status("Starting Frida server (non-root)...")

                try:
                    # Use nohup to ensure process runs in background
                    subprocess.run(
                        ["adb", "shell", f"nohup {server_path} > /dev/null 2>&1 &"],
                        check=False,
                        timeout=3
                    )
                except subprocess.TimeoutExpired:
                    pass

                # Check if frida-server started successfully
                server_running = False
                with console.progress() as progress:
                    task = progress.add_task("[yellow]Waiting for Frida server (non-root)...", total=5)

                    for i in range(5):
                        # Update progress bar
                        progress.update(task, completed=i,
                                        description=f"[yellow]Waiting for server (non-root)... Attempt {i + 1}/5")
                        time.sleep(1)

                        if check_frida_server_running():
                            server_running = True
                            progress.update(task, completed=5, description="[green]Frida server started successfully")
                            break

                if server_running:
                    console.warning(
                        f"Started {os.path.basename(server_path)} without root privileges. Some features may not work.")
                    return True

                # Try alternative method
                console.status("First method failed, trying alternative method (non-root)...")
                try:
                    # Use subprocess.Popen with new session
                    subprocess.Popen(
                        ["adb", "shell", f"{server_path}"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True
                    )
                except Exception as e:
                    console.error(f"Alternative method error: {str(e)}")

                # Check again if server started
                server_running = False
                with console.progress() as progress:
                    task = progress.add_task("[yellow]Checking alternative method (non-root)...", total=5)

                    for i in range(5):
                        progress.update(task, completed=i,
                                        description=f"[yellow]Checking alternative (non-root)... Attempt {i + 1}/5")
                        time.sleep(1)

                        if check_frida_server_running():
                            server_running = True
                            progress.update(task, completed=5, description="[green]Frida server started successfully")
                            break

                if server_running:
                    console.warning(
                        f"Started {os.path.basename(server_path)} without root privileges (alternative method). Some features may not work.")
                    return True

                raise Exception("Failed to start frida-server without root privileges after all attempts")
        return False
    except Exception as e:
        console.error(f"Error starting frida-server: {str(e)}")
        return False

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
                server_path = check_frida_server()
                if server_path:
                    return server_path
                continue

            # Check if the user-provided path exists
            server_path = check_frida_server(user_input)
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
        if not check_device_connection():
            console.error("No Android device connected")
            console.info("Please connect your Android device via USB and enable USB debugging")
            console.info("Then run 'adb devices' to verify the connection")
            return

        console.success("Android device connected")

        # Check if frida-server is already running
        if check_frida_server_running():
            console.success("Frida server is already running")
            # Display the banner and continue
            display_are_banner()
            
            # Create and run the main ARE session
            are = Are()
            are._start_console()
            return

        # Check for frida-server
        server_path = check_frida_server()
        if not server_path:
            # Prompt user for frida-server path until valid or exit
            server_path = prompt_for_frida_server()

        # Try to start frida-server with the found path
        start_success = start_frida_server(server_path)
        
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
            if not check_root_access():
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
@click.argument('process_spec', required=True)
@click.option('--device', '-d', help='Target device serial number')
def watching(process_spec, device=None):
    """
    Attach to a process

    PROCESS_SPEC can be just a process name or 'process_name with command'
    """
    # 解析process_spec
    match = re.match(r'^(.*?)(?: with (.*))?$', process_spec)
    if not match:
        console.error("Invalid process specification")
        return

    process_name = match.group(1)
    command = match.group(2)

    # Check if we need to start the Frida server first
    if not check_frida_server_running():
        server_path = check_frida_server()
        if server_path:
            if start_frida_server(server_path):
                console.success("Frida server started successfully")
                time.sleep(1)  # Give it a moment to start
            else:
                console.warning("Failed to start Frida server automatically")
                console.info("Some features may not work properly")
        else:
            console.warning("Frida server not found")
            console.info("Please start it manually for full functionality")

    # Create the ARE instance and attach to the process
    are = Are(device_id=device)
    success = are.attach(process_name, command)
    
    if not success:
        console.error(f"Failed to attach to process: {process_name}")
        return

@cli.command()
def hello():
    """Show welcome animation with drifting cherry blossom petals lasting 2 seconds."""
    console = Console()
    console.clear()
    # 欢迎横幅
    console.print(
        Panel("[bold magenta]🌸 Welcome to ARE - Android Reverse Engineering Toolkit 🌸[/bold magenta]", expand=False))
    time.sleep(1)

    # 清屏并显示帮助
    console.clear()
    console.print("[bold green]Thank you for using ARE![/bold green]\n")
    console.print("[bold]Available commands:[/bold]")
    console.print("  [cyan]are watching <process_spec>[/cyan]    - Attach to an existing process")
    console.print("  [cyan]are spawn <process_name> [cmd][/cyan] - Spawn and attach to a process")
    console.print("  [cyan]are devices[/cyan]                   - List available devices")
    console.print("  [cyan]are version[/cyan]                   - Display current version")
    console.print("  [cyan]are help[/cyan]                      - Show help")

@cli.command()
def version():
    """Display the current version"""
    from are import __version__
    click.echo(f"ARE version {__version__}")

@cli.command()
def devices():
    """List available devices"""
    list_devices()

def main():
    """命令行主入口点"""
    try:
        # 检查命令行参数
        if len(sys.argv) > 1:
            # 如果第一个参数不是子命令或选项，假设它是一个处理规范
            if sys.argv[1] not in ['hello', 'watching', 'version', 'devices', '--help', '-h'] and not sys.argv[
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