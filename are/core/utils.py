#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/utils.py

import os
import frida
import json
import subprocess
import tempfile
import time
from typing import Optional, List, Dict, Any
from are.core.ui import AreConsole
import re

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

def check_device_connection():
    """检查是否有Android设备通过ADB连接"""
    try:
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

def check_root_access():
    """检查我们是否在设备上拥有root访问权限"""
    try:
        result = subprocess.run(
            ["adb", "shell", "su", "-c", "id"],
            capture_output=True,
            text=True,
            check=False
        )

        # 如果命令成功且包含"uid=0"，则我们拥有root访问权限
        return result.returncode == 0 and "uid=0" in result.stdout
    except Exception as e:
        console.error(f"检查root访问权限时出错: {str(e)}")
        return False

def check_frida_server(custom_path=None):
    """检查frida-server是否存在于指定的路径或默认位置"""
    try:
        paths_to_check = []

        # 添加自定义路径（如果提供）
        if custom_path:
            paths_to_check.append(custom_path)

        # 添加默认路径
        paths_to_check.extend(["/data/local/tmp/frida-server", "/data/local/tmp/fs"])

        for path in paths_to_check:
            result = subprocess.run(
                ["adb", "shell", f"[ -f {path} ]"],
                capture_output=True,
                check=False
            )
            if result.returncode == 0:
                return path  # 返回找到的服务器路径

        return None  # 如果未找到服务器，则返回None
    except Exception as e:
        console.error(f"检查frida-server时出错: {str(e)}")
        return None

def check_frida_server_running():
    """检查frida-server是否已经在运行"""
    try:
        console.info("检查frida-server是否正在运行...")
        
        # 方法1: 检查端口27042是否在使用中（默认frida-server端口）
        port_result = subprocess.run(
            ["adb", "shell", "netstat -tlnp | grep 27042"],
            capture_output=True,
            text=True,
            check=False
        )
        
        console.info(f"netstat检查结果: 返回码={port_result.returncode}, 输出={port_result.stdout}")
        
        # 方法2: 尝试使用ps命令查找frida-server进程
        ps_result = subprocess.run(
            ["adb", "shell", "ps | grep -E 'frida-server|fs' | grep -v grep"],
            capture_output=True,
            text=True,
            check=False
        )
        
        console.info(f"ps检查结果: 返回码={ps_result.returncode}, 输出={ps_result.stdout}")
        
        # 方法3: 尝试列出可用的frida设备
        try:
            from frida.core import Device, DeviceManager
            devices = Device.enumerate_devices()
            usb_devices = [d for d in devices if d.type == 'usb']
            console.info(f"frida.Device.enumerate_devices() 结果: USB设备数量={len(usb_devices)}")
            if usb_devices:
                for d in usb_devices:
                    console.info(f"找到USB设备: {d.id} (名称: {d.name})")
        except Exception as frida_ex:
            console.info(f"frida API检查失败: {str(frida_ex)}")

        # 综合判断frida-server是否在运行
        running_by_port = "27042" in port_result.stdout
        running_by_ps = ps_result.returncode == 0 and ps_result.stdout.strip() != ""
        
        is_running = running_by_port or running_by_ps
        
        console.info(f"frida-server运行状态: {'运行中' if is_running else '未运行'} " + 
                     f"(基于端口检查: {'是' if running_by_port else '否'}, " + 
                     f"基于进程检查: {'是' if running_by_ps else '否'})")
                    
        return is_running
    except Exception as e:
        console.error(f"❌ 检查frida-server是否运行时出错: {str(e)}")
        import traceback
        console.debug(traceback.format_exc())
        return False

def start_frida_server(server_path):
    """尝试在指定路径启动frida-server"""
    try:
        if server_path:
            # 检查frida-server是否已经在运行
            if check_frida_server_running():
                console.success("✅ Frida服务器已经在运行")
                return True

            # 尝试获取root访问权限（最多5次尝试）
            root_access = False
            # 不显示请求root状态消息，静默检查
            for i in range(5):
                # 尝试请求root，但不显示任何输出
                subprocess.run(
                    ["adb", "shell", "su", "-c", "echo ''"], 
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False
                )
                
                # 检查是否授予root访问权限
                if check_root_access():
                    root_access = True
                    console.success("✅ 已授予root访问权限")
                    break

                time.sleep(1)

            if root_access:
                # 终止所有现有的frida-server实例
                subprocess.run(
                    ["adb", "shell", "su", "-c", "killall frida-server 2>/dev/null"],
                    check=False
                )

                # 检查文件权限
                is_executable = False
                console.status("📋 检查文件权限...")

                for i in range(5):

                    # 检查文件是否可执行
                    check_exec = subprocess.run(
                        ["adb", "shell", "su", "-c", f"[ -x {server_path} ] && echo 'executable'"],
                        capture_output=True,
                        text=True,
                        check=False
                    )

                    if "executable" in check_exec.stdout:
                        is_executable = True
                        console.success("✅ 文件可执行")
                        break

                    # 授予可执行权限
                    subprocess.run(
                        ["adb", "shell", "su", "-c", f"chmod 755 {server_path}"],
                        check=False
                    )

                    time.sleep(1)

                if not is_executable:
                    raise Exception("5次尝试后仍未能设置可执行权限")

                # 使用nohup启动frida-server以防止挂起
                console.status("🚀 正在启动Frida服务器...")

                try:
                    # 方法1：使用nohup确保进程在后台运行
                    subprocess.run(
                        ["adb", "shell", "su", "-c", f"nohup {server_path} > /dev/null 2>&1 &"],
                        check=False,
                        timeout=3  # 添加超时以防止挂起
                    )
                except subprocess.TimeoutExpired:
                    # 如果超时发生，这可能是正常的 - 服务器可能正在后台启动
                    pass

                # 检查frida-server是否成功启动
                server_running = False

                for i in range(5):
                    time.sleep(1)

                    if check_frida_server_running():
                        server_running = True
                        console.success("Frida服务器成功启动")
                        break

                if server_running:
                    console.success(f"已使用root权限启动 {os.path.basename(server_path)}")
                    return True

                # 如果第一种方法失败，尝试替代方法
                console.status("第一种方法失败，尝试替代方法...")
                try:
                    # 方法2：使用带有新会话的subprocess.Popen
                    subprocess.Popen(
                        ["adb", "shell", "su", "-c", f"{server_path}"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True
                    )
                except Exception as e:
                    console.error(f"替代方法错误: {str(e)}")

                # 再次检查服务器是否启动
                server_running = False
                console.status("检查替代方法...")

                for i in range(5):
                    time.sleep(1)

                    if check_frida_server_running():
                        server_running = True
                        console.success("Frida服务器成功启动")
                        break

                if server_running:
                    console.success(
                        f"已使用root权限启动 {os.path.basename(server_path)}（替代方法）")
                    return True

                raise Exception("所有尝试后均未能使用root权限启动frida-server")
            else:
                # 尝试不使用root
                console.warning("未能获取root访问权限，尝试不使用root...")

                # 检查文件权限
                is_executable = False
                console.status("检查文件权限（非root）...")

                for i in range(5):

                    # 检查文件是否可执行
                    check_exec = subprocess.run(
                        ["adb", "shell", f"[ -x {server_path} ] && echo 'executable'"],
                        capture_output=True,
                        text=True,
                        check=False
                    )

                    if "executable" in check_exec.stdout:
                        is_executable = True
                        console.success("文件可执行")
                        break

                    # 授予可执行权限
                    subprocess.run(
                        ["adb", "shell", f"chmod 755 {server_path}"],
                        check=False
                    )

                    time.sleep(1)

                if not is_executable:
                    raise Exception("5次尝试后仍未能设置可执行权限（非root）")

                # 使用nohup启动frida-server
                console.status("正在启动Frida服务器（非root）...")

                try:
                    # 使用nohup确保进程在后台运行
                    subprocess.run(
                        ["adb", "shell", f"nohup {server_path} > /dev/null 2>&1 &"],
                        check=False,
                        timeout=3
                    )
                except subprocess.TimeoutExpired:
                    pass

                # 检查frida-server是否成功启动
                server_running = False
                console.status("等待Frida服务器（非root）...")

                for i in range(5):
                    time.sleep(1)

                    if check_frida_server_running():
                        server_running = True
                        console.success("Frida服务器成功启动")
                        break

                if server_running:
                    console.warning(
                        f"已不使用root权限启动 {os.path.basename(server_path)}。某些功能可能无法正常工作。")
                    return True

                # 尝试替代方法
                console.status("第一种方法失败，尝试替代方法（非root）...")
                try:
                    # 使用带有新会话的subprocess.Popen
                    subprocess.Popen(
                        ["adb", "shell", f"{server_path}"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True
                    )
                except Exception as e:
                    console.error(f"替代方法错误: {str(e)}")

                # 再次检查服务器是否启动
                server_running = False
                console.status("检查替代方法（非root）...")

                for i in range(5):
                    time.sleep(1)

                    if check_frida_server_running():
                        server_running = True
                        console.success("Frida服务器成功启动")
                        break

                if server_running:
                    console.warning(
                        f"已不使用root权限启动 {os.path.basename(server_path)}（替代方法）。某些功能可能无法正常工作。")
                    return True

                raise Exception("所有尝试后均未能不使用root权限启动frida-server")
        return False
    except Exception as e:
        console.error(f"启动frida-server时出错: {str(e)}")
        return False

def get_pid_by_port(port):
    """获取占用特定端口的进程ID
    
    参数:
        port: 端口号
        
    返回:
        占用该端口的进程ID，如果未找到则返回None
    """
    console.info(f"尝试获取占用端口 {port} 的进程ID...")
    
    # 尝试不同的命令组合来查找进程
    commands = []
    
    # 使用root权限的命令
    if check_root_access():
        commands.extend([
            f"su -c \"netstat -anp tcp | grep {port}\"",
            f"su -c \"netstat -tanp | grep {port}\"",
            f"su -c \"lsof -i :{port}\"",
            f"su -c \"ss -tanp | grep {port}\""
        ])
    
    # 通用命令，不需要root权限
    commands.extend([
        f"netstat -anp tcp | grep {port}",
        f"netstat -tanp | grep {port}",
        f"ss -tanp | grep {port}"
    ])
    
    for i, cmd in enumerate(commands):
        console.info(f"尝试方法 {i+1}: adb shell {cmd}")
        result = subprocess.run(
            ["adb", "shell", cmd], 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        out = result.stdout.strip()
        console.info(f"命令输出: {out}")
        
        if out:
            # 尝试不同的正则表达式来匹配PID
            patterns = [
                r"\b(\d+)/\S+",  # 匹配 "5091/fs" 或类似格式
                r"LISTEN\s+(\d+)",  # 匹配 "LISTEN 5091" 或类似格式
                r"pid=(\d+)",  # 匹配 "pid=5091" 或类似格式
                r":(\d+)\s+\(LISTEN\)"  # 匹配某些系统上的特殊格式
            ]
            
            for pattern in patterns:
                match = re.search(pattern, out)
                if match:
                    pid = match.group(1)
                    console.info(f"找到占用端口 {port} 的进程PID: {pid}")
                    return pid
    
    # 如果上述方法都失败，尝试直接检查正在运行的frida-server进程
    console.info("通过端口查找失败，尝试直接查找frida-server进程")
    frida_cmds = [
        "ps | grep -E 'frida-server|fs' | grep -v grep",
        "ps -ef | grep -E 'frida-server|fs' | grep -v grep"
    ]
    
    for cmd in frida_cmds:
        result = subprocess.run(
            ["adb", "shell", cmd], 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        out = result.stdout.strip()
        console.info(f"frida进程查询结果: {out}")
        
        if out:
            # 尝试从ps输出中提取PID
            import re
            # 尝试多种匹配模式来适应不同的ps输出格式
            pid_patterns = [
                r'\s*(\d+)\s+',  # 标准格式：PID位于开头
                r'^\s*\S+\s+(\d+)',  # 用户名后的PID
                r'\s+(\d+)\s+\d+\s+\d+',  # Android特有格式
            ]
            
            for line in out.splitlines():
                for pattern in pid_patterns:
                    match = re.search(pattern, line)
                    if match:
                        pid = match.group(1)
                        console.info(f"找到frida-server进程PID: {pid}")
                        return pid
    
    console.warning(f"未找到占用端口 {port} 或正在运行的frida-server进程")
    return None

def restart_frida_server():
    console.info("🔄 尝试重启Frida服务器...")
    if check_frida_server_running():
        console.info("🔍 检测到端口27042有进程正在运行，尝试关闭...")
        try:
            pid = get_pid_by_port(27042)
            if not pid:
                console.warning("⚠️ 未找到端口27042对应的进程ID")
            else:
                kill_cmd = f"kill -9 {pid}"
                if check_root_access():
                    kill_cmd = f"su -c \"{kill_cmd}\""
                subprocess.run(
                    ["adb", "shell", kill_cmd],
                    capture_output=True,
                    text=True
                )
                console.success(f"✅ 已杀死 PID={pid} 的进程")
        except Exception as e:
            console.error(f"❌ 操作失败: {e}")
    else:
        console.info("🔍 端口27042没有进程在运行，将启动新实例")

    server_path = check_frida_server()
    if not server_path:
        console.warning("⚠️ 未找到Frida服务器，请确保已安装")
        return False

    console.info(f"🚀 正在启动Frida服务器: {server_path}")
    if start_frida_server(server_path):
        console.success("✅ Frida服务器已成功启动")
        return True
    else:
        console.error("❌ Frida服务器启动失败")
        return False

def kill_frida_server():
    """停止frida-server进程"""
    try:
        console.info("========== 开始尝试停止 frida-server 进程 ==========")
        
        # 检查当前frida-server运行状态
        is_running = check_frida_server_running()
        console.info(f"初始状态检查: frida-server {'正在运行' if is_running else '未运行'}")
        
        if not is_running:
            console.info("frida-server 未运行，无需停止")
            return True
        
        # 获取运行frida-server的PID
        pid = get_pid_by_port(27042)
        console.info(f"获取PID结果: {pid or '未找到'}")
        
        if pid:
            console.info(f"找到frida-server进程，PID: {pid}")
            
            # 首先尝试使用root权限杀死进程
            kill_cmd = f"kill -9 {pid}"
            console.info(f"尝试执行命令: su -c '{kill_cmd}'")
            
            # 使用root权限
            result = subprocess.run(
                ["adb", "shell", "su", "-c", f"{kill_cmd}"],
                capture_output=True,
                text=True,
                check=False
            )
            console.info(f"命令执行结果: 返回码={result.returncode}, 输出={result.stdout}, 错误={result.stderr}")
            
            # 检查是否还在运行
            is_running = check_frida_server_running()
            console.info(f"kill -9 后检查: frida-server {'仍在运行' if is_running else '已停止'}")
            
            if not is_running:
                console.success("✅ 已使用root权限停止Frida服务器")
                return True
                
            # 如果仍在运行，尝试使用killall命令
            console.info("尝试使用killall命令杀死frida-server")
            result = subprocess.run(
                ["adb", "shell", "su", "-c", "killall frida-server 2>/dev/null"],
                capture_output=True,
                text=True,
                check=False
            )
            console.info(f"killall命令执行结果: 返回码={result.returncode}, 输出={result.stdout}, 错误={result.stderr}")
            
            # 检查是否还在运行
            is_running = check_frida_server_running()
            console.info(f"killall frida-server后检查: frida-server {'仍在运行' if is_running else '已停止'}")
            
            if not is_running:
                console.success("✅ 已使用root权限停止Frida服务器")
                return True
            
            # 尝试杀死fs进程（frida-server的另一个可能名称）
            console.info("尝试使用killall命令杀死fs进程")
            result = subprocess.run(
                ["adb", "shell", "su", "-c", "killall fs 2>/dev/null"],
                capture_output=True,
                text=True,
                check=False
            )
            console.info(f"killall fs命令执行结果: 返回码={result.returncode}, 输出={result.stdout}, 错误={result.stderr}")
            
            # 最后检查
            is_running = check_frida_server_running()
            console.info(f"killall fs后检查: frida-server {'仍在运行' if is_running else '已停止'}")
            
            if not is_running:
                console.success("✅ 已停止Frida服务器")
                return True
            
        # 尝试直接在Android中找到并终止frida相关进程
        console.info("尝试通过Android系统命令找到并终止frida相关进程")
        
        # 尝试更直接地查找frida进程
        find_cmds = [
            "ps -ef | grep -E 'frida-server|fs' | grep -v grep",
            "ps | grep -E 'frida-server|fs' | grep -v grep",
            "ps -A | grep -E 'frida-server|fs' | grep -v grep",
            "top -n 1 | grep -E 'frida-server|fs'"
        ]
        
        for cmd in find_cmds:
            console.info(f"执行命令: {cmd}")
            find_result = subprocess.run(
                ["adb", "shell", cmd],
                capture_output=True,
                text=True,
                check=False
            )
            console.info(f"命令结果: {find_result.stdout}")
            
            if find_result.stdout.strip():
                console.info("找到frida相关进程，尝试解析PID")
                # 尝试从不同格式的ps输出中提取PID
                import re
                
                # 尝试多种匹配模式来适应不同的ps输出格式
                pid_patterns = [
                    r'\s*(\d+)\s+',  # 标准格式：PID位于开头
                    r'^\s*\S+\s+(\d+)',  # 用户名后的PID
                    r'\s+(\d+)\s+\d+\s+\d+',  # Android特有格式
                ]
                
                pids = set()
                for line in find_result.stdout.splitlines():
                    for pattern in pid_patterns:
                        match = re.search(pattern, line)
                        if match:
                            pids.add(match.group(1))
                            break
                
                if pids:
                    console.info(f"找到以下PID: {', '.join(pids)}")
                    for pid in pids:
                        console.info(f"尝试终止PID {pid}")
                        # 使用多种方式尝试终止进程
                        kill_commands = [
                            f"su -c 'kill -9 {pid}'",
                            f"su -c 'kill -SIGKILL {pid}'",
                            f"su 0 kill -9 {pid}",
                            f"su -c 'echo 9 > /proc/{pid}/oom_adj && echo 1 > /proc/{pid}/oom_score_adj'",
                            f"su -c 'am force-stop org.frida.server'",
                        ]
                        
                        for kill_cmd in kill_commands:
                            console.info(f"执行: {kill_cmd}")
                            kill_result = subprocess.run(
                                ["adb", "shell", kill_cmd],
                                capture_output=True,
                                text=True,
                                check=False
                            )
                            console.info(f"结果: 返回码={kill_result.returncode}, 输出={kill_result.stdout}, 错误={kill_result.stderr}")
                            
                            # 检查是否还在运行
                            if not check_frida_server_running():
                                console.success(f"✅ 已成功停止Frida服务器(PID {pid})")
                                return True
                
        # 尝试使用Android的activity manager进行清理
        console.info("尝试使用Android系统方法清理")
        am_commands = [
            "su -c 'am force-stop org.frida.server'",
            "su -c 'am kill org.frida.server'",
            "su -c 'svc power reboot'"  # 最后的手段 - 重启设备
        ]
        
        for am_cmd in am_commands:
            console.info(f"执行系统命令: {am_cmd}")
            am_result = subprocess.run(
                ["adb", "shell", am_cmd],
                capture_output=True,
                text=True,
                check=False
            )
            console.info(f"结果: 返回码={am_result.returncode}, 输出={am_result.stdout}")
            
            # 检查是否还在运行
            if not check_frida_server_running():
                console.success("✅ 已成功停止Frida服务器")
                return True
                
        # 最终检查
        is_running = check_frida_server_running()
        console.info(f"最终状态检查: frida-server {'仍在运行' if is_running else '已停止'}")
        
        if not is_running:
            return True
        else:
            console.error("❌ 所有尝试都失败，无法停止frida-server")
            return False
            
    except Exception as e:
        console.error(f"停止Frida服务器时出错: {str(e)}")
        import traceback
        console.debug(traceback.format_exc())
        return False