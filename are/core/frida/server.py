#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/frida/server.py

import os
import time
import subprocess
import re
from are.core.theme.ui import AreConsole

# 控制台实例
console = AreConsole()

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

def get_pid_by_port(port):
    """获取占用特定端口的进程ID

    参数:
        port: 端口号

    返回:
        占用该端口的进程ID，如果未找到则返回None
    """
    console.info(f"尝试获取占用端口 {port} 的进程ID...")

    # 仅使用root权限下的netstat命令
    if not check_root_access():
        console.warning("未获取到root权限，无法执行查询")
        return None

    # 使用root权限下的netstat命令
    cmd = f"su -c \"netstat -tanp | grep {port}\""

    console.info(f"执行命令: adb shell {cmd}")

    try:
        # 添加超时参数避免命令卡住
        result = subprocess.run(
            ["adb", "shell", cmd],
            capture_output=True,
            text=True,
            check=False,
            timeout=10  # 设置10秒超时
        )

        out = result.stdout.strip()
        console.info(f"命令输出: {out}")

        if out:
            # 尝试匹配PID（格式通常为"数字/进程名"）
            match = re.search(r"\b(\d+)/\S+", out)
            if match:
                pid = match.group(1)
                console.info(f"找到占用端口 {port} 的进程PID: {pid}")
                return pid

            # 备用正则表达式匹配
            match = re.search(r"LISTEN\s+(\d+)", out)
            if match:
                pid = match.group(1)
                console.info(f"找到占用端口 {port} 的进程PID: {pid}")
                return pid

        console.warning(f"未找到占用端口 {port} 的进程")
        return None

    except subprocess.TimeoutExpired:
        console.error(f"执行命令超时")
        return None
    except Exception as e:
        console.error(f"获取PID时出错: {str(e)}")
        return None

def check_frida_server_running():
    """检查frida-server是否已经在运行（仅使用端口检测方式）"""
    try:
        console.info("检查frida-server是否正在运行...")

        # 检查默认frida-server端口 27042
        frida_port = 27042

        # 获取占用该端口的进程ID
        pid = get_pid_by_port(frida_port)

        is_running = pid is not None

        console.info(f"frida-server运行状态: {'运行中' if is_running else '未运行'} " +
                     f"(进程ID: {pid if is_running else 'N/A'})")

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

def kill_frida_server():
    """停止frida-server进程"""
    try:
        # 1. 检测是否有杀死进程的需求（检查frida-server是否在运行）
        is_running = check_frida_server_running()
        if not is_running:
            return True

        # 2. 通过get_pid_by_port函数，找到Frida-server所属的进程ID
        pid = get_pid_by_port(27042)
        if not pid:
            return False

        # 3. 用root身份杀死这个进程
        kill_cmd = f"kill -9 {pid}"
        result = subprocess.run(
            ["adb", "shell", "su", "-c", f"{kill_cmd}"],
            capture_output=True,
            text=True,
            check=False
        )

        # 检查是否成功停止
        is_running = check_frida_server_running()

        if not is_running:
            console.success("✅ 已成功停止Frida服务器")
            return True
        else:
            console.error("❌ 无法停止frida-server")
            return False

    except Exception as e:
        console.error(f"停止Frida服务器时出错: {str(e)}")
        return False

def restart_frida_server():
    """重启Frida服务器"""
    console.info("🔄 尝试重启Frida服务器...")

    # 1. 先停止现有的Frida服务器
    kill_result = kill_frida_server()
    if not kill_result:
        console.warning("⚠️ 停止Frida服务器过程中出现问题，但将继续尝试启动")

    # 2. 检查Frida服务器路径
    server_path = check_frida_server()
    if not server_path:
        console.error("❌ 未找到Frida服务器，请确保已安装")
        return False

    # 3. 启动Frida服务器
    console.info(f"🚀 正在启动Frida服务器: {server_path}")
    if start_frida_server(server_path):
        console.success("✅ Frida服务器已成功重启")
        return True
    else:
        console.error("❌ Frida服务器启动失败")
        return False 