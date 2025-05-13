#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
import json
from typing import Dict, Optional, List, Any, Callable

from frida import _frida

from are.core.ui import AreConsole
from are.core.utils import compile_typescript

# 控制台实例
console = AreConsole()


class Session:
    """Frida会话管理类"""

    def __init__(self, frida_session: frida.core.Session, target: _frida.Process, device: frida.core.Device):
        """
        初始化会话

        参数:
            frida_session: Frida会话对象
            target: 目标进程对象
            device: 设备对象
        """
        self.frida_session = frida_session
        self.target = target
        self.device = device
        self.scripts: Dict[str, frida.core.Script] = {}
        self.message_handlers: Dict[str, Callable] = {}

        # 注册通用消息处理器
        self.register_message_handler("log", self._handle_log)
        self.register_message_handler("error", self._handle_error)
        self.register_message_handler("status", self._handle_status)

    def is_active(self) -> bool:
        """检查会话是否活动"""
        return self.frida_session is not None

    def detach(self):
        """解除会话"""
        if self.frida_session:
            # 卸载所有脚本
            for name, script in self.scripts.items():
                try:
                    script.unload()
                except Exception as e:
                    console.error(f"Error unloading script {name}: {str(e)}")

            # 解除会话
            try:
                self.frida_session.detach()
            except Exception as e:
                console.error(f"Error detaching session: {str(e)}")

            self.frida_session = None
            self.scripts = {}

    def _on_message(self, message: Dict[str, Any], data: Any):
        """
        处理来自Frida的消息

        参数:
            message: 消息对象
            data: 二进制数据
        """
        if message["type"] == "send":
            payload = message.get("payload", {})

            # 处理类型化消息
            if isinstance(payload, dict) and "type" in payload:
                msg_type = payload["type"]
                if msg_type in self.message_handlers:
                    self.message_handlers[msg_type](payload, data)
                else:
                    console.debug(f"Unhandled message type: {msg_type}")
                    console.debug(json.dumps(payload, indent=2))
            else:
                # 处理一般消息
                console.info(f"Message: {payload}")

        elif message["type"] == "error":
            console.error(f"Script Error: {message.get('description', 'Unknown error')}")
            if "stack" in message:
                console.debug(f"Stack trace: {message['stack']}")

    def register_message_handler(self, msg_type: str, handler: Callable):
        """
        注册消息处理器

        参数:
            msg_type: 消息类型
            handler: 处理函数
        """
        self.message_handlers[msg_type] = handler

    def _handle_log(self, payload: Dict[str, Any], data: Any):
        """处理日志消息"""
        level = payload.get("level", "info")
        message = payload.get("message", "")

        if level == "debug":
            console.debug(message)
        elif level == "info":
            console.info(message)
        elif level == "warning":
            console.warning(message)
        elif level == "error":
            console.error(message)
        else:
            console.info(message)

    def _handle_error(self, payload: Dict[str, Any], data: Any):
        """处理错误消息"""
        message = payload.get("message", "Unknown error")
        stack = payload.get("stack", "")

        console.error(message)
        if stack:
            console.debug(f"Stack trace: {stack}")

    def _handle_status(self, payload: Dict[str, Any], data: Any):
        """处理状态消息"""
        message = payload.get("message", "")
        console.status(message)

    def load_typescript(self, script_name: str, options: Optional[Dict[str, Any]] = None) -> bool:
        """
        加载TypeScript脚本

        参数:
            script_name: 脚本名称
            options: 脚本选项

        返回:
            是否成功
        """
        if not self.is_active():
            console.error("Session is not active")
            return False

        if script_name in self.scripts:
            console.warning(f"Script {script_name} is already loaded")
            return True

        try:
            # 加载并编译TypeScript脚本
            js_code = compile_typescript(script_name)
            if not js_code:
                console.error(f"Failed to compile TypeScript script: {script_name}")
                return False

            # 创建脚本选项对象
            script_options = {}
            if options:
                script_options.update(options)

            # 创建并加载脚本
            script = self.frida_session.create_script(js_code, name=script_name, runtime="v8")
            script.on("message", self._on_message)
            script.load()

            # 存储脚本
            self.scripts[script_name] = script

            # 传递选项给脚本
            if options:
                script.post({"type": "options", "options": options})

            return True

        except Exception as e:
            console.error(f"Error loading script {script_name}: {str(e)}")
            return False

    def unload_script(self, script_name: str) -> bool:
        """
        卸载脚本

        参数:
            script_name: 脚本名称

        返回:
            是否成功
        """
        if not self.is_active():
            console.error("Session is not active")
            return False

        if script_name not in self.scripts:
            console.warning(f"Script {script_name} is not loaded")
            return False

        try:
            self.scripts[script_name].unload()
            del self.scripts[script_name]
            return True
        except Exception as e:
            console.error(f"Error unloading script {script_name}: {str(e)}")
            return False

    def call_script_function(self, script_name: str, function_name: str,
                             args: Optional[List[Any]] = None) -> Any:
        """
        调用脚本中的函数

        参数:
            script_name: 脚本名称
            function_name: 函数名称
            args: 函数参数

        返回:
            函数返回值
        """
        if not self.is_active():
            console.error("Session is not active")
            return None

        if script_name not in self.scripts:
            console.warning(f"Script {script_name} is not loaded")
            return None

        try:
            if args is None:
                args = []

            return self.scripts[script_name].exports.call(function_name, *args)
        except Exception as e:
            console.error(f"Error calling function {function_name}: {str(e)}")
            return None