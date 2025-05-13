#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/memory.py

from typing import List, Any
from prompt_toolkit.completion import Completion
from are.commands.base import CommandBase
from are.core import AreConsole

# 控制台实例
console = AreConsole()


class MemoryCommand(CommandBase):
    """内存操作命令"""

    name = "memory"
    help_short = "Memory operations"
    help_text = "Perform memory operations on the target process"
    usage = "memory [search|dump|write|pattern] [arguments]"
    examples = [
        "memory search 0x1000 0x2000 00 01 02 03",
        "memory dump 0x12345678 32",
        "memory write 0x12345678 00 01 02 03",
        "memory pattern 00 ?? 02 ?? 04"
    ]

    def execute(self, context: Any, args: str):
        """
        执行命令

        参数:
            context: ARE实例
            args: 命令参数
        """
        if not context.current_session:
            console.error("No active session!")
            return

        parts = args.strip().split(maxsplit=1)
        if not parts:
            self._show_help()
            return

        subcommand = parts[0]
        subargs = parts[1] if len(parts) > 1 else ""

        if subcommand == "search":
            self._memory_search(context, subargs)
        elif subcommand == "dump":
            self._memory_dump(context, subargs)
        elif subcommand == "write":
            self._memory_write(context, subargs)
        elif subcommand == "pattern":
            self._memory_pattern(context, subargs)
        else:
            console.error(f"Unknown subcommand: {subcommand}")
            self._show_help()

    def _show_help(self):
        """显示命令帮助"""
        console.panel(
            """memory search <start_addr> <end_addr> <pattern>
  Search for a byte pattern in memory range

memory dump <address> <size>
  Dump memory contents at the specified address

memory write <address> <bytes>
  Write bytes to the specified memory address

memory pattern <pattern>
  Search for a pattern with wildcards (??)""",
            title="Memory Command Help",
            style="info"
        )

    def _memory_search(self, context: Any, args: str):
        """内存搜索"""
        parts = args.strip().split()
        if len(parts) < 3:
            console.error("Usage: memory search <start_addr> <end_addr> <pattern>")
            return

        try:
            # 解析地址
            start_addr = int(parts[0], 0)
            end_addr = int(parts[1], 0)

            # 解析模式
            pattern = " ".join(parts[2:])
            pattern_bytes = self._parse_pattern(pattern)

            if not pattern_bytes:
                console.error("Invalid pattern format")
                return

            # 调用Frida脚本
            console.info(f"Searching for pattern in range 0x{start_addr:x} - 0x{end_addr:x}...")

            # 这里应该调用实际的Frida脚本
            # 示例实现
            results = []  # 应从Frida脚本获取结果

            if results:
                console.success(f"Found {len(results)} matches")
                for i, addr in enumerate(results):
                    console.print(f"[{i}] 0x{addr:x}")
            else:
                console.warning("No matches found")

        except ValueError as e:
            console.error(f"Error parsing arguments: {str(e)}")
        except Exception as e:
            console.error(f"Error during memory search: {str(e)}")

    def _memory_dump(self, context: Any, args: str):
        """内存转储"""
        parts = args.strip().split()
        if len(parts) < 2:
            console.error("Usage: memory dump <address> <size>")
            return

        try:
            # 解析参数
            address = int(parts[0], 0)
            size = int(parts[1], 0)

            # 调用Frida脚本
            console.info(f"Dumping {size} bytes from 0x{address:x}...")

            # 这里应该调用实际的Frida脚本
            # 示例实现
            dump_data = b"\x00" * size  # 应从Frida脚本获取数据

            # 显示转储数据
            from hexdump import hexdump
            dump_text = hexdump(dump_data, result="return")
            console.print(dump_text)

        except ValueError as e:
            console.error(f"Error parsing arguments: {str(e)}")
        except Exception as e:
            console.error(f"Error during memory dump: {str(e)}")

    def _memory_write(self, context: Any, args: str):
        """内存写入"""
        parts = args.strip().split()
        if len(parts) < 2:
            console.error("Usage: memory write <address> <bytes>")
            return

        try:
            # 解析参数
            address = int(parts[0], 0)

            # 解析字节
            byte_str = " ".join(parts[1:])
            bytes_to_write = self._parse_pattern(byte_str)

            if not bytes_to_write:
                console.error("Invalid byte format")
                return

            # 调用Frida脚本
            console.info(f"Writing {len(bytes_to_write)} bytes to 0x{address:x}...")

            # 这里应该调用实际的Frida脚本
            # 示例实现
            success = True  # 应从Frida脚本获取结果

            if success:
                console.success("Memory write successful")
            else:
                console.error("Memory write failed")

        except ValueError as e:
            console.error(f"Error parsing arguments: {str(e)}")
        except Exception as e:
            console.error(f"Error during memory write: {str(e)}")

    def _memory_pattern(self, context: Any, args: str):
        """模式搜索"""
        if not args.strip():
            console.error("Usage: memory pattern <pattern>")
            return

        try:
            # 解析模式
            pattern = args.strip()

            # 调用Frida脚本
            console.info(f"Searching for pattern: {pattern}...")

            # 这里应该调用实际的Frida脚本
            # 示例实现
            results = []  # 应从Frida脚本获取结果

            if results:
                console.success(f"Found {len(results)} matches")
                for i, addr in enumerate(results):
                    console.print(f"[{i}] 0x{addr:x}")
            else:
                console.warning("No matches found")

        except Exception as e:
            console.error(f"Error during pattern search: {str(e)}")

    def _parse_pattern(self, pattern: str) -> List[int]:
        """
        解析字节模式

        参数:
            pattern: 字节模式字符串

        返回:
            字节列表
        """
        result = []

        # 移除空格
        pattern = pattern.replace(" ", "")

        # 逐个处理字节
        i = 0
        while i < len(pattern):
            if i + 2 > len(pattern):
                return []

            byte_str = pattern[i:i + 2]

            if byte_str == "??":
                # 通配符
                result.append(-1)
            else:
                try:
                    # 解析十六进制字节
                    byte_val = int(byte_str, 16)
                    result.append(byte_val)
                except ValueError:
                    return []

            i += 2

        return result

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        if not args:
            # 子命令补全
            subcommands = ["search", "dump", "write", "pattern"]
            for subcommand in subcommands:
                yield Completion(subcommand, start_position=0,
                                 display=subcommand, display_meta=f"memory {subcommand}")
            return

        # 子命令已输入
        subcommand = args[0]

        if subcommand == "search" and len(args) == 1:
            yield Completion("0x", start_position=0,
                             display="0x", display_meta="start address")
        elif subcommand == "dump" and len(args) == 1:
            yield Completion("0x", start_position=0,
                             display="0x", display_meta="address")
        elif subcommand == "write" and len(args) == 1:
            yield Completion("0x", start_position=0,
                             display="0x", display_meta="address")