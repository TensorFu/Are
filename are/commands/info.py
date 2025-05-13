#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Any
from prompt_toolkit.completion import Completion
from are.commands.base import CommandBase
from are.core import AreConsole

# 控制台实例
console = AreConsole()


class InfoCommand(CommandBase):
    """信息查询命令"""

    name = "info"
    help_short = "Query information about objects"
    help_text = "Query detailed information about classes, methods, or other objects"
    usage = "info <type> <name>"
    examples = [
        "info class UIViewController",
        "info method UIView initWithFrame:",
        "info address 0x1234abcd",
        "info module UIKit"
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
        if len(parts) < 2:
            console.error("Usage: info <type> <name>")
            return

        info_type = parts[0].lower()
        name = parts[1]

        if info_type == "class":
            self._show_class_info(context, name)
        elif info_type == "method":
            self._show_method_info(context, name)
        elif info_type == "address":
            self._show_address_info(context, name)
        elif info_type == "module":
            self._show_module_info(context, name)
        else:
            console.error(f"Unknown info type: {info_type}")
            console.info("Available types: class, method, address, module")

    def _show_class_info(self, context: Any, class_name: str):
        """显示类信息"""
        console.info(f"Querying information for class '{class_name}'...")

        try:
            # 这里应该调用实际的Frida脚本获取类信息
            # 示例实现
            class_info = f"""
Superclass: NSObject
Protocols: UITableViewDataSource, UITableViewDelegate
Instance Methods:
  - initWithFrame:
  - viewDidLoad
  - tableView:cellForRowAtIndexPath:
  - dealloc
Class Methods:
  + alloc
  + new
Instance Variables:
  - _tableView (UITableView*)
  - _dataSource (NSArray*)
            """

            console.panel(
                class_info.strip(),
                title=f"Class: {class_name}",
                style="info"
            )

        except Exception as e:
            console.error(f"Error querying class info: {str(e)}")

    def _show_method_info(self, context: Any, method_spec: str):
        """显示方法信息"""
        # 从method_spec中解析类名和方法名
        parts = method_spec.split(maxsplit=1)
        if len(parts) < 2:
            console.error("Usage: info method <class_name> <method_name>")
            return

        class_name = parts[0]
        method_name = parts[1]

        console.info(f"Querying information for method '{method_name}' in class '{class_name}'...")

        try:
            # 这里应该调用实际的Frida脚本获取方法信息
            # 示例实现
            method_info = f"""
Signature: - (void)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
Implementation: 0x00123456
Return Type: UITableViewCell*
Arguments:
  1. tableView (UITableView*)
  2. indexPath (NSIndexPath*)
            """

            console.panel(
                method_info.strip(),
                title=f"Method: {class_name} {method_name}",
                style="info"
            )

        except Exception as e:
            console.error(f"Error querying method info: {str(e)}")

    def _show_address_info(self, context: Any, address: str):
        """显示地址信息"""
        try:
            # 解析地址
            addr = int(address, 0)

            console.info(f"Querying information for address 0x{addr:x}...")

            # 这里应该调用实际的Frida脚本获取地址信息
            # 示例实现
            address_info = f"""
Module: UIKit
Symbol: -[UIViewController viewDidLoad]
Offset: +0x24
Memory Protection: rwx
            """

            console.panel(
                address_info.strip(),
                title=f"Address: 0x{addr:x}",
                style="info"
            )

        except ValueError:
            console.error(f"Invalid address format: {address}")
        except Exception as e:
            console.error(f"Error querying address info: {str(e)}")

    def _show_module_info(self, context: Any, module_name: str):
        """显示模块信息"""
        console.info(f"Querying information for module '{module_name}'...")

        try:
            # 这里应该调用实际的Frida脚本获取模块信息
            # 示例实现
            module_info = f"""
Base Address: 0x180000000
Size: 14.5 MB
Path: /System/Library/Frameworks/UIKit.framework/UIKit
Exported Classes: 247
            """

            console.panel(
                module_info.strip(),
                title=f"Module: {module_name}",
                style="info"
            )

        except Exception as e:
            console.error(f"Error querying module info: {str(e)}")

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        if len(args) == 0 or (len(args) == 1 and not document.text.endswith(' ')):
            # 补全info类型
            word = args[0] if args else ""
            for info_type in ["class", "method", "address", "module"]:
                if info_type.startswith(word):
                    yield Completion(info_type, start_position=-len(word),
                                     display=info_type, display_meta=f"Query {info_type} info")

        elif len(args) == 1 or (len(args) == 2 and not document.text.endswith(' ')):
            # 根据类型提供不同的补全
            info_type = args[0].lower()
            word = args[1] if len(args) > 1 else ""

            if info_type == "class":
                # 提供类名补全
                class_list = ["UIView", "UIViewController", "NSString", "NSArray"]
                for cls in class_list:
                    if cls.startswith(word):
                        yield Completion(cls, start_position=-len(word),
                                         display=cls, display_meta="class")

            elif info_type == "module":
                # 提供模块名补全
                module_list = ["UIKit", "Foundation", "CoreGraphics", "CoreLocation"]
                for module in module_list:
                    if module.startswith(word):
                        yield Completion(module, start_position=-len(word),
                                         display=module, display_meta="module")