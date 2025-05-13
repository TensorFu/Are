#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/hook.py

from typing import List, Any, Set
from prompt_toolkit.completion import Completion
from are.commands.base import CommandBase
from are.core import AreConsole

# 控制台实例
console = AreConsole()


class HookCommand(CommandBase):
    """方法钩子命令"""

    name = "hook"
    help_short = "Hook methods and functions"
    help_text = "Hook Java/Objective-C methods or native functions to view their parameters and return values"
    usage = "hook <class_method> [args] [return] [backtrace]"
    examples = [
        "hook com.example.app.MainActivity.onCreate",
        "hook java.net.URL.openConnection args return",
        "hook com.company.app.Api.login args return backtrace",
        "hook libnative.so!decrypt args return"
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

        parts = args.strip().split()
        if not parts:
            console.error("Usage: hook <class_method> [args] [return] [backtrace]")
            return

        target = parts[0]
        options = set(part.lower() for part in parts[1:])
        
        # 默认行为：如果没有指定选项，则显示所有信息
        show_args = "args" in options or not options
        show_return = "return" in options or not options
        show_backtrace = "backtrace" in options or not options

        console.info(f"Hooking: {target}")
        console.info(f"Options: " + 
                    f"{'arguments ' if show_args else ''}" +
                    f"{'return_value ' if show_return else ''}" +
                    f"{'backtrace' if show_backtrace else ''}")

        try:
            # 构建hook脚本
            hook_script = self._build_hook_script(target, show_args, show_return, show_backtrace)
            
            # 执行hook脚本
            if not hook_script:
                console.error("Failed to create hook script")
                return
                
            # 调用Frida脚本来执行hook
            console.success(f"Hook installed for {target}")
            console.info("Waiting for method to be called...")
            
            # 这里应该调用实际的Frida API来执行脚本
            # 示例: context.current_session.frida_session.create_script(hook_script).load()
            
        except Exception as e:
            console.error(f"Error hooking method: {str(e)}")

    def _build_hook_script(self, target: str, show_args: bool, show_return: bool, show_backtrace: bool) -> str:
        """
        构建Hook脚本

        参数:
            target: 目标方法或函数
            show_args: 是否显示参数
            show_return: 是否显示返回值
            show_backtrace: 是否显示调用栈

        返回:
            JavaScript hook脚本
        """
        # 检测目标类型（Java、ObjC或Native）
        if target.startswith("com.") or target.startswith("android.") or target.startswith("java."):
            return self._build_java_hook(target, show_args, show_return, show_backtrace)
        elif "!" in target:
            return self._build_native_hook(target, show_args, show_return, show_backtrace)
        else:
            return self._build_objc_hook(target, show_args, show_return, show_backtrace)

    def _build_java_hook(self, target: str, show_args: bool, show_return: bool, show_backtrace: bool) -> str:
        """
        构建Java方法的Hook脚本
        """
        class_parts = target.split(".")
        method_name = class_parts[-1]
        class_name = ".".join(class_parts[:-1])
        
        script = f"""
Java.perform(function() {{
    try {{
        var targetClass = Java.use("{class_name}");
        
        targetClass.{method_name}.overload().implementation = function() {{
            console.log("[*] {target} called");
            
            {"// 显示参数\\n            console.log('Arguments: ' + JSON.stringify(arguments));\\n" if show_args else ""}
            
            {"// 显示调用栈\\n            console.log('Backtrace:\\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));\\n" if show_backtrace else ""}
            
            var retval = this.{method_name}.apply(this, arguments);
            
            {"// 显示返回值\\n            console.log('Return value: ' + retval);\\n" if show_return else ""}
            
            return retval;
        }};
        
        console.log("[+] Successfully hooked {target}");
    }} catch(e) {{
        console.log("[-] Error hooking {target}: " + e.message);
    }}
}});
        """
        return script

    def _build_native_hook(self, target: str, show_args: bool, show_return: bool, show_backtrace: bool) -> str:
        """
        构建Native函数的Hook脚本
        """
        parts = target.split("!")
        library = parts[0]
        function_name = parts[1]
        
        script = f"""
Interceptor.attach(Module.findExportByName("{library}", "{function_name}"), {{
    onEnter: function(args) {{
        console.log("[*] {target} called");
        
        {"// 显示参数\\n        console.log('Arguments: ' + args[0] + ', ' + args[1] + '...');\\n" if show_args else ""}
        
        {"// 显示调用栈\\n        console.log('Backtrace:\\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));\\n" if show_backtrace else ""}
        
        this.args = args;
    }},
    
    onLeave: function(retval) {{
        {"// 显示返回值\\n        console.log('Return value: ' + retval);\\n" if show_return else ""}
    }}
}});
console.log("[+] Successfully hooked {target}");
        """
        return script

    def _build_objc_hook(self, target: str, show_args: bool, show_return: bool, show_backtrace: bool) -> str:
        """
        构建Objective-C方法的Hook脚本
        """
        parts = target.split(".")
        class_name = parts[0]
        method_name = parts[1] if len(parts) > 1 else ""
        
        script = f"""
ObjC.available && Interceptor.attach(ObjC.classes.{class_name}["{'- ' if not method_name.startswith('+') else ''}{method_name}"].implementation, {{
    onEnter: function(args) {{
        console.log("[*] {target} called");
        
        {"// 显示参数\\n        var obj = ObjC.Object(args[0]);\\n        console.log('Arguments: ' + obj);\\n" if show_args else ""}
        
        {"// 显示调用栈\\n        console.log('Backtrace:\\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));\\n" if show_backtrace else ""}
        
        this.args = args;
    }},
    
    onLeave: function(retval) {{
        {"// 显示返回值\\n        console.log('Return value: ' + ObjC.Object(retval));\\n" if show_return else ""}
    }}
}});
console.log("[+] Successfully hooked {target}");
        """
        return script

    def get_completions(self, document, args: List[str]):
        """获取命令补全"""
        if len(args) == 0 or (len(args) == 1 and not document.text.endswith(' ')):
            # 在这里可以提供常用的类或方法名补全
            common_classes = [
                "com.android.app.Activity", 
                "java.net.URL",
                "android.webkit.WebView",
                "java.security.MessageDigest",
                "javax.crypto.Cipher"
            ]
            
            word = args[0] if args else ""
            for cls in common_classes:
                if cls.startswith(word):
                    yield Completion(cls, start_position=-len(word),
                                    display=cls, display_meta="class/method")
            return
            
        if len(args) >= 1 and document.text.endswith(' '):
            # 提供选项补全
            options = ["args", "return", "backtrace"]
            used_options = set(arg.lower() for arg in args[1:])
            
            for option in options:
                if option not in used_options:
                    yield Completion(option, start_position=0,
                                    display=option, display_meta="hook option") 