#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/frida/hook.py

import os
import sys
import frida
import time
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from are.core.theme.ui import AreConsole

# 控制台实例
console = AreConsole()

class FridaHook:
    """Frida Hook 管理类"""
    
    def __init__(self):
        """初始化 Frida Hook 管理器"""
        self.script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        self.ts_path = self.script_dir / "scripts" / "src"
        self.dist_path = self.script_dir / "scripts" / "dist"
        
        # 确保目录存在
        os.makedirs(self.ts_path, exist_ok=True)
        os.makedirs(self.dist_path, exist_ok=True)
        
        # 检查源文件是否存在
        hook_ts_path = self.ts_path / "hook.ts"
        if not hook_ts_path.exists():
            console.warning(f"TypeScript源文件不存在: {hook_ts_path}")
            console.info("尝试查找替代位置...")
            
            # 查找可能的替代位置
            module_dir = Path(__file__).parent.parent.parent
            alt_paths = [
                module_dir / "core" / "frida" / "scripts" / "src" / "hook.ts",
                module_dir / "resources" / "frida" / "scripts" / "src" / "hook.ts"
            ]
            
            found = False
            for alt_path in alt_paths:
                if alt_path.exists():
                    console.success(f"找到替代源文件: {alt_path}")
                    # 确保目标目录存在
                    os.makedirs(self.ts_path, exist_ok=True)
                    # 复制文件
                    try:
                        shutil.copy2(alt_path, hook_ts_path)
                        console.success("已复制源文件到正确位置")
                        found = True
                        break
                    except Exception as e:
                        console.error(f"复制文件时出错: {str(e)}")
                        continue
            
            if not found:
                console.warning("无法找到TypeScript源文件，将在首次运行时自动创建")

    def compile_typescript(self) -> bool:
        """编译 TypeScript 脚本"""
        # 检查JavaScript文件是否已经存在，如果存在直接返回成功
        hook_js_path = self.dist_path / "hook.js"
        if hook_js_path.exists():
            console.info("已找到编译后的JavaScript文件，跳过编译")
            return True
            
        try:
            console.info("正在编译 TypeScript Frida 脚本...")
            
            # 使用线程和超时来避免卡在编译过程中
            compile_result = {"success": False, "error": None}
            compile_done = threading.Event()
            
            def compile_thread():
                try:
                    # 检查node
                    try:
                        node_version_proc = subprocess.run(
                            ["node", "--version"], 
                            capture_output=True, 
                            text=True,
                            check=False,
                            timeout=3  # 3秒超时
                        )
                        
                        if node_version_proc.returncode != 0:
                            compile_result["error"] = "未找到Node.js"
                            compile_done.set()
                            return
                            
                        console.info(f"Node.js版本: {node_version_proc.stdout.strip()}")
                        
                        # 检查TypeScript编译器
                        tsc_version_proc = subprocess.run(
                            ["npx", "tsc", "--version"], 
                            capture_output=True, 
                            text=True,
                            check=False,
                            timeout=3  # 3秒超时
                        )
                        
                        if tsc_version_proc.returncode != 0:
                            console.info("尝试安装TypeScript...")
                            npm_install_proc = subprocess.run(
                                ["npm", "install", "-g", "typescript"],
                                capture_output=True,
                                text=True,
                                check=False,
                                timeout=30  # 30秒超时
                            )
                            
                            if npm_install_proc.returncode != 0:
                                compile_result["error"] = f"安装TypeScript失败: {npm_install_proc.stderr}"
                                compile_done.set()
                                return
                                
                            console.success("TypeScript安装成功")
                        else:
                            console.info(f"TypeScript版本: {tsc_version_proc.stdout.strip()}")
                        
                        # 确保tsconfig.json存在
                        tsconfig_path = self.script_dir / "scripts" / "tsconfig.json"
                        if not tsconfig_path.exists():
                            console.info("创建基本的tsconfig.json...")
                            
                            tsconfig_content = """{
  "compilerOptions": {
    "target": "es2020",
    "module": "commonjs",
    "lib": ["es2020"],
    "outDir": "../dist",
    "rootDir": "./src",
    "strict": false,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "noImplicitAny": false
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}"""
                            
                            with open(tsconfig_path, 'w') as f:
                                f.write(tsconfig_content)
                                
                            console.success("tsconfig.json创建成功")
                        
                        # 确保frida.d.ts文件存在
                        frida_dts_path = self.ts_path / "frida.d.ts"
                        if not frida_dts_path.exists():
                            console.info("创建基本的frida.d.ts...")
                            # 这里应该有一个基本的frida.d.ts内容，但由于长度限制，我们可以创建一个最小版本
                            # 在实际项目中应该添加完整的类型定义
                            frida_dts_content = """/**
 * 简化版Frida类型定义
 */
declare function recv(type: string, callback: (message: any, data: any) => void): void;
declare function send(message: any, data?: any): void;

declare namespace Process {
  const argv: string[];
  function exit(code?: number): void;
}

declare namespace Java {
  let available: boolean;
  function perform(fn: Function): void;
  function use(className: string): any;
}

declare namespace Interceptor {
  function attach(target: any, callbacks: any): any;
}

declare namespace Thread {
  function backtrace(context: any, backtracer?: string): any[];
}

declare namespace DebugSymbol {
  function fromAddress(address: any): any;
}

declare namespace Module {
  function findBaseAddress(name: string): any;
  function enumerateExports(name: string): any[];
}

declare namespace console {
  function log(message?: any, ...optionalParams: any[]): void;
}"""
                            
                            with open(frida_dts_path, 'w') as f:
                                f.write(frida_dts_content)
                                
                            console.success("frida.d.ts创建成功")
                        
                        # 确保hook.ts文件存在
                        hook_ts_path = self.ts_path / "hook.ts"
                        if not hook_ts_path.exists():
                            console.warning("hook.ts文件不存在，无法编译")
                            compile_result["error"] = "hook.ts文件不存在"
                            compile_done.set()
                            return
                        
                        # 运行编译
                        console.info("运行TypeScript编译...")
                        
                        compile_proc = subprocess.run(
                            ["npx", "tsc", "-p", str(tsconfig_path)],
                            capture_output=True,
                            text=True,
                            check=False,
                            timeout=10  # 10秒超时
                        )
                        
                        if compile_proc.returncode != 0:
                            console.warning(f"编译失败: {compile_proc.stderr}")
                            console.info("尝试使用--skipLibCheck选项...")
                            
                            skiplib_proc = subprocess.run(
                                ["npx", "tsc", "-p", str(tsconfig_path), "--skipLibCheck"],
                                capture_output=True,
                                text=True,
                                check=False,
                                timeout=10  # 10秒超时
                            )
                            
                            if skiplib_proc.returncode != 0:
                                compile_result["error"] = f"编译失败(使用--skipLibCheck): {skiplib_proc.stderr}"
                                compile_done.set()
                                return
                                
                            console.success("使用--skipLibCheck编译成功")
                        else:
                            console.success("TypeScript编译成功")
                        
                        # 检查编译后的文件
                        if hook_js_path.exists():
                            compile_result["success"] = True
                        else:
                            compile_result["error"] = "编译完成但未生成JS文件"
                            
                    except subprocess.TimeoutExpired as e:
                        compile_result["error"] = f"命令执行超时: {str(e)}"
                    except Exception as e:
                        compile_result["error"] = f"编译过程出错: {str(e)}"
                        
                except Exception as e:
                    compile_result["error"] = f"编译线程出错: {str(e)}"
                    
                compile_done.set()
                
            # 启动编译线程
            compile_thread = threading.Thread(target=compile_thread)
            compile_thread.daemon = True
            compile_thread.start()
            
            # 等待编译完成或超时
            if not compile_done.wait(timeout=60):  # 60秒总超时
                console.error("编译超时，创建基本的JavaScript文件...")
                
                # 创建一个基本的JS文件
                basic_js = """
console.log('[*] 基本Frida Hook脚本已加载');

// 处理消息
recv('args', function(message) {
    console.log('[*] 收到参数: ' + JSON.stringify(message.payload));
    
    var methodSignature = '';
    
    // 解析参数
    if (typeof message.payload === 'string') {
        // 如果是字符串，直接作为方法签名
        methodSignature = message.payload;
    } else if (Array.isArray(message.payload) && message.payload.length > 0) {
        // 如果是数组，取第一个元素作为方法签名
        methodSignature = message.payload[0];
    } else if (typeof message.payload === 'object' && message.payload.methodSignature) {
        // 如果是对象，取methodSignature属性
        methodSignature = message.payload.methodSignature;
    }
    
    console.log('[*] 目标方法: ' + methodSignature);
    
    if (!methodSignature) {
        console.log('[-] 错误: 未提供方法签名');
        return;
    }
    
    // 尝试解析方法签名
    var parts = methodSignature.includes('#') 
        ? methodSignature.split('#') 
        : methodSignature.split('.');
    
    var methodName = parts.pop() || '';
    var className = parts.join('.');
    
    if (!className || !methodName) {
        console.log('[-] 错误: 无效的方法签名');
        return;
    }
    
    // 判断是Java方法还是Native方法
    if (className.includes('.')) {
        // Java方法
        console.log('[*] 尝试hook Java方法: ' + className + '.' + methodName);
        
        if (Java.available) {
            Java.perform(function() {
                try {
                    var targetClass = Java.use(className);
                    
                    if (targetClass[methodName]) {
                        console.log('[+] 找到方法: ' + className + '.' + methodName);
                        
                        var overloads = targetClass[methodName].overloads;
                        console.log('[*] 检测到 ' + overloads.length + ' 个重载版本');
                        
                        overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                console.log('[+] 调用 ' + className + '.' + methodName);
                                
                                // 添加参数信息
                                console.log('[*] 参数:');
                                for (var i = 0; i < arguments.length; i++) {
                                    var arg = arguments[i];
                                    console.log('   参数[' + i + ']: ' + (arg === null ? 'null' : arg === undefined ? 'undefined' : JSON.stringify(arg)));
                                }
                                
                                // 调用原始方法
                                var returnValue = this[methodName].apply(this, arguments);
                                
                                // 添加返回值信息
                                console.log('[*] 返回值: ' + (returnValue === null ? 'null' : returnValue === undefined ? 'undefined' : JSON.stringify(returnValue)));
                                
                                return returnValue;
                            };
                        });
                        
                        console.log('[+] 成功hook方法: ' + className + '.' + methodName);
                    } else {
                        console.log('[-] 在类 ' + className + ' 中找不到方法 ' + methodName);
                    }
                } catch (e) {
                    console.log('[-] Hook Java方法时出错: ' + e);
                }
            });
        } else {
            console.log('[-] Java VM不可用，无法hook Java方法');
        }
    } else {
        // Native方法 (格式: libname!funcname)
        console.log('[*] 尝试hook Native方法: ' + className + '!' + methodName);
        console.log('[-] 简化版不支持Native方法hook');
    }
});

console.log('[*] 等待参数...');
"""
                
                with open(hook_js_path, 'w') as f:
                    f.write(basic_js)
                    
                console.warning("已创建基本JavaScript文件，功能可能有限")
                return True
                
            # 检查编译结果
            if compile_result["success"]:
                return True
            else:
                console.error(f"编译失败: {compile_result['error']}")
                
                # 如果编译失败但JavaScript文件已存在，仍然使用
                if hook_js_path.exists():
                    console.warning("使用现有的JavaScript文件")
                    return True
                    
                # 创建基本的JavaScript文件
                console.info("创建基本的JavaScript文件...")
                
                basic_js = """
console.log('[*] 基本Frida Hook脚本已加载');

// 处理消息
recv('args', function(message) {
    console.log('[*] 收到参数: ' + JSON.stringify(message.payload));
    
    var methodSignature = '';
    
    // 解析参数
    if (typeof message.payload === 'string') {
        // 如果是字符串，直接作为方法签名
        methodSignature = message.payload;
    } else if (Array.isArray(message.payload) && message.payload.length > 0) {
        // 如果是数组，取第一个元素作为方法签名
        methodSignature = message.payload[0];
    } else if (typeof message.payload === 'object' && message.payload.methodSignature) {
        // 如果是对象，取methodSignature属性
        methodSignature = message.payload.methodSignature;
    }
    
    console.log('[*] 目标方法: ' + methodSignature);
    
    if (!methodSignature) {
        console.log('[-] 错误: 未提供方法签名');
        return;
    }
    
    // 尝试解析方法签名
    var parts = methodSignature.includes('#') 
        ? methodSignature.split('#') 
        : methodSignature.split('.');
    
    var methodName = parts.pop() || '';
    var className = parts.join('.');
    
    if (!className || !methodName) {
        console.log('[-] 错误: 无效的方法签名');
        return;
    }
    
    // 判断是Java方法还是Native方法
    if (className.includes('.')) {
        // Java方法
        console.log('[*] 尝试hook Java方法: ' + className + '.' + methodName);
        
        if (Java.available) {
            Java.perform(function() {
                try {
                    var targetClass = Java.use(className);
                    
                    if (targetClass[methodName]) {
                        console.log('[+] 找到方法: ' + className + '.' + methodName);
                        
                        var overloads = targetClass[methodName].overloads;
                        console.log('[*] 检测到 ' + overloads.length + ' 个重载版本');
                        
                        overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                console.log('[+] 调用 ' + className + '.' + methodName);
                                
                                // 添加参数信息
                                console.log('[*] 参数:');
                                for (var i = 0; i < arguments.length; i++) {
                                    var arg = arguments[i];
                                    console.log('   参数[' + i + ']: ' + (arg === null ? 'null' : arg === undefined ? 'undefined' : JSON.stringify(arg)));
                                }
                                
                                // 调用原始方法
                                var returnValue = this[methodName].apply(this, arguments);
                                
                                // 添加返回值信息
                                console.log('[*] 返回值: ' + (returnValue === null ? 'null' : returnValue === undefined ? 'undefined' : JSON.stringify(returnValue)));
                                
                                return returnValue;
                            };
                        });
                        
                        console.log('[+] 成功hook方法: ' + className + '.' + methodName);
                    } else {
                        console.log('[-] 在类 ' + className + ' 中找不到方法 ' + methodName);
                    }
                } catch (e) {
                    console.log('[-] Hook Java方法时出错: ' + e);
                }
            });
        } else {
            console.log('[-] Java VM不可用，无法hook Java方法');
        }
    } else {
        // Native方法 (格式: libname!funcname)
        console.log('[*] 尝试hook Native方法: ' + className + '!' + methodName);
        console.log('[-] 简化版不支持Native方法hook');
    }
});

console.log('[*] 等待参数...');
"""
                
                with open(hook_js_path, 'w') as f:
                    f.write(basic_js)
                    
                console.warning("已创建基本JavaScript文件，功能可能有限")
                return True
                
        except Exception as e:
            console.error(f"编译TypeScript脚本时出错: {str(e)}")
            
            # 如果出错但JavaScript文件已存在，仍然使用
            if hook_js_path.exists():
                console.warning("使用现有的JavaScript文件")
                return True
                
            return False

    def hook_method(self, session: frida.core.Session, method_signature: str, 
                   include_backtrace: bool = False, 
                   include_args: bool = True,
                   include_return_value: bool = True) -> None:
        """
        在已有会话中hook指定方法
        
        参数:
            session: Frida会话对象
            method_signature: 方法签名 (格式: com.example.Class.method 或 libname!funcname)
            include_backtrace: 是否包含回溯信息
            include_args: 是否包含参数信息
            include_return_value: 是否包含返回值信息
        """
        try:
            # 编译TypeScript
            if not self.compile_typescript():
                console.error("由于编译失败，无法继续")
                return
                
            # 构建参数
            options = []
            if include_backtrace:
                options.append("includeBacktrace")
            if include_args:
                options.append("includeArgs")
            if include_return_value:
                options.append("includeReturnValue")
                
            # 获取hook.js路径
            hook_js_path = self.dist_path / "hook.js"
            
            # 加载脚本
            console.info(f"加载Frida脚本，目标方法: {method_signature}")
            
            with open(hook_js_path, 'r') as f:
                script_source = f.read()
                
            # 创建消息处理函数
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message.get('payload', '')
                    console.info(f"[Frida] {payload}")
                elif message['type'] == 'error':
                    stack = message.get('stack', '')
                    description = message.get('description', '未知错误')
                    console.error(f"[Frida Error] {description}")
                    if stack:
                        console.debug(f"错误详情: {stack}")
            
            # 创建脚本
            script = session.create_script(script_source)
            script.on('message', on_message)
            
            try:
                script.load()
                console.success("脚本加载成功")
            except Exception as e:
                console.error(f"脚本加载失败: {str(e)}")
                return
                
            # 发送参数
            try:
                # 对于两层会话模式，只需要传递方法签名和选项
                script.post({
                    'type': 'args', 
                    'payload': [method_signature] + options
                })
                console.success("参数传递成功")
            except Exception as e:
                console.error(f"参数传递失败: {str(e)}")
                
            # 返回脚本对象，以便在需要时可以卸载
            return script
            
        except Exception as e:
            console.error(f"Hook方法时出错: {str(e)}")
            import traceback
            console.debug(traceback.format_exc())
            return None

    def run_hook(self, process_name: str, method_signature: str, 
                include_backtrace: bool = False, 
                include_args: bool = True,
                include_return_value: bool = True) -> None:
        """
        运行 Frida hook
        
        参数:
            process_name: 目标进程名称
            method_signature: 方法签名 (格式: com.example.Class.method 或 libname!funcname)
            include_backtrace: 是否包含回溯信息
            include_args: 是否包含参数信息
            include_return_value: 是否包含返回值信息
        """
        try:
            # 编译TypeScript
            if not self.compile_typescript():
                console.error("由于编译失败，无法继续")
                return
            
            # 构建命令行参数
            cmd_args = [method_signature]
            
            if include_backtrace:
                cmd_args.append("includeBacktrace")
            
            if include_args:
                cmd_args.append("includeArgs")
                
            if include_return_value:
                cmd_args.append("includeReturnValue")
            
            # 获取hook.js路径
            hook_js_path = self.dist_path / "hook.js"
            
            if not hook_js_path.exists():
                console.error(f"找不到脚本文件: {hook_js_path}")
                return
            
            console.info(f"正在启动Frida，目标进程: {process_name}")
            console.info(f"Hook目标方法: {method_signature}")
            
            try:
                # 创建Frida会话
                try:
                    console.info("尝试连接到USB设备...")
                    device = frida.get_usb_device(1)  # 1秒超时
                except Exception as e:
                    console.warning(f"无法连接到USB设备: {str(e)}")
                    console.info("尝试连接到本地设备...")
                    device = frida.get_local_device()
                
                console.info(f"已连接到设备: {device.name}")
                
                try:
                    console.info(f"尝试spawn进程: {process_name}")
                    pid = device.spawn([process_name])
                    console.success(f"进程已启动，PID: {pid}")
                except Exception as e:
                    console.warning(f"无法spawn进程: {str(e)}")
                    console.info("尝试附加到已运行的进程...")
                    pid = device.get_process(process_name).pid
                    console.success(f"已找到运行中的进程，PID: {pid}")
                
                console.info(f"附加到进程 {pid}...")
                session = device.attach(pid)
                
                # 创建消息处理函数
                def on_message(message, data):
                    if message['type'] == 'send':
                        payload = message.get('payload', '')
                        console.info(f"[Frida] {payload}")
                    elif message['type'] == 'error':
                        stack = message.get('stack', '')
                        description = message.get('description', '未知错误')
                        console.error(f"[Frida Error] {description}")
                        if stack:
                            console.debug(f"错误详情: {stack}")
                
                # 加载脚本
                with open(hook_js_path, 'r') as f:
                    script_source = f.read()
                
                console.info("正在加载Frida脚本...")
                script = session.create_script(script_source)
                script.on('message', on_message)
                
                try:
                    script.load()
                    console.success("脚本加载成功")
                except Exception as e:
                    console.error(f"脚本加载失败: {str(e)}")
                    # 尝试显示脚本错误的部分
                    if hasattr(e, 'lineNumber') and hasattr(e, 'columnNumber'):
                        console.error(f"错误位置: 行 {e.lineNumber}, 列 {e.columnNumber}")
                        lines = script_source.split('\n')
                        if 0 <= e.lineNumber - 1 < len(lines):
                            console.error(f"错误行: {lines[e.lineNumber - 1]}")
                    return
                
                # 向脚本传递参数
                console.info("正在传递参数到脚本...")
                try:
                    script.post({'type': 'args', 'payload': cmd_args})
                    console.success("参数传递成功")
                except Exception as e:
                    console.error(f"参数传递失败: {str(e)}")
                    return
                
                # 恢复进程执行
                try:
                    console.info("恢复进程执行...")
                    device.resume(pid)
                    console.success("进程已恢复执行")
                except Exception as e:
                    console.warning(f"恢复进程时出错: {str(e)}")
                
                console.success(f"成功附加到进程 {process_name} (PID: {pid})")
                console.info("按 Ctrl+C 停止监控")
                
                # 保持脚本运行
                try:
                    sys.stdin.read()
                except KeyboardInterrupt:
                    console.info("用户中断，停止 hook")
                finally:
                    try:
                        session.detach()
                        console.info("已从进程分离")
                    except:
                        pass
                
            except frida.ProcessNotFoundError:
                console.error(f"找不到进程: {process_name}")
            except frida.ServerNotRunningError:
                console.error("Frida 服务器未运行，请确保已启动 frida-server")
            
        except KeyboardInterrupt:
            console.info("用户中断，停止 hook")
        except Exception as e:
            console.error(f"运行 Frida hook 时出错: {str(e)}")
            import traceback
            console.debug(traceback.format_exc())
