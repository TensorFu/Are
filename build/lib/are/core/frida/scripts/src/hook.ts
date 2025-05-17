/**
 * are/core/frida/scripts/src/hook.ts
 * 
 * 基于Frida的通用hook脚本，用于hook指定方法
 */

// 接收命令行参数
interface IFridaArguments {
    processName: string;    // 进程名称
    methodSignature: string; // 方法签名
    includeBacktrace?: boolean; // 是否包含回溯
    includeArgs?: boolean;  // 是否包含参数
    includeReturnValue?: boolean; // 是否包含返回值
}

// 扩展 Frida 回调接口以支持额外属性
interface IFridaCallbacks {
    context?: any;
    args?: any;
    onEnter?: (args: any) => void;
    onLeave?: (retval: any) => void;
}

// 全局参数
let args: IFridaArguments = {
    processName: '',
    methodSignature: '',
    includeBacktrace: false,
    includeArgs: false,
    includeReturnValue: false
};

// 解析命令行参数函数
function parseArguments(): void {
    try {
        // 检查是否有足够的参数
        if (Process.argv.length < 2) {
            console.log('参数不足: 需要提供方法签名');
            console.log('用法: <方法签名> [includeBacktrace] [includeArgs] [includeReturnValue]');
            return;
        }

        // 设置参数 - 在两层会话模式下不需要进程名
        // 在这种模式下，第一个参数就是方法签名
        args = {
            processName: '', // 进程名已经通过watching指定
            methodSignature: Process.argv[1] || '',
            includeBacktrace: Process.argv.indexOf('includeBacktrace') !== -1,
            includeArgs: Process.argv.indexOf('includeArgs') !== -1, 
            includeReturnValue: Process.argv.indexOf('includeReturnValue') !== -1
        };

        console.log(`[*] 目标方法: ${args.methodSignature}`);
        console.log(`[*] 选项: 回溯=${args.includeBacktrace}, 参数=${args.includeArgs}, 返回值=${args.includeReturnValue}`);
    } catch (e) {
        console.log(`参数解析错误: ${e}`);
    }
}

// 解析Java方法签名
function parseMethodSignature(signature: string): { className: string, methodName: string } {
    try {
        // 支持 com.example.Class.method 或 com.example.Class#method 格式
        const parts = signature.includes('#') 
            ? signature.split('#') 
            : signature.split('.');
        
        const methodName = parts.pop() || '';
        const className = parts.join('.');
        
        return { className, methodName };
    } catch (e) {
        console.log(`解析方法签名错误: ${e}`);
        return { className: '', methodName: '' };
    }
}

// 生成回溯信息
function generateBacktrace(context: any): string {
    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .map((addr) => DebugSymbol.fromAddress(addr).toString())
            .join('\n');
    } catch (e) {
        return `无法生成回溯: ${e}`;
    }
}

// 格式化参数
function formatArgument(arg: any): string {
    if (arg === null) return 'null';
    if (arg === undefined) return 'undefined';
    
    try {
        if (arg !== null && typeof arg === 'object' && arg.toString && typeof arg.toString === 'function') {
            const str = arg.toString();
            if (str !== '[object Object]') {
                return str;
            }
        }
        
        return JSON.stringify(arg);
    } catch (e) {
        return `<无法格式化: ${e}>`;
    }
}

// Hook Java方法
function hookJavaMethod(className: string, methodName: string): void {
    try {
        if (Java.available) {
            Java.perform(function() {
                try {
                    const targetClass = Java.use(className);
                    
                    // 获取指定的方法
                    if (targetClass[methodName]) {
                        console.log(`[+] 找到方法: ${className}.${methodName}`);
                        
                        // 对所有重载进行处理
                        const overloads = targetClass[methodName].overloads;
                        console.log(`[*] 检测到 ${overloads.length} 个重载版本`);
                        
                        overloads.forEach(function(overload: any) {
                            overload.implementation = function() {
                                const self = this;
                                // 保存参数以便在内部函数中使用
                                const callArgs = arguments;
                                
                                // 创建基本输出
                                let output = `[+] 调用 ${className}.${methodName}`;
                                
                                // 添加参数信息
                                if (args.includeArgs) {
                                    output += "\n[*] 参数:";
                                    for (let i = 0; i < callArgs.length; i++) {
                                        output += `\n   参数[${i}]: ${formatArgument(callArgs[i])}`;
                                    }
                                }
                                
                                // 添加回溯信息
                                if (args.includeBacktrace) {
                                    output += "\n[*] 回溯:";
                                    output += "\n" + generateBacktrace(this.context);
                                }
                                
                                // 输出当前信息
                                console.log(output);
                                
                                // 调用原始方法
                                const returnValue = this[methodName].apply(this, callArgs);
                                
                                // 添加返回值信息
                                if (args.includeReturnValue) {
                                    console.log(`[*] 返回值: ${formatArgument(returnValue)}`);
                                }
                                
                                return returnValue;
                            };
                        });
                        
                        console.log(`[+] 成功hook方法: ${className}.${methodName}`);
                    } else {
                        console.log(`[-] 在类 ${className} 中找不到方法 ${methodName}`);
                    }
                } catch (e) {
                    console.log(`[-] Hook Java方法时出错: ${e}`);
                }
            });
        } else {
            console.log('[-] Java VM不可用，无法hook Java方法');
        }
    } catch (e) {
        console.log(`[-] 执行JavaHook时出错: ${e}`);
    }
}

// Hook Native方法
function hookNativeMethod(moduleName: string, methodName: string): void {
    try {
        const module = Process.findModuleByName(moduleName);
        if (module) {
            console.log(`[+] 找到模块 ${moduleName} 加载在 ${module.base}`);
            
            const exportSymbols = module.enumerateExports();
            let targetSymbol: ModuleExportDetails | undefined = undefined;
            
            for (const sym of exportSymbols) {
                if (sym.name === methodName) {
                    targetSymbol = sym;
                    break;
                }
            }
            
            if (targetSymbol && targetSymbol.address) {
                console.log(`[+] 找到导出符号 ${methodName} 在地址 ${targetSymbol.address}`);
                
                // 使用泛型接口而非引用特定模块类型
                const callbacks: IFridaCallbacks = {
                    onEnter: function(args) {
                        // 存储上下文供onLeave使用
                        this.context = this.context;
                        this.args = args;
                        
                        let output = `[+] 调用 ${moduleName}!${methodName}`;
                        
                        // 添加参数信息
                        if (args && args.includeArgs) {
                            output += "\n[*] 参数 (前4个):";
                            for (let i = 0; i < 4; i++) {
                                output += `\n   arg${i}: ${args[i]}`;
                            }
                        }
                        
                        // 添加回溯信息
                        if (args && args.includeBacktrace && this.context) {
                            output += "\n[*] 回溯:";
                            output += "\n" + generateBacktrace(this.context);
                        }
                        
                        console.log(output);
                    },
                    onLeave: function(retval) {
                        if (args && args.includeReturnValue) {
                            console.log(`[*] 返回值: ${retval}`);
                        }
                        
                        return retval;
                    }
                };
                
                Interceptor.attach(targetSymbol.address, callbacks);
                
                console.log(`[+] 成功hook原生方法: ${moduleName}!${methodName}`);
            } else {
                console.log(`[-] 在模块 ${moduleName} 中找不到方法 ${methodName}`);
            }
        } else {
            console.log(`[-] 找不到模块 ${moduleName}`);
        }
    } catch (e) {
        console.log(`[-] 执行NativeHook时出错: ${e}`);
    }
}

// 接收消息处理
function onMessage(message: any): void {
    try {
        if (message.type === 'args' && message.payload) {
            const payload = message.payload;
            
            console.log(`[*] 通过消息收到参数，类型: ${typeof payload}`);
            
            // 根据两层会话模式调整参数处理
            if (typeof payload === 'string') {
                // 如果只传递了一个字符串参数，假设它是方法签名
                args.methodSignature = payload;
            } else if (Array.isArray(payload)) {
                // 如果是数组，可能是原来的参数形式
                if (payload.length >= 1) {
                    args.methodSignature = payload[0];
                    args.includeBacktrace = payload.indexOf('includeBacktrace') !== -1;
                    args.includeArgs = payload.indexOf('includeArgs') !== -1;
                    args.includeReturnValue = payload.indexOf('includeReturnValue') !== -1;
                }
            } else if (typeof payload === 'object' && payload !== null) {
                // 如果是对象，直接使用，但要小心处理
                if (payload.methodSignature !== undefined) {
                    args.methodSignature = String(payload.methodSignature);
                }
                
                if (payload.includeBacktrace !== undefined) {
                    args.includeBacktrace = Boolean(payload.includeBacktrace);
                }
                
                if (payload.includeArgs !== undefined) {
                    args.includeArgs = Boolean(payload.includeArgs);
                }
                
                if (payload.includeReturnValue !== undefined) {
                    args.includeReturnValue = Boolean(payload.includeReturnValue);
                }
            }
            
            console.log(`[*] 目标进程: ${args.processName}`);
            console.log(`[*] 目标方法: ${args.methodSignature}`);
            console.log(`[*] 选项: 回溯=${args.includeBacktrace}, 参数=${args.includeArgs}, 返回值=${args.includeReturnValue}`);
            
            // 接收到参数后，立即启动Hook
            main();
        }
    } catch (e) {
        console.log(`消息处理错误: ${e}`);
    }
}

// 主函数
function main(): void {
    try {
        // 如果没有参数，尝试解析命令行参数
        if (!args || !args.methodSignature) {
            parseArguments();
        }
        
        // 检查参数是否有效
        if (!args || !args.methodSignature) {
            console.log('缺少方法签名');
            return;
        }
        
        const { className, methodName } = parseMethodSignature(args.methodSignature);
        
        if (!className || !methodName) {
            console.log('无效的方法签名');
            return;
        }
        
        // 判断是Java方法还是Native方法
        if (className.includes('.')) {
            // Java方法
            hookJavaMethod(className, methodName);
        } else {
            // Native方法 (格式: libname!funcname)
            hookNativeMethod(className, methodName);
        }
    } catch (e) {
        console.log(`主函数执行错误: ${e}`);
    }
}

// 注册消息处理函数
try {
    recv('args', onMessage);
    console.log('[*] 已注册消息处理函数，等待参数...');
} catch (e) {
    console.log(`注册消息处理函数错误: ${e}`);
}

// 程序启动时执行主函数
// 注意：当通过-l参数直接加载脚本时，将从命令行获取参数
// 当通过session.create_script加载时，将通过消息获取参数
try {
    if (Process.argv && Process.argv.length > 1) {
        console.log('[*] 发现命令行参数，直接启动');
        main();
    } else {
        console.log("[*] 等待参数...");
    }
} catch (e) {
    console.log(`初始执行错误: ${e}`);
}
