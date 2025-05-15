/**
 * 预编译的Frida hook脚本，用于在TypeScript编译失败时使用
 */

// 全局参数
var args = {
    processName: '',
    methodSignature: '',
    includeBacktrace: false,
    includeArgs: false,
    includeReturnValue: false
};

// 解析命令行参数
function parseArguments() {
    try {
        if (Process.argv.length < 3) {
            console.log('参数不足: 需要提供进程名和方法签名');
            console.log('用法: frida -f <进程名> -l hook.js --no-pause -- <方法签名> [includeBacktrace] [includeArgs] [includeReturnValue]');
            return;
        }

        args = {
            processName: Process.argv[1] || '',
            methodSignature: Process.argv[2] || '',
            includeBacktrace: Process.argv.indexOf('includeBacktrace') !== -1,
            includeArgs: Process.argv.indexOf('includeArgs') !== -1, 
            includeReturnValue: Process.argv.indexOf('includeReturnValue') !== -1
        };

        console.log('[*] 目标进程: ' + args.processName);
        console.log('[*] 目标方法: ' + args.methodSignature);
        console.log('[*] 选项: 回溯=' + args.includeBacktrace + ', 参数=' + args.includeArgs + ', 返回值=' + args.includeReturnValue);
    } catch (e) {
        console.log('参数解析错误: ' + e);
    }
}

// 解析Java方法签名
function parseMethodSignature(signature) {
    try {
        var parts = signature.includes('#') 
            ? signature.split('#') 
            : signature.split('.');
        
        var methodName = parts.pop() || '';
        var className = parts.join('.');
        
        return { className: className, methodName: methodName };
    } catch (e) {
        console.log('解析方法签名错误: ' + e);
        return { className: '', methodName: '' };
    }
}

// 生成回溯信息
function generateBacktrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .map(function(addr) { return DebugSymbol.fromAddress(addr).toString(); })
            .join('\n');
    } catch (e) {
        return '无法生成回溯: ' + e;
    }
}

// 格式化参数
function formatArgument(arg) {
    if (arg === null) return 'null';
    if (arg === undefined) return 'undefined';
    
    try {
        if (typeof arg === 'object' && arg.toString && typeof arg.toString === 'function') {
            var str = arg.toString();
            if (str !== '[object Object]') {
                return str;
            }
        }
        
        return JSON.stringify(arg);
    } catch (e) {
        return '<无法格式化: ' + e + '>';
    }
}

// Hook Java方法
function hookJavaMethod(className, methodName) {
    try {
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
                                var callArgs = arguments;
                                
                                var output = '[+] 调用 ' + className + '.' + methodName;
                                
                                if (args.includeArgs) {
                                    output += "\n[*] 参数:";
                                    for (var i = 0; i < callArgs.length; i++) {
                                        output += "\n   参数[" + i + "]: " + formatArgument(callArgs[i]);
                                    }
                                }
                                
                                if (args.includeBacktrace) {
                                    output += "\n[*] 回溯:";
                                    output += "\n" + generateBacktrace(this.context);
                                }
                                
                                console.log(output);
                                
                                var returnValue = this[methodName].apply(this, callArgs);
                                
                                if (args.includeReturnValue) {
                                    console.log('[*] 返回值: ' + formatArgument(returnValue));
                                }
                                
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
    } catch (e) {
        console.log('[-] 执行JavaHook时出错: ' + e);
    }
}

// Hook Native方法
function hookNativeMethod(moduleName, methodName) {
    try {
        var baseAddr = Module.findBaseAddress(moduleName);
        if (baseAddr) {
            console.log('[+] 找到模块 ' + moduleName + ' 加载在 ' + baseAddr);
            
            var exportSymbols = Module.enumerateExports(moduleName);
            var targetSymbol = null;
            
            for (var i = 0; i < exportSymbols.length; i++) {
                var sym = exportSymbols[i];
                if (sym.name === methodName) {
                    targetSymbol = sym;
                    break;
                }
            }
            
            if (targetSymbol && targetSymbol.address) {
                console.log('[+] 找到导出符号 ' + methodName + ' 在地址 ' + targetSymbol.address);
                
                Interceptor.attach(targetSymbol.address, {
                    onEnter: function(args) {
                        this.context = this.context || {};
                        this.args = args || [];
                        
                        var output = '[+] 调用 ' + moduleName + '!' + methodName;
                        
                        if (args && args.includeArgs) {
                            output += "\n[*] 参数 (前4个):";
                            for (var i = 0; i < 4; i++) {
                                output += "\n   arg" + i + ": " + args[i];
                            }
                        }
                        
                        if (args && args.includeBacktrace && this.context) {
                            output += "\n[*] 回溯:";
                            output += "\n" + generateBacktrace(this.context);
                        }
                        
                        console.log(output);
                    },
                    onLeave: function(retval) {
                        if (args && args.includeReturnValue) {
                            console.log('[*] 返回值: ' + retval);
                        }
                        
                        return retval;
                    }
                });
                
                console.log('[+] 成功hook原生方法: ' + moduleName + '!' + methodName);
            } else {
                console.log('[-] 在模块 ' + moduleName + ' 中找不到方法 ' + methodName);
            }
        } else {
            console.log('[-] 找不到模块 ' + moduleName);
        }
    } catch (e) {
        console.log('[-] 执行NativeHook时出错: ' + e);
    }
}

// 接收消息处理
function onMessage(message) {
    try {
        if (message.type === 'args' && message.payload) {
            var payload = message.payload;
            args = {
                processName: payload[0] || '',
                methodSignature: payload[1] || '',
                includeBacktrace: payload.indexOf('includeBacktrace') !== -1,
                includeArgs: payload.indexOf('includeArgs') !== -1,
                includeReturnValue: payload.indexOf('includeReturnValue') !== -1
            };
            
            console.log('[*] 通过消息收到参数');
            console.log('[*] 目标进程: ' + args.processName);
            console.log('[*] 目标方法: ' + args.methodSignature);
            console.log('[*] 选项: 回溯=' + args.includeBacktrace + ', 参数=' + args.includeArgs + ', 返回值=' + args.includeReturnValue);
            
            // 接收到参数后，立即启动Hook
            main();
        }
    } catch (e) {
        console.log('消息处理错误: ' + e);
    }
}

// 主函数
function main() {
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
        
        var signature = parseMethodSignature(args.methodSignature);
        var className = signature.className;
        var methodName = signature.methodName;
        
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
        console.log('主函数执行错误: ' + e);
    }
}

// 注册消息处理函数
try {
    recv('args', onMessage);
    console.log('[*] 已注册消息处理函数');
} catch (e) {
    console.log('注册消息处理函数错误: ' + e);
}

// 程序启动时执行主函数
// 注意：当通过-l参数直接加载脚本时，将从命令行获取参数
// 当通过session.create_script加载时，将通过消息获取参数
try {
    if (Process.argv && Process.argv.length > 2) {
        console.log('[*] 发现命令行参数，直接启动');
        main();
    } else {
        console.log('[*] 等待参数...');
    }
} catch (e) {
    console.log('初始执行错误: ' + e);
}
