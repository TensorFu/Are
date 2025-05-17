/**
 * are/core/frida/scripts/src/hook.ts
 *
 * 基于Frida的通用hook脚本，用于hook指定方法
 */
// 全局参数
var args = {
    processName: '',
    methodSignature: '',
    includeBacktrace: false,
    includeArgs: false,
    includeReturnValue: false
};
// 解析命令行参数函数
function parseArguments() {
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
            processName: '',
            methodSignature: Process.argv[1] || '',
            includeBacktrace: Process.argv.indexOf('includeBacktrace') !== -1,
            includeArgs: Process.argv.indexOf('includeArgs') !== -1,
            includeReturnValue: Process.argv.indexOf('includeReturnValue') !== -1
        };
        console.log("[*] 目标方法: ".concat(args.methodSignature));
        console.log("[*] \u9009\u9879: \u56DE\u6EAF=".concat(args.includeBacktrace, ", \u53C2\u6570=").concat(args.includeArgs, ", \u8FD4\u56DE\u503C=").concat(args.includeReturnValue));
    }
    catch (e) {
        console.log("\u53C2\u6570\u89E3\u6790\u9519\u8BEF: ".concat(e));
    }
}
// 解析Java方法签名
function parseMethodSignature(signature) {
    try {
        // 支持 com.example.Class.method 或 com.example.Class#method 格式
        var parts = signature.includes('#')
            ? signature.split('#')
            : signature.split('.');
        var methodName = parts.pop() || '';
        var className = parts.join('.');
        return { className: className, methodName: methodName };
    }
    catch (e) {
        console.log("\u89E3\u6790\u65B9\u6CD5\u7B7E\u540D\u9519\u8BEF: ".concat(e));
        return { className: '', methodName: '' };
    }
}
// 生成回溯信息
function generateBacktrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .map(function (addr) { return DebugSymbol.fromAddress(addr).toString(); })
            .join('\n');
    }
    catch (e) {
        return "\u65E0\u6CD5\u751F\u6210\u56DE\u6EAF: ".concat(e);
    }
}
// 格式化参数
function formatArgument(arg) {
    if (arg === null)
        return 'null';
    if (arg === undefined)
        return 'undefined';
    try {
        if (arg !== null && typeof arg === 'object' && arg.toString && typeof arg.toString === 'function') {
            var str = arg.toString();
            if (str !== '[object Object]') {
                return str;
            }
        }
        return JSON.stringify(arg);
    }
    catch (e) {
        return "<\u65E0\u6CD5\u683C\u5F0F\u5316: ".concat(e, ">");
    }
}
// Hook Java方法
function hookJavaMethod(className, methodName) {
    try {
        if (Java.available) {
            Java.perform(function () {
                try {
                    var targetClass = Java.use(className);
                    // 获取指定的方法
                    if (targetClass[methodName]) {
                        console.log("[+] \u627E\u5230\u65B9\u6CD5: ".concat(className, ".").concat(methodName));
                        // 对所有重载进行处理
                        var overloads = targetClass[methodName].overloads;
                        console.log("[*] \u68C0\u6D4B\u5230 ".concat(overloads.length, " \u4E2A\u91CD\u8F7D\u7248\u672C"));
                        overloads.forEach(function (overload) {
                            overload.implementation = function () {
                                var self = this;
                                // 保存参数以便在内部函数中使用
                                var callArgs = arguments;
                                // 创建基本输出
                                var output = "[+] \u8C03\u7528 ".concat(className, ".").concat(methodName);
                                // 添加参数信息
                                if (args.includeArgs) {
                                    output += "\n[*] 参数:";
                                    for (var i = 0; i < callArgs.length; i++) {
                                        output += "\n   \u53C2\u6570[".concat(i, "]: ").concat(formatArgument(callArgs[i]));
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
                                var returnValue = this[methodName].apply(this, callArgs);
                                // 添加返回值信息
                                if (args.includeReturnValue) {
                                    console.log("[*] \u8FD4\u56DE\u503C: ".concat(formatArgument(returnValue)));
                                }
                                return returnValue;
                            };
                        });
                        console.log("[+] \u6210\u529F\u0068\u006F\u006F\u006B\u65B9\u6CD5: ".concat(className, ".").concat(methodName));
                    }
                    else {
                        console.log("[-] \u5728\u7C7B ".concat(className, " \u4E2D\u627E\u4E0D\u5230\u65B9\u6CD5 ").concat(methodName));
                    }
                }
                catch (e) {
                    console.log("[-] Hook Java\u65B9\u6CD5\u65F6\u51FA\u9519: ".concat(e));
                }
            });
        }
        else {
            console.log('[-] Java VM不可用，无法hook Java方法');
        }
    }
    catch (e) {
        console.log("[-] \u6267\u884CJavaHook\u65F6\u51FA\u9519: ".concat(e));
    }
}
// Hook Native方法
function hookNativeMethod(moduleName, methodName) {
    try {
        var module = Process.findModuleByName(moduleName);
        if (module) {
            console.log("[+] \u627E\u5230\u6A21\u5757 ".concat(moduleName, " \u52A0\u8F7D\u5728 ").concat(module.base));
            var exportSymbols = module.enumerateExports();
            var targetSymbol = undefined;
            for (var _i = 0, exportSymbols_1 = exportSymbols; _i < exportSymbols_1.length; _i++) {
                var sym = exportSymbols_1[_i];
                if (sym.name === methodName) {
                    targetSymbol = sym;
                    break;
                }
            }
            if (targetSymbol && targetSymbol.address) {
                console.log("[+] \u627E\u5230\u5BFC\u51FA\u7B26\u53F7 ".concat(methodName, " \u5728\u5730\u5740 ").concat(targetSymbol.address));
                // 使用泛型接口而非引用特定模块类型
                var callbacks = {
                    onEnter: function (args) {
                        // 存储上下文供onLeave使用
                        this.context = this.context;
                        this.args = args;
                        var output = "[+] \u8C03\u7528 ".concat(moduleName, "!").concat(methodName);
                        // 添加参数信息
                        if (args && args.includeArgs) {
                            output += "\n[*] 参数 (前4个):";
                            for (var i = 0; i < 4; i++) {
                                output += "\n   arg".concat(i, ": ").concat(args[i]);
                            }
                        }
                        // 添加回溯信息
                        if (args && args.includeBacktrace && this.context) {
                            output += "\n[*] 回溯:";
                            output += "\n" + generateBacktrace(this.context);
                        }
                        console.log(output);
                    },
                    onLeave: function (retval) {
                        if (args && args.includeReturnValue) {
                            console.log("[*] \u8FD4\u56DE\u503C: ".concat(retval));
                        }
                        return retval;
                    }
                };
                Interceptor.attach(targetSymbol.address, callbacks);
                console.log("[+] \u6210\u529F\u0068\u006F\u006F\u006B\u539F\u751F\u65B9\u6CD5: ".concat(moduleName, "!").concat(methodName));
            }
            else {
                console.log("[-] \u5728\u6A21\u5757 ".concat(moduleName, " \u4E2D\u627E\u4E0D\u5230\u65B9\u6CD5 ").concat(methodName));
            }
        }
        else {
            console.log("[-] \u627E\u4E0D\u5230\u6A21\u5757 ".concat(moduleName));
        }
    }
    catch (e) {
        console.log("[-] \u6267\u884CNativeHook\u65F6\u51FA\u9519: ".concat(e));
    }
}
// 接收消息处理
function onMessage(message) {
    try {
        if (message.type === 'args' && message.payload) {
            var payload = message.payload;
            console.log("[*] \u901A\u8FC7\u6D88\u606F\u6536\u5230\u53C2\u6570\uFF0C\u7C7B\u578B: ".concat(typeof payload));
            // 根据两层会话模式调整参数处理
            if (typeof payload === 'string') {
                // 如果只传递了一个字符串参数，假设它是方法签名
                args.methodSignature = payload;
            }
            else if (Array.isArray(payload)) {
                // 如果是数组，可能是原来的参数形式
                if (payload.length >= 1) {
                    args.methodSignature = payload[0];
                    args.includeBacktrace = payload.indexOf('includeBacktrace') !== -1;
                    args.includeArgs = payload.indexOf('includeArgs') !== -1;
                    args.includeReturnValue = payload.indexOf('includeReturnValue') !== -1;
                }
            }
            else if (typeof payload === 'object' && payload !== null) {
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
            console.log("[*] \u76EE\u6807\u8FDB\u7A0B: ".concat(args.processName));
            console.log("[*] \u76EE\u6807\u65B9\u6CD5: ".concat(args.methodSignature));
            console.log("[*] \u9009\u9879: \u56DE\u6EAF=".concat(args.includeBacktrace, ", \u53C2\u6570=").concat(args.includeArgs, ", \u8FD4\u56DE\u503C=").concat(args.includeReturnValue));
            // 接收到参数后，立即启动Hook
            main();
        }
    }
    catch (e) {
        console.log("\u6D88\u606F\u5904\u7406\u9519\u8BEF: ".concat(e));
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
        var _a = parseMethodSignature(args.methodSignature), className = _a.className, methodName = _a.methodName;
        if (!className || !methodName) {
            console.log('无效的方法签名');
            return;
        }
        // 判断是Java方法还是Native方法
        if (className.includes('.')) {
            // Java方法
            hookJavaMethod(className, methodName);
        }
        else {
            // Native方法 (格式: libname!funcname)
            hookNativeMethod(className, methodName);
        }
    }
    catch (e) {
        console.log("\u4E3B\u51FD\u6570\u6267\u884C\u9519\u8BEF: ".concat(e));
    }
}
// 注册消息处理函数
try {
    recv('args', onMessage);
    console.log('[*] 已注册消息处理函数，等待参数...');
}
catch (e) {
    console.log("\u6CE8\u518C\u6D88\u606F\u5904\u7406\u51FD\u6570\u9519\u8BEF: ".concat(e));
}
// 程序启动时执行主函数
// 注意：当通过-l参数直接加载脚本时，将从命令行获取参数
// 当通过session.create_script加载时，将通过消息获取参数
try {
    if (Process.argv && Process.argv.length > 1) {
        console.log('[*] 发现命令行参数，直接启动');
        main();
    }
    else {
        console.log("[*] 等待参数...");
    }
}
catch (e) {
    console.log("\u521D\u59CB\u6267\u884C\u9519\u8BEF: ".concat(e));
}
