/**
 * ARE - 基础脚本
 *
 * 提供基础的进程监控和与主程序通信的功能
 */

import { log, warn, error } from './modules/logger';

/**
 * 向主程序发送消息
 */
function sendMessage(type: string, message: any) {
    send({
        type: type,
        ...message
    });
}

/**
 * 初始化脚本
 */
function initialize() {
    log('Script loaded and initialized');

    // 发送状态消息
    sendMessage('status', {
        message: 'Script ready'
    });

    // 设置未捕获异常处理
    Process.setExceptionHandler((exception) => {
        sendMessage('error', {
            message: `Exception: ${exception.message}`,
            stack: exception.stackData ? hexdump(exception.stackData) : '(no stack data)'
        });
        return true;
    });
}

/**
 * 内存操作
 */
export namespace Memory {
    /**
     * 查找内存中的模式
     */
    export function findPattern(pattern: string): ArrayBuffer[] {
        try {
            const ranges = Process.enumerateRangesSync({
                protection: 'r--',
                coalesce: true
            });

            const results: ArrayBuffer[] = [];

            for (const range of ranges) {
                const matches = Memory.scanSync(range.base, range.size, pattern);

                for (const match of matches) {
                    results.push(match.address.readByteArray(16) as ArrayBuffer);
                }
            }

            return results;
        } catch (e) {
            error(`Error finding pattern: ${e}`);
            return [];
        }
    }

    /**
     * 读取特定地址的内存
     */
    export function readMemory(address: string | number, size: number): ArrayBuffer | null {
        try {
            const ptr = typeof address === 'string'
                ? ptr(address)
                : new NativePointer(address.toString());

            return ptr.readByteArray(size) as ArrayBuffer;
        } catch (e) {
            error(`Error reading memory: ${e}`);
            return null;
        }
    }

    /**
     * 写入特定地址的内存
     */
    export function writeMemory(address: string | number, data: ArrayBuffer | number[]): boolean {
        try {
            const ptr = typeof address === 'string'
                ? ptr(address)
                : new NativePointer(address.toString());

            if (data instanceof ArrayBuffer) {
                ptr.writeByteArray(data);
            } else {
                for (let i = 0; i < data.length; i++) {
                    ptr.add(i).writeU8(data[i]);
                }
            }

            return true;
        } catch (e) {
            error(`Error writing memory: ${e}`);
            return false;
        }
    }
}

/**
 * 堆栈回溯
 */
export namespace Backtracer {
    /**
     * 获取当前线程的堆栈回溯
     */
    export function getCurrentThreadBacktrace(context?: any): Backtrace | null {
        try {
            return Thread.backtrace(context, Backtracer.ACCURATE);
        } catch (e) {
            error(`Error getting backtrace: ${e}`);
            return null;
        }
    }

    /**
     * 格式化堆栈回溯
     */
    export function formatBacktrace(backtrace: Backtrace): string {
        try {
            return backtrace.map((frame, index) => {
                const symbol = DebugSymbol.fromAddress(frame);
                return `#${index} ${frame} ${symbol.name || ''} (${symbol.moduleName || '??'})`;
            }).join('\n');
        } catch (e) {
            error(`Error formatting backtrace: ${e}`);
            return '';
        }
    }
}

/**
 * 类和方法操作
 */
export namespace Java {
    /**
     * 列出所有已加载的类
     */
    export function listClasses(pattern?: string): string[] {
        try {
            // 确保Java可用
            if (!Java.available) {
                throw new Error('Java not available');
            }

            // 列出类
            const classes = Java.enumerateLoadedClassesSync();

            // 过滤类
            if (pattern) {
                const regex = new RegExp(pattern);
                return classes.filter(name => regex.test(name));
            }

            return classes;
        } catch (e) {
            error(`Error listing classes: ${e}`);
            return [];
        }
    }

    /**
     * 查找类的方法
     */
    export function listMethods(className: string): string[] {
        try {
            // 确保Java可用
            if (!Java.available) {
                throw new Error('Java not available');
            }

            // 获取类
            const javaClass = Java.use(className);

            // 获取方法
            const methods = javaClass.class.getDeclaredMethods();

            // 转换为字符串数组
            return methods.map((method: any) => method.toString());
        } catch (e) {
            error(`Error listing methods: ${e}`);
            return [];
        }
    }

    /**
     * 钩住方法
     */
    export function hookMethod(className: string, methodName: string, callback: Function): boolean {
        try {
            // 确保Java可用
            if (!Java.available) {
                throw new Error('Java not available');
            }

            // 获取类
            const javaClass = Java.use(className);

            // 查找重载方法
            const overloads = javaClass[methodName].overloads;

            // 钩住所有重载
            for (const overload of overloads) {
                overload.implementation = function(...args: any[]) {
                    const result = callback(this, args, () => overload.call(this, ...args));
                    return result !== undefined ? result : overload.call(this, ...args);
                };
            }

            return true;
        } catch (e) {
            error(`Error hooking method: ${e}`);
            return false;
        }
    }
}

/**
 * 主入口点
 */
rpc.exports = {
    init: function() {
        initialize();
        return true;
    },

    findPattern: function(pattern: string) {
        return Memory.findPattern(pattern);
    },

    listClasses: function(pattern?: string) {
        return Java.listClasses(pattern);
    },

    listMethods: function(className: string) {
        return Java.listMethods(className);
    },

    hookMethod: function(className: string, methodName: string, callbackScript: string) {
        const callback = new Function('target', 'args', 'original', callbackScript);
        return Java.hookMethod(className, methodName, callback);
    }
};

// 初始化脚本
initialize();