/**
 * ARE - 日志模块
 *
 * 提供日志记录功能
 */

/**
 * 发送日志消息
 */
export function log(message: string) {
    send({
        type: 'log',
        level: 'info',
        message: message
    });

    // 同时输出到控制台
    console.log(message);
}

/**
 * 发送调试消息
 */
export function debug(message: string) {
    send({
        type: 'log',
        level: 'debug',
        message: message
    });

    // 同时输出到控制台
    console.debug(message);
}

/**
 * 发送警告消息
 */
export function warn(message: string) {
    send({
        type: 'log',
        level: 'warning',
        message: message
    });

    // 同时输出到控制台
    console.warn(message);
}

/**
 * 发送错误消息
 */
export function error(message: string) {
    send({
        type: 'log',
        level: 'error',
        message: message
    });

    // 同时输出到控制台
    console.error(message);
}