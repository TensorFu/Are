/**
 * frida.d.ts
 * Frida API类型定义文件
 */

// Process命名空间
declare namespace Process {
  function arch(): string;
  function platform(): string;
  function id(): number;
  function pageSize(): number;
  function pointerSize(): number;
  function codeSigningPolicy(): string;
  function isDebuggerAttached(): boolean;
  function getCurrentThreadId(): number;
  function enumerateThreads(): ThreadDetails[];
  function enumerateModules(): Module[];
  function findModuleByAddress(address: NativePointer): Module | null;
  function findModuleByName(name: string): Module | null;
  function enumerateRanges(protection: string | string[], options?: EnumerateRangesOptions): AddressRange[];
  const mainModule: Module;
  function setExceptionHandler(callback: Function): void;
  function getCurrentDir(): string;
  function getHomeDir(): string;
  function getTmpDir(): string;
  const argv: string[];
  function wait(): Promise<any>;
  function waitFor(pid: number): Promise<any>;
  function exit(code?: number): void;
}

// Thread相关接口
interface ThreadDetails {
  id: number;
  state: string;
  context: CpuContext;
}

// Module接口
interface Module {
  name: string;
  base: NativePointer;
  size: number;
  path: string;
  enumerateImports(): ModuleImportDetails[];
  enumerateExports(): ModuleExportDetails[];
  enumerateSymbols(): ModuleSymbolDetails[];
  enumerateRanges(protection: string | string[]): AddressRange[];
  findExportByName(name: string): NativePointer | null;
}

// Module导入细节
interface ModuleImportDetails {
  type: string;
  name: string;
  module: string;
  address: NativePointer;
}

// Module导出细节
interface ModuleExportDetails {
  type: string;
  name: string;
  address: NativePointer;
}

// Module符号细节
interface ModuleSymbolDetails {
  type: string;
  name: string;
  address: NativePointer;
  size: number;
}

// 地址范围
interface AddressRange {
  base: NativePointer;
  size: number;
  protection: string;
}

// 枚举范围选项
interface EnumerateRangesOptions {
  coalesce?: boolean;
}

// CPU上下文
interface CpuContext {
  pc: NativePointer;
  sp: NativePointer;
}

// NativePointer类型
type NativePointer = any;

// Java命名空间
declare namespace Java {
  let available: boolean;
  function perform(fn: Function): void;
  function use(className: string): any;
  function choose(className: string, callbacks: object): void;
  function deoptimizeEverything(): void;
  function deoptimizeMethod(method: any): void;
}

// Interceptor命名空间
declare namespace Interceptor {
  function attach(target: NativePointer, callbacks: InterceptorCallbacks): RemoteResource;
  function detachAll(): void;
  function replace(target: NativePointer, replacementFunction: NativeCallback): RemoteResource;
  function revert(target: NativePointer): void;
}

// Interceptor回调
interface InterceptorCallbacks {
  onEnter?: (args: any) => void;
  onLeave?: (retval: any) => void;
}

// RemoteResource接口
interface RemoteResource {
  detach(): void;
}

// Thread命名空间
declare namespace Thread {
  function backtrace(context: CpuContext, backtracer?: Backtracer): NativePointer[];
  function getCurrentPid(): number;
  function getCurrentThreadId(): number;
}

// Backtracer枚举
declare enum Backtracer {
  ACCURATE = 'accurate',
  FUZZY = 'fuzzy',
  FRAME_POINTER = 'frame_pointer'
}

// DebugSymbol命名空间
declare namespace DebugSymbol {
  function fromAddress(address: NativePointer): DebugSymbolDetails;
  function fromName(name: string): DebugSymbolDetails[];
  function getFunctionByName(name: string): NativePointer;
  function findFunctionsMatching(pattern: string): NativePointer[];
  function findFunctionsNamed(name: string): NativePointer[];
}

// DebugSymbol详情
interface DebugSymbolDetails {
  address: NativePointer;
  name: string;
  moduleName: string;
  fileName: string;
  lineNumber: number;
  toString(): string;
}

// NativeCallback类型
type NativeCallback = any;

// ObjC命名空间
declare namespace ObjC {
  let available: boolean;
  function implement(method: NativePointer, returnType: any, argumentTypes: any[]): NativeCallback;
  function registerProxy(properties: any): ObjCProxy;
  function registerClass(spec: any): ObjCPrototype;
  const api: any;
  const classes: any;
  const protocols: any;
  const mainQueue: any;
  function schedule(queue: any, work: Function): void;
}

// ObjC代理
interface ObjCProxy {
  handle: NativePointer;
}

// ObjC原型
interface ObjCPrototype {
  handle: NativePointer;
}

// Memory命名空间
declare namespace Memory {
  function scan(address: NativePointer, size: number, pattern: string, callbacks: MemoryScanCallbacks): void;
  function scanSync(address: NativePointer, size: number, pattern: string): MemoryScanMatch[];
  function alloc(size: number): NativePointer;
  function copy(dst: NativePointer, src: NativePointer, size: number): void;
  function dup(mem: ArrayBuffer | NativePointer, size?: number): ArrayBuffer;
  function protect(address: NativePointer, size: number, protection: string): boolean;
}

// Memory扫描回调
interface MemoryScanCallbacks {
  onMatch: (address: NativePointer, size: number) => void;
  onComplete: () => void;
}

// Memory扫描匹配
interface MemoryScanMatch {
  address: NativePointer;
  size: number;
}

// 全局控制台对象
declare namespace console {
  function log(message?: any, ...optionalParams: any[]): void;
  function warn(message?: any, ...optionalParams: any[]): void;
  function error(message?: any, ...optionalParams: any[]): void;
  function info(message?: any, ...optionalParams: any[]): void;
  function debug(message?: any, ...optionalParams: any[]): void;
}

// JSON对象
declare namespace JSON {
  function stringify(value: any, replacer?: (key: string, value: any) => any | (number | string)[] | null, space?: string | number): string;
  function parse(text: string, reviver?: (key: string, value: any) => any): any;
}

// 全局函数
declare function rpc(name: string): Function;
declare function recv(type: string, callback: (message: any, data: any) => void): void;
declare function send(message: any, data?: ArrayBuffer | NativePointer): void;
declare function setImmediate(callback: () => void): void;
declare function setTimeout(callback: () => void, delay: number): number;
declare function clearTimeout(id: number): void;
declare function setInterval(callback: () => void, interval: number): number;
declare function clearInterval(id: number): void;
