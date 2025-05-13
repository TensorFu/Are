# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

import sys

def show_intro():
    print("欢迎来到这个项目！")
    print("这是一个示例 Python 脚本，用于演示命令行交互。")
    print("用法：")
    print("  are hello    显示项目介绍")
    print("  are <name>   打招呼，例如：are Tensor")

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press ⌘F8 to toggle the breakpoint.

if __name__ == '__main__':
    # 解析命令行参数
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'hello':
            show_intro()
        else:
            # 默认行为：打招呼
            print(f'Hi, {cmd}')
    else:
        print("请提供参数，例如：are hello 或 are <name>")
