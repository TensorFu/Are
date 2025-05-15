#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# examples/cache_example.py
"""
缓存数据库使用示例
"""

import sys
import os
import json
from datetime import datetime

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入缓存模块
from are.core.cache import (
    CacheDatabase,
    cache_set,
    cache_get,
    cache_delete,
    cache_list,
    cache_clear
)


def print_separator():
    """打印分隔线"""
    print("\n" + "=" * 50 + "\n")


def timestamp_to_str(timestamp):
    """将时间戳转换为可读字符串"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def print_cache_item(item):
    """打印缓存项"""
    print(f"ID: {item['id']}")
    print(f"键: {item['key']}")
    print(f"值: {json.dumps(item['value'], ensure_ascii=False, indent=2)}")
    print(f"分类: {item['category']}")
    print(f"创建时间: {timestamp_to_str(item['created_at'])}")
    print(f"更新时间: {timestamp_to_str(item['updated_at'])}")


def main():
    """主函数"""
    print("缓存数据库示例")
    print_separator()

    # 使用简便函数
    print("1. 使用简便函数设置缓存")
    cache_set("user_info", {"name": "张三", "age": 30}, "user")
    cache_set("app_settings", {"theme": "dark", "language": "zh-CN"}, "settings")
    
    print("已设置缓存数据")
    print_separator()

    # 获取缓存
    print("2. 获取缓存数据")
    user_info = cache_get("user_info")
    print(f"用户信息: {user_info}")
    
    app_settings = cache_get("app_settings")
    print(f"应用设置: {app_settings}")
    
    # 获取不存在的缓存
    not_exist = cache_get("not_exist", "默认值")
    print(f"不存在的缓存: {not_exist}")
    print_separator()

    # 列出所有缓存
    print("3. 列出所有缓存")
    all_cache = cache_list()
    for item in all_cache:
        print_cache_item(item)
        print()
    print_separator()

    # 按分类列出缓存
    print("4. 按分类列出缓存")
    user_cache = cache_list("user")
    print("用户分类:")
    for item in user_cache:
        print_cache_item(item)
        print()
    print_separator()

    # 更新缓存
    print("5. 更新缓存")
    cache_set("user_info", {"name": "张三", "age": 31, "email": "zhangsan@example.com"}, "user")
    updated_user = cache_get("user_info")
    print(f"更新后的用户信息: {updated_user}")
    print_separator()

    # 使用 CacheDatabase 类
    print("6. 使用 CacheDatabase 类")
    with CacheDatabase("example.db") as db:
        db.create("test_key", "测试值", "test")
        test_value = db.get_value("test_key")
        print(f"测试值: {test_value}")
        
        # 设置元数据
        db.set_metadata("last_run", datetime.now().isoformat())
        last_run = db.get_metadata("last_run")
        print(f"上次运行时间: {last_run}")
    print_separator()

    # 删除缓存
    print("7. 删除缓存")
    cache_delete("app_settings")
    remaining = cache_list()
    print(f"剩余缓存数量: {len(remaining)}")
    print_separator()

    # 清除所有缓存
    print("8. 清除所有缓存")
    cleared = cache_clear()
    print(f"已清除 {cleared} 条缓存记录")
    
    # 验证清除结果
    remaining = cache_list()
    print(f"剩余缓存数量: {len(remaining)}")
    print_separator()


if __name__ == "__main__":
    main()
