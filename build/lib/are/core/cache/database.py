#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/cache/database.py
"""
数据库缓存模块，用于缓存命令行工具的数据。
提供创建、修改、查看和删除缓存数据的功能。
"""

import os
import sqlite3
import json
import time
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path


class CacheDatabase:
    """
    缓存数据库类，使用SQLite实现数据的持久化存储。
    支持创建、修改、查看和删除缓存数据。
    """

    def __init__(self, db_name: str = "are_cache.db"):
        """
        初始化缓存数据库

        参数:
            db_name: 数据库文件名，默认为 are_cache.db
        """
        # 确保缓存目录存在
        cache_dir = self._get_cache_dir()
        self.db_path = os.path.join(cache_dir, db_name)
        
        # 初始化数据库连接
        self.conn = None
        self.cursor = None
        
        # 连接数据库并创建表
        self._connect()
        self._create_tables()
    
    def _get_cache_dir(self) -> str:
        """
        获取缓存目录路径，如果不存在则创建

        返回:
            缓存目录路径
        """
        # 使用用户主目录下的 .are/cache 目录
        home_dir = os.path.expanduser("~")
        cache_dir = os.path.join(home_dir, ".are", "cache")
        
        # 确保目录存在
        os.makedirs(cache_dir, exist_ok=True)
        
        return cache_dir
    
    def _connect(self) -> None:
        """
        连接到SQLite数据库
        """
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row  # 使结果可以通过列名访问
            self.cursor = self.conn.cursor()
        except sqlite3.Error as e:
            raise Exception(f"数据库连接错误: {str(e)}")
    
    def _create_tables(self) -> None:
        """
        创建必要的数据库表
        """
        try:
            # 创建缓存数据表
            self.cursor.execute('''
            -- language=SQLite
            CREATE TABLE IF NOT EXISTS cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                category TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            ''')
            
            # 创建元数据表
            self.cursor.execute('''
            -- language=SQLite
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL
            )
            ''')
            
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise Exception(f"创建表错误: {str(e)}")
    
    def close(self) -> None:
        """
        关闭数据库连接
        """
        if self.conn:
            self.conn.close()
    
    def create(self, key: str, value: Any, category: Optional[str] = None) -> bool:
        """
        创建新的缓存数据

        参数:
            key: 缓存数据的键
            value: 缓存数据的值（将被转换为JSON字符串）
            category: 可选的分类标签

        返回:
            是否成功创建
        """
        try:
            # 将值转换为JSON字符串
            value_json = json.dumps(value, ensure_ascii=False)
            current_time = int(time.time())
            
            # 插入数据
            self.cursor.execute(
                "-- language=SQLite\nINSERT INTO cache (key, value, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (key, value_json, category, current_time, current_time)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # 键已存在
            self.conn.rollback()
            return False
        except Exception as e:
            self.conn.rollback()
            raise Exception(f"创建缓存数据错误: {str(e)}")
    
    def update(self, key: str, value: Any, category: Optional[str] = None) -> bool:
        """
        更新现有的缓存数据

        参数:
            key: 缓存数据的键
            value: 新的缓存数据值（将被转换为JSON字符串）
            category: 可选的新分类标签

        返回:
            是否成功更新
        """
        try:
            # 将值转换为JSON字符串
            value_json = json.dumps(value, ensure_ascii=False)
            current_time = int(time.time())
            
            # 更新数据
            if category is not None:
                self.cursor.execute(
                    "UPDATE cache SET value = ?, category = ?, updated_at = ? WHERE key = ?",
                    (value_json, category, current_time, key)
                )
            else:
                self.cursor.execute(
                    "UPDATE cache SET value = ?, updated_at = ? WHERE key = ?",
                    (value_json, current_time, key)
                )
            
            if self.cursor.rowcount > 0:
                self.conn.commit()
                return True
            else:
                self.conn.rollback()
                return False
        except Exception as e:
            self.conn.rollback()
            raise Exception(f"更新缓存数据错误: {str(e)}")
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        获取缓存数据

        参数:
            key: 缓存数据的键

        返回:
            包含缓存数据的字典，如果不存在则返回None
        """
        try:
            self.cursor.execute(
                "SELECT * FROM cache WHERE key = ?",
                (key,)
            )
            row = self.cursor.fetchone()
            
            if row:
                return {
                    "id": row["id"],
                    "key": row["key"],
                    "value": json.loads(row["value"]),
                    "category": row["category"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None
        except Exception as e:
            raise Exception(f"获取缓存数据错误: {str(e)}")
    
    def get_value(self, key: str, default: Any = None) -> Any:
        """
        获取缓存数据的值

        参数:
            key: 缓存数据的键
            default: 如果键不存在，返回的默认值

        返回:
            缓存数据的值，如果不存在则返回默认值
        """
        result = self.get(key)
        if result:
            return result["value"]
        return default
    
    def delete(self, key: str) -> bool:
        """
        删除缓存数据

        参数:
            key: 缓存数据的键

        返回:
            是否成功删除
        """
        try:
            self.cursor.execute(
                "DELETE FROM cache WHERE key = ?",
                (key,)
            )
            
            if self.cursor.rowcount > 0:
                self.conn.commit()
                return True
            else:
                self.conn.rollback()
                return False
        except Exception as e:
            self.conn.rollback()
            raise Exception(f"删除缓存数据错误: {str(e)}")
    
    def list(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        列出所有缓存数据

        参数:
            category: 可选的分类过滤

        返回:
            包含缓存数据的字典列表
        """
        try:
            if category:
                self.cursor.execute(
                    "SELECT * FROM cache WHERE category = ? ORDER BY updated_at DESC",
                    (category,)
                )
            else:
                self.cursor.execute("SELECT * FROM cache ORDER BY updated_at DESC")
            
            rows = self.cursor.fetchall()
            result = []
            
            for row in rows:
                result.append({
                    "id": row["id"],
                    "key": row["key"],
                    "value": json.loads(row["value"]),
                    "category": row["category"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                })
            
            return result
        except Exception as e:
            raise Exception(f"列出缓存数据错误: {str(e)}")
    
    def clear(self, category: Optional[str] = None) -> int:
        """
        清除缓存数据

        参数:
            category: 可选的分类过滤，如果为None则清除所有数据

        返回:
            清除的记录数
        """
        try:
            if category:
                self.cursor.execute(
                    "DELETE FROM cache WHERE category = ?",
                    (category,)
                )
            else:
                self.cursor.execute("DELETE FROM cache")
            
            deleted_count = self.cursor.rowcount
            self.conn.commit()
            return deleted_count
        except Exception as e:
            self.conn.rollback()
            raise Exception(f"清除缓存数据错误: {str(e)}")
    
    def set_metadata(self, key: str, value: Any) -> bool:
        """
        设置元数据

        参数:
            key: 元数据的键
            value: 元数据的值（将被转换为JSON字符串）

        返回:
            是否成功设置
        """
        try:
            # 将值转换为JSON字符串
            value_json = json.dumps(value, ensure_ascii=False)
            
            # 尝试更新，如果不存在则插入
            self.cursor.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (key, value_json)
            )
            self.conn.commit()
            return True
        except Exception as e:
            self.conn.rollback()
            raise Exception(f"设置元数据错误: {str(e)}")
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        获取元数据

        参数:
            key: 元数据的键
            default: 如果键不存在，返回的默认值

        返回:
            元数据的值，如果不存在则返回默认值
        """
        try:
            self.cursor.execute(
                "SELECT value FROM metadata WHERE key = ?",
                (key,)
            )
            row = self.cursor.fetchone()
            
            if row:
                return json.loads(row["value"])
            return default
        except Exception as e:
            raise Exception(f"获取元数据错误: {str(e)}")
    
    def create_or_update(self, key: str, value: Any, category: Optional[str] = None) -> bool:
        """
        创建或更新缓存数据

        参数:
            key: 缓存数据的键
            value: 缓存数据的值（将被转换为JSON字符串）
            category: 可选的分类标签

        返回:
            是否成功操作
        """
        if self.get(key):
            return self.update(key, value, category)
        else:
            return self.create(key, value, category)
    
    def __enter__(self):
        """
        支持上下文管理器
        """
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        退出上下文管理器时关闭连接
        """
        self.close()


# 提供一个简单的单例实例，方便直接使用
_default_instance = None

def get_cache_db() -> CacheDatabase:
    """
    获取默认的缓存数据库实例

    返回:
        CacheDatabase实例
    """
    global _default_instance
    if _default_instance is None:
        _default_instance = CacheDatabase()
    return _default_instance


# 简便函数，直接使用默认实例
def cache_set(key: str, value: Any, category: Optional[str] = None) -> bool:
    """
    设置缓存数据

    参数:
        key: 缓存数据的键
        value: 缓存数据的值
        category: 可选的分类标签

    返回:
        是否成功
    """
    db = get_cache_db()
    return db.create_or_update(key, value, category)


def cache_get(key: str, default: Any = None) -> Any:
    """
    获取缓存数据

    参数:
        key: 缓存数据的键
        default: 如果键不存在，返回的默认值

    返回:
        缓存数据的值
    """
    db = get_cache_db()
    return db.get_value(key, default)


def cache_delete(key: str) -> bool:
    """
    删除缓存数据

    参数:
        key: 缓存数据的键

    返回:
        是否成功
    """
    db = get_cache_db()
    return db.delete(key)


def cache_list(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    列出缓存数据

    参数:
        category: 可选的分类过滤

    返回:
        缓存数据列表
    """
    db = get_cache_db()
    return db.list(category)


def cache_clear(category: Optional[str] = None) -> int:
    """
    清除缓存数据

    参数:
        category: 可选的分类过滤

    返回:
        清除的记录数
    """
    db = get_cache_db()
    return db.clear(category)
