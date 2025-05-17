#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/alternative_explore.py
"""
探索APK文件的替代工具，不依赖androguard库。
"""

import os
import sys
import subprocess
import zipfile
import xml.dom.minidom as minidom
import traceback
from pathlib import Path
from are.commands.base import CommandBase
from are.core import AreConsole

console = AreConsole()

class AlternativeExploreCommand(CommandBase):
    """APK探索命令 (替代版本)"""

    name = "explore"
    help_short = "分析APK文件并提取信息 (不使用androguard)"
    help_text = """
    分析指定的APK文件，提取包名并创建相应的分析环境。
    
    此命令将:
    1. 解析APK文件，提取包名
    2. 在ARE目录下创建以该包名命名的子文件夹
    3. 在该子文件夹中创建cache.db数据库文件以存储分析数据
    
    注意: 此版本不使用androguard库，功能有限。
    """
    usage = "explore <apk文件路径>"
    examples = [
        "explore /path/to/app.apk",
        "explore ~/Downloads/example.apk"
    ]

    def execute(self, context, args):
        """
        执行命令

        参数:
            context: 命令上下文（ARE实例）
            args: 命令参数
        """
        # 检查参数
        if not args:
            console.error("未提供APK文件路径")
            console.info(f"用法: {self.usage}")
            return

        # 获取APK文件路径并检查是否存在
        apk_path = args.strip()
        
        # 处理引号内的路径
        if apk_path.startswith('"') and apk_path.endswith('"'):
            apk_path = apk_path[1:-1]
        elif apk_path.startswith("'") and apk_path.endswith("'"):
            apk_path = apk_path[1:-1]
            
        apk_path = os.path.expanduser(apk_path)
        
        if not os.path.isfile(apk_path):
            console.error(f"找不到APK文件: {apk_path}")
            return

        try:
            # 验证这是一个有效的APK文件
            self._verify_apk(apk_path)
            
            # 尝试使用aapt工具提取包名
            package_name = self._extract_package_name_with_aapt(apk_path)
            
            if not package_name:
                # 如果aapt失败，尝试解析二进制AndroidManifest.xml
                console.info("尝试使用AXMLPrinter解析AndroidManifest.xml...")
                package_name = self._extract_package_name_with_axmlprinter(apk_path)
            
            if not package_name:
                # 如果仍然失败，使用文件名生成包名
                console.warning("无法提取包名，使用文件名代替")
                base_name = os.path.basename(apk_path)
                package_name = f"com.unknown.{os.path.splitext(base_name)[0].lower()}"
                
            console.success(f"提取的包名: {package_name}")
            
            # 创建ARE目录（如果不存在）
            current_dir = os.getcwd()
            are_dir = os.path.join(current_dir, "ARE")
            os.makedirs(are_dir, exist_ok=True)
            
            # 创建包名对应的子文件夹
            package_dir = os.path.join(are_dir, package_name)
            os.makedirs(package_dir, exist_ok=True)
            
            # 创建cache.db文件
            db_path = os.path.join(package_dir, "cache.db")
            self._create_simple_database(db_path, package_name, apk_path)
            
            # 提取和保存基本信息
            apk_info = self._extract_apk_info(apk_path)
            self._save_apk_info(db_path, apk_info)
            
            console.success(f"已创建分析环境: {package_dir}")
            console.success(f"数据库文件: {db_path}")
            
        except Exception as e:
            console.error(f"分析APK文件时出错: {str(e)}")
            console.debug(traceback.format_exc())

    def _verify_apk(self, apk_path):
        """验证APK文件有效性"""
        if not zipfile.is_zipfile(apk_path):
            raise ValueError(f"{apk_path} 不是有效的ZIP文件")
            
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            file_list = zip_ref.namelist()
            
            if 'AndroidManifest.xml' not in file_list:
                raise ValueError(f"{apk_path} 缺少AndroidManifest.xml")
                
            if not any(name.endswith('.dex') for name in file_list):
                raise ValueError(f"{apk_path} 缺少.dex文件")
                
        console.success(f"验证 {os.path.basename(apk_path)} 是有效的APK文件")

    def _extract_package_name_with_aapt(self, apk_path):
        """使用aapt工具提取包名"""
        console.info("尝试使用aapt工具提取包名...")
        
        try:
            aapt_cmd = ["aapt", "dump", "badging", apk_path]
            result = subprocess.run(aapt_cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('package:'):
                        # 解析行格式: package: name='com.example.app' ...
                        name_part = line.split('name=')[1].split("'")[1]
                        console.success(f"使用aapt提取包名成功: {name_part}")
                        return name_part
            else:
                console.warning(f"aapt命令失败: {result.stderr}")
                
        except FileNotFoundError:
            console.warning("找不到aapt工具")
        except Exception as e:
            console.warning(f"使用aapt提取包名时出错: {str(e)}")
            
        return None

    def _extract_package_name_with_axmlprinter(self, apk_path):
        """使用AXMLPrinter解析AndroidManifest.xml提取包名"""
        try:
            # 检查是否安装了pycryptodome和axmlprinter
            try:
                from androguard.core.bytecodes.axml import AXMLPrinter
                from androguard.core.bytecodes.apk import APK
                
                # 如果成功导入AXMLPrinter，直接使用APK类
                apk = APK(apk_path)
                package_name = apk.get_package()
                console.success(f"使用androguard提取包名成功: {package_name}")
                return package_name
                
            except ImportError:
                console.warning("找不到AXMLPrinter模块")
                
                # 尝试使用普通的zipfile和minidom
                with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                    try:
                        # 提取AndroidManifest.xml（这是二进制格式，可能无法直接解析）
                        manifest_data = zip_ref.read('AndroidManifest.xml')
                        
                        # 尝试将二进制转换为文本（可能会失败）
                        try:
                            manifest_text = manifest_data.decode('utf-8', errors='ignore')
                            if 'package=' in manifest_text:
                                # 简单尝试解析package属性
                                package_part = manifest_text.split('package=')[1]
                                package_name = package_part.split('"')[1]
                                console.success(f"从原始清单提取包名成功: {package_name}")
                                return package_name
                        except:
                            console.warning("无法解析二进制AndroidManifest.xml")
                            
                    except:
                        console.warning("无法提取AndroidManifest.xml")
                
        except Exception as e:
            console.warning(f"解析AndroidManifest.xml时出错: {str(e)}")
            
        return None
        
    def _extract_apk_info(self, apk_path):
        """提取APK基本信息"""
        info = {
            "file_name": os.path.basename(apk_path),
            "file_size": os.path.getsize(apk_path),
            "modified_time": int(os.path.getmtime(apk_path))
        }
        
        # 尝试使用aapt提取更多信息
        try:
            aapt_cmd = ["aapt", "dump", "badging", apk_path]
            result = subprocess.run(aapt_cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('package:'):
                        # 提取版本信息
                        if 'versionName=' in line:
                            info["version_name"] = line.split('versionName=')[1].split("'")[1]
                        if 'versionCode=' in line:
                            info["version_code"] = line.split('versionCode=')[1].split("'")[1]
                    elif line.startswith('sdkVersion:'):
                        info["min_sdk_version"] = line.split(':')[1].strip("'")
                    elif line.startswith('targetSdkVersion:'):
                        info["target_sdk_version"] = line.split(':')[1].strip("'")
                    elif line.startswith('application:'):
                        if 'label=' in line:
                            info["app_name"] = line.split('label=')[1].split("'")[1]
        except:
            pass
            
        return info
    
    def _create_simple_database(self, db_path, package_name, apk_path):
        """创建简单数据库"""
        try:
            import sqlite3
            
            # 创建数据库连接
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # 创建基本表结构
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL
            )
            ''')
            
            # 创建APK分析表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS apk_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                app_name TEXT,
                version_name TEXT,
                version_code TEXT,
                min_sdk_version TEXT,
                target_sdk_version TEXT,
                max_sdk_version TEXT,
                file_size INTEGER,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # 创建AndroidManifest分析表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS manifest_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT,
                parent TEXT,
                additional_info TEXT
            )
            ''')
            
            # 添加元数据
            cursor.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?)",
                ("package_name", package_name)
            )
            
            cursor.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?)",
                ("apk_path", apk_path)
            )
            
            cursor.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?)",
                ("analyzed_at", str(int(os.path.getmtime(apk_path))))
            )
            
            # 保存基本APK信息
            cursor.execute(
                "INSERT INTO apk_info (package_name, app_name) VALUES (?, ?)",
                (package_name, os.path.basename(apk_path))
            )
            
            # 提交事务
            conn.commit()
            conn.close()
            
            console.success("数据库初始化成功")
            
        except Exception as e:
            console.error(f"创建数据库时出错: {str(e)}")
            console.debug(traceback.format_exc())
            
    def _save_apk_info(self, db_path, apk_info):
        """保存APK信息到数据库"""
        try:
            import sqlite3
            
            # 创建数据库连接
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # 更新APK信息
            update_fields = []
            values = []
            
            for key, value in apk_info.items():
                if key not in ["file_name", "modified_time"]:  # 忽略这些字段
                    if key == "file_size":
                        update_fields.append(f"{key} = ?")
                        values.append(value)
                    elif key in ["version_name", "version_code", "min_sdk_version", "target_sdk_version", "app_name"]:
                        if value:  # 只更新非空值
                            update_fields.append(f"{key} = ?")
                            values.append(value)
            
            if update_fields and values:
                # 从现有记录中获取ID
                cursor.execute("SELECT id FROM apk_info LIMIT 1")
                row = cursor.fetchone()
                
                if row:
                    apk_id = row[0]
                    
                    # 更新记录
                    sql = f"UPDATE apk_info SET {', '.join(update_fields)} WHERE id = ?"
                    values.append(apk_id)
                    
                    cursor.execute(sql, values)
                    
                    # 提交事务
                    conn.commit()
                    console.success("APK信息更新成功")
            
            conn.close()
            
        except Exception as e:
            console.error(f"保存APK信息时出错: {str(e)}")
            console.debug(traceback.format_exc())
