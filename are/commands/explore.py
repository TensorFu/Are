#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/explore.py
"""
探索APK文件的工具，提取包名并创建相应的缓存数据库。
"""

import os
import sys
import subprocess
import importlib
import traceback
import pkgutil
from pathlib import Path
from are.commands.base import CommandBase
from are.core import AreConsole

# 初始化控制台
console = AreConsole()

class ExploreCommand(CommandBase):
    """APK探索命令"""

    name = "explore"
    help_short = "分析APK文件并提取信息"
    help_text = """
    分析指定的APK文件，提取包名并创建相应的分析环境。
    
    此命令将:
    1. 解析APK文件，提取包名
    2. 在ARE目录下创建以该包名命名的子文件夹
    3. 在该子文件夹中创建cache.db数据库文件以存储分析数据
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

        # 确保安装了 androguard 并可以正确导入
        if not self._ensure_androguard_available():
            return

        try:
            # 导入 androguard 模块（这应该已经在前面的函数中确认成功）
            from androguard.core.bytecodes.apk import APK
            
            # 分析APK文件
            console.info(f"正在分析APK文件: {apk_path}")
            apk = APK(apk_path)
            package_name = apk.get_package()
            
            if not package_name:
                console.error("无法提取包名")
                return
                
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
            self._create_database(db_path, apk, apk_path)
            
            # 解析AndroidManifest.xml
            console.info("正在解析AndroidManifest.xml...")
            try:
                # 尝试动态导入并使用 manifest_parser
                try:
                    from are.core.apk_analysis.manifest_parser import AndroidManifestParser
                    parser = AndroidManifestParser(apk_path)
                    parser.save_to_database(db_path)
                    console.success("AndroidManifest.xml解析完成")
                except ImportError as e:
                    # 如果无法导入 manifest_parser，尝试使用替代方法
                    console.warning(f"无法导入AndroidManifestParser模块: {str(e)}")
                    console.info("尝试使用替代方法分析...")
                    
                    # 提取基本信息
                    try:
                        # 使用 aapt 工具提取信息
                        aapt_cmd = ["aapt", "dump", "badging", apk_path]
                        result = subprocess.run(aapt_cmd, capture_output=True, text=True, check=False)
                        
                        if result.returncode == 0:
                            # 提取权限信息
                            permissions = []
                            for line in result.stdout.split('\n'):
                                if line.startswith('uses-permission:'):
                                    perm = line.split(':')[1].strip().strip("'")
                                    permissions.append({"name": perm, "type": "uses-permission"})
                            
                            # 保存到数据库
                            if permissions:
                                for perm in permissions:
                                    db.cursor.execute(
                                        "INSERT INTO manifest_info (type, name, value) VALUES (?, ?, ?)",
                                        ("permission", perm["name"], "true")
                                    )
                                db.conn.commit()
                                console.success(f"保存了 {len(permissions)} 个权限信息")
                    except Exception as ex:
                        console.warning(f"使用替代方法分析时出错: {str(ex)}")
            except Exception as e:
                console.error(f"解析AndroidManifest.xml时出错: {str(e)}")
                console.debug(traceback.format_exc())
            
            console.success(f"已创建分析环境: {package_dir}")
            console.success(f"数据库文件: {db_path}")
            
        except Exception as e:
            console.error(f"分析APK文件时出错: {str(e)}")
            console.debug(traceback.format_exc())

    def _ensure_androguard_available(self):
        """
        确保androguard库可用
        
        返回:
            是否成功导入
        """
        try:
            # 尝试导入androguard
            import androguard
            console.debug(f"导入的androguard版本: {getattr(androguard, '__version__', '未知')}")
            
            # 检查核心模块是否可用
            try:
                import androguard.core
                import androguard.core.bytecodes
                from androguard.core.bytecodes.apk import APK
                console.success("成功导入androguard及其所有必要组件")
                return True
            except ImportError as e:
                console.error(f"无法导入androguard的核心组件: {str(e)}")
                console.debug(traceback.format_exc())
                
                # 输出诊断信息
                console.info("正在收集诊断信息...")
                
                # 检查androguard包的结构
                console.debug("androguard包结构:")
                try:
                    package_path = os.path.dirname(androguard.__file__)
                    console.debug(f"androguard包路径: {package_path}")
                    
                    # 检查子目录
                    core_path = os.path.join(package_path, "core")
                    if os.path.exists(core_path):
                        console.debug(f"core目录存在: {core_path}")
                        
                        bytecodes_path = os.path.join(core_path, "bytecodes")
                        if os.path.exists(bytecodes_path):
                            console.debug(f"bytecodes目录存在: {bytecodes_path}")
                            
                            apk_path = os.path.join(bytecodes_path, "apk.py")
                            if os.path.exists(apk_path):
                                console.debug(f"apk.py文件存在: {apk_path}")
                            else:
                                console.debug("apk.py文件不存在")
                        else:
                            console.debug("bytecodes目录不存在")
                    else:
                        console.debug("core目录不存在")
                except Exception as e:
                    console.debug(f"检查包结构时出错: {str(e)}")
                
                # 尝试修复
                console.info("尝试重新安装androguard...")
                
                try:
                    # 尝试卸载并重新安装
                    console.debug("正在卸载旧版本...")
                    subprocess.run(
                        [sys.executable, "-m", "pip", "uninstall", "-y", "androguard"],
                        capture_output=True,
                        check=False
                    )
                    
                    console.debug("正在安装新版本...")
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "--upgrade", "androguard"],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    if result.returncode != 0:
                        console.error(f"安装失败: {result.stderr}")
                        return False
                    
                    # 重新加载模块
                    console.debug("正在重新加载模块...")
                    importlib.invalidate_caches()
                    
                    # 清除旧模块
                    for key in list(sys.modules.keys()):
                        if key.startswith('androguard'):
                            del sys.modules[key]
                    
                    # 再次尝试导入
                    import androguard
                    import androguard.core
                    import androguard.core.bytecodes
                    from androguard.core.bytecodes.apk import APK
                    
                    console.success("成功修复androguard安装和导入")
                    return True
                except Exception as e:
                    console.error(f"重新安装androguard失败: {str(e)}")
                    console.debug(traceback.format_exc())
                    
                    # 让用户查看诊断信息和尝试手动修复
                    console.info("请运行 python diagnose_androguard.py 查看更详细的诊断信息")
                    console.info("或尝试在命令行中手动安装:")
                    console.info(f"{sys.executable} -m pip install --upgrade androguard")
                    console.info("安装后，可能需要重启应用")
                    
                    return False
        except ImportError:
            console.error("找不到androguard库")
            console.info("正在尝试安装androguard...")
            
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "androguard"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                console.success("安装androguard成功")
                
                # 重新加载模块
                importlib.invalidate_caches()
                
                # 再次尝试导入
                import androguard
                import androguard.core
                import androguard.core.bytecodes
                from androguard.core.bytecodes.apk import APK
                
                console.success("导入androguard成功")
                return True
            except Exception as e:
                console.error(f"安装androguard失败: {str(e)}")
                console.debug(traceback.format_exc())
                
                console.info("请在命令行中手动安装:")
                console.info(f"{sys.executable} -m pip install --upgrade androguard")
                
                return False
    
    def _create_database(self, db_path, apk, apk_path):
        """
        创建并初始化SQLite数据库
        
        参数:
            db_path: 数据库文件路径
            apk: APK对象
            apk_path: APK文件路径
        """
        try:
            from are.core.cache.database import CacheDatabase
            
            # 创建数据库
            db = CacheDatabase(os.path.basename(db_path))
            db.db_path = db_path  # 直接设置数据库路径
            
            # 重新连接到指定的数据库文件
            db._connect()
            
            # 创建基本表结构
            db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL
            )
            ''')
            
            # 创建APK分析表
            db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS apk_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                app_name TEXT,
                version_name TEXT,
                version_code TEXT,
                min_sdk_version TEXT,
                target_sdk_version TEXT,
                max_sdk_version TEXT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # 创建AndroidManifest分析表
            db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS manifest_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT,
                parent TEXT,
                additional_info TEXT
            )
            ''')
            
            # 保存APK基本信息到数据库
            db.cursor.execute(
                "INSERT INTO apk_info (package_name, app_name, version_name, version_code, min_sdk_version, target_sdk_version, max_sdk_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    apk.get_package(),
                    apk.get_app_name(),
                    apk.get_androidversion_name(),
                    apk.get_androidversion_code(),
                    apk.get_min_sdk_version(),
                    apk.get_target_sdk_version(),
                    apk.get_max_sdk_version()
                )
            )
            
            # 保存元数据
            db.set_metadata("apk_path", apk_path)
            db.set_metadata("analyzed_at", int(os.path.getmtime(apk_path)))
            db.set_metadata("package_name", apk.get_package())
            
            # 提交事务
            db.conn.commit()
            db.close()
            
            console.success("数据库初始化成功")
            
        except Exception as e:
            console.error(f"创建数据库时出错: {str(e)}")
            console.debug(traceback.format_exc())
