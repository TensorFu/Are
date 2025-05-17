#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/androguard/manifest_parser.py
"""
AndroidManifest.xml 解析工具，提取并分类各种清单信息。
"""

import os
import sys
import json
import logging
import importlib
import site
import subprocess
from typing import Dict, List, Any, Optional, Union

from are.core.cache.database import CacheDatabase

# 尝试禁用androguard日志
logging.getLogger("androguard").setLevel(logging.ERROR)

# 全局APK定义
APK = None


class AndroidManifestParser:
    """AndroidManifest.xml 解析器"""

    def __init__(self, apk_path: str):
        """
        初始化解析器
        
        参数:
            apk_path: APK文件路径
        """
        self.apk_path = apk_path
        self.apk = None
        
        # 初始化连接
        self._load_apk()
    
    def _load_apk(self):
        """加载APK文件"""
        # 使用全局变量
        global APK
        try:
            # 检查androguard是否已安装
            try:
                from androguard.core.bytecodes.apk import APK
            except ImportError:
                # 尝试自动安装androguard
                import subprocess
                import sys
                import importlib
                
                # 尝试安装androguard
                pip_cmd = [sys.executable, "-m", "pip", "install", "androguard"]
                print(f"找不到androguard库，尝试自动安装: {' '.join(pip_cmd)}")
                
                try:
                    result = subprocess.run(pip_cmd, check=True, capture_output=True, text=True)
                    print("androguard库安装成功！")
                    
                    # 重新加载 sys.modules，确保Python能看到新安装的包
                    importlib.invalidate_caches()
                    
                    # 强制重新加载 sys.path
                    import site
                    importlib.reload(site)
                    
                    # 强制重新加载模块
                    sys_path_added = False
                    
                    # 查找并添加androguard安装路径
                    try:
                        result = subprocess.run(
                            [sys.executable, "-m", "pip", "show", "androguard"],
                            capture_output=True, text=True, check=True
                        )
                        location_line = next((line for line in result.stdout.split("\n") 
                                            if line.startswith("Location:")), None)
                        
                        if location_line:
                            location = location_line.split(": ")[1].strip()
                            print(f"发现androguard位置: {location}")
                            
                            if location not in sys.path:
                                sys.path.insert(0, location)
                                sys_path_added = True
                                print(f"已添加 {location} 到Python路径")
                    except Exception as e:
                        print(f"查找androguard位置时出错: {str(e)}")
                    
                    # 尝试清理sys.modules中的androguard缓存
                    for key in list(sys.modules.keys()):
                        if key.startswith('androguard'):
                            del sys.modules[key]
                            print(f"已从sys.modules中删除 {key}")
                    
                    # 再次尝试导入
                    try:
                        from androguard.core.bytecodes.apk import APK
                    except ImportError:
                        print("安装androguard后导入仍然失败，可能是系统环境问题")
                        
                        # 尝试一种替代方法 - 使用pip安装到临时目录
                        import os
                        temp_dir = os.path.join(os.getcwd(), "ARE", "temp_packages")
                        os.makedirs(temp_dir, exist_ok=True)
                        
                        print(f"尝试安装到临时目录: {temp_dir}")
                        try:
                            alt_pip_cmd = [
                                sys.executable, "-m", "pip", "install", 
                                "--target", temp_dir, "androguard"
                            ]
                            subprocess.run(alt_pip_cmd, check=True, capture_output=True, text=True)
                            
                            # 将临时目录添加到路径
                            if temp_dir not in sys.path:
                                sys.path.insert(0, temp_dir)
                                print(f"已添加临时目录 {temp_dir} 到Python路径")
                            
                            # 最后一次尝试导入
                            try:
                                from androguard.core.bytecodes.apk import APK
                                print("成功从临时目录导入androguard!")
                            except ImportError:
                                print("从临时目录导入仍然失败")
                                print("请尝试手动安装并确保正确安装在当前Python环境中:")
                                print(f"{sys.executable} -m pip install androguard")
                                raise ImportError("找不到androguard库，请先安装: pip install androguard")
                        except Exception as e:
                            print(f"安装到临时目录失败: {str(e)}")
                            print("请尝试手动安装并确保正确安装在当前Python环境中:")
                            print(f"{sys.executable} -m pip install androguard")
                            raise ImportError("找不到androguard库，请先安装: pip install androguard")
                except subprocess.CalledProcessError as e:
                    print(f"安装androguard失败: {e.stderr}")
                    print("请手动安装:")
                    print(f"{sys.executable} -m pip install androguard")
                    raise ImportError("找不到androguard库，请先安装: pip install androguard")
            
            # 加载APK
            self.apk = APK(self.apk_path)
        except ImportError as e:
            # APK已在方法顶部定义
            raise e
        except Exception as e:
            raise Exception(f"加载APK文件时出错: {str(e)}")
    
    def get_package_name(self) -> str:
        """
        获取包名
        
        返回:
            包名
        """
        if not self.apk:
            raise Exception("APK未加载")
        
        return self.apk.get_package()
    
    def parse_manifest(self) -> Dict[str, Any]:
        """
        解析AndroidManifest.xml
        
        返回:
            包含清单信息的字典
        """
        if not self.apk:
            raise Exception("APK未加载")
        
        manifest_info = {
            "package_info": self._get_package_info(),
            "permissions": self._get_permissions(),
            "activities": self._get_activities(),
            "services": self._get_services(),
            "receivers": self._get_receivers(),
            "providers": self._get_providers(),
            "intent_filters": self._get_intent_filters(),
            "features": self._get_features(),
            "metadata": self._get_metadata()
        }
        
        return manifest_info
    
    def save_to_database(self, db_path: str) -> bool:
        """
        将解析结果保存到数据库
        
        参数:
            db_path: 数据库文件路径
            
        返回:
            是否成功
        """
        try:
            # 解析清单
            manifest_info = self.parse_manifest()
            
            # 连接到数据库
            db = CacheDatabase(os.path.basename(db_path))
            db.db_path = db_path  # 直接设置数据库路径
            
            # 重新连接到指定的数据库文件
            db._connect()
            
            # 创建清单信息表
            db.cursor.execute('''
            -- language=SQLite
            CREATE TABLE IF NOT EXISTS manifest_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT,
                parent TEXT,
                additional_info TEXT
            )
            ''')
            
            # 清空表
            db.cursor.execute("DELETE FROM manifest_info")
            
            # 保存包信息
            for key, value in manifest_info["package_info"].items():
                db.cursor.execute(
                    "INSERT INTO manifest_info (type, name, value) VALUES (?, ?, ?)",
                    ("package_info", key, str(value))
                )
            
            # 保存权限信息
            for perm in manifest_info["permissions"]:
                db.cursor.execute(
                    "INSERT INTO manifest_info (type, name, value) VALUES (?, ?, ?)",
                    ("permission", perm["name"], json.dumps(perm))
                )
            
            # 保存活动信息
            for activity in manifest_info["activities"]:
                name = activity.pop("name")
                db.cursor.execute(
                    "INSERT INTO manifest_info (type, name, value, additional_info) VALUES (?, ?, ?, ?)",
                    ("activity", name, activity.get("exported", "false"), json.dumps(activity))
                )
            
            # 保存服务信息
            for service in manifest_info["services"]:
                name = service.pop("name")
                db.cursor.execute(
                    "INSERT INTO manifest_info (type, name, value, additional_info) VALUES (?, ?, ?, ?)",
                    ("service", name, service.get("exported", "false"), json.dumps(service))
                )
            
            # 保存广播接收器信息
            for receiver in manifest_info["receivers"]:
                name = receiver.pop("name")
                db.cursor.execute(
                    "INSERT INTO manifest_info (type, name, value, additional_info) VALUES (?, ?, ?, ?)",
                    ("receiver", name, receiver.get("exported", "false"), json.dumps(receiver))
                )
            
            # 保存内容提供者信息
            for provider in manifest_info["providers"]:
                name = provider.pop("name")
                db.cursor.execute(
                    "INSERT INTO manifest_info (type, name, value, additional_info) VALUES (?, ?, ?, ?)",
                    ("provider", name, provider.get("exported", "false"), json.dumps(provider))
                )
            
            # 保存Intent过滤器信息
            for intent_filter in manifest_info["intent_filters"]:
                component = intent_filter.pop("component_name")
                filter_type = intent_filter.pop("component_type")
                db.cursor.execute(
                    "INSERT INTO manifest_info (type, name, value, parent, additional_info) VALUES (?, ?, ?, ?, ?)",
                    ("intent_filter", filter_type, json.dumps(intent_filter.get("actions", [])), 
                     component, json.dumps(intent_filter))
                )
            
            # 保存特性信息
            for feature in manifest_info["features"]:
                db.cursor.execute(
                    "INSERT INTO manifest_info (type, name, value) VALUES (?, ?, ?)",
                    ("feature", feature["name"], feature.get("required", "false"))
                )
            
            # 保存元数据信息
            for metadata in manifest_info["metadata"]:
                db.cursor.execute(
                    "INSERT INTO manifest_info (type, name, value, parent) VALUES (?, ?, ?, ?)",
                    ("metadata", metadata["name"], metadata.get("value", ""), 
                     metadata.get("parent", ""))
                )
            
            # 保存包名到元数据表
            db.set_metadata("package_name", self.get_package_name())
            db.set_metadata("apk_path", self.apk_path)
            db.set_metadata("manifest_parsed_at", int(os.path.getmtime(self.apk_path)))
            
            # 提交事务
            db.conn.commit()
            db.close()
            
            return True
        except Exception as e:
            import traceback
            print(f"保存数据库时出错: {str(e)}")
            print(traceback.format_exc())
            return False
    
    def _get_package_info(self) -> Dict[str, str]:
        """
        获取APK包信息
        
        返回:
            包信息字典
        """
        return {
            "package_name": self.apk.get_package(),
            "version_name": self.apk.get_androidversion_name(),
            "version_code": self.apk.get_androidversion_code(),
            "min_sdk_version": self.apk.get_min_sdk_version(),
            "target_sdk_version": self.apk.get_target_sdk_version(),
            "max_sdk_version": self.apk.get_max_sdk_version(),
            "application_name": self.apk.get_app_name(),
            "main_activity": self.apk.get_main_activity()
        }
    
    def _get_permissions(self) -> List[Dict[str, str]]:
        """
        获取APK权限信息
        
        返回:
            权限信息列表
        """
        permissions = []
        
        # 获取使用的权限
        for perm in self.apk.get_permissions():
            permissions.append({
                "name": perm,
                "type": "uses-permission"
            })
        
        # 获取定义的权限
        for perm, details in self.apk.get_declared_permissions().items():
            protection_level = details.get("protectionLevel", "normal")
            permissions.append({
                "name": perm,
                "type": "permission",
                "protection_level": protection_level,
                "description": details.get("description", "")
            })
        
        return permissions
    
    def _get_activities(self) -> List[Dict[str, Any]]:
        """
        获取活动信息
        
        返回:
            活动信息列表
        """
        activities = []
        
        # 获取所有活动
        for activity in self.apk.get_activities():
            exported = self.apk.get_activity_exported(activity) or False
            main = activity == self.apk.get_main_activity()
            
            activities.append({
                "name": activity,
                "exported": str(exported).lower(),
                "main": str(main).lower(),
                "permission": self.apk.get_element("activity", "permission", activity) or "",
                "launch_mode": self.apk.get_element("activity", "launchMode", activity) or "standard",
                "orientation": self.apk.get_element("activity", "screenOrientation", activity) or "unspecified",
                "theme": self.apk.get_element("activity", "theme", activity) or ""
            })
        
        return activities
    
    def _get_services(self) -> List[Dict[str, Any]]:
        """
        获取服务信息
        
        返回:
            服务信息列表
        """
        services = []
        
        # 获取所有服务
        for service in self.apk.get_services():
            exported = self.apk.get_service_exported(service) or False
            
            services.append({
                "name": service,
                "exported": str(exported).lower(),
                "permission": self.apk.get_element("service", "permission", service) or "",
                "process": self.apk.get_element("service", "process", service) or ""
            })
        
        return services
    
    def _get_receivers(self) -> List[Dict[str, Any]]:
        """
        获取广播接收器信息
        
        返回:
            广播接收器信息列表
        """
        receivers = []
        
        # 获取所有广播接收器
        for receiver in self.apk.get_receivers():
            exported = self.apk.get_receiver_exported(receiver) or False
            
            receivers.append({
                "name": receiver,
                "exported": str(exported).lower(),
                "permission": self.apk.get_element("receiver", "permission", receiver) or "",
                "process": self.apk.get_element("receiver", "process", receiver) or ""
            })
        
        return receivers
    
    def _get_providers(self) -> List[Dict[str, Any]]:
        """
        获取内容提供者信息
        
        返回:
            内容提供者信息列表
        """
        providers = []
        
        # 获取所有内容提供者
        for provider in self.apk.get_providers():
            exported = self.apk.get_provider_exported(provider) or False
            
            providers.append({
                "name": provider,
                "exported": str(exported).lower(),
                "permission": self.apk.get_element("provider", "permission", provider) or "",
                "process": self.apk.get_element("provider", "process", provider) or "",
                "authorities": self.apk.get_element("provider", "authorities", provider) or "",
                "grant_uri_permissions": self.apk.get_element("provider", 
                                                    "grantUriPermissions", provider) or "false"
            })
        
        return providers
    
    def _get_intent_filters(self) -> List[Dict[str, Any]]:
        """
        获取Intent过滤器信息
        
        返回:
            Intent过滤器信息列表
        """
        intent_filters = []
        
        # 处理活动的Intent过滤器
        for activity in self.apk.get_activities():
            for intent_filter in self._get_component_intent_filters("activity", activity):
                intent_filter["component_name"] = activity
                intent_filter["component_type"] = "activity"
                intent_filters.append(intent_filter)
        
        # 处理服务的Intent过滤器
        for service in self.apk.get_services():
            for intent_filter in self._get_component_intent_filters("service", service):
                intent_filter["component_name"] = service
                intent_filter["component_type"] = "service"
                intent_filters.append(intent_filter)
        
        # 处理广播接收器的Intent过滤器
        for receiver in self.apk.get_receivers():
            for intent_filter in self._get_component_intent_filters("receiver", receiver):
                intent_filter["component_name"] = receiver
                intent_filter["component_type"] = "receiver"
                intent_filters.append(intent_filter)
        
        return intent_filters
    
    def _get_component_intent_filters(self, component_type: str, component_name: str) -> List[Dict[str, Any]]:
        """
        获取组件的Intent过滤器
        
        参数:
            component_type: 组件类型
            component_name: 组件名称
            
        返回:
            Intent过滤器列表
        """
        filters = []
        
        try:
            # 获取组件的Intent过滤器
            for intent_filter in self.apk.get_intent_filters(component_type, component_name):
                filter_info = {}
                
                # 收集操作
                actions = []
                for action in intent_filter.getElementsByTagName("action"):
                    action_name = action.getAttributeNS(
                        "http://schemas.android.com/apk/res/android", "name")
                    if action_name:
                        actions.append(action_name)
                filter_info["actions"] = actions
                
                # 收集类别
                categories = []
                for category in intent_filter.getElementsByTagName("category"):
                    category_name = category.getAttributeNS(
                        "http://schemas.android.com/apk/res/android", "name")
                    if category_name:
                        categories.append(category_name)
                filter_info["categories"] = categories
                
                # 收集数据
                data_entries = []
                for data in intent_filter.getElementsByTagName("data"):
                    data_info = {}
                    
                    # 收集数据属性
                    for attr in ["scheme", "host", "port", "path", "pathPattern", "pathPrefix", 
                                "mimeType", "type"]:
                        value = data.getAttributeNS("http://schemas.android.com/apk/res/android", attr)
                        if value:
                            data_info[attr] = value
                    
                    if data_info:
                        data_entries.append(data_info)
                
                filter_info["data"] = data_entries
                
                # 添加到过滤器列表
                if actions or categories or data_entries:
                    filters.append(filter_info)
        except Exception as e:
            # 忽略错误，返回已收集的过滤器
            logging.debug(f"获取组件Intent过滤器时出错: {str(e)}")
        
        return filters
    
    def _get_features(self) -> List[Dict[str, str]]:
        """
        获取设备特性信息
        
        返回:
            特性信息列表
        """
        features = []
        
        try:
            # 使用APK的方法获取
            for name, required in self.apk.get_features():
                features.append({
                    "name": name,
                    "required": str(required).lower()
                })
        except Exception as e:
            # 忽略错误，返回空列表
            logging.debug(f"获取设备特性时出错: {str(e)}")
        
        return features
    
    def _get_metadata(self) -> List[Dict[str, str]]:
        """
        获取元数据信息
        
        返回:
            元数据信息列表
        """
        metadata = []
        
        try:
            # 获取应用程序级别的元数据
            for meta_key, meta_value in self.apk.get_all_attribute_value("application", "meta-data", 
                                                            "name", "value").items():
                metadata.append({
                    "name": meta_key,
                    "value": meta_value,
                    "parent": "application"
                })
            
            # 获取活动级别的元数据
            for activity in self.apk.get_activities():
                for meta_key, meta_value in self.apk.get_all_attribute_value("activity", "meta-data", 
                                                             "name", "value", activity).items():
                    metadata.append({
                        "name": meta_key,
                        "value": meta_value,
                        "parent": activity
                    })
            
            # 获取服务级别的元数据
            for service in self.apk.get_services():
                for meta_key, meta_value in self.apk.get_all_attribute_value("service", "meta-data", 
                                                             "name", "value", service).items():
                    metadata.append({
                        "name": meta_key,
                        "value": meta_value,
                        "parent": service
                    })
            
            # 获取接收器级别的元数据
            for receiver in self.apk.get_receivers():
                for meta_key, meta_value in self.apk.get_all_attribute_value("receiver", "meta-data", 
                                                             "name", "value", receiver).items():
                    metadata.append({
                        "name": meta_key,
                        "value": meta_value,
                        "parent": receiver
                    })
        except Exception as e:
            # 忽略错误，返回部分数据
            logging.debug(f"获取元数据时出错: {str(e)}")
        
        return metadata


# 提供一个便捷的函数用于直接解析APK文件并保存到数据库
def parse_and_save_manifest(apk_path: str, db_path: str) -> bool:
    """
    解析APK的AndroidManifest.xml并保存到数据库
    
    参数:
        apk_path: APK文件路径
        db_path: 数据库文件路径
        
    返回:
        是否成功
    """
    try:
        parser = AndroidManifestParser(apk_path)
        return parser.save_to_database(db_path)
    except Exception as e:
        import traceback
        print(f"解析并保存清单时出错: {str(e)}")
        print(traceback.format_exc())
        return False
