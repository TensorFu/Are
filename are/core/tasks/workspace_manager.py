#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/tasks/workspace_manager.py
from enum import Enum
from typing import Dict, Optional, Any, List, Callable
import os

# 工作空间类型枚举
class WorkspaceType(Enum):
    """工作空间类型"""
    MAIN = 1      # 主工作空间
    PROCESS = 2   # 进程监视工作空间
    
class Workspace:
    """表示一个工作空间"""
    
    def __init__(self, 
                 workspace_id: str, 
                 name: str, 
                 type: WorkspaceType,
                 metadata: Dict[str, Any] = None,
                 command_handler: Optional[Callable] = None):
        """
        初始化工作空间
        
        参数:
            workspace_id: 工作空间ID
            name: 工作空间名称
            type: 工作空间类型
            metadata: 工作空间元数据
            command_handler: 命令处理函数
        """
        self.id = workspace_id
        self.name = name
        self.type = type
        self.metadata = metadata or {}
        self.command_handler = command_handler
        self.history = []  # 命令历史
        
    def handle_command(self, command: str) -> bool:
        """
        处理命令
        
        参数:
            command: 要处理的命令
            
        返回:
            是否成功处理
        """
        if self.command_handler:
            # 将命令添加到历史记录
            self.history.append(command)
            
            # 调用命令处理函数
            return self.command_handler(command)
        return False
        
    def get_prompt(self) -> str:
        """
        获取工作空间提示符
        
        返回:
            格式化的提示符字符串
        """
        if self.type == WorkspaceType.MAIN:
            device_name = self.metadata.get("device_name", "unknown device")
            return f"ARE is running on [{device_name}] # "
        elif self.type == WorkspaceType.PROCESS:
            process_name = self.metadata.get("process_name", "unknown")
            device_name = self.metadata.get("device_name", "device")
            connection_type = self.metadata.get("connection_type", "usb")
            return f"{process_name} on ({device_name}) [{connection_type}] # "
        return f"{self.name} > "


class WorkspaceManager:
    """管理多个工作空间"""
    
    def __init__(self):
        """初始化工作空间管理器"""
        self.workspaces: Dict[str, Workspace] = {}
        self.current_workspace_id: Optional[str] = None
        self.workspace_stack: List[str] = []  # 用于实现工作空间跳转历史
        
    def create_workspace(self, 
                        name: str, 
                        type: WorkspaceType, 
                        metadata: Dict[str, Any] = None,
                        command_handler: Optional[Callable] = None) -> Workspace:
        """
        创建新工作空间
        
        参数:
            name: 工作空间名称
            type: 工作空间类型
            metadata: 工作空间元数据
            command_handler: 命令处理函数
            
        返回:
            新创建的工作空间
        """
        workspace_id = f"{type.name.lower()}_{len(self.workspaces) + 1}_{name.lower().replace(' ', '_')}"
        workspace = Workspace(
            workspace_id=workspace_id,
            name=name,
            type=type,
            metadata=metadata,
            command_handler=command_handler
        )
        
        self.workspaces[workspace_id] = workspace
        
        # 如果这是第一个工作空间，设置为当前工作空间
        if not self.current_workspace_id:
            self.current_workspace_id = workspace_id
            self.workspace_stack.append(workspace_id)
            
        return workspace
    
    def switch_to_workspace(self, workspace_id: str) -> bool:
        """
        切换到指定工作空间
        
        参数:
            workspace_id: 工作空间ID
            
        返回:
            是否成功
        """
        if workspace_id in self.workspaces:
            self.current_workspace_id = workspace_id
            
            # 如果工作空间已经在栈中，先移除它
            if workspace_id in self.workspace_stack:
                self.workspace_stack.remove(workspace_id)
                
            # 将当前工作空间添加到栈顶
            self.workspace_stack.append(workspace_id)
            
            return True
        return False
    
    def get_current_workspace(self) -> Optional[Workspace]:
        """
        获取当前工作空间
        
        返回:
            当前工作空间，如果没有则返回None
        """
        if not self.current_workspace_id:
            return None
        return self.workspaces.get(self.current_workspace_id)
    
    def get_all_workspaces(self) -> List[Workspace]:
        """
        获取所有工作空间
        
        返回:
            工作空间列表
        """
        return list(self.workspaces.values())
    
    def delete_workspace(self, workspace_id: str) -> bool:
        """
        删除工作空间
        
        参数:
            workspace_id: 工作空间ID
            
        返回:
            是否成功
        """
        if workspace_id in self.workspaces:
            del self.workspaces[workspace_id]
            
            # 更新工作空间栈
            if workspace_id in self.workspace_stack:
                self.workspace_stack.remove(workspace_id)
            
            # 如果删除的是当前工作空间，切换到上一个工作空间
            if self.current_workspace_id == workspace_id:
                self.current_workspace_id = self.workspace_stack[-1] if self.workspace_stack else None
                
            return True
        return False
    
    def back_to_previous_workspace(self) -> bool:
        """
        返回上一个工作空间
        
        返回:
            是否成功
        """
        if len(self.workspace_stack) > 1:
            # 移除当前工作空间
            current_id = self.workspace_stack.pop()
            
            # 设置为上一个工作空间
            self.current_workspace_id = self.workspace_stack[-1]
            
            return True
        return False 