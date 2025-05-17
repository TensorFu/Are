#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/tasks/task_manager.py
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class Task:
    """表示一个监视任务"""
    id: str  # 任务唯一标识符（通常是时间戳）
    pid: int  # 进程ID
    process_name: str  # 进程名称
    created_at: float  # 创建时间戳
    description: str = ""  # 任务描述
    is_spawned: bool = False  # 是否是使用spawn模式启动的进程
    metadata: Dict[str, Any] = field(default_factory=dict)  # 存储任务相关的元数据


class TaskManager:
    """管理进程监视任务"""
    
    def __init__(self):
        """初始化任务管理器"""
        self.tasks: Dict[str, Task] = {}  # 任务字典，键为任务ID
        self.current_task_id: Optional[str] = None
    
    def create_task(self, pid: int, process_name: str, description: str = "", is_spawned: bool = False) -> Task:
        """
        创建新任务
        
        参数:
            pid: 进程ID
            process_name: 进程名称
            description: 任务描述
            is_spawned: 是否是使用spawn模式启动的进程
            
        返回:
            新创建的任务
        """
        task_id = f"{int(time.time())}-{pid}"
        task = Task(
            id=task_id,
            pid=pid,
            process_name=process_name,
            created_at=time.time(),
            description=description,
            is_spawned=is_spawned
        )
        
        self.tasks[task_id] = task
        self.current_task_id = task_id
        return task
    
    def get_current_task(self) -> Optional[Task]:
        """获取当前任务"""
        if not self.current_task_id:
            return None
        return self.tasks.get(self.current_task_id)
    
    def set_current_task(self, task_id: str) -> bool:
        """
        设置当前任务
        
        参数:
            task_id: 任务ID
            
        返回:
            是否成功
        """
        if task_id in self.tasks:
            self.current_task_id = task_id
            return True
        return False
    
    def get_all_tasks(self) -> List[Task]:
        """
        获取所有任务
        
        返回:
            任务列表，按创建时间排序
        """
        return sorted(self.tasks.values(), key=lambda t: t.created_at)
    
    def delete_task(self, task_id: str) -> bool:
        """
        删除任务
        
        参数:
            task_id: 任务ID
            
        返回:
            是否成功
        """
        if task_id in self.tasks:
            del self.tasks[task_id]
            
            # 如果删除的是当前任务，重置当前任务
            if self.current_task_id == task_id:
                self.current_task_id = next(iter(self.tasks)) if self.tasks else None
                
            return True
        return False
    
    def update_task(self, task_id: str, **kwargs) -> bool:
        """
        更新任务属性
        
        参数:
            task_id: 任务ID
            **kwargs: 要更新的属性
            
        返回:
            是否成功
        """
        if task_id in self.tasks:
            task = self.tasks[task_id]
            
            for key, value in kwargs.items():
                if hasattr(task, key):
                    setattr(task, key, value)
            
            return True
        return False 