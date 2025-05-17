#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/commands/tasks.py
from are.commands.base import CommandBase
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import radiolist_dialog, button_dialog
from prompt_toolkit.styles import Style
from rich.table import Table
import asyncio
import os
import time


class TasksCommand(CommandBase):
    """任务管理命令"""

    name = "tasks"
    help_short = "管理和查看进程监视任务"
    help_text = """
    管理和查看进程监视任务。
    
    此命令允许您列出、切换、删除和管理当前的进程监视任务。您可以使用箭头键和回车键在不同任务之间切换。
    """
    usage = "tasks [list|switch|delete|info]"
    examples = [
        "tasks",             # 显示任务列表并允许切换
        "tasks list",        # 仅显示任务列表
        "tasks switch",      # 交互式切换任务
        "tasks delete",      # 交互式删除任务
        "tasks info"         # 显示当前任务的详细信息
    ]

    def execute(self, context, args: str):
        """
        执行命令
        
        参数:
            context: ARE实例
            args: 命令参数
        """
        # 确保在主工作空间中
        if context.workspace_manager.get_current_workspace().type.name != "MAIN":
            context.console.error("只能在主工作空间中管理任务")
            return
            
        # 解析参数
        args = args.strip().lower()
        
        # 如果没有任务，显示提示信息
        if not context.task_manager.tasks:
            context.console.info("没有活动的任务。使用 'watching <pid>' 来创建一个任务。")
            return
            
        # 根据子命令执行不同操作
        if not args or args == "list":
            self._list_tasks(context)
        elif args == "switch":
            self._switch_task(context)
        elif args == "delete":
            self._delete_task(context)
        elif args == "info":
            self._show_task_info(context)
        else:
            context.console.error(f"未知的子命令: {args}")
            context.console.info(f"有效的子命令: list, switch, delete, info")
    
    def _list_tasks(self, context):
        """
        列出所有任务
        
        参数:
            context: ARE实例
        """
        tasks = context.task_manager.get_all_tasks()
        current_task = context.task_manager.get_current_task()
        
        # 创建表格
        table = Table(title="进程监视任务")
        table.add_column("ID", style="dim")
        table.add_column("进程名称", style="green")
        table.add_column("PID", style="blue")
        table.add_column("创建时间", style="yellow")
        table.add_column("状态", style="cyan")
        
        # 添加行
        for task in tasks:
            status = "当前" if current_task and task.id == current_task.id else ""
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(task.created_at))
            table.add_row(
                task.id,
                task.process_name,
                str(task.pid),
                timestamp,
                status
            )
        
        # 显示表格
        context.console.print(table)
    
    def _switch_task(self, context):
        """
        交互式切换任务
        
        参数:
            context: ARE实例
        """
        # 获取任务列表
        tasks = context.task_manager.get_all_tasks()
        if not tasks:
            context.console.info("没有可供切换的任务")
            return
            
        # 准备任务选项
        task_options = []
        for task in tasks:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(task.created_at))
            label = f"{task.process_name} (PID: {task.pid}, 创建于: {timestamp})"
            task_options.append((task.id, label))
        
        # 显示选择对话框
        try:
            # 退出当前的 prompt_session 控制台环境
            os.system('clear' if os.name == 'posix' else 'cls')
            
            # 创建异步任务选择对话框
            async def show_dialog():
                result = await radiolist_dialog(
                    title="选择任务",
                    text="使用箭头键选择要切换的任务:",
                    values=task_options
                )
                return result
            
            # 运行对话框并获取结果
            task_id = asyncio.run(show_dialog())
            
            # 切换任务
            if task_id:
                self._do_switch_task(context, task_id)
        except Exception as e:
            context.console.error(f"切换任务时出错: {str(e)}")
    
    def _do_switch_task(self, context, task_id):
        """
        执行任务切换
        
        参数:
            context: ARE实例
            task_id: 任务ID
        """
        # 设置当前任务
        if context.task_manager.set_current_task(task_id):
            task = context.task_manager.get_current_task()
            
            # 查找相应的工作空间
            process_workspaces = [
                ws for ws in context.workspace_manager.get_all_workspaces() 
                if ws.type.name == "PROCESS" and ws.metadata.get("task_id") == task_id
            ]
            
            if process_workspaces:
                # 切换到相应的工作空间
                context.workspace_manager.switch_to_workspace(process_workspaces[0].id)
                context.console.success(f"已切换到任务: {task.process_name} (PID: {task.pid})")
                
                # 启动新的控制台会话
                context._start_console()
            else:
                context.console.error(f"找不到与任务关联的工作空间: {task.process_name} (PID: {task.pid})")
        else:
            context.console.error(f"切换任务失败: 找不到任务 {task_id}")
    
    def _delete_task(self, context):
        """
        交互式删除任务
        
        参数:
            context: ARE实例
        """
        # 获取任务列表
        tasks = context.task_manager.get_all_tasks()
        if not tasks:
            context.console.info("没有可供删除的任务")
            return
            
        # 准备任务选项
        task_options = []
        for task in tasks:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(task.created_at))
            label = f"{task.process_name} (PID: {task.pid}, 创建于: {timestamp})"
            task_options.append((task.id, label))
        
        # 显示选择对话框
        try:
            # 退出当前的 prompt_session 控制台环境
            os.system('clear' if os.name == 'posix' else 'cls')
            
            # 创建异步任务选择对话框
            async def show_dialog():
                task_id = await radiolist_dialog(
                    title="选择要删除的任务",
                    text="使用箭头键选择要删除的任务:",
                    values=task_options
                )
                
                if not task_id:
                    return None
                    
                # 确认删除
                confirm = await button_dialog(
                    title="确认删除",
                    text=f"确定要删除选定的任务吗?",
                    buttons=[
                        ("是", True),
                        ("否", False),
                    ],
                )
                
                return task_id if confirm else None
            
            # 运行对话框并获取结果
            task_id = asyncio.run(show_dialog())
            
            # 删除任务
            if task_id:
                # 查找相应的工作空间
                process_workspaces = [
                    ws for ws in context.workspace_manager.get_all_workspaces() 
                    if ws.type.name == "PROCESS" and ws.metadata.get("task_id") == task_id
                ]
                
                # 删除工作空间
                for ws in process_workspaces:
                    context.workspace_manager.delete_workspace(ws.id)
                
                # 删除任务
                if context.task_manager.delete_task(task_id):
                    task = next((t for t in tasks if t.id == task_id), None)
                    if task:
                        context.console.success(f"已删除任务: {task.process_name} (PID: {task.pid})")
                else:
                    context.console.error(f"删除任务失败: 找不到任务 {task_id}")
        except Exception as e:
            context.console.error(f"删除任务时出错: {str(e)}")
    
    def _show_task_info(self, context):
        """
        显示当前任务的详细信息
        
        参数:
            context: ARE实例
        """
        current_task = context.task_manager.get_current_task()
        
        if not current_task:
            context.console.info("当前没有活动的任务")
            return
            
        # 创建表格
        table = Table(title=f"任务信息: {current_task.process_name}")
        table.add_column("属性", style="blue")
        table.add_column("值", style="green")
        
        # 添加行
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_task.created_at))
        table.add_row("ID", current_task.id)
        table.add_row("进程名称", current_task.process_name)
        table.add_row("PID", str(current_task.pid))
        table.add_row("创建时间", timestamp)
        table.add_row("描述", current_task.description or "无")
        
        # 添加元数据
        if current_task.metadata:
            table.add_row("元数据", "")
            for key, value in current_task.metadata.items():
                table.add_row(f"  {key}", str(value))
        
        # 显示表格
        context.console.print(table) 