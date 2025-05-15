#!/usr/bin/env python
# -*- coding: utf-8 -*-

# are/core/markdown/md.py

import os
from typing import List, Dict, Union, Optional, Tuple, Any


class MarkdownGenerator:
    """
    Markdown 文档生成器
    支持所有 Markdown 格式和文本，提供接口供其他函数调用
    """

    def __init__(self, file_path: Optional[str] = None):
        """
        初始化 Markdown 生成器

        Args:
            file_path: Markdown 文件保存路径，如果为 None，则使用默认路径 'markdown/Main.md'
                       路径相对于命令行启动的当前工作目录
        """
        self.content = []  # 存储 Markdown 内容
        # 使用绝对路径，确保相对于当前工作目录（而不是脚本所在目录）
        if file_path:
            self.file_path = os.path.abspath(file_path)
        else:
            # 获取当前工作目录（命令行启动目录）
            current_working_dir = os.getcwd()
            self.file_path = os.path.join(current_working_dir, "markdown", "Main.md")

        self.toc_items = []  # 目录项
        self.indent_level = 0  # 当前缩进级别

        # 确保 markdown 文件夹和 Main.md 文件存在
        self._ensure_file_exists()

    def get_content(self) -> str:
        """
        获取生成的 Markdown 内容

        Returns:
            str: 完整的 Markdown 内容
        """
        return "\n".join(self.content)

    def _ensure_file_exists(self) -> None:
        """
        确保 markdown 文件夹和目标文件存在
        如果不存在，则创建
        """
        # 确保文件夹存在
        folder_path = os.path.dirname(os.path.abspath(self.file_path))
        if not os.path.exists(folder_path):
            os.makedirs(folder_path, exist_ok=True)
            print(f"已创建文件夹: {folder_path}")

        # 确保文件存在
        if not os.path.exists(self.file_path):
            with open(self.file_path, 'w', encoding='utf-8') as f:
                pass  # 创建空文件
            print(f"已创建文件: {self.file_path}")

        # 如果文件存在但为空，不执行任何操作
        # 如果文件存在且不为空，则读取内容到 self.content
        elif os.path.getsize(self.file_path) > 0:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                self.content = f.read().splitlines()

    def save(self, file_path: Optional[str] = None) -> str:
        """
        保存 Markdown 内容到文件

        Args:
            file_path: 文件保存路径，如果为 None，则使用初始化时的路径
                       路径相对于命令行启动的当前工作目录

        Returns:
            str: 文件保存路径（绝对路径）
        """
        if file_path:
            # 转换为绝对路径，确保相对于当前工作目录
            save_path = os.path.abspath(file_path)

            # 临时更改文件路径用于确保文件存在
            old_path = self.file_path
            self.file_path = save_path
            self._ensure_file_exists()
            self.file_path = old_path
        else:
            save_path = self.file_path
            self._ensure_file_exists()

        # 写入内容
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(self.get_content())

        return save_path

    def clear(self) -> None:
        """
        清空当前内容
        """
        self.content = []
        self.toc_items = []

    # ============= 基本元素 =============

    def add_raw(self, text: str) -> 'MarkdownGenerator':
        """
        添加原始文本，不做任何格式化

        Args:
            text: 原始文本

        Returns:
            self: 支持链式调用
        """
        self._ensure_file_exists()  # 确保文件存在
        self.content.append(text)
        return self

    def add_line(self, text: str = "") -> 'MarkdownGenerator':
        """
        添加一行文本

        Args:
            text: 文本内容，默认为空行

        Returns:
            self: 支持链式调用
        """
        self._ensure_file_exists()  # 确保文件存在
        indentation = "    " * self.indent_level if self.indent_level > 0 else ""
        self.content.append(f"{indentation}{text}")
        return self

    def add_lines(self, lines: List[str]) -> 'MarkdownGenerator':
        """
        添加多行文本

        Args:
            lines: 文本行列表

        Returns:
            self: 支持链式调用
        """
        for line in lines:
            self.add_line(line)
        return self

    def add_newline(self, count: int = 1) -> 'MarkdownGenerator':
        """
        添加空行

        Args:
            count: 空行数量

        Returns:
            self: 支持链式调用
        """
        for _ in range(count):
            self.add_line()
        return self

    # ============= 标题 =============

    def add_heading(self, text: str, level: int = 1, add_to_toc: bool = True) -> 'MarkdownGenerator':
        """
        添加标题

        Args:
            text: 标题文本
            level: 标题级别 (1-6)
            add_to_toc: 是否添加到目录

        Returns:
            self: 支持链式调用
        """
        if not 1 <= level <= 6:
            raise ValueError("标题级别必须在 1-6 之间")

        self.add_line(f"{'#' * level} {text}")
        self.add_newline()

        if add_to_toc:
            self.toc_items.append((text, level))

        return self

    def add_toc(self, title: str = "目录") -> 'MarkdownGenerator':
        """
        生成目录

        Args:
            title: 目录标题，如果为空则不添加标题

        Returns:
            self: 支持链式调用
        """
        if title:
            self.add_heading(title, level=2, add_to_toc=False)

        for text, level in self.toc_items:
            indent = "    " * (level - 1)
            self.add_line(f"{indent}- [{text}](#{text.lower().replace(' ', '-')})")

        self.add_newline()
        return self

    # ============= 文本样式 =============

    def add_bold(self, text: str) -> str:
        """
        添加粗体文本

        Args:
            text: 要加粗的文本

        Returns:
            str: 加粗后的文本
        """
        return f"**{text}**"

    def add_italic(self, text: str) -> str:
        """
        添加斜体文本

        Args:
            text: 要倾斜的文本

        Returns:
            str: 倾斜后的文本
        """
        return f"*{text}*"

    def add_strikethrough(self, text: str) -> str:
        """
        添加删除线文本

        Args:
            text: 要添加删除线的文本

        Returns:
            str: 添加删除线后的文本
        """
        return f"~~{text}~~"

    def add_code(self, text: str) -> str:
        """
        添加行内代码

        Args:
            text: 代码文本

        Returns:
            str: 格式化后的行内代码
        """
        return f"`{text}`"

    def add_link(self, text: str, url: str, title: Optional[str] = None) -> str:
        """
        添加链接

        Args:
            text: 链接文本
            url: 链接URL
            title: 链接标题（可选）

        Returns:
            str: 格式化后的链接
        """
        if title:
            return f"[{text}]({url} \"{title}\")"
        return f"[{text}]({url})"

    def add_image(self, alt_text: str, url: str, title: Optional[str] = None) -> str:
        """
        添加图片

        Args:
            alt_text: 替代文本
            url: 图片URL
            title: 图片标题（可选）

        Returns:
            str: 格式化后的图片标记
        """
        if title:
            return f"![{alt_text}]({url} \"{title}\")"
        return f"![{alt_text}]({url})"

    # ============= 段落和引用 =============

    def add_paragraph(self, text: str) -> 'MarkdownGenerator':
        """
        添加段落

        Args:
            text: 段落文本

        Returns:
            self: 支持链式调用
        """
        self.add_line(text)
        self.add_newline()
        return self

    def add_blockquote(self, text: str, multi_line: bool = False) -> 'MarkdownGenerator':
        """
        添加引用块

        Args:
            text: 引用文本
            multi_line: 是否为多行引用

        Returns:
            self: 支持链式调用
        """
        if multi_line:
            lines = text.split('\n')
            for line in lines:
                self.add_line(f"> {line}")
        else:
            self.add_line(f"> {text}")
        
        self.add_newline()
        return self

    # ============= 水平线 =============

    def add_horizontal_rule(self) -> 'MarkdownGenerator':
        """
        添加水平分割线

        Returns:
            self: 支持链式调用
        """
        self.add_line("---")
        self.add_newline()
        return self

    # ============= 列表 =============

    def add_unordered_list(self, items: List[str], nested_level: int = 0) -> 'MarkdownGenerator':
        """
        添加无序列表

        Args:
            items: 列表项
            nested_level: 嵌套级别（用于缩进）

        Returns:
            self: 支持链式调用
        """
        indent = "    " * nested_level
        for item in items:
            self.add_line(f"{indent}- {item}")
        
        self.add_newline()
        return self

    def add_ordered_list(self, items: List[str], start_num: int = 1, nested_level: int = 0) -> 'MarkdownGenerator':
        """
        添加有序列表

        Args:
            items: 列表项
            start_num: 起始编号
            nested_level: 嵌套级别（用于缩进）

        Returns:
            self: 支持链式调用
        """
        indent = "    " * nested_level
        for i, item in enumerate(items, start=start_num):
            self.add_line(f"{indent}{i}. {item}")
        
        self.add_newline()
        return self

    def add_task_list(self, items: List[Tuple[str, bool]], nested_level: int = 0) -> 'MarkdownGenerator':
        """
        添加任务列表

        Args:
            items: 列表项元组 (文本, 是否完成)
            nested_level: 嵌套级别（用于缩进）

        Returns:
            self: 支持链式调用
        """
        indent = "    " * nested_level
        for text, completed in items:
            checkbox = "[x]" if completed else "[ ]"
            self.add_line(f"{indent}- {checkbox} {text}")
        
        self.add_newline()
        return self

    # ============= 代码块 =============

    def add_code_block(self, code: str, language: str = "") -> 'MarkdownGenerator':
        """
        添加代码块

        Args:
            code: 代码内容
            language: 代码语言（用于语法高亮）

        Returns:
            self: 支持链式调用
        """
        self.add_line(f"```{language}")
        
        # 处理多行代码
        lines = code.split('\n')
        for line in lines:
            self.add_line(line)
            
        self.add_line("```")
        self.add_newline()
        return self

    # ============= 表格 =============

    def add_table(self, headers: List[str], rows: List[List[str]],
                  alignments: Optional[List[str]] = None) -> 'MarkdownGenerator':
        """
        添加表格

        Args:
            headers: 表头列表
            rows: 表格数据（行列表）
            alignments: 对齐方式列表，可以是 'left'、'center'、'right' 或 None

        Returns:
            self: 支持链式调用
        """
        # 验证行数据
        for row in rows:
            if len(row) != len(headers):
                raise ValueError("表格行的列数必须与表头列数相同")

        # 构建表头
        header_row = "| " + " | ".join(headers) + " |"
        self.add_line(header_row)

        # 构建对齐行
        if not alignments:
            alignments = ["left"] * len(headers)
        elif len(alignments) != len(headers):
            raise ValueError("对齐方式列表长度必须与表头列数相同")

        separator_parts = []
        for align in alignments:
            if align == "left":
                separator_parts.append(":---")
            elif align == "center":
                separator_parts.append(":---:")
            elif align == "right":
                separator_parts.append("---:")
            else:
                separator_parts.append("---")

        separator_row = "| " + " | ".join(separator_parts) + " |"
        self.add_line(separator_row)

        # 构建数据行
        for row in rows:
            data_row = "| " + " | ".join(row) + " |"
            self.add_line(data_row)

        self.add_newline()
        return self

    # ============= 定义列表 =============

    def add_definition_list(self, definitions: Dict[str, str]) -> 'MarkdownGenerator':
        """
        添加定义列表

        Args:
            definitions: 定义字典 {术语: 定义}

        Returns:
            self: 支持链式调用
        """
        for term, definition in definitions.items():
            self.add_line(term)
            self.add_line(f": {definition}")
            self.add_newline()
        return self

    # ============= 脚注 =============

    def add_footnote(self, text: str, footnote_id: str, footnote_text: str) -> str:
        """
        添加脚注

        Args:
            text: 要添加脚注的文本
            footnote_id: 脚注ID
            footnote_text: 脚注内容

        Returns:
            str: 带有脚注的文本
        """
        # 在文档末尾添加脚注定义
        self.add_line(f"[^{footnote_id}]: {footnote_text}")
        
        # 返回带有脚注引用的文本
        return f"{text}[^{footnote_id}]"

    # ============= 缩写 =============

    def add_abbreviation(self, text: str, abbreviations: Dict[str, str]) -> 'MarkdownGenerator':
        """
        添加缩写定义

        Args:
            text: 包含缩写的文本
            abbreviations: 缩写字典 {缩写: 全称}

        Returns:
            self: 支持链式调用
        """
        # 先添加文本
        self.add_paragraph(text)
        
        # 然后添加缩写定义
        self.add_newline()
        for abbr, full in abbreviations.items():
            self.add_line(f"*[{abbr}]: {full}")
        
        self.add_newline()
        return self

    # ============= 图表 =============

    def add_mermaid(self, diagram_code: str) -> 'MarkdownGenerator':
        """
        添加 Mermaid 图表

        Args:
            diagram_code: Mermaid 图表代码

        Returns:
            self: 支持链式调用
        """
        self.add_line("```mermaid")
        
        # 处理多行代码
        lines = diagram_code.split('\n')
        for line in lines:
            self.add_line(line)
            
        self.add_line("```")
        self.add_newline()
        return self

    # ============= 数学公式 =============

    def add_mathjax(self, formula: str, inline: bool = False) -> str:
        """
        添加 MathJax 数学公式

        Args:
            formula: 数学公式
            inline: 是否为行内公式

        Returns:
            str: 格式化后的数学公式
        """
        if inline:
            return f"${formula}$"
        return f"$${formula}$$"

    # ============= 提示框 =============

    def add_callout(self, text: str, callout_type: str = "note") -> 'MarkdownGenerator':
        """
        添加提示框

        Args:
            text: 提示文本
            callout_type: 提示类型（note, info, warning, danger）

        Returns:
            self: 支持链式调用
        """
        self.add_line(f"> [{callout_type}] {text}")
        self.add_newline()
        return self

    # ============= 折叠内容 =============

    def add_details(self, summary: str, content: str) -> 'MarkdownGenerator':
        """
        添加折叠内容

        Args:
            summary: 摘要（标题）
            content: 折叠内容

        Returns:
            self: 支持链式调用
        """
        self.add_line("<details>")
        self.add_line(f"<summary>{summary}</summary>")
        self.add_newline()
        
        # 添加内容（可能包含多行）
        lines = content.split('\n')
        for line in lines:
            self.add_line(line)
            
        self.add_newline()
        self.add_line("</details>")
        self.add_newline()
        return self

    # ============= 缩进控制 =============

    def indent(self, level: int = 1) -> 'MarkdownGenerator':
        """
        增加缩进级别

        Args:
            level: 增加的缩进级别数

        Returns:
            self: 支持链式调用
        """
        self.indent_level += level
        return self

    def dedent(self, level: int = 1) -> 'MarkdownGenerator':
        """
        减少缩进级别

        Args:
            level: 减少的缩进级别数

        Returns:
            self: 支持链式调用
        """
        self.indent_level = max(0, self.indent_level - level)
        return self

    # ============= 上下文管理 =============

    def with_context(self, indent_level: int = 1):
        """
        创建一个缩进上下文，用于 with 语句

        Args:
            indent_level: 缩进级别

        Returns:
            IndentContext: 缩进上下文管理器
        """
        return self.IndentContext(self, indent_level)

    class IndentContext:
        """缩进上下文管理器内部类"""
        
        def __init__(self, md_generator, level):
            self.md = md_generator
            self.level = level
            
        def __enter__(self):
            self.md.indent(self.level)
            return self.md
            
        def __exit__(self, exc_type, exc_val, exc_tb):
            self.md.dedent(self.level)


def example_usage():
    # 创建 Markdown 生成器实例 - 将在当前工作目录下自动创建 markdown/Main.md
    md = MarkdownGenerator()
    
    # 添加标题
    md.add_heading("Markdown Generator Example", level=1)
    
    # 添加段落
    md.add_paragraph("This is an example of using the MarkdownGenerator class to create Markdown content programmatically.")
    
    # 添加粗体和斜体文本
    md.add_paragraph(f"You can add {md.add_bold('bold')} or {md.add_italic('italic')} text easily.")
    
    # 添加无序列表
    md.add_heading("Features", level=2)
    md.add_unordered_list([
        "Simple API",
        "Support for all common Markdown elements",
        "Chainable methods",
        "Auto-generated table of contents"
    ])
    
    # 添加代码块
    md.add_heading("Code Example", level=2)
    md.add_code_block('''
def hello_world():
    print("Hello, world!")
    
hello_world()
''', language="python")
    
    # 添加表格
    md.add_heading("Comparison Table", level=2)
    md.add_table(
        headers=["Feature", "MarkdownGenerator", "Manual Writing"],
        rows=[
            ["Ease of use", "High", "Medium"],
            ["Consistency", "High", "Variable"],
            ["Speed", "Fast", "Depends on user"]
        ],
        alignments=["left", "center", "right"]
    )
    
    # 生成目录 (必须在添加完所有标题后)
    md.add_toc("Table of Contents")
    
    # 保存文件
    file_path = md.save()
    print(f"Markdown file saved to: {file_path}")
    
    # 获取生成的内容
    content = md.get_content()
    print("\nGenerated content preview:")
    print(f"{content[:200]}...")


if __name__ == "__main__":
    example_usage() 