#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
/markdown_generator.py
Markdown 文档生成器 - 支持所有 Markdown 格式和文本，提供接口供其他函数调用
"""
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
            link_text = text.lower().replace(" ", "-").replace(".", "").replace(",", "")
            self.add_line(f"{indent}- [{text}](#{link_text})")

        self.add_newline()
        return self

    # ============= 文本格式 =============

    def add_bold(self, text: str) -> str:
        """
        加粗文本

        Args:
            text: 要加粗的文本

        Returns:
            str: 加粗后的文本
        """
        return f"**{text}**"

    def add_italic(self, text: str) -> str:
        """
        斜体文本

        Args:
            text: 要设为斜体的文本

        Returns:
            str: 斜体文本
        """
        return f"*{text}*"

    def add_strikethrough(self, text: str) -> str:
        """
        删除线文本

        Args:
            text: 要添加删除线的文本

        Returns:
            str: 添加删除线后的文本
        """
        return f"~~{text}~~"

    def add_code(self, text: str) -> str:
        """
        行内代码

        Args:
            text: 代码文本

        Returns:
            str: 行内代码格式文本
        """
        return f"`{text}`"

    def add_link(self, text: str, url: str, title: Optional[str] = None) -> str:
        """
        添加链接

        Args:
            text: 链接文本
            url: 链接地址
            title: 链接标题（可选）

        Returns:
            str: Markdown 链接格式
        """
        if title:
            return f"[{text}]({url} \"{title}\")"
        return f"[{text}]({url})"

    def add_image(self, alt_text: str, url: str, title: Optional[str] = None) -> str:
        """
        添加图片

        Args:
            alt_text: 图片替代文本
            url: 图片地址
            title: 图片标题（可选）

        Returns:
            str: Markdown 图片格式
        """
        if title:
            return f"![{alt_text}]({url} \"{title}\")"
        return f"![{alt_text}]({url})"

    # ============= 段落元素 =============

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
            nested_level: 嵌套级别

        Returns:
            self: 支持链式调用
        """
        old_indent = self.indent_level
        self.indent_level = nested_level

        for item in items:
            prefix = "    " * nested_level
            self.add_line(f"{prefix}- {item}")

        self.indent_level = old_indent
        self.add_newline()
        return self

    def add_ordered_list(self, items: List[str], start_num: int = 1, nested_level: int = 0) -> 'MarkdownGenerator':
        """
        添加有序列表

        Args:
            items: 列表项
            start_num: 起始编号
            nested_level: 嵌套级别

        Returns:
            self: 支持链式调用
        """
        old_indent = self.indent_level
        self.indent_level = nested_level

        for i, item in enumerate(items, start=start_num):
            prefix = "    " * nested_level
            self.add_line(f"{prefix}{i}. {item}")

        self.indent_level = old_indent
        self.add_newline()
        return self

    def add_task_list(self, items: List[Tuple[str, bool]], nested_level: int = 0) -> 'MarkdownGenerator':
        """
        添加任务列表

        Args:
            items: 列表项元组 (文本, 是否完成)
            nested_level: 嵌套级别

        Returns:
            self: 支持链式调用
        """
        old_indent = self.indent_level
        self.indent_level = nested_level

        for text, is_completed in items:
            prefix = "    " * nested_level
            checkbox = "[x]" if is_completed else "[ ]"
            self.add_line(f"{prefix}- {checkbox} {text}")

        self.indent_level = old_indent
        self.add_newline()
        return self

    # ============= 代码块 =============

    def add_code_block(self, code: str, language: str = "") -> 'MarkdownGenerator':
        """
        添加代码块

        Args:
            code: 代码内容
            language: 语言（用于语法高亮）

        Returns:
            self: 支持链式调用
        """
        self.add_line(f"```{language}")

        # 处理多行代码
        code_lines = code.split('\n')
        for line in code_lines:
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
            rows: 行数据的列表的列表
            alignments: 对齐方式列表 ('left', 'center', 'right')，默认全部左对齐

        Returns:
            self: 支持链式调用
        """
        if not alignments:
            alignments = ['left'] * len(headers)

        if len(headers) != len(alignments):
            raise ValueError("表头和对齐方式数量不匹配")

        # 添加表头
        header_line = "| " + " | ".join(headers) + " |"
        self.add_line(header_line)

        # 添加对齐行
        alignment_markers = []
        for align in alignments:
            if align == 'left':
                alignment_markers.append(':---')
            elif align == 'center':
                alignment_markers.append(':---:')
            elif align == 'right':
                alignment_markers.append('---:')
            else:
                alignment_markers.append('---')  # 默认左对齐

        align_line = "| " + " | ".join(alignment_markers) + " |"
        self.add_line(align_line)

        # 添加数据行
        for row in rows:
            if len(row) != len(headers):
                # 填充或截断行以匹配表头数量
                if len(row) < len(headers):
                    row = row + [""] * (len(headers) - len(row))
                else:
                    row = row[:len(headers)]

            row_line = "| " + " | ".join(row) + " |"
            self.add_line(row_line)

        self.add_newline()
        return self

    # ============= 高级元素 =============

    def add_definition_list(self, definitions: Dict[str, str]) -> 'MarkdownGenerator':
        """
        添加定义列表

        Args:
            definitions: 术语和定义的字典

        Returns:
            self: 支持链式调用
        """
        for term, definition in definitions.items():
            self.add_line(term)
            self.add_line(f": {definition}")
            self.add_newline()

        return self

    def add_footnote(self, text: str, footnote_id: str, footnote_text: str) -> str:
        """
        添加脚注引用

        Args:
            text: 要添加脚注的文本
            footnote_id: 脚注标识符
            footnote_text: 脚注内容

        Returns:
            str: 添加了脚注引用的文本
        """
        # 将脚注内容添加到文档末尾
        self.content.append(f"[^{footnote_id}]: {footnote_text}")

        # 返回带有脚注引用的文本
        return f"{text}[^{footnote_id}]"

    def add_abbreviation(self, text: str, abbreviations: Dict[str, str]) -> 'MarkdownGenerator':
        """
        添加缩写定义

        Args:
            text: 包含缩写的文本
            abbreviations: 缩写和其定义的字典

        Returns:
            self: 支持链式调用
        """
        self.add_line(text)
        self.add_newline()

        for abbr, definition in abbreviations.items():
            self.add_line(f"*[{abbr}]: {definition}")

        self.add_newline()
        return self

    # ============= 扩展功能 =============

    def add_mermaid(self, diagram_code: str) -> 'MarkdownGenerator':
        """
        添加 Mermaid 图表

        Args:
            diagram_code: Mermaid 图表代码

        Returns:
            self: 支持链式调用
        """
        self.add_line("```mermaid")
        diagram_lines = diagram_code.split('\n')
        for line in diagram_lines:
            self.add_line(line)
        self.add_line("```")
        self.add_newline()
        return self

    def add_mathjax(self, formula: str, inline: bool = False) -> str:
        """
        添加数学公式

        Args:
            formula: 数学公式（LaTeX 格式）
            inline: 是否为行内公式

        Returns:
            str: 数学公式的 Markdown 表示
        """
        if inline:
            return f"${formula}$"
        else:
            return f"$${formula}$$"

    def add_callout(self, text: str, callout_type: str = "note") -> 'MarkdownGenerator':
        """
        添加提示框（仅在某些 Markdown 扩展中支持）

        Args:
            text: 提示文本
            callout_type: 提示类型（note, warning, tip, important, caution 等）

        Returns:
            self: 支持链式调用
        """
        self.add_line(f"> [{callout_type.upper()}]")
        self.add_line(f"> {text}")
        self.add_newline()
        return self

    def add_details(self, summary: str, content: str) -> 'MarkdownGenerator':
        """
        添加可折叠详情块

        Args:
            summary: 摘要文本
            content: 详情内容

        Returns:
            self: 支持链式调用
        """
        self.add_line("<details>")
        self.add_line(f"<summary>{summary}</summary>")
        self.add_newline()
        self.add_line(content)
        self.add_newline()
        self.add_line("</details>")
        self.add_newline()
        return self

    # ============= 辅助方法 =============

    def indent(self, level: int = 1) -> 'MarkdownGenerator':
        """
        增加缩进级别

        Args:
            level: 增加的缩进级别

        Returns:
            self: 支持链式调用
        """
        self.indent_level += level
        return self

    def dedent(self, level: int = 1) -> 'MarkdownGenerator':
        """
        减少缩进级别

        Args:
            level: 减少的缩进级别

        Returns:
            self: 支持链式调用
        """
        self.indent_level = max(0, self.indent_level - level)
        return self

    def with_context(self, indent_level: int = 1):
        """
        创建一个上下文管理器来管理缩进

        Args:
            indent_level: 上下文中的缩进级别

        Returns:
            上下文管理器
        """

        class IndentContext:
            def __init__(self, md_generator, level):
                self.md = md_generator
                self.level = level

            def __enter__(self):
                self.md.indent(self.level)
                return self.md

            def __exit__(self, exc_type, exc_val, exc_tb):
                self.md.dedent(self.level)

        return IndentContext(self, indent_level)


# 使用示例
def example_usage():
    # 创建 Markdown 生成器实例 - 将在当前工作目录下自动创建 markdown/Main.md
    md = MarkdownGenerator()
    print(f"将在工作目录创建文件: {md.file_path}")

    # 添加标题和目录
    md.add_heading("Markdown 生成器示例", 1)
    md.add_paragraph("这是一个 Markdown 生成器的示例文档。")

    # 添加目录
    md.add_toc()

    # 添加各种元素
    md.add_heading("基本文本格式", 2)
    md.add_paragraph(f"这是一个段落，包含{md.add_bold('粗体')}、{md.add_italic('斜体')}和{md.add_code('代码')}。")

    md.add_heading("列表", 2)
    md.add_unordered_list(["无序列表项 1", "无序列表项 2", "无序列表项 3"])
    md.add_ordered_list(["有序列表项 1", "有序列表项 2", "有序列表项 3"])

    md.add_heading("代码块", 2)
    md.add_code_block("""def hello_world():
    print("Hello, World!")
    return True""", "python")

    md.add_heading("表格", 2)
    md.add_table(
        ["姓名", "年龄", "职业"],
        [
            ["张三", "25", "工程师"],
            ["李四", "30", "设计师"],
            ["王五", "28", "产品经理"]
        ],
        ["left", "center", "right"]
    )

    md.add_heading("引用", 2)
    md.add_blockquote("这是一个引用块。", multi_line=False)

    md.add_heading("任务列表", 2)
    md.add_task_list([
        ("完成文档", True),
        ("实现功能", True),
        ("编写测试", False)
    ])

    md.add_heading("数学公式", 2)
    md.add_paragraph(f"行内公式: {md.add_mathjax('E=mc^2', inline=True)}")
    md.add_paragraph(f"独立公式:")
    md.add_line(md.add_mathjax(r'\sum_{i=1}^{n} i = \frac{n(n+1)}{2}', inline=False))
    md.add_newline()

    md.add_heading("图表", 2)
    md.add_mermaid("""graph TD
    A[开始] --> B{是否继续?}
    B -->|是| C[处理]
    C --> B
    B -->|否| D[结束]""")

    # 保存文档到默认路径
    file_path = md.save()
    print(f"Markdown 文档已保存到: {file_path}")

    # 也可以保存到工作目录下的其他路径
    another_path = os.path.join(os.getcwd(), "markdown", "Example.md")
    md.save(another_path)
    print(f"Markdown 文档的副本已保存到: {another_path}")

    # 也可以使用相对路径（相对于当前工作目录）
    md.save("markdown/Another.md")
    print(f"使用相对路径保存文档到: {os.path.join(os.getcwd(), 'markdown', 'Another.md')}")

    return md.get_content()


if __name__ == "__main__":
    example_usage()