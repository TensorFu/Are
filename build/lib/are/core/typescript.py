#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/typescript.py

import os
import subprocess
import tempfile
import shutil
import json
from typing import Optional
import logging

# 设置日志
logger = logging.getLogger(__name__)


def compile_typescript(source_code: str, tsconfig: Optional[dict] = None) -> str:
    """
    编译TypeScript代码为JavaScript

    参数:
        source_code: TypeScript源代码
        tsconfig: TypeScript编译配置

    返回:
        编译后的JavaScript代码
    """
    # 检查是否已安装TypeScript编译器
    try:
        subprocess.run(["tsc", "--version"], check=True, capture_output=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        raise RuntimeError(
            "TypeScript compiler (tsc) not found. Please install it with 'npm install -g typescript'")

    # 创建临时目录
    temp_dir = tempfile.mkdtemp()
    try:
        # 源文件和输出文件路径
        source_file = os.path.join(temp_dir, "script.ts")
        output_file = os.path.join(temp_dir, "script.js")

        # 写入源代码
        with open(source_file, "w", encoding="utf-8") as f:
            f.write(source_code)

        # 默认编译配置
        default_config = {
            "compilerOptions": {
                "target": "ES2020",
                "module": "CommonJS",
                "strict": True,
                "esModuleInterop": True,
                "skipLibCheck": True,
                "forceConsistentCasingInFileNames": True,
                "outFile": output_file
            },
            "files": [source_file]
        }

        # 合并用户配置
        if tsconfig:
            config = default_config.copy()
            config["compilerOptions"].update(tsconfig.get("compilerOptions", {}))
        else:
            config = default_config

        # 写入配置文件
        config_file = os.path.join(temp_dir, "tsconfig.json")
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        # 编译TypeScript
        try:
            result = subprocess.run(
                ["tsc", "-p", config_file],
                check=True,
                capture_output=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"TypeScript compilation failed: {e.stderr}")

        # 读取编译后的代码
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                compiled_code = f.read()
            return compiled_code
        except FileNotFoundError:
            raise RuntimeError("Compilation did not produce output file")

    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)


def compile_frida_script(source_code: str) -> str:
    """
    编译Frida TypeScript脚本

    参数:
        source_code: Frida TypeScript脚本源代码

    返回:
        编译后的JavaScript代码
    """
    # Frida特定的编译配置
    frida_config = {
        "compilerOptions": {
            "target": "ES2020",
            "lib": ["ES2020"],
            "allowJs": True,
            "noEmit": False,
            "declaration": False,
            "experimentalDecorators": True,
        }
    }

    return compile_typescript(source_code, frida_config)