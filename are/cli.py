#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import click
import re
from are.core.are import Are
from are.core.utils import get_version, list_devices


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """ARE - A Frida-based process instrumentation tool"""
    # 如果没有子命令，显示帮助
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.argument('process_spec', required=True)
@click.option('--device', '-d', help='Target device serial number')
def watching(process_spec, device=None):
    """
    Attach to an existing process

    PROCESS_SPEC can be just a process name or 'process_name with command'
    """
    # 解析process_spec
    match = re.match(r'^(.*?)(?: with (.*))?$', process_spec)
    if not match:
        click.echo("Invalid process specification")
        return

    process_name = match.group(1)
    command = match.group(2)

    are = Are(device_id=device)
    are.attach(process_name, command)


@cli.command()
@click.argument('process_name', required=True)
@click.argument('command', required=False)
@click.option('--device', '-d', help='Target device serial number')
def spawn(process_name, command=None, device=None):
    """Spawn and instrument a new process"""
    are = Are(device_id=device)
    are.spawn_and_attach(process_name, command)


@cli.command()
def version():
    """Display the current version"""
    from are import __version__
    click.echo(f"ARE version {__version__}")


@cli.command()
def devices():
    """List available devices"""
    list_devices()


def main():
    """命令行主入口点"""
    try:
        # 检查命令行参数
        if len(sys.argv) > 1:
            # 如果第一个参数不是子命令或选项，假设它是一个处理规范
            if sys.argv[1] not in ['watching', 'spawn', 'version', 'devices', '--help', '-h'] and not sys.argv[
                1].startswith('-'):
                process_spec = sys.argv[1]
                sys.argv.pop(1)
                sys.argv.insert(1, 'watching')
                sys.argv.insert(2, process_spec)

        cli()
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user")
    except Exception as e:
        click.echo(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()