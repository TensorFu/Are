#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# are/core/are.py
# are/core/are.py
import os
import sys
import time
import frida
import threading
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.prompt import Prompt
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from are.core import AreConsole
from are.commands import get_all_commands


class AreCompleter(Completer):
    """Command completer for the ARE console"""

    def __init__(self, are_instance):
        self.are_instance = are_instance
        self.commands = get_all_commands()

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor.lstrip()

        # Split text into command and arguments
        parts = text.split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:] if len(parts) > 1 else []

        # Get completions for commands
        if not text or not cmd:
            # Show all commands
            for name, cmd_obj in self.commands.items():
                yield Completion(
                    name,
                    start_position=-len(text),
                    display=name,
                    display_meta=cmd_obj.help_short
                )
            return

        # If it's a partial command, complete it
        if len(parts) == 1:
            for name, cmd_obj in self.commands.items():
                if name.startswith(cmd):
                    yield Completion(
                        name,
                        start_position=-len(cmd),
                        display=name,
                        display_meta=cmd_obj.help_short
                    )
            return

        # If it's a command with arguments, delegate to the command's completer
        if cmd in self.commands:
            cmd_obj = self.commands[cmd]
            yield from cmd_obj.get_completions(document, args)


class Are:
    """Main ARE class"""

    def __init__(self, device_id: Optional[str] = None):
        """
        Initialize ARE

        Args:
            device_id: frida device ID
        """
        self.console = AreConsole()
        self.device_id = device_id
        self.device = None
        self.script = None
        self.session = None
        self.process = None
        self.current_session = None
        self.commands = get_all_commands()
        self.running = False
        self.device_name = "Unknown Device"
        self.process_name = None

        # Try to get the device
        self._get_device()

    def _get_device(self):
        """Get the frida device"""
        try:
            # Get all devices
            devices = frida.enumerate_devices()

            if not devices:
                self.console.error("No devices found")
                return False

            # If device_id is specified, find that device
            if self.device_id:
                for device in devices:
                    if device.id == self.device_id:
                        self.device = device
                        self.device_name = device.name
                        return True

                self.console.error(f"Device with ID {self.device_id} not found")
                return False

            # Otherwise, use the first USB device
            for device in devices:
                if device.type == "usb":
                    self.device = device
                    self.device_name = device.name
                    return True

            # If no USB device, use the first device
            self.device = devices[0]
            self.device_name = self.device.name
            return True

        except Exception as e:
            self.console.error(f"Error getting device: {str(e)}")
            return False

    def attach(self, process_name: str, cmd: Optional[str] = None):
        """
        Attach to a process

        Args:
            process_name: Process name or PID
            cmd: JavaScript command to execute
            
        Returns:
            bool: Whether the attachment was successful
        """
        try:
            # Try to get the device first
            if not self.device and not self._get_device():
                return False

            # Try to attach to the process
            try:
                # Check if process_name is a PID
                if process_name.isdigit():
                    pid = int(process_name)
                    self.session = self.device.attach(pid)
                    # Get process name from PID
                    for process in self.device.enumerate_processes():
                        if process.pid == pid:
                            self.process_name = process.name
                            break
                else:
                    # Find processes matching the name
                    processes = [p for p in self.device.enumerate_processes() if process_name.lower() in p.name.lower()]

                    if not processes:
                        self.console.error(f"No process matching '{process_name}' found")
                        return False

                    # If multiple matches, show them and ask user to select
                    if len(processes) > 1:
                        self.console.info(f"Found {len(processes)} processes matching '{process_name}':")
                        for i, p in enumerate(processes):
                            self.console.print(f"[{i}] {p.name} (PID: {p.pid})")

                        index = Prompt.ask("Select process", default="0")
                        try:
                            index = int(index)
                            if index < 0 or index >= len(processes):
                                self.console.error("Invalid selection")
                                return False
                        except ValueError:
                            self.console.error("Invalid selection")
                            return False

                        process = processes[index]
                    else:
                        process = processes[0]

                    self.process_name = process.name
                    self.session = self.device.attach(process.pid)

                self.current_session = {
                    "device": self.device,
                    "session": self.session,
                    "process_name": self.process_name
                }

                # Execute the command if specified
                if cmd:
                    script = self.session.create_script(cmd)
                    script.load()

                # Start the console
                self._start_console()
                return True

            except frida.ProcessNotFoundError:
                self.console.error(f"Process '{process_name}' not found")
                return False
            except Exception as e:
                self.console.error(f"Error attaching to process: {str(e)}")
                return False

        except Exception as e:
            self.console.error(f"Error: {str(e)}")
            return False

    def _start_console(self):
        """Start the interactive console"""
        # Set up history
        history_file = os.path.expanduser("~/.are_history")

        # Set up prompt style
        style = Style.from_dict({
            'prompt': 'green bold',
        })

        # Set up session
        session = PromptSession(
            history=FileHistory(history_file),
            auto_suggest=AutoSuggestFromHistory(),
            completer=AreCompleter(self),
            style=style
        )

        self.running = True

        # Before starting the console, show a welcome message
        if not self.process_name:
            # In the main ARE session
            prompt_text = f"are is running on {self.device_name} -> "
            self.console.success(f"ARE is now running on {self.device_name}")
            self.console.info("Type 'watching <process_name>' to attach to a process")
            self.console.info("Type 'help' to see all available commands")
        else:
            # In a process-specific session
            connection_type = "usb" if self.device.type == "usb" else "remote"
            # Format the prompt to match the desired format for process sessions
            device_name = self.device_name if self.device_name else "Unknown"
            prompt_text = f"{self.process_name} on ({device_name}) [{connection_type}] # "
            self.console.success(f"Attached to process: {self.process_name}")
            self.console.info("You can now execute commands like 'hook com.example.Class.method'")

        while self.running:
            try:
                # Get input
                command = session.prompt(prompt_text)

                # Skip empty commands
                if not command.strip():
                    continue

                # Process the command
                self._process_command(command)

            except KeyboardInterrupt:
                # Catch Ctrl+C
                self.console.print("\nUse 'exit' or 'quit' to exit")
            except EOFError:
                # Catch Ctrl+D
                self.running = False
                self.console.print("\nGoodbye!")
            except Exception as e:
                self.console.error(f"Error: {str(e)}")

    def _process_command(self, command: str):
        """
        Process a command

        Args:
            command: The command string
        """
        # Split command and arguments
        parts = command.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        # Handle built-in commands
        if cmd in ["exit", "quit"]:
            self.running = False
            self.console.print("Goodbye!")
            return

        # Handle help command
        if cmd == "help":
            self._show_help(args)
            return

        # Handle other commands
        if cmd in self.commands:
            try:
                self.commands[cmd].execute(self, args)
            except Exception as e:
                self.console.error(f"Error executing command: {str(e)}")
        else:
            self.console.error(f"Unknown command: {cmd}")
            self.console.info("Type 'help' to see available commands")

    def _show_help(self, args: str):
        """
        Show help for commands

        Args:
            args: Command to show help for
        """
        if args:
            # Show help for specific command
            cmd = args.strip().lower()
            if cmd in self.commands:
                cmd_obj = self.commands[cmd]
                self.console.panel(
                    f"{cmd_obj.help_text}\n\nUsage: {cmd_obj.usage}\n\nExamples:\n" +
                    "\n".join([f"  {ex}" for ex in cmd_obj.examples]),
                    title=f"Help for '{cmd}'",
                    style="info"
                )
            else:
                self.console.error(f"Unknown command: {cmd}")
        else:
            # Show general help
            self.console.panel(
                "\n".join([f"{name.ljust(15)} - {cmd.help_short}" for name, cmd in self.commands.items()]),
                title="Available Commands",
                style="info"
            )
            self.console.info("Type 'help <command>' for more information on a specific command")