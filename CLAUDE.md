# Development Guidelines for Are (Android Reverse Engineering Toolkit)

## Build & Run Commands
- Install: `python setup.py install`
- Run: `are`
- Development mode: `pip install -e .`

## Code Style Guidelines
- Use PEP 8 conventions with UTF-8 encoding
- Add `#!/usr/bin/env python3` and `# -*- coding: utf-8 -*-` to top of files
- Use explicit type annotations with typing module
- Import order: standard library → third-party → local modules
- Error handling: Use try/except blocks with descriptive error messages
- Docstrings: Use Google-style with parameter descriptions
- Naming: snake_case for variables/functions, CamelCase for classes
- UI messages through AreConsole for consistent styling
- TypeScript for agent scripts, ES2020 syntax
- Exception handling should be granular with specific exception types

## Project Structure
- Commands defined in separate classes extending CommandBase
- Core functionality in are/core/
- Frida scripts in are/scripts/ (.ts files)