"""
Setup verification script — run after scaffolding to confirm everything is in place.
Checks: directory tree, all files present, .env readable, Groq API key set,
all imports work, Garak installed, PyRIT installed.

Run: python scripts/verify_setup.py
"""
from __future__ import annotations


def check_directory_tree() -> list[str]:
    """Return list of any missing expected directories."""
    raise NotImplementedError


def check_required_files() -> list[str]:
    """Return list of any missing expected files."""
    raise NotImplementedError


def check_env_variables() -> list[str]:
    """Return list of any required .env variables that are not set."""
    raise NotImplementedError


def check_imports() -> list[str]:
    """Try importing all core modules. Return list of any that fail."""
    raise NotImplementedError


def check_external_tools() -> dict[str, bool]:
    """Check garak and pyrit are installed and accessible."""
    raise NotImplementedError


def main() -> None:
    """Run all checks and print a coloured pass/fail summary."""
    raise NotImplementedError


if __name__ == "__main__":
    main()