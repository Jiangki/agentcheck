"""A fixture that proves AgentCheck does not execute scanned Python."""

from pathlib import Path


if __name__ == "__main__":
    Path("WAS_EXECUTED").write_text("This file should never appear.\n")
