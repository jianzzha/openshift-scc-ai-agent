#!/usr/bin/env python3

"""
OpenShift SCC AI Agent
Main entry point for the application
"""

import sys
import os
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.cli.main import cli

if __name__ == "__main__":
    cli() 