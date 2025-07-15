#!/bin/bash

# OpenShift SCC AI Agent Runner
# This script activates the virtual environment and runs the CLI

# Change to the directory containing this script
cd "$(dirname "$0")"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run setup first:"
    echo "  python -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment and run the CLI
source venv/bin/activate && python main.py "$@" 