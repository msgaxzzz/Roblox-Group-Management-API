#!/bin/bash

if command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
else
    echo "Neither python nor python3 found. Exiting."
    exit 1
fi

while true; do
    echo "$(date) starting"
    $PYTHON_CMD Main.py || echo "Error running Main.py"
    echo "$(date) Waiting"
    sleep 700
done
