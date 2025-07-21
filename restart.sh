#!/bin/bash

while true; do
    echo "$(date) starting"
    python Main.py
    echo "$(date) Waiting"
    sleep 700
done
