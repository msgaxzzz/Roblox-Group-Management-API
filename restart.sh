#!/bin/bash

while true; do
    echo "$(date) starting"
    python Main.py
    echo "$(date) wait 20mins"
    sleep 700
done
