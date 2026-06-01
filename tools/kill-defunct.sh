#!/bin/bash
# Kill parent processes of defunct (zombie) processes.
# Zombies cannot be killed directly; must kill their parent.

set -euo pipefail

zombies=$(ps aux | awk '$8 ~ /Z/ {print $2}')

if [ -z "$zombies" ]; then
    echo "No defunct processes found."
    exit 0
fi

echo "Found defunct processes:"
ps aux | awk '$8 ~ /Z/ {print}'

echo ""
echo "Finding parent PIDs..."

for zpid in $zombies; do
    # Get parent PID
    ppid=$(ps -o ppid= -p "$zpid" 2>/dev/null | tr -d ' ' || true)
    
    if [ -z "$ppid" ] || [ "$ppid" = "1" ]; then
        echo "Zombie $zpid: parent is PID 1 (init), cannot kill"
        continue
    fi
    
    parent_cmd=$(ps -o comm= -p "$ppid" 2>/dev/null || echo "unknown")
    echo "Zombie $zpid: parent is PID $ppid ($parent_cmd)"
    echo "  Kill parent? (y/N): "
    read -r response
    
    if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
        echo "  Killing PID $ppid..."
        kill "$ppid" || echo "  Failed to kill $ppid"
    else
        echo "  Skipped."
    fi
done
