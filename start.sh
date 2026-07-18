#!/bin/bash
set -e

# Directory where start.sh is located
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$DIR/venv/bin/python3"

echo "=============================================="
echo " Starting Sentinel + Auditor8"
echo " Project Directory: $DIR"
echo "=============================================="

if [ ! -f "$VENV_PY" ]; then
    echo "[!] Virtual environment not found in $DIR/venv."
    echo "    Run first: ./install.sh"
    exit 1
fi

# Program command strings
CMD_SENTINEL="cd '$DIR' && sudo '$VENV_PY' sentinel.py; echo; echo '[Sentinel closed. Press Enter to close]'; read"
CMD_AUDIT="cd '$DIR' && '$VENV_PY' audit.py; echo; echo '[Audit8 closed. Press Enter to close]'; read"

open_terminal() {
    local title="$1"
    local command="$2"

    if command -v mate-terminal &> /dev/null; then
        mate-terminal --title="$title" -- bash -c "$command"
    elif command -v gnome-terminal &> /dev/null; then
        gnome-terminal --title="$title" -- bash -c "$command"
    elif command -v xfce4-terminal &> /dev/null; then
        xfce4-terminal --title="$title" -e "bash -c \"$command\""
    elif command -v konsole &> /dev/null; then
        konsole --new-tab -p tabtitle="$title" -e bash -c "$command"
    elif command -v xterm &> /dev/null; then
        xterm -T "$title" -e bash -c "$command" &
    else
        echo "[!] No known terminal emulator found."
        echo "    Run manually in two terminals:"
        echo "    1) sudo $VENV_PY sentinel.py"
        echo "    2) $VENV_PY audit.py"
        exit 1
    fi
}

echo "[1/2] Opening Sentinel terminal (packet capture)..."
open_terminal "Sentinel" "$CMD_SENTINEL"

# Short delay for Sentinel to start before Audit8
sleep 2

echo "[2/2] Opening Audit8 terminal (analysis engine)..."
open_terminal "Audit8" "$CMD_AUDIT"

echo ""
echo "Ready! Two terminals opened:"
echo "  - Sentinel: will request sudo password (packet capture)"
echo "  - Audit8: real-time dashboard"
echo ""
echo "To stop: close the windows or use Ctrl+C in each one."
