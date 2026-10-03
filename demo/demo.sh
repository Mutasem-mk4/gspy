#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# gspy interactive demo runner

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[*] Building gspy and demo target...${NC}"
make build
go build -o demo/target demo/target.go

echo -e "${GREEN}[+] Starting target process...${NC}"
DEMO_LOG=$(mktemp)
./demo/target "$DEMO_LOG" > /dev/null 2>&1 &
TARGET_PID=$!
trap 'kill "$TARGET_PID" 2>/dev/null || true; wait "$TARGET_PID" 2>/dev/null || true; rm -f "$DEMO_LOG"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo -e "${BLUE}[*] Target is running with PID ${TARGET_PID}${NC}"
echo -e "${BLUE}[*] Launching gspy in 2 seconds...${NC}"
sleep 2

sudo ./bin/gspy "$TARGET_PID"
