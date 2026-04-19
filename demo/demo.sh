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

echo -e "${GREEN}[+] Starting target process (PID: $!)...${NC}"
./demo/target > /dev/null 2>&1 &
TARGET_PID=$!

echo -e "${BLUE}[*] Target is running with PID ${TARGET_PID}${NC}"
echo -e "${BLUE}[*] Launching gspy in 2 seconds...${NC}"
sleep 2

trap "kill $TARGET_PID; echo -e '\n${GREEN}[+] Cleaned up demo target.${NC}'; exit" INT TERM EXIT

sudo ./bin/gspy --pid $TARGET_PID
