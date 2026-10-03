#!/bin/bash
set -euo pipefail
cd /opt/payload
mkdir -p parrot-results
exec > >(tee parrot-results/setup.log) 2>&1
finish() {
    code=$?
    printf '%s\n' "$code" > parrot-results/exit-code.txt
    if [ -d journey-results ]; then cp -a journey-results parrot-results/; fi
    journalctl -b --no-pager > parrot-results/boot-journal.txt
    sync
    systemctl poweroff
}
trap finish EXIT
uname -a > parrot-results/kernel.txt
cat /etc/os-release > parrot-results/os-release.txt
test -r /sys/kernel/btf/vmlinux
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-cache policy python3-mcp python3-typing-inspection > parrot-results/mcp-archive-availability.txt
apt-get install -y python3-venv python3-pip clang llvm libbpf-dev libelf-dev sudo
apt-get install -y ./packages/gspy/*.deb ./packages/procscope/*.deb
export PATH=/opt/payload/go/bin:$PATH
export GOPATH=/opt/payload/go-workspace
mkdir -p "$GOPATH"
apt-get install -y ./packages/mcpwn-red/*.deb
dpkg-query -W -f='${Package} ${Version}\n' mcpwn-red python3-mcp > parrot-results/debian-mcp-versions.txt
printf 'tools:\n  - name: echo\n    command: echo\n' > mcpwn.yaml
PATH="/opt/payload:$PATH" mcpwn-red probe --transport stdio > parrot-results/debian-probe.txt 2>&1
set +e
PATH="/opt/payload:$PATH" mcpwn-red scan --all --transport stdio --confirm-write --mcpwn-command /opt/payload/mcpwn --output-dir parrot-results/debian-assessment > parrot-results/debian-scan.txt 2>&1
scan_exit=$?
set -e
printf '%s\n' "$scan_exit" > parrot-results/debian-scan-exit.txt
test "$scan_exit" -eq 2
python3 -c 'import json; r=json.load(open("parrot-results/debian-assessment/results.json")); assert r["assessment_kind"] == "deployment" and r["summary"]["ERROR"] == 0 and r["summary"]["UNKNOWN"] > 0'
mcpwn-red report --input parrot-results/debian-assessment/results.json --format html --output parrot-results/debian-report.html
apt-get remove -y mcpwn-red
if command -v mcpwn-red; then exit 1; fi
python3 -m venv mcp-env
mcp-env/bin/pip install ./mcpwn-red-source pyte==0.8.2
useradd -M -d /opt/payload -s /bin/bash journey-user
printf 'journey-user ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/journey-user
chmod 0440 /etc/sudoers.d/journey-user
chown -R journey-user:journey-user /opt/payload
runuser -u journey-user -- env PATH="$PATH" GOPATH="$GOPATH" /opt/payload/mcp-env/bin/python qa/user_journey.py --out journey-results
