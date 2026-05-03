#!/bin/bash
# setup_victim.sh - Install eBPF attack dependencies on Ubuntu victim VM
# Run this ONCE on the victim VM before running exfiltrate.py
# Usage: sudo bash setup_victim.sh

set -e

echo "  eBPF Attack setup"

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root: sudo bash setup_victim.sh"
    exit 1
fi

echo "update apt packages"
apt update -q

echo "installing linux depenedencies"
apt install -y linux-headers-$(uname -r)
apt install -y python3-bpfcc bpfcc-tools libbpfcc-dev
apt install -y linux-tools-$(uname -r) linux-tools-common || \
apt install -y bpftool || \
apt install -y auditd audispd-plugins
cat >> /etc/audit/rules.d/ebpf-monitor.rules << 'EOF'
# Monitor bpf() syscall invocations
-a always,exit -F arch=b64 -S bpf -k bpf_call
-a always,exit -F arch=b32 -S bpf -k bpf_call
EOF
service auditd restart


echo "Making sure perms are correct"
# In a real scenario this would already be set on a dev account
# For the lab we explicitly grant it to the ubuntu user
setcap cap_bpf+eip /usr/bin/python3 2>/dev/null || true

echo "installing python dependencies"
apt install -y python3-pip
pip3 install psutil 2>/dev/null || true

echo ""
echo "setup complete"
echo "Kernel version: $(uname -r)"
echo "BCC version: $(python3 -c 'import bcc; print(bcc.__version__)' 2>/dev/null || echo 'check manually')"