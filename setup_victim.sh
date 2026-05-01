#!/bin/bash
# setup_victim.sh - Install eBPF attack dependencies on Ubuntu victim VM
# Run this ONCE on the victim VM before running exfiltrate.py
# Usage: sudo bash setup_victim.sh

set -e

echo "=================================================="
echo "  eBPF Attack Lab - Victim VM Setup"
echo "=================================================="
echo ""

# Check we're root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root: sudo bash setup_victim.sh"
    exit 1
fi

echo "[*] Updating package list..."
apt update -q

echo "[*] Installing kernel headers (required for eBPF compilation)..."
apt install -y linux-headers-$(uname -r)

echo "[*] Installing BCC (eBPF Python bindings)..."
apt install -y python3-bpfcc bpfcc-tools libbpfcc-dev

echo "[*] Installing bpftool (used by detection/mitigation)..."
apt install -y linux-tools-$(uname -r) linux-tools-common || \
apt install -y bpftool || \
echo "[!] bpftool install failed - try manually: apt install bpftool"

echo "[*] Installing auditd (used by detection agent)..."
apt install -y auditd audispd-plugins

echo "[*] Configuring auditd to monitor bpf() syscall..."
# Add audit rule to monitor bpf() syscall
cat >> /etc/audit/rules.d/ebpf-monitor.rules << 'EOF'
# Monitor bpf() syscall invocations
-a always,exit -F arch=b64 -S bpf -k bpf_call
-a always,exit -F arch=b32 -S bpf -k bpf_call
EOF

# Restart auditd to apply rules
service auditd restart
echo "[+] auditd configured and restarted"

echo "[*] Granting CAP_BPF to demonstrate the attack..."
# In a real scenario this would already be set on a dev account
# For the lab we explicitly grant it to the ubuntu user
setcap cap_bpf+eip /usr/bin/python3 2>/dev/null || true

echo "[*] Installing Python dependencies..."
apt install -y python3-pip
pip3 install psutil 2>/dev/null || true

echo ""
echo "=================================================="
echo "[+] Setup complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo "  1. Start receiver.py on Kali VM (10.10.0.10):"
echo "     python3 receiver.py"
echo ""
echo "  2. Run the attack on this victim VM:"
echo "     sudo python3 exfiltrate.py"
echo ""
echo "  3. To generate interesting interceptable data, run in another terminal:"
echo "     watch -n 1 cat /etc/passwd"
echo "     OR: while true; do echo 'secret_api_key=abc123' | cat; sleep 2; done"
echo ""
echo "Kernel version: $(uname -r)"
echo "BCC version: $(python3 -c 'import bcc; print(bcc.__version__)' 2>/dev/null || echo 'check manually')"