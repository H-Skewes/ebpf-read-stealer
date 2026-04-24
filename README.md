# eBPF Program Injection Attack - Lab Files

Educational simulation of an eBPF kernel rootkit for the cloud security lab.
Simulates techniques used by BPFDoor and Symbiote malware.

## Files

| File | Runs On | Purpose |
|------|---------|---------|
| `intercept.c` | Victim VM (kernel) | eBPF program that hooks read() syscall |
| `exfiltrate.py` | Victim VM | Loads eBPF program, reads ring buffer, sends data to attacker |
| `receiver.py` | Kali Attacker VM | Listens for and saves exfiltrated data |
| `setup_victim.sh` | Victim VM | Installs all dependencies |

## Lab Network

```
Kali Attacker VM:  10.10.0.10  <- run receiver.py here
Victim Ubuntu VM:  10.10.0.30  <- run exfiltrate.py here
Log Collector VM:  10.10.0.20  <- runs detection agent
```

## Setup Steps

### Step 1 - On Victim VM (10.10.0.30)
Copy all files to the victim VM:
```bash
scp intercept.c exfiltrate.py setup_victim.sh ubuntu@10.10.0.30:~/ebpf_attack/
```

Install dependencies:
```bash
sudo bash setup_victim.sh
```

### Step 2 - On Kali VM (10.10.0.10)
Copy receiver to Kali:
```bash
scp receiver.py kali@10.10.0.10:~/
```

### Step 3 - Run The Attack

**On Kali - start the receiver FIRST:**
```bash
python3 receiver.py
```

**On Victim VM - launch the attack:**
```bash
sudo python3 exfiltrate.py
```

**On Victim VM - generate interesting data to intercept (new terminal):**
```bash
# Simulate credentials being read
while true; do
    echo "db_password=SuperSecret123" > /tmp/creds.txt
    cat /tmp/creds.txt
    sleep 2
done
```

You should see the intercepted data appear on the Kali receiver in real time.

## How It Works

```
Victim VM Kernel:
  read() syscall → eBPF hook triggers → data written to ring buffer
                                                    ↓
Victim VM Userspace:
  exfiltrate.py reads ring buffer → sends over TCP to Kali
                                                    ↓
Kali VM:
  receiver.py receives data → saves to stolen_data.txt → displays in terminal
```

## Troubleshooting

**"BCC not found"**
```bash
sudo apt install python3-bpfcc
```

**"Failed to load eBPF program"**
```bash
sudo apt install linux-headers-$(uname -r)
```

**"Connection refused" on victim**
Make sure receiver.py is running on Kali before starting exfiltrate.py

**"Permission denied"**
exfiltrate.py must be run with sudo

## Detection (for log collection agent)

The attack generates these detectable signals:
1. `bpf()` syscall from non-whitelisted process (visible in auditd)
2. New outbound TCP connection from victim to attacker on port 4444
3. `bpftool prog list` shows unexpected loaded program

Check auditd logs:
```bash
sudo ausearch -k bpf_call
```

Check loaded eBPF programs:
```bash
sudo bpftool prog list
```
