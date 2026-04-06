#!/usr/bin/env python3
"""QEMU wrapper for RISC-V demo — kills QEMU after METRIC line or timeout.

sifive_e has no semihosting exit mechanism, so we monitor serial output
and terminate QEMU once the METRIC line appears (or on timeout).
"""

import subprocess
import sys
import threading

TIMEOUT = 60  # seconds


def main():
    if len(sys.argv) < 2:
        print("Usage: qemu_wrapper.py <elf>", file=sys.stderr)
        return 1

    elf = sys.argv[1]
    cmd = [
        "qemu-system-riscv32",
        "-nographic",
        "-machine", "sifive_e",
        "-bios", "none",
        "-kernel", elf,
    ]

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )

    timed_out = [False]

    def on_timeout():
        timed_out[0] = True
        proc.kill()

    timer = threading.Timer(TIMEOUT, on_timeout)
    timer.start()

    accepted = False
    try:
        for raw_line in iter(proc.stdout.readline, b""):
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            print(line, flush=True)
            if "rsa ACCEPT" in line:
                accepted = True
            if "rsa REJECT" in line:
                accepted = False
            if line.startswith("METRIC ") or line.startswith("PANIC:"):
                proc.terminate()
                break
    finally:
        timer.cancel()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    if timed_out[0]:
        print("TIMEOUT", file=sys.stderr)
        return 1

    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
