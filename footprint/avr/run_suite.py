#!/usr/bin/env python3
"""Build and run RSA verification on simavr for AVR ATmega2560.

Generates a markdown metrics table from the results.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

# Full local sweep. Sizes >= 2048 take >300s wall-clock under simavr so they
# are not even listed here; the chip itself can do them, simavr is the limit.
EXAMPLES_FULL = [
    # (example, variant, [features])
    ("baseline",   "baseline",        ["baseline"]),
    # SHA-1 + e=3 at 512-bit — the lightest workload cell in the matrix.
    ("rsa_verify", "rsa512_sha1",     ["key_512",  "hash_sha1"]),
    # SHA-256 + e=65537 sweep.
    ("rsa_verify", "rsa512_sha256",   ["key_512",  "hash_sha256"]),
    ("rsa_verify", "rsa768_sha256",   ["key_768",  "hash_sha256"]),
    ("rsa_verify", "rsa1024_sha256",  ["key_1024", "hash_sha256"]),
    ("rsa_verify", "rsa1536_sha256",  ["key_1536", "hash_sha256"]),
]
# CI ("fast") sweep — only 512-bit cells. Anything above that pushes the
# GitHub-runner wall-clock past patience. Trigger via --fast or RSA_FOOTPRINT_FAST=1.
EXAMPLES_FAST = [
    ("baseline",   "baseline",        ["baseline"]),
    ("rsa_verify", "rsa512_sha1",     ["key_512",  "hash_sha1"]),
    ("rsa_verify", "rsa512_sha256",   ["key_512",  "hash_sha256"]),
]

FAST = "--fast" in sys.argv or os.environ.get("RSA_FOOTPRINT_FAST") == "1"
EXAMPLES = EXAMPLES_FAST if FAST else EXAMPLES_FULL

# Variant -> (key bits label, hash label) in render order.
KEY_VARIANTS_FULL = [
    ("rsa512_sha1",    "512",  "sha1"),
    ("rsa512_sha256",  "512",  "sha256"),
    ("rsa768_sha256",  "768",  "sha256"),
    ("rsa1024_sha256", "1024", "sha256"),
    ("rsa1536_sha256", "1536", "sha256"),
]
KEY_VARIANTS_FAST = [
    ("rsa512_sha1",    "512",  "sha1"),
    ("rsa512_sha256",  "512",  "sha256"),
]
KEY_VARIANTS = KEY_VARIANTS_FAST if FAST else KEY_VARIANTS_FULL
TIMEOUT_RUN = 600  # seconds per simavr run (4096-bit AVR takes ~minute)
TIMEOUT_BUILD = 600  # seconds for cargo build
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(tempfile.gettempdir(), "rsa_footprint_avr")


def run_cmd(args, timeout=TIMEOUT_RUN, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    env = os.environ.copy()
    env.setdefault("CARGO_TARGET_DIR", TARGET_DIR)
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=SCRIPT_DIR,
        env=env,
        **kwargs
    )
    return result.returncode, result.stdout, result.stderr


def build(example, features):
    """Build the examples. Returns True on success."""
    args = ["cargo", "build", "--release", "--example", example]
    if features:
        args.extend(["--features", ",".join(features)])
    rc, _out, err = run_cmd(
        args,
        timeout=TIMEOUT_BUILD,
    )
    if rc != 0:
        print("BUILD FAILED:", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_simavr(example, features):
    """Run the example via cargo run (uses .cargo/config.toml runner). Returns stdout+stderr."""
    args = ["cargo", "run", "--release", "--example", example]
    if features:
        args.extend(["--features", ",".join(features)])
    rc, out, err = run_cmd(
        args
    )
    combined = out + err
    if rc != 0 and "ACCEPT" not in combined and "REJECT" not in combined:
        print(f"    cargo run failed (rc={rc}):", file=sys.stderr)
        print(combined, file=sys.stderr)
    return combined


def get_text_size(example, features):
    """Get .text section size via cargo-bloat JSON output."""
    try:
        args = [
            "cargo", "bloat", "--release", "--example", example,
            "--message-format=json",
        ]
        if features:
            args.extend(["--features", ",".join(features)])
        rc, out, err = run_cmd(args, timeout=TIMEOUT_BUILD)
        if rc == 0:
            json_line = out.strip().split("\n")[-1]
            data = json.loads(json_line)
            return data.get("text-section-size")
        else:
            print(f"    cargo-bloat failed (rc={rc}): {err.strip()}", file=sys.stderr)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"    cargo-bloat not available: {e}", file=sys.stderr)
    except (json.JSONDecodeError, IndexError) as e:
        print(f"    cargo-bloat JSON parse error: {e}", file=sys.stderr)
    return None


def parse_output(output):
    """Parse AVR serial output. Returns dict with accept, stack, time_ms, ticks."""
    result = {"accepted": False, "stack": None, "time_ms": None, "ticks": None}

    result["accepted"] = "ACCEPT" in output

    measurement = re.search(
        r"EM_MEASUREMENT schema:\d+ benchmark:\S+ ticks:(\d+) "
        r"unit:timer-ticks frequency_hz:(\d+) wrapped:([01])",
        output,
    )
    if measurement:
        if measurement.group(3) == "0" and int(measurement.group(2)) > 0:
            result["ticks"] = int(measurement.group(1))
            result["time_ms"] = result["ticks"] * 1000 // int(measurement.group(2))
    else:
        m = re.search(r"Time:\s*(\d+)\s*ms\s*\((\d+)\s*ticks\)", output)
        if m:
            result["time_ms"] = int(m.group(1))
            result["ticks"] = int(m.group(2))

    m = re.search(r"Max stack usage:\s*(\d+)\s*bytes", output)
    if m:
        result["stack"] = int(m.group(1))

    return result


def delta(verify_row, baseline_row, key, formatter=str):
    verify_value = verify_row.get(key)
    baseline_value = baseline_row.get(key)
    if verify_value is None or baseline_value is None:
        return "-"
    return formatter(verify_value - baseline_value)


def main():
    # `cargo run` rebuilds with the specified features. Since each combo
    # writes to the same example binary path, we build+run+size in sequence
    # per combo rather than batch-building up-front.
    print("Running examples for AVR...", file=sys.stderr)

    results = {}
    failures = []
    for example, variant, features in EXAMPLES:
        feat_str = ",".join(features) if features else "no-features"
        example_variant = f"{example}:{variant}"
        print(f"  {example} [{feat_str}] on simavr...", file=sys.stderr)
        try:
            output = run_simavr(example, features)
        except subprocess.TimeoutExpired:
            print("    TIMEOUT", file=sys.stderr)
            failures.append(f"Timeout: {example_variant}")
            continue

        result = parse_output(output)
        text_size = get_text_size(example, features)
        status = "ACCEPT" if result["accepted"] else "REJECT"
        print(f"    {status}", file=sys.stderr)

        missing = []
        if result["stack"] is None:
            missing.append("stack")
        if result["time_ms"] is None:
            missing.append("time")
        if text_size is None:
            missing.append(".text size")
        if missing:
            print(f"    Missing metrics: {', '.join(missing)}", file=sys.stderr)
            failures.append(f"Missing metrics for {example_variant}: {', '.join(missing)}")
        if not result["accepted"]:
            failures.append(f"REJECT: {example_variant}")

        results[variant] = {
            "accepted": result["accepted"],
            "stack": result["stack"],
            "time_ms": result["time_ms"],
            "ticks": result["ticks"],
            "text_size": text_size,
        }

    baseline = results.get("baseline")

    print()
    print("Metrics below are verify-minus-baseline deltas: the incremental flash, stack, and approximate runtime cost of RSA verification.")
    print()
    print("| Target | Key bits | Hash   | Backend | .text (KiB) | Stack (bytes) | Approx time (ms) |")
    print("|--------|----------|--------|---------|-------------|---------------|------------------|")
    for variant, key_label, hash_label in KEY_VARIANTS:
        verify = results.get(variant)
        if not (baseline and verify):
            print(f"| ATmega2560 | {key_label} | {hash_label} | u8 | - | - | - |")
            continue
        delta_text = delta(
            verify,
            baseline,
            "text_size",
            formatter=lambda value: f"{value / 1024:.1f}",
        )
        delta_stack = delta(verify, baseline, "stack")
        delta_time = delta(verify, baseline, "time_ms")
        print(f"| ATmega2560 | {key_label} | {hash_label} | u8 | {delta_text} | {delta_stack} | {delta_time} |")

    print()
    print("Approx time is measured by the demo harness timer and should be treated as a rough runtime proxy, not a precise benchmark.")

    if failures:
        print(f"\nFailures (shown as `-` in table): {len(failures)}", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
