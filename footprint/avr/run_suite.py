#!/usr/bin/env python3
"""Build and run RSA verification on simavr for AVR ATmega2560.

Generates a markdown metrics table from the results.
"""

import os
import re
import subprocess
import sys
import tempfile

EXAMPLES = [
    ("baseline", "baseline", ["baseline"]),
    ("test_verify", "verify", []),
]
TIMEOUT_RUN = 120  # seconds per simavr run
TIMEOUT_BUILD = 600  # seconds for cargo build
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(tempfile.gettempdir(), "rsa_footprint_avr")
SYSROOT = subprocess.run(
    ["rustc", "--print", "sysroot"], capture_output=True, text=True, check=True
).stdout.strip()


def run_cmd(args, timeout=TIMEOUT_RUN, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    env = os.environ.copy()
    env.setdefault("CARGO_TARGET_DIR", TARGET_DIR)
    env["PATH"] = r"E:\m\depot_tools;" + env.get("PATH", "")
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
    """Get .text section size via cargo-size output."""
    try:
        args = ["cargo", "size", "--release", "--example", example]
        if features:
            args.extend(["--features", ",".join(features)])
        args.extend(["--", "-A"])
        rc, out, err = run_cmd(args, timeout=TIMEOUT_BUILD)
        if rc == 0:
            match = re.search(r"^\.text\s+(\d+)\s", out, re.MULTILINE)
            if match:
                return int(match.group(1))
        else:
            print(f"    cargo size failed (rc={rc}): {err.strip()}", file=sys.stderr)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"    cargo size not available: {e}", file=sys.stderr)
    return None


def parse_output(output):
    """Parse AVR serial output. Returns dict with accept, stack, time_ms, ticks."""
    result = {"accepted": False, "stack": None, "time_ms": None, "ticks": None}

    result["accepted"] = "ACCEPT" in output

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
    print("Building for AVR...", file=sys.stderr)
    for example, variant, features in EXAMPLES:
        if not build(example, features):
            print("\nFailures: 1", file=sys.stderr)
            print(f"  Build failed: {variant}", file=sys.stderr)
            return 1

    results = {}
    failures = []
    for example, variant, features in EXAMPLES:
        example_variant = f"{example}:{variant}"
        print(f"  Running {example_variant} on simavr...", file=sys.stderr)
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
    verify = results.get("verify")

    print()
    print("Metrics below are verify-minus-baseline deltas: the incremental flash, stack, and approximate runtime cost of RSA verification.")
    print()
    print("| Target | Backend | .text (KiB) | Stack (bytes) | Approx time (ms) |")
    print("|--------|---------|-------------|---------------|------------------|")
    if baseline and verify:
        delta_text = delta(
            verify,
            baseline,
            "text_size",
            formatter=lambda value: f"{value / 1024:.1f}",
        )
        delta_stack = delta(verify, baseline, "stack")
        delta_time = delta(verify, baseline, "time_ms")
        print(f"| ATmega2560 | u8 | {delta_text} | {delta_stack} | {delta_time} |")
    else:
        print("| ATmega2560 | u8 | - | - | - |")

    print()
    print("Approx time is measured by the demo harness timer and should be treated as a rough runtime proxy, not a precise benchmark.")

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
