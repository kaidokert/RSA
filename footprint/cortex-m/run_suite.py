#!/usr/bin/env python3
"""Build and run RSA examples on QEMU for all Cortex-M targets.

Generates a markdown metrics table from the results.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

EXAMPLES = [
    ("baseline", "baseline", "baseline", ["baseline"]),
    ("ed25519_u8", "u8", "verify", []),
    ("ed25519_u32", "u32", "verify", []),
]
TARGETS = [
    ("thumbv6m-none-eabi", "M0"),
    ("thumbv7m-none-eabi", "M3"),
    ("thumbv7em-none-eabi", "M4"),
]
TIMEOUT_RUN = 120  # seconds per QEMU run
TIMEOUT_BUILD = 600  # seconds for cargo build
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(tempfile.gettempdir(), "rsa_footprint_cortexm")
SYSROOT = subprocess.run(
    ["rustc", "--print", "sysroot"], capture_output=True, text=True, check=True
).stdout.strip()
LLVM_SIZE = Path(SYSROOT) / "lib" / "rustlib" / "x86_64-pc-windows-msvc" / "bin" / "llvm-size.exe"


def run_cmd(args, timeout=TIMEOUT_RUN, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    env = os.environ.copy()
    env.setdefault("CARGO_TARGET_DIR", TARGET_DIR)
    env["PATH"] = r"C:\Program Files\qemu;" + env.get("PATH", "")
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


def build_examples(target, features):
    """Build all examples for a target. Returns True on success."""
    args = ["cargo", "build", "--target", target, "--release", "--examples"]
    if features:
        args.extend(["--features", ",".join(features)])
    rc, _out, err = run_cmd(
        args,
        timeout=TIMEOUT_BUILD,
    )
    if rc != 0:
        print(f"BUILD FAILED for {target}:", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_qemu(target, example, features):
    """Run an example on QEMU via cargo run. Returns stdout+stderr."""
    args = ["cargo", "run", "--target", target, "--release", "--example", example]
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


def artifact_path(target, example):
    return Path(TARGET_DIR) / target / "release" / "examples" / example


def get_text_size(target, example, features):
    """Get .text section size via llvm-size output."""
    try:
        args = [str(LLVM_SIZE), "-A", str(artifact_path(target, example))]
        rc, out, err = run_cmd(args, timeout=TIMEOUT_BUILD)
        if rc == 0:
            match = re.search(r"^\.text\s+(\d+)\s", out, re.MULTILINE)
            if match:
                return int(match.group(1))
        else:
            print(f"    llvm-size failed (rc={rc}): {err.strip()}", file=sys.stderr)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"    llvm-size not available: {e}", file=sys.stderr)
    return None


def parse_metric(output):
    """Parse METRIC line from QEMU output. Returns dict or None."""
    m = re.search(
        r"METRIC stack:(\d+) cycles:(\d+) target:(\S+) backend:(\S+)", output
    )
    if m:
        return {
            "stack": int(m.group(1)),
            "cycles": int(m.group(2)),
            "target": m.group(3),
            "backend": m.group(4),
        }
    return None


def delta(verify_row, baseline_row, key, formatter=str):
    verify_value = verify_row.get(key)
    baseline_value = baseline_row.get(key)
    if verify_value is None or baseline_value is None:
        return "-"
    return formatter(verify_value - baseline_value)


def main():
    results = {}  # (example, target) -> {stack, cycles, text_size, accepted}
    failures = []

    for target, label in TARGETS:
        print(f"Building for {target}...", file=sys.stderr)
        build_status = {}
        feature_variants = {}
        for _, _, variant, features in EXAMPLES:
            feature_key = tuple(features)
            feature_variants.setdefault(feature_key, []).append(variant)
        for feature_key, variants in feature_variants.items():
            feature_list = list(feature_key)
            build_ok = build_examples(target, feature_list)
            build_status[feature_key] = build_ok
            if not build_ok:
                joined_variants = ", ".join(sorted(set(variants)))
                failures.append(f"Build failed: {target} ({joined_variants})")
        for example, backend, variant, features in EXAMPLES:
            feature_key = tuple(features)
            if not build_status.get(feature_key, False):
                continue
            key = (backend, variant, target)
            print(f"  Running {example} on {label}...", file=sys.stderr)
            try:
                output = run_qemu(target, example, features)
            except subprocess.TimeoutExpired:
                print("    TIMEOUT", file=sys.stderr)
                failures.append(f"Timeout: {example} on {label}")
                continue

            accepted = "rsa ACCEPT" in output
            metric = parse_metric(output)
            text_size = get_text_size(target, example, features)

            if not metric:
                print(f"    METRIC line missing", file=sys.stderr)
                failures.append(f"Missing METRIC: {example} on {label}")
            if text_size is None:
                print(f"    .text size unavailable", file=sys.stderr)
                failures.append(f"Missing .text size: {example} on {label}")

            results[key] = {
                "accepted": accepted,
                "backend": backend,
                "variant": variant,
                "stack": metric["stack"] if metric else None,
                "cycles": metric["cycles"] if metric else None,
                "text_size": text_size,
            }

            status = "ACCEPT" if accepted else "REJECT"
            print(f"    {status}", file=sys.stderr)
            if not accepted:
                failures.append(f"REJECT: {example} on {label}")

    print()
    print("Metrics below are verify-minus-baseline deltas: the incremental flash, stack, and approximate cycle cost of RSA verification.")
    print()
    print("| Target | Backend | .text (KiB) | Stack (bytes) | Approx cycles (k) |")
    print("|--------|---------|-------------|---------------|-------------------|")
    for target, label in TARGETS:
        baseline_row = results.get(("baseline", "baseline", target))
        for backend in ("u8", "u32"):
            verify_row = results.get((backend, "verify", target))
            if verify_row is None or baseline_row is None:
                print(f"| {label} | {backend} | - | - | - |")
                continue
            delta_text = delta(
                verify_row,
                baseline_row,
                "text_size",
                formatter=lambda value: f"{value / 1024:.1f}",
            )
            delta_stack = delta(verify_row, baseline_row, "stack")
            delta_cycles = delta(verify_row, baseline_row, "cycles")
            print(f"| {label} | {backend} | {delta_text} | {delta_stack} | {delta_cycles} |")

    print()
    print("Approx cycles are derived from the demo harness counters and should be treated as a rough instruction-cost proxy, not a precise benchmark.")

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
