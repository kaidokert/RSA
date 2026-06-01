#!/usr/bin/env python3
"""Build and run RSA verification on QEMU for RISC-V sifive_e.

Generates a markdown metrics table from the results.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

EXAMPLES = [
    # (example, backend, variant, [features])
    ("baseline",   "baseline", "baseline",         ["baseline"]),
    # SHA-1 + e=3 at 512-bit — the lightest workload cell in the matrix.
    ("rsa_verify", "u8",       "rsa512_sha1",      ["key_512",  "limb_u8",  "hash_sha1"]),
    ("rsa_verify", "u32",      "rsa512_sha1",      ["key_512",  "limb_u32", "hash_sha1"]),
    # SHA-256 + e=65537 sweep — the rest of the matrix.
    ("rsa_verify", "u8",       "rsa512_sha256",    ["key_512",  "limb_u8",  "hash_sha256"]),
    ("rsa_verify", "u32",      "rsa512_sha256",    ["key_512",  "limb_u32", "hash_sha256"]),
    ("rsa_verify", "u8",       "rsa768_sha256",    ["key_768",  "limb_u8",  "hash_sha256"]),
    ("rsa_verify", "u32",      "rsa768_sha256",    ["key_768",  "limb_u32", "hash_sha256"]),
    ("rsa_verify", "u8",       "rsa1024_sha256",   ["key_1024", "limb_u8",  "hash_sha256"]),
    ("rsa_verify", "u32",      "rsa1024_sha256",   ["key_1024", "limb_u32", "hash_sha256"]),
    ("rsa_verify", "u8",       "rsa1536_sha256",   ["key_1536", "limb_u8",  "hash_sha256"]),
    ("rsa_verify", "u32",      "rsa1536_sha256",   ["key_1536", "limb_u32", "hash_sha256"]),
    ("rsa_verify", "u8",       "rsa2048_sha256",   ["key_2048", "limb_u8",  "hash_sha256"]),
    ("rsa_verify", "u32",      "rsa2048_sha256",   ["key_2048", "limb_u32", "hash_sha256"]),
    # 3072/4096 time out under the QEMU runtime budget — re-enable when fixed.
    # ("rsa_verify", "u8",       "rsa3072_sha256",   ["key_3072", "limb_u8",  "hash_sha256"]),
    # ("rsa_verify", "u32",      "rsa3072_sha256",   ["key_3072", "limb_u32", "hash_sha256"]),
    # ("rsa_verify", "u8",       "rsa4096_sha256",   ["key_4096", "limb_u8",  "hash_sha256"]),
    # ("rsa_verify", "u32",      "rsa4096_sha256",   ["key_4096", "limb_u32", "hash_sha256"]),
]
# Variant -> (key bits label, hash label) in render order.
KEY_VARIANTS = [
    ("rsa512_sha1",    "512",  "sha1"),
    ("rsa512_sha256",  "512",  "sha256"),
    ("rsa768_sha256",  "768",  "sha256"),
    ("rsa1024_sha256", "1024", "sha256"),
    ("rsa1536_sha256", "1536", "sha256"),
    ("rsa2048_sha256", "2048", "sha256"),
    # ("rsa3072_sha256", "3072", "sha256"),
    # ("rsa4096_sha256", "4096", "sha256"),
]
TIMEOUT_RUN = 300  # seconds per QEMU run (4096-bit can take a while)
TIMEOUT_BUILD = 600  # seconds for cargo build
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(tempfile.gettempdir(), "rsa_footprint_riscv")


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


def build(features):
    """Build all examples. Returns True on success."""
    args = ["cargo", "build", "--release", "--examples"]
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


def run_qemu(example, features):
    """Run an example via cargo run (uses .cargo/config.toml runner). Returns stdout+stderr."""
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
    results = {}  # (backend, variant) -> {accepted, stack, cycles, text_size}
    failures = []

    print("Running examples for RISC-V...", file=sys.stderr)
    for example, backend, variant, features in EXAMPLES:
        feat_str = ",".join(features) if features else "no-features"
        print(f"  {example} [{feat_str}] on QEMU sifive_e...", file=sys.stderr)
        try:
            # cargo run rebuilds with the specified features. Each
            # (example, features) combo produces a fresh binary at the
            # same path, so we run+size for each combo in sequence.
            output = run_qemu(example, features)
        except subprocess.TimeoutExpired:
            print("    TIMEOUT", file=sys.stderr)
            failures.append(f"Timeout: {example} [{feat_str}]")
            continue

        accepted = "rsa ACCEPT" in output
        metric = parse_metric(output)
        text_size = get_text_size(example, features)

        status = "ACCEPT" if accepted else "REJECT"
        print(f"    {status}", file=sys.stderr)

        if not metric:
            print("    METRIC line missing", file=sys.stderr)
            failures.append(f"Missing METRIC: {example} [{feat_str}]")
        if text_size is None:
            print("    .text size unavailable", file=sys.stderr)
            failures.append(f"Missing .text size: {example} [{feat_str}]")
        if not accepted:
            failures.append(f"REJECT: {example} [{feat_str}]")

        results[(backend, variant)] = {
            "accepted": accepted,
            "stack": metric["stack"] if metric else None,
            "cycles": metric["cycles"] if metric else None,
            "text_size": text_size,
        }

    # Generate markdown table
    print()
    print("Metrics below are verify-minus-baseline deltas: the incremental flash, stack, and approximate cycle cost of RSA verification.")
    print()
    print("| Target | Key bits | Hash   | Backend | .text (KiB) | Stack (bytes) | Approx cycles (k) |")
    print("|--------|----------|--------|---------|-------------|---------------|-------------------|")

    baseline = results.get(("baseline", "baseline"))
    for variant, key_label, hash_label in KEY_VARIANTS:
        for backend in ("u8", "u32"):
            verify = results.get((backend, variant))
            if verify is None or baseline is None:
                print(f"| sifive_e (RV32) | {key_label} | {hash_label} | {backend} | - | - | - |")
                continue
            delta_text = delta(
                verify,
                baseline,
                "text_size",
                formatter=lambda value: f"{value / 1024:.1f}",
            )
            delta_stack = delta(verify, baseline, "stack")
            # Wire format from lib.rs already pre-scales cycles by 1000 so the
            # METRIC value is in "k" units, matching cortex-m. Don't divide again.
            delta_cycles = delta(verify, baseline, "cycles")
            print(f"| sifive_e (RV32) | {key_label} | {hash_label} | {backend} | {delta_text} | {delta_stack} | {delta_cycles} |")

    print()
    print("Approx cycles are derived from the demo harness counters and should be treated as a rough instruction-cost proxy, not a precise benchmark.")

    if failures:
        print(f"\nFailures (non-fatal — shown as `-` in table): {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
