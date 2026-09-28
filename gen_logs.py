"""
gen_logs.py — Log Generator for RedDragon Demo
================================================
Generates realistic log lines with configurable scenarios.
Each scenario prints a timestamped injection record so results
can be matched against detector alerts.

Usage:
    python gen_logs.py normal          # steady ~4% error rate
    python gen_logs.py spike           # normal → burst → recovery
    python gen_logs.py drift           # 5% → 40% gradual rise
    python gen_logs.py new_error       # inject novel error patterns
    python gen_logs.py rotate          # truncate file mid-stream
    python gen_logs.py garbage         # inject malformed lines
"""

import os
import sys

# Fix Windows console encoding
if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

import time
import random
import argparse
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "app.log")

# ── Realistic service names and messages ────────────────────────────────────

SERVICES = [
    "api-gateway", "auth-service", "payment-service",
    "data-pipeline", "user-service",
]

INFO_MESSAGES = [
    "Request processed successfully in {latency}ms",
    "Health check passed",
    "Cache hit for key user:{user_id}",
    "Session validated for user {user_id}",
    "Metrics flushed: {count} events",
    "Connection pool stats: active={active}, idle={idle}",
    "Scheduled task completed: cleanup_expired_sessions",
    "TLS handshake completed in {latency}ms",
    "Message consumed from queue: batch_id={batch_id}",
    "Rate limiter token replenished for client {client_id}",
]

WARN_MESSAGES = [
    "High latency detected: {latency}ms (threshold: 500ms)",
    "Connection pool usage at {pct}%",
    "Retry attempt {attempt} for downstream call to {service}",
    "Rate limit approaching: {count}/100 requests in current window",
    "Slow query detected: {latency}ms on users_table",
    "Memory usage at {pct}% of allocated heap",
]

# Known errors — these will be seen during warm-up (familiar)
ERROR_MESSAGES = [
    "Database connection timeout after {latency}ms",
    "Failed to process request: connection refused by {service}",
    "HTTP 503 from upstream: {service} unavailable",
    "Disk write failed: IO error on /var/data/logs",
    "Request validation failed: missing required field 'user_id'",
]

# Novel errors — NEVER generated during normal/warm-up traffic
NOVEL_ERROR_MESSAGES = [
    "FATAL: Certificate chain validation failed for endpoint vault.internal.corp",
    "SECURITY: Unauthorized token refresh attempt detected from unknown origin",
    "PANIC: Consensus protocol violation in distributed lock manager node-7",
    "CRITICAL: Data corruption detected in WAL segment at offset 8192",
]


# ── Helpers ─────────────────────────────────────────────────────────────────

def ts_now() -> str:
    """Current timestamp in log format."""
    now = datetime.now()
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}"


def fill_template(template: str) -> str:
    """Replace placeholders with realistic random values."""
    return template.format(
        latency=random.randint(50, 5000),
        user_id=random.randint(1000, 9999),
        count=random.randint(1, 500),
        active=random.randint(1, 50),
        idle=random.randint(0, 20),
        client_id=f"client-{random.randint(100, 999)}",
        batch_id=f"batch-{random.randint(10000, 99999)}",
        pct=random.randint(60, 95),
        attempt=random.randint(1, 5),
        service=random.choice(SERVICES),
    )


def make_line(level: str, service: str = None, message: str = None) -> str:
    """Build one log line in the canonical format."""
    svc = service or random.choice(SERVICES)
    if message is None:
        if level == "INFO":
            message = fill_template(random.choice(INFO_MESSAGES))
        elif level == "WARN":
            message = fill_template(random.choice(WARN_MESSAGES))
        else:
            message = fill_template(random.choice(ERROR_MESSAGES))
    return f"{ts_now()} [{level}] {svc} - {message}\n"


def write_lines(f, lines_per_sec: int, error_pct: float,
                duration: float, novel: bool = False):
    """Write log lines at a given rate for a given duration."""
    interval = 1.0 / max(lines_per_sec, 1)
    start = time.time()
    while time.time() - start < duration:
        r = random.random()
        if r < error_pct:
            if novel:
                line = make_line("ERROR", message=random.choice(NOVEL_ERROR_MESSAGES))
            else:
                line = make_line("ERROR")
        elif r < error_pct + 0.08:
            line = make_line("WARN")
        else:
            line = make_line("INFO")
        f.write(line)
        f.flush()
        time.sleep(interval)


def marker(msg: str):
    """Print a timestamped scenario marker."""
    print(f"[{ts_now()}] {msg}")


# ── Scenarios ───────────────────────────────────────────────────────────────

def scenario_normal(args):
    marker(f"📊 NORMAL — steady ~4% errors for {args.duration}s")
    with open(args.file, "a") as f:
        write_lines(f, args.rate, 0.04, args.duration)
    marker("✅ NORMAL complete")


def scenario_spike(args):
    marker(f"💥 SPIKE — pre={args.pre}s, burst={args.spike_duration}s "
           f"at {int(args.spike_pct * 100)}%, post={args.post}s")
    with open(args.file, "a") as f:
        marker("  Phase 1: Normal traffic")
        write_lines(f, args.rate, 0.04, args.pre)

        marker(f"  Phase 2: 💥 ERROR SPIKE at {int(args.spike_pct * 100)}%")
        write_lines(f, args.rate, args.spike_pct, args.spike_duration)

        marker("  Phase 3: Recovery (normal)")
        write_lines(f, args.rate, 0.04, args.post)
    marker("✅ SPIKE complete")


def scenario_drift(args):
    marker(f"📈 DRIFT — 5% → 40% over {args.duration}s")
    interval = 1.0 / max(args.rate, 1)
    start = time.time()
    last_report = 0

    with open(args.file, "a") as f:
        while time.time() - start < args.duration:
            progress = (time.time() - start) / args.duration
            error_pct = 0.05 + 0.35 * progress

            elapsed = int(time.time() - start)
            if elapsed > 0 and elapsed % 15 == 0 and elapsed != last_report:
                marker(f"  Drift: error rate ≈ {error_pct:.0%}")
                last_report = elapsed

            r = random.random()
            if r < error_pct:
                f.write(make_line("ERROR"))
            elif r < error_pct + 0.08:
                f.write(make_line("WARN"))
            else:
                f.write(make_line("INFO"))
            f.flush()
            time.sleep(interval)
    marker("✅ DRIFT complete")


def scenario_new_error(args):
    marker(f"🆕 NEW_ERROR — inject novel patterns over {args.duration}s")
    interval = 1.0 / max(args.rate, 1)
    start = time.time()
    novel_count = 0

    with open(args.file, "a") as f:
        while time.time() - start < args.duration:
            r = random.random()
            if r < 0.05:                              # ~5% errors total
                if random.random() < 0.3:             # 30% of errors are novel
                    msg = random.choice(NOVEL_ERROR_MESSAGES)
                    f.write(make_line("ERROR", message=msg))
                    novel_count += 1
                    if novel_count <= 8:
                        marker(f"  🆕 Injected: {msg[:70]}")
                else:
                    f.write(make_line("ERROR"))
            else:
                f.write(make_line("INFO"))
            f.flush()
            time.sleep(interval)
    marker(f"✅ NEW_ERROR complete ({novel_count} novel errors injected)")


def scenario_rotate(args):
    marker("🔄 ROTATE — write, truncate, resume")
    with open(args.file, "a") as f:
        marker("  Phase 1: Normal traffic for 10s")
        write_lines(f, args.rate, 0.04, 10)

    marker("  🔄 TRUNCATING log file now")
    open(args.file, "w").close()
    time.sleep(2)

    with open(args.file, "a") as f:
        marker("  Phase 2: Resumed traffic after rotation for 10s")
        write_lines(f, args.rate, 0.04, 10)
    marker("✅ ROTATE complete")


def scenario_garbage(args):
    marker(f"🗑️  GARBAGE — malformed lines mixed in for {args.duration}s")
    garbage_lines = [
        "this is not a log line at all\n",
        "{{{{malformed json}}}\n",
        "\n",
        "ERROR but no timestamp or service\n",
        "2026-01-01T00:00:00.000 missing brackets - oops\n",
        "   \t  \n",
    ]
    interval = 1.0 / max(args.rate, 1)
    start = time.time()
    garbage_count = 0

    with open(args.file, "a") as f:
        while time.time() - start < args.duration:
            if random.random() < 0.20:                # 20% garbage
                f.write(random.choice(garbage_lines))
                garbage_count += 1
            else:
                f.write(make_line("INFO"))
            f.flush()
            time.sleep(interval)
    marker(f"✅ GARBAGE complete ({garbage_count} malformed lines)")


# ── CLI ─────────────────────────────────────────────────────────────────────

SCENARIOS = {
    "normal":    scenario_normal,
    "spike":     scenario_spike,
    "drift":     scenario_drift,
    "new_error": scenario_new_error,
    "rotate":    scenario_rotate,
    "garbage":   scenario_garbage,
}


def main():
    parser = argparse.ArgumentParser(
        description="RedDragon Log Generator — realistic log scenarios for demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Scenarios:
  normal     Steady low error rate (~4%%)
  spike      Normal → sudden burst → recovery
  drift      Error rate rising from 5%% to 40%%
  new_error  Inject never-before-seen error patterns
  rotate     Truncate the file mid-stream
  garbage    Mix malformed lines with normal traffic
""",
    )
    parser.add_argument(
        "scenario", choices=SCENARIOS.keys(), help="Scenario to run"
    )
    parser.add_argument("--file", default=LOG_FILE_PATH,
                        help=f"Log file (default: {LOG_FILE_PATH})")
    parser.add_argument("--rate", type=int, default=20,
                        help="Lines per second (default: 20)")
    parser.add_argument("--duration", type=int, default=120,
                        help="Duration in seconds (default: 120)")
    # Spike-specific
    parser.add_argument("--pre", type=int, default=40,
                        help="Spike: normal seconds before burst (default: 40)")
    parser.add_argument("--spike-duration", type=int, default=20,
                        help="Spike: burst duration (default: 20)")
    parser.add_argument("--spike-pct", type=float, default=0.65,
                        help="Spike: error %% during burst (default: 0.65)")
    parser.add_argument("--post", type=int, default=30,
                        help="Spike: normal seconds after burst (default: 30)")

    args = parser.parse_args()

    print(f"\n{'=' * 54}")
    print(f"  🐉 RedDragon Log Generator")
    print(f"     File:     {args.file}")
    print(f"     Scenario: {args.scenario}")
    print(f"     Rate:     {args.rate} lines/sec")
    print(f"{'=' * 54}\n")

    try:
        SCENARIOS[args.scenario](args)
    except KeyboardInterrupt:
        print(f"\n[{ts_now()}] Stopped by user (Ctrl+C)")
    except Exception as e:
        print(f"\n[{ts_now()}] ❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
