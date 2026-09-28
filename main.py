"""
RedDragon: Real-Time Log Anomaly Detection That Fights Alert Fatigue
====================================================================
A deterministic, real-time log anomaly detector using robust statistics
(median + MAD), incident grouping, and novel pattern detection.

No LLM, no ML model -- pure statistics, sub-second latency, zero training.
"""

import os
import sys

# Fix Windows console encoding (cp1252 cannot print Unicode emoji)
if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
import re
import time
import json
import uuid
import hashlib
import asyncio
import logging
import statistics
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

# ── Load environment variables ──────────────────────────────────────────────
load_dotenv()

# ── Logging setup ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("reddragon")

# ── Configuration (all from env vars with sensible defaults) ────────────────
LOG_FILE_PATH       = os.getenv("LOG_FILE_PATH", "app.log")
WARMUP_SECONDS      = int(os.getenv("WARMUP_SECONDS", "30"))
Z_THRESHOLD         = float(os.getenv("Z_THRESHOLD", "3.5"))
EPSILON             = float(os.getenv("EPSILON", "0.01"))
MIN_ABS_CHANGE      = float(os.getenv("MIN_ABS_CHANGE", "0.05"))
WINDOW_SECONDS      = int(os.getenv("WINDOW_SECONDS", "20"))
BUCKET_SECONDS      = int(os.getenv("BUCKET_SECONDS", "10"))
INCIDENT_CLOSE_SECS = int(os.getenv("INCIDENT_CLOSE_SECONDS", "15"))

# AWS Configuration
AWS_REGION          = os.getenv("AWS_REGION", "us-east-1")
AWS_ENDPOINT_URL    = os.getenv("AWS_ENDPOINT_URL", "").strip()  # empty → real AWS
AWS_ACCESS_KEY_ID   = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
AWS_SESSION_TOKEN   = os.getenv("AWS_SESSION_TOKEN", "").strip()
CW_LOG_GROUP        = os.getenv("CW_LOG_GROUP", "/reddragon/anomalies")
CW_LOG_STREAM       = os.getenv("CW_LOG_STREAM", "alerts")

# ── Log line regex ──────────────────────────────────────────────────────────
# Format: 2026-09-28T14:00:00.000 [INFO] service-name - Message here
LOG_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"\[(\w+)\]\s+"
    r"([\w._-]+)\s+-\s+"
    r"(.*)$"
)

# Pattern normalization: strip timestamps, numbers, UUIDs, IPs
PATTERN_STRIP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[\.\d]*|"
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|"
    r"\b0x[0-9a-fA-F]+\b|"
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|"
    r"\d+"
)


# ════════════════════════════════════════════════════════════════════════════
#  Data Structures
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class LogEntry:
    timestamp: float   # POSIX seconds
    level: str         # INFO, WARN, ERROR, FATAL
    service: str
    message: str


@dataclass
class Alert:
    id: str
    timestamp: str
    severity: str
    z_score: float
    rate: float
    baseline_median: float
    upper_band: float
    why: str
    alert_type: str            # "rate_anomaly" or "novel_pattern"
    pattern_hash: Optional[str] = None


# ════════════════════════════════════════════════════════════════════════════
#  Log Parser  (Req 1 helper)
# ════════════════════════════════════════════════════════════════════════════

def parse_log_line(line: str) -> Optional[LogEntry]:
    """Parse a single log line. Returns None for malformed lines (never crashes)."""
    try:
        m = LOG_LINE_RE.match(line.strip())
        if not m:
            return None
        ts_str, level, service, message = m.groups()
        ts = datetime.fromisoformat(ts_str).timestamp()
        return LogEntry(timestamp=ts, level=level.upper(), service=service, message=message)
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════════════════
#  Sliding Window  (Req 2)
# ════════════════════════════════════════════════════════════════════════════

class SlidingWindow:
    """Time-based sliding window that tracks events and computes error rate."""

    def __init__(self, window_seconds: int = WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.events: deque = deque()  # (timestamp_float, is_error_bool)

    def add(self, ts: float, is_error: bool):
        self.events.append((ts, is_error))
        self._expire()

    def _expire(self, now: float = None):
        if now is None:
            now = self.events[-1][0] if self.events else time.time()
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def error_rate(self) -> float:
        """Fraction of events in the window that are errors (0.0–1.0)."""
        self._expire(time.time())
        if not self.events:
            return 0.0
        errors = sum(1 for _, is_err in self.events if is_err)
        return errors / len(self.events)

    @property
    def total(self) -> int:
        self._expire(time.time())
        return len(self.events)


# ════════════════════════════════════════════════════════════════════════════
#  Baseline Tracker  (Req 3)
#  - Median + MAD of 10-second bucket error rates
#  - Warm-up period before alerting
#  - FREEZES inside this class when z > threshold (independent of IncidentManager)
# ════════════════════════════════════════════════════════════════════════════

class BaselineTracker:
    """Robust baseline using median + MAD.  Freezes during active anomalies."""

    def __init__(self):
        self.bucket_history: deque = deque()          # per-bucket error rates
        self.max_buckets = int(600 / BUCKET_SECONDS)  # ~10 min of history
        self.last_bucket_time: Optional[float] = None
        self.warmup_start: Optional[float] = None
        self._warmed_up = False
        self.frozen = False           # ← freezing lives HERE, not in IncidentManager

        # Current baseline values
        self.median = 0.0
        self.mad = 0.0
        self.upper_band = 0.0

    @property
    def is_warmed_up(self) -> bool:
        return self._warmed_up

    @property
    def warmup_elapsed(self) -> float:
        if self.warmup_start is None:
            return 0.0
        return time.time() - self.warmup_start

    def maybe_record_bucket(self, now: float, rate: float, has_data: bool):
        """Record a new bucket if BUCKET_SECONDS have elapsed and data exists."""
        if not has_data:
            return  # don't start warm-up until real log lines arrive

        if self.warmup_start is None:
            self.warmup_start = now
            self.last_bucket_time = now
            return

        if now - self.last_bucket_time < BUCKET_SECONDS:
            return

        self.last_bucket_time = now

        # Collect buckets during warm-up; SKIP during active anomaly (frozen)
        if not self.frozen:
            self.bucket_history.append(rate)
            while len(self.bucket_history) > self.max_buckets:
                self.bucket_history.popleft()
            self._recompute()

        # Warm-up completion
        if not self._warmed_up and (now - self.warmup_start) >= WARMUP_SECONDS:
            self._warmed_up = True
            logger.info(
                f"✅ Warm-up complete ({len(self.bucket_history)} buckets). "
                f"Baseline: median={self.median:.1%}, upper_band={self.upper_band:.1%}"
            )

    def _recompute(self):
        if len(self.bucket_history) < 2:
            return
        rates = list(self.bucket_history)
        self.median = statistics.median(rates)
        self.mad = statistics.median([abs(r - self.median) for r in rates])
        self.upper_band = self.median + Z_THRESHOLD * (1.4826 * self.mad + EPSILON)

    def is_anomaly(self, rate: float, window_total: int) -> tuple:
        """
        Returns (is_anomaly: bool, z_score: float).
        Freezes baseline updates whenever z > threshold.
        """
        # Guard against phantom error rate spikes when traffic drops to zero
        if not self._warmed_up or len(self.bucket_history) < 2 or window_total < 20:
            return False, 0.0

        denominator = 1.4826 * self.mad + EPSILON
        z = (rate - self.median) / denominator

        # ── Freeze baseline when z exceeds threshold (anomaly active) ──
        self.frozen = z > Z_THRESHOLD

        # Alert requires BOTH statistical AND practical significance
        is_anom = z > Z_THRESHOLD and abs(rate - self.median) >= MIN_ABS_CHANGE
        return is_anom, z


# ════════════════════════════════════════════════════════════════════════════
#  Severity Assignment  (Req 5)
#  z 3.5–<5 LOW │ 5–<8 MEDIUM │ 8–<12 HIGH │ ≥12 OR ≥30s CRITICAL
# ════════════════════════════════════════════════════════════════════════════

def assign_severity(z: float, persistence_secs: float,
                    rate: float, baseline_median: float) -> tuple:
    """Returns (severity_str, human-readable why_str)."""
    rate_pct = f"{rate * 100:.1f}%"
    base_pct = f"{baseline_median * 100:.1f}%"

    if z >= 12 or persistence_secs >= 30:
        parts = [f"z={z:.1f}", f"error rate {rate_pct} vs baseline {base_pct}"]
        if persistence_secs >= 30:
            parts.append(f"sustained {persistence_secs:.0f}s")
        return "CRITICAL", f"CRITICAL: {', '.join(parts)}"

    if z >= 8:
        return "HIGH", f"HIGH: z={z:.1f}, error rate {rate_pct} vs baseline {base_pct}"

    if z >= 5:
        return "MEDIUM", f"MEDIUM: z={z:.1f}, error rate {rate_pct} vs baseline {base_pct}"

    return "LOW", f"LOW: z={z:.1f}, error rate {rate_pct} vs baseline {base_pct}"


# ════════════════════════════════════════════════════════════════════════════
#  Pattern Tracker  (Novel Error Detection — simplified hash-based)
# ════════════════════════════════════════════════════════════════════════════

class PatternTracker:
    """Detects novel error patterns unseen during warm-up."""

    def __init__(self):
        self.known_hashes: set = set()   # hashes seen during warm-up
        self.all_hashes: set = set()     # all hashes ever seen
        self._recording = True           # True during warm-up

    def _normalize_and_hash(self, message: str) -> str:
        """Strip timestamps/numbers, take first 60 chars, MD5 hash."""
        normalized = " ".join(PATTERN_STRIP_RE.sub("#", message).split()[:4])
        return hashlib.md5(normalized.encode()).hexdigest()[:12]

    def end_warmup(self):
        self._recording = False
        logger.info(f"PatternTracker: locked {len(self.known_hashes)} known error patterns")

    def check(self, message: str) -> Optional[str]:
        """Returns hash if this is a NOVEL pattern, else None."""
        h = self._normalize_and_hash(message)

        if self._recording:
            self.known_hashes.add(h)
            self.all_hashes.add(h)
            return None

        if h not in self.all_hashes:
            self.all_hashes.add(h)
            logger.warning(f"🆕 Novel error pattern (hash={h}): {message[:80]}")
            return h
        return None


# ════════════════════════════════════════════════════════════════════════════
#  Incident Manager  (Anti Alert-Fatigue)
#  One updating incident card instead of per-tick alert spam
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Incident:
    id: str
    start_time: float
    start_timestamp: str
    peak_z: float
    current_z: float
    peak_rate: float
    current_rate: float
    severity: str
    why: str
    alert_count: int = 1
    status: str = "open"
    close_time: Optional[float] = None
    normal_since: Optional[float] = None
    raw_breaches: int = 1


class IncidentManager:
    """Groups continuous anomaly ticks into single incidents."""

    SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def __init__(self):
        self.active: Optional[Incident] = None
        self.history: list = []
        self.incident_counter = 0
        self.total_raw_breaches = 0

    def on_anomaly(self, z: float, rate: float, severity: str, why: str):
        """Called each tick during an anomaly. Returns (incident, 'opened'|'updated')."""
        self.total_raw_breaches += 1
        now = time.time()
        ts = datetime.now().strftime("%H:%M:%S")

        if self.active is None:
            self.incident_counter += 1
            self.active = Incident(
                id=f"INC-{self.incident_counter}", start_time=now,
                start_timestamp=ts, peak_z=z, current_z=z,
                peak_rate=rate, current_rate=rate,
                severity=severity, why=why,
            )
            logger.warning(f"🚨 Incident {self.active.id} OPENED — {why}")
            return self.active, "opened"

        inc = self.active
        inc.current_z = z
        inc.current_rate = rate
        inc.peak_z = max(inc.peak_z, z)
        inc.peak_rate = max(inc.peak_rate, rate)
        inc.alert_count += 1
        inc.raw_breaches += 1
        inc.normal_since = None
        # Severity only escalates, never downgrades during one incident
        if self.SEV_ORDER.get(severity, 0) > self.SEV_ORDER.get(inc.severity, 0):
            inc.severity = severity
        inc.why = why
        return inc, "updated"

    def on_normal(self):
        """Called each tick when rate is normal. Returns (incident, 'closed') or None."""
        if self.active is None:
            return None
        now = time.time()
        if self.active.normal_since is None:
            self.active.normal_since = now
        if now - self.active.normal_since >= INCIDENT_CLOSE_SECS:
            inc = self.active
            inc.status = "closed"
            inc.close_time = now
            dur = now - inc.start_time
            logger.info(
                f"✅ Incident {inc.id} CLOSED — "
                f"duration={dur:.0f}s, peak_z={inc.peak_z:.1f}, alerts={inc.alert_count}"
            )
            self.history.append(inc)
            self.active = None
            return inc, "closed"
        return None

    @property
    def duration(self) -> float:
        if self.active is None:
            return 0.0
        return time.time() - self.active.start_time


# ════════════════════════════════════════════════════════════════════════════
#  CloudWatch Pusher  (Req 8)
#  Async outbox → boto3 put_log_events (real AWS or moto emulator)
#  Never blocks or crashes detection.
# ════════════════════════════════════════════════════════════════════════════

class CloudWatchPusher:
    """Pushes alerts to CloudWatch Logs with retry.  Works with real AWS or moto."""

    def __init__(self):
        self.client = None
        self.sequence_token = None
        self.queue: asyncio.Queue = asyncio.Queue()
        self.pushes_ok = 0
        self.pushes_failed = 0
        self._flush_task = None
        self.using_emulator = False
        self.target_label = "unknown"
        self.connected = False

    # ── startup self-test ──────────────────────────────────────────────────
    def initialize(self) -> bool:
        """Create log group/stream if missing, push one self-test event."""
        try:
            # Setup masked access key string for logging
            masked_key = AWS_ACCESS_KEY_ID[:4] + "****" if len(AWS_ACCESS_KEY_ID) >= 4 else "****"
            
            client_kwargs = {"region_name": AWS_REGION}
            if AWS_ACCESS_KEY_ID:
                client_kwargs["aws_access_key_id"] = AWS_ACCESS_KEY_ID
            AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
            if AWS_SECRET_ACCESS_KEY:
                client_kwargs["aws_secret_access_key"] = AWS_SECRET_ACCESS_KEY
            if AWS_SESSION_TOKEN:
                client_kwargs["aws_session_token"] = AWS_SESSION_TOKEN

            if AWS_ENDPOINT_URL:
                client_kwargs["endpoint_url"] = AWS_ENDPOINT_URL
                self.using_emulator = True
                self.target_label = f"AWS-compatible emulator (moto)"
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] Target AWS: moto emulator at {AWS_ENDPOINT_URL}")
            else:
                self.using_emulator = False
                self.target_label = f"Real AWS CloudWatch Logs ({AWS_REGION}, {CW_LOG_GROUP})"
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] Target AWS: Real AWS (Region: {AWS_REGION}, Key: {masked_key})")
                
            self.client = boto3.client("logs", **client_kwargs)
            
            # STS Identity Check (Verify credentials)
            try:
                sts_client = boto3.client("sts", **client_kwargs)
                identity = sts_client.get_caller_identity()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] AWS Identity: Account {identity.get('Account')} | ARN: {identity.get('Arn')}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "InvalidClientTokenId" or code == "SignatureDoesNotMatch":
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] AWS STS Error: Invalid credentials or signature. Check AWS_ACCESS_KEY_ID / SECRET.")
                elif code == "ExpiredToken":
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] AWS STS Error: Session token expired. Refresh AWS_SESSION_TOKEN.")
                elif code == "AccessDenied":
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] AWS STS Error: Access Denied. Check IAM permissions.")
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] AWS STS Error: {e}")
                # Continue anyway, let CloudWatch creation try and explicitly fail
            except Exception as e:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] AWS STS Connection Error: {e}")

            # Create log group if missing
            try:
                self.client.describe_log_groups(logGroupNamePrefix=CW_LOG_GROUP)
                self.client.create_log_group(logGroupName=CW_LOG_GROUP)
                logger.info(f"Created log group: {CW_LOG_GROUP}")
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                    raise

            # Create log stream if missing
            try:
                self.client.create_log_stream(
                    logGroupName=CW_LOG_GROUP, logStreamName=CW_LOG_STREAM
                )
                logger.info(f"Created log stream: {CW_LOG_STREAM}")
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                    raise

            # Get current sequence token
            streams = self.client.describe_log_streams(
                logGroupName=CW_LOG_GROUP,
                logStreamNamePrefix=CW_LOG_STREAM, limit=1,
            )
            if streams.get("logStreams"):
                self.sequence_token = streams["logStreams"][0].get("uploadSequenceToken")

            # Self-test push
            self._put_events([{
                "timestamp": int(time.time() * 1000),
                "message": json.dumps({
                    "type": "self_test", "message": "RedDragon startup",
                    "timestamp": datetime.now().isoformat(),
                }),
            }])

            self.connected = True
            print("\n" + "=" * 64)
            print(f"[OK] CloudWatch self-test PASSED")
            print(f"   Target:     {self.target_label}")
            print(f"   Log Group:  {CW_LOG_GROUP}")
            print(f"   Log Stream: {CW_LOG_STREAM}")
            print("=" * 64 + "\n")
            return True

        except NoCredentialsError:
            self.connected = False
            print("\n" + "=" * 64)
            print("FAILED: No AWS credentials found. Check .env variables.")
            print("=" * 64 + "\n")
            return False
        except ClientError as e:
            self.connected = False
            code = e.response["Error"]["Code"]
            print("\n" + "=" * 64)
            print(f"FAILED: AWS CloudWatch self-test failed.")
            print(f"   Error Code: {code}")
            if code == "AccessDeniedException":
                print("   Fix: Check IAM policy for logs:CreateLogGroup, logs:PutLogEvents, etc.")
            elif code == "ResourceNotFoundException":
                print("   Fix: Check AWS Region or if Log Group exists.")
            print("=" * 64 + "\n")
            return False
        except Exception as e:
            self.connected = False
            print("\n" + "=" * 64)
            print(f"FAILED: CloudWatch self-test failed: {e}")
            if self.using_emulator:
                print(f"   Fix: Make sure moto_server is running: moto_server -p 4566")
            else:
                print(f"   Fix: Check network connection to AWS.")
            print("=" * 64 + "\n")
            return False

    # ── low-level put ──────────────────────────────────────────────────────
    def _put_events(self, events: list):
        kwargs = {
            "logGroupName": CW_LOG_GROUP,
            "logStreamName": CW_LOG_STREAM,
            "logEvents": sorted(events, key=lambda e: e["timestamp"]),
        }
        if self.sequence_token:
            kwargs["sequenceToken"] = self.sequence_token
        try:
            resp = self.client.put_log_events(**kwargs)
            self.sequence_token = resp.get("nextSequenceToken")
            return resp
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidSequenceTokenException", "DataAlreadyAcceptedException"):
                msg = e.response["Error"].get("Message", "")
                if "sequenceToken is:" in msg:
                    token = msg.split("sequenceToken is:")[-1].strip()
                    self.sequence_token = token if token != "null" else None
                else:
                    self.sequence_token = None
                kwargs.pop("sequenceToken", None)
                if self.sequence_token:
                    kwargs["sequenceToken"] = self.sequence_token
                resp = self.client.put_log_events(**kwargs)
                self.sequence_token = resp.get("nextSequenceToken")
                return resp
            raise

    # ── async push (non-blocking) ─────────────────────────────────────────
    async def push(self, alert_data: dict):
        await self.queue.put(alert_data)

    async def flush_loop(self):
        """Background task: drain the outbox queue with retry/backoff."""
        while True:
            try:
                data = await self.queue.get()
                if not self.connected or self.client is None:
                    logger.warning(f"[CW-OFFLINE] Dropped: {json.dumps(data, default=str)[:120]}")
                    self.pushes_failed += 1
                    continue

                event = {
                    "timestamp": int(time.time() * 1000),
                    "message": json.dumps(data, default=str),
                }
                for attempt in range(3):
                    try:
                        await asyncio.to_thread(self._put_events, [event])
                        self.pushes_ok += 1
                        tag = data.get("incident_id") or data.get("alert_id") or data.get("type", "?")
                        logger.info(f"✅ CloudWatch push succeeded: {tag}")
                        break
                    except Exception as e:
                        self.pushes_failed += 1
                        logger.error(f"CloudWatch push attempt {attempt+1}/3 failed: {e}")
                        if attempt < 2:
                            await asyncio.sleep(2 ** attempt)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Flush loop error: {e}")
                await asyncio.sleep(1.0)

    # ── read back stored alerts (proof for Req 8) ─────────────────────────
    def read_alerts(self, limit: int = 20) -> list:
        """Read recent events from CloudWatch Logs using filter_log_events."""
        if not self.connected or self.client is None:
            return []
        
        def _fetch():
            resp = self.client.get_log_events(
                logGroupName=CW_LOG_GROUP,
                logStreamName=CW_LOG_STREAM,
                limit=limit,
                startFromHead=False,
            )
            evs = []
            for ev in reversed(resp.get("events", [])):  # Reverse so newest is first in UI
                try:
                    evs.append(json.loads(ev["message"]))
                except Exception:
                    evs.append({"raw": ev["message"]})
            return evs

        try:
            events = _fetch()
            # If using real AWS, handle ingestion delay
            if not events and not self.using_emulator:
                logger.info("Real AWS CloudWatch ingestion delay - retrying fetch in 2s...")
                time.sleep(2.0)
                events = _fetch()
            return events
        except Exception as e:
            logger.error(f"CloudWatch read failed: {e}")
            return []


# ════════════════════════════════════════════════════════════════════════════
#  Global State
# ════════════════════════════════════════════════════════════════════════════

class AppState:
    def __init__(self):
        self.lines_processed = 0
        self.malformed_lines = 0
        self.anomaly_start_time: Optional[float] = None
        self.novel_alerts: list = []
        self.recent_alerts: deque = deque(maxlen=50)
        self.recent_incidents: deque = deque(maxlen=20)
        self.timeline: deque = deque(maxlen=300)  # 5 min of 1-sec ticks


state = AppState()
window = SlidingWindow()
baseline = BaselineTracker()
pattern_tracker = PatternTracker()
incident_mgr = IncidentManager()
cw_pusher = CloudWatchPusher()


# ════════════════════════════════════════════════════════════════════════════
#  WebSocket Manager
# ════════════════════════════════════════════════════════════════════════════

class ConnectionManager:
    def __init__(self):
        self.connections: set = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.add(ws)
        logger.info(f"WS client connected ({len(self.connections)} total)")

    def disconnect(self, ws: WebSocket):
        self.connections.discard(ws)
        logger.info(f"WS client disconnected ({len(self.connections)} total)")

    async def broadcast(self, data: dict):
        dead = set()
        msg = json.dumps(data, default=str)
        for ws in self.connections:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        self.connections -= dead


ws_manager = ConnectionManager()


# ════════════════════════════════════════════════════════════════════════════
#  File Tailer  (Req 1)
#  Tracks byte offset, handles rotation/truncation, waits if file missing
# ════════════════════════════════════════════════════════════════════════════

async def tail_log_file():
    """Async generator yielding complete lines from a growing log file."""
    offset = 0
    file_announced = False

    while True:
        try:
            path = Path(LOG_FILE_PATH)

            if not path.exists():
                if not file_announced:
                    logger.info(f"Waiting for log file: {LOG_FILE_PATH}")
                    file_announced = True
                await asyncio.sleep(0.5)
                continue

            if not file_announced:
                logger.info(f"Tailing log file: {LOG_FILE_PATH}")
                file_announced = True

            file_size = path.stat().st_size

            # Rotation/truncation: file shrank → reset to start
            if file_size < offset:
                logger.warning(
                    f"Log file truncated (size {file_size} < offset {offset}), resetting"
                )
                offset = 0

            if file_size <= offset:
                await asyncio.sleep(0.1)
                continue

            # Read new bytes (binary mode for accurate offset tracking)
            with open(LOG_FILE_PATH, "rb") as f:
                f.seek(offset)
                raw = f.read()

            # Only process complete lines ending with \n
            last_nl = raw.rfind(b"\n")
            if last_nl == -1:
                await asyncio.sleep(0.1)
                continue

            complete = raw[: last_nl + 1]
            offset += len(complete)

            text = complete.decode("utf-8", errors="replace")
            for line in text.split("\n"):
                line = line.strip()
                if line:
                    yield line

        except Exception as e:
            logger.error(f"Tailer error: {e}")
            await asyncio.sleep(1.0)


# ════════════════════════════════════════════════════════════════════════════
#  Ingestion Loop — reads lines, parses, feeds window + pattern tracker
# ════════════════════════════════════════════════════════════════════════════

async def ingestion_loop():
    async for line in tail_log_file():
        state.lines_processed += 1
        entry = parse_log_line(line)
        if entry is None:
            state.malformed_lines += 1
            continue

        is_error = entry.level in ("ERROR", "FATAL")
        window.add(entry.timestamp, is_error)

        # Novel pattern detection
        if is_error:
            novel_hash = pattern_tracker.check(entry.message)
            if novel_hash and baseline.is_warmed_up:
                alert = Alert(
                    id=f"NP-{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    severity="MEDIUM",
                    z_score=0.0,
                    rate=window.error_rate(),
                    baseline_median=baseline.median,
                    upper_band=baseline.upper_band,
                    why=f"MEDIUM: Novel error pattern detected (hash={novel_hash}), not seen during warm-up",
                    alert_type="novel_pattern",
                    pattern_hash=novel_hash,
                )
                state.novel_alerts.append(alert)


# ════════════════════════════════════════════════════════════════════════════
#  Detection Loop — runs every second  (Req 4)
# ════════════════════════════════════════════════════════════════════════════

async def detection_loop():
    pattern_warmup_ended = False

    while True:
        await asyncio.sleep(1.0)
        now = time.time()
        rate = window.error_rate()

        # ── Record bucket for baseline (only if we have data) ──
        baseline.maybe_record_bucket(now, rate, has_data=(window.total > 0))

        # ── End pattern warm-up when baseline warm-up ends ──
        if baseline.is_warmed_up and not pattern_warmup_ended:
            pattern_tracker.end_warmup()
            pattern_warmup_ended = True

        # ── Anomaly detection ──
        is_anom, z = baseline.is_anomaly(rate, window.total)

        # ── Persistence tracking ──
        persistence = 0.0
        if is_anom:
            if state.anomaly_start_time is None:
                state.anomaly_start_time = now
            persistence = now - state.anomaly_start_time
        else:
            state.anomaly_start_time = None

        severity = None
        why = None

        if is_anom:
            severity, why = assign_severity(z, persistence, rate, baseline.median)

            # ── Incident management ──
            prev_sev = incident_mgr.active.severity if incident_mgr.active else None
            inc, action = incident_mgr.on_anomaly(z, rate, severity, why)
            inc_data = {
                "type": "incident",
                "id": inc.id, "status": action,
                "start_timestamp": inc.start_timestamp,
                "peak_z": round(inc.peak_z, 1),
                "current_z": round(z, 1),
                "peak_rate": round(inc.peak_rate, 4),
                "current_rate": round(rate, 4),
                "duration_secs": round(now - inc.start_time),
                "severity": inc.severity, "why": why,
                "alert_count": inc.alert_count,
                "raw_breaches": inc.raw_breaches,
            }
            await ws_manager.broadcast(inc_data)
            
            # Deduplicate the deque so it doesn't just fill up with one incident updates
            state.recent_incidents = deque((x for x in state.recent_incidents if x["id"] != inc.id), maxlen=20)
            state.recent_incidents.appendleft(inc_data)

            SO = IncidentManager.SEV_ORDER
            if action == "opened" or (prev_sev and SO.get(inc.severity, 0) > SO.get(prev_sev, 0)):
                await cw_pusher.push({
                    "type": "incident_open" if action == "opened" else "incident_escalate",
                    "incident_id": inc.id,
                    "timestamp": datetime.now().isoformat(),
                    "severity": inc.severity, "z_score": round(z, 2),
                    "rate": round(rate, 4),
                    "baseline_median": round(baseline.median, 4),
                    "upper_band": round(baseline.upper_band, 4),
                    "why": why,
                })
        else:
            # ── Check for incident closure ──
            result = incident_mgr.on_normal()
            if result:
                closed_inc, _ = result
                dur = (closed_inc.close_time or now) - closed_inc.start_time
                close_data = {
                    "type": "incident", "id": closed_inc.id, "status": "closed",
                    "start_timestamp": closed_inc.start_timestamp,
                    "peak_z": round(closed_inc.peak_z, 1), "current_z": 0.0,
                    "peak_rate": round(closed_inc.peak_rate, 4),
                    "current_rate": round(rate, 4),
                    "duration_secs": round(dur),
                    "severity": closed_inc.severity,
                    "why": f"Incident {closed_inc.id} closed — duration={dur:.0f}s, peak z={closed_inc.peak_z:.1f}",
                    "alert_count": closed_inc.alert_count,
                    "raw_breaches": closed_inc.raw_breaches,
                }
                await ws_manager.broadcast(close_data)
                state.recent_incidents.appendleft(close_data)
                await cw_pusher.push({
                    "type": "incident_close", "incident_id": closed_inc.id,
                    "timestamp": datetime.now().isoformat(),
                    "duration_secs": round(dur),
                    "peak_z": round(closed_inc.peak_z, 2),
                    "peak_rate": round(closed_inc.peak_rate, 4),
                    "severity": closed_inc.severity,
                    "alert_count": closed_inc.alert_count,
                })

        # ── Process queued novel pattern alerts ──
        while state.novel_alerts:
            alert = state.novel_alerts.pop(0)
            alert_data = {
                "type": "alert", "id": alert.id,
                "timestamp": alert.timestamp, "severity": alert.severity,
                "z_score": round(alert.z_score, 1),
                "rate": round(alert.rate, 4),
                "baseline_median": round(alert.baseline_median, 4),
                "upper_band": round(alert.upper_band, 4),
                "why": alert.why, "alert_type": alert.alert_type,
                "pattern_hash": alert.pattern_hash,
            }
            await ws_manager.broadcast(alert_data)
            state.recent_alerts.appendleft(alert_data)
            await cw_pusher.push({
                "type": "novel_pattern_alert", "alert_id": alert.id,
                "timestamp": datetime.now().isoformat(),
                "severity": alert.severity, "why": alert.why,
                "pattern_hash": alert.pattern_hash,
            })

        # ── Timeline tick ──
        tl_entry = {"state": "anomaly" if is_anom else "normal", "severity": severity}
        state.timeline.append(tl_entry)

        # ── Console output (every 5s normal, every 1s anomaly) ──
        if state.lines_processed > 0:
            warmup_str = ""
            if not baseline.is_warmed_up:
                warmup_str = f" | ⏳ Warm-up: {baseline.warmup_elapsed:.0f}/{WARMUP_SECONDS}s"

            if is_anom:
                logger.warning(
                    f"⚠️  rate={rate:.1%} | baseline={baseline.median:.1%} | "
                    f"band={baseline.upper_band:.1%} | z={z:.1f} | {severity}{warmup_str}"
                )
            elif int(now) % 5 == 0:
                frozen = " [FROZEN]" if baseline.frozen else ""
                logger.info(
                    f"📊 rate={rate:.1%} | baseline={baseline.median:.1%} | "
                    f"band={baseline.upper_band:.1%} | z={z:.1f}{frozen}{warmup_str}"
                )

        # ── Broadcast metrics tick ──
        metrics = {
            "type": "metrics",
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "rate": round(rate, 4),
            "baseline_median": round(baseline.median, 4),
            "upper_band": round(baseline.upper_band, 4),
            "z_score": round(z, 1),
            "is_warmed_up": baseline.is_warmed_up,
            "warmup_elapsed": round(baseline.warmup_elapsed),
            "warmup_total": WARMUP_SECONDS,
            "is_anomaly": is_anom,
            "severity": severity,
            "lines_processed": state.lines_processed,
            "malformed_lines": state.malformed_lines,
            "aws_pushes_ok": cw_pusher.pushes_ok,
            "aws_pushes_failed": cw_pusher.pushes_failed,
            "cw_connected": cw_pusher.connected,
            "cw_target": cw_pusher.target_label,
            "cw_using_emulator": cw_pusher.using_emulator,
            "incident_active": incident_mgr.active is not None,
            "incident_id": incident_mgr.active.id if incident_mgr.active else None,
            "raw_breaches": incident_mgr.total_raw_breaches,
            "incidents_total": incident_mgr.incident_counter,
            "baseline_frozen": baseline.frozen,
            "window_events": window.total,
            "timeline": tl_entry,
        }
        await ws_manager.broadcast(metrics)


# ════════════════════════════════════════════════════════════════════════════
#  FastAPI Application
# ════════════════════════════════════════════════════════════════════════════

from fastapi.staticfiles import StaticFiles

app = FastAPI(title="RedDragon", description="Real-Time Log Anomaly Detection")
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_dashboard():
    return FileResponse("static/index.html", media_type="text/html")


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive; client sends nothing
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)


@app.get("/api/state")
async def get_state():
    """Polling fallback: current metrics + recent alerts/incidents."""
    return JSONResponse({
        "rate": round(window.error_rate(), 4),
        "baseline_median": round(baseline.median, 4),
        "upper_band": round(baseline.upper_band, 4),
        "is_warmed_up": baseline.is_warmed_up,
        "lines_processed": state.lines_processed,
        "malformed_lines": state.malformed_lines,
        "aws_pushes_ok": cw_pusher.pushes_ok,
        "aws_pushes_failed": cw_pusher.pushes_failed,
        "cw_connected": cw_pusher.connected,
        "cw_target": cw_pusher.target_label,
        "recent_alerts": list(state.recent_alerts),
        "recent_incidents": list(state.recent_incidents),
        "timeline": list(state.timeline),
    })


@app.get("/api/cloudwatch")
async def get_cloudwatch_events():
    """Read stored alerts back from CloudWatch Logs — proof that Req 8 works."""
    events = await asyncio.to_thread(cw_pusher.read_alerts, 30)
    return JSONResponse({
        "source": cw_pusher.target_label,
        "log_group": CW_LOG_GROUP,
        "log_stream": CW_LOG_STREAM,
        "event_count": len(events),
        "events": events,
    })


@app.on_event("startup")
async def startup():
    logger.info("🐉 RedDragon starting up...")
    logger.info(f"   Log file:       {LOG_FILE_PATH}")
    logger.info(f"   Window:         {WINDOW_SECONDS}s")
    logger.info(f"   Warm-up:        {WARMUP_SECONDS}s")
    logger.info(f"   Z-threshold:    {Z_THRESHOLD}")
    logger.info(f"   Buckets:        {BUCKET_SECONDS}s")
    logger.info(f"   Incident close: {INCIDENT_CLOSE_SECS}s")
    if AWS_ENDPOINT_URL:
        logger.info(f"   CW endpoint:    {AWS_ENDPOINT_URL} (moto emulator)")
    else:
        logger.info(f"   CW endpoint:    Real AWS ({AWS_REGION})")

    cw_pusher.initialize()

    asyncio.create_task(ingestion_loop())
    asyncio.create_task(detection_loop())
    asyncio.create_task(cw_pusher.flush_loop())

    logger.info("🐉 RedDragon ready — open http://localhost:8000")
