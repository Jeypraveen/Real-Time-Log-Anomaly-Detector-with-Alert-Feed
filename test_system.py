import pytest
import time
from main import SlidingWindow, BaselineTracker, IncidentManager, parse_log_line

from main import SlidingWindow, BaselineTracker, IncidentManager, assign_severity, parse_log_line
import time

def test_sliding_window():
    window = SlidingWindow(window_seconds=60)
    now = time.time()
    
    # Simulate adding ok and error lines
    for _ in range(10):
        window.add(now, is_error=False)
    for _ in range(2):
        window.add(now, is_error=True)
        
    rate = window.error_rate()
    # 2 errors out of 12 total = 16.66%
    assert 0.16 < rate < 0.17

def test_baseline_tracker():
    baseline = BaselineTracker()
    now = time.time()
    
    # We must call maybe_record_bucket with 10s intervals to pass warmup (WARMUP_SECONDS=30)
    # First call sets warmup_start
    baseline.maybe_record_bucket(now, rate=0.05, has_data=True)
    
    for i in range(1, 4):
        baseline.maybe_record_bucket(now + i*10, rate=0.05, has_data=True)
        
    assert baseline.is_warmed_up
    assert baseline.median == 0.05
    assert baseline.upper_band > 0.05

def test_incident_manager():
    mgr = IncidentManager()
    
    # Simulate a critical incident (Z > 3.5)
    severity, why = assign_severity(z=5.0, persistence_secs=5.0, rate=0.20, baseline_median=0.05)
    incident, action = mgr.on_anomaly(z=5.0, rate=0.20, severity=severity, why=why)
    
    assert action == "opened"
    assert mgr.active is not None
    assert mgr.active.severity == "MEDIUM"  # 5.0 is medium!
    assert mgr.incident_counter == 1
    
    # Simulate resolving the incident (on_normal called > INCIDENT_CLOSE_SECS)
    mgr.active.normal_since = time.time() - 20
    inc, action_close = mgr.on_normal()
    assert action_close == "closed"
    assert inc.status == "closed"
    assert mgr.active is None

def test_log_parser():
    line1 = "2026-09-28T10:00:00.000 [INFO] data-pipeline - User login successful"
    entry1 = parse_log_line(line1)
    assert entry1 is not None
    assert entry1.level == "INFO"
    assert "User login successful" in entry1.message
    
    line2 = "2026-09-28T10:00:01.000 [ERROR] user-service - Database connection failed"
    entry2 = parse_log_line(line2)
    assert entry2 is not None
    assert entry2.level == "ERROR"
    assert "Database connection failed" in entry2.message


