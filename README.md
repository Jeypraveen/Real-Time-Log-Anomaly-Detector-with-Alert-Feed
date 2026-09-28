# 🐉 RedDragon: Real-Time Log Anomaly Detection

**Hackathon**: HackForge
**Problem Statement Chosen**: Python (Real-Time Log Anomaly Detector with Alert Feed)

> *"Monitoring systems need to identify abnormal behavior quickly before it becomes a major issue. Log streams can contain increasing error rates or unusual activity that needs to be detected and reported immediately."*

---

## 💡 The "Why" (Our Approach)

Most log anomaly detectors fall into two traps:
1. **Static Thresholds**: Hardcoded at 5% error rate, triggering hundreds of false positives during traffic spikes, or missing slow-burning issues.
2. **Alert Fatigue**: When things break, they span thousands of log lines. Pinging an on-call engineer for *every single error line* is a quick way to get your alerts muted.

**RedDragon** takes a purely deterministic, statistical approach using **Robust Z-Scores (Median + MAD)**. 
- No LLMs, no heavy ML models, zero training time. 
- It groups continuous anomalies into **Incidents** (saving on-call sanity).
- It freezes the baseline during active anomalies (preventing the system from accepting broken state as the "new normal").
- It hashes error lines to detect **Novel Patterns** (things we've never seen during normal operation).

> **Important Note for Judges**: 
> Alerts are pushed through the real `boto3` CloudWatch Logs API directly to AWS CloudWatch Logs (Log Group: `/reddragon/anomalies`). 
> *Fallback:* If you do not have an AWS account available for the hackathon, you can use the local AWS-compatible emulator (`moto`) by setting `AWS_ENDPOINT_URL=http://localhost:4566` in your `.env`.

---

## ✅ Minimum Requirements Checklist

1. **Monitor an active log file**: ✅ `tail_log_file()` handles appending, truncation (rotation), and waiting for file creation asynchronously.
2. **Sliding window error rates**: ✅ `SlidingWindow` precisely tracks events over a configurable rolling window (default 20s to minimize recovery lag).
3. **Calculate a baseline and z-score**: ✅ `BaselineTracker` waits for a warm-up period, computing Median and Median Absolute Deviation (MAD). **Crucially, baseline updates FREEZE when `z > threshold`**.
4. **Detection Loop**: ✅ Runs concurrently at 1Hz, evaluating the window against the frozen baseline.
5. **Severity Rubric**: ✅ Strict mapping: `z 3.5 to <5` = LOW; `5 to <8` = MEDIUM; `8 to <12` = HIGH; `>=12 OR >=30s` = CRITICAL. Novel patterns are MEDIUM.
6. **Real-time Alert Feed**: ✅ FastAPI + WebSockets power a reactive, 0-dependency HTML dashboard.
7. **Configurable Alerting Rules**: ✅ Fully configurable via `.env` (Warmup, thresholds, window sizes).
8. **CloudWatch Logs Output**: ✅ Pushes alerts asynchronously via `boto3.client('logs').put_log_events()` to a `moto` emulator. The dashboard includes an API button to fetch these stored events back as proof.

---

## 🛠️ Extra Features

- **Incident Manager (Anti Alert-Fatigue)**: Instead of firing 50 alerts for a 50-second anomaly, we group them into a single `INC-X` incident card that updates live on the dashboard, tracking peak Z-score and duration. 
- **Novel Pattern Detection**: Strips timestamps/UUIDs from ERROR lines and hashes them. If a hash was never seen during the warm-up period, it triggers an immediate alert.
- **Resilient AWS Outbox**: If the CloudWatch push fails, it uses exponential backoff rather than crashing the detection loop.

## ☁️ AWS Setup (Real CloudWatch)

To use real AWS CloudWatch:
1. Create an IAM User (or use temporary STS credentials) with the following permissions:
   - `logs:CreateLogGroup`
   - `logs:CreateLogStream`
   - `logs:PutLogEvents`
   - `logs:DescribeLogGroups`
   - `logs:DescribeLogStreams`
   - `logs:FilterLogEvents`
2. Copy `.env.example` to `.env`.
3. Clear `AWS_ENDPOINT_URL` (leave it blank).
4. Fill in `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and (if using temporary credentials) `AWS_SESSION_TOKEN`.

---

## 🚀 How to Run the Demo

You need 3 terminal windows to run the full simulation.

### 1. Start the AWS Emulator (Terminal 1)
```bash
pip install -r requirements.txt
python -m moto.server -p 4566
```

### 2. Start the RedDragon Detector (Terminal 2)
```bash
# Ensure Python outputs UTF-8 on Windows
$env:PYTHONIOENCODING="utf-8"
python -m uvicorn main:app --port 8000
```
Open **http://localhost:8000** in your browser. You will see it waiting for the log file.

### 3. Generate Traffic Scenarios (Terminal 3)
We built a deterministic log generator with multiple scenarios to prove the detector works.
```bash
# Wait for 30 seconds of "warm-up" on the dashboard, then hit Ctrl+C to stop it.
python gen_logs.py normal

# Watch the detector catch a burst, create an Incident, and close it when recovery happens.
python gen_logs.py spike

# Inject errors the system has never seen before!
python gen_logs.py new_error
```

### 4. Verify in AWS Console
1. Click the **"Refresh"** button on the CloudWatch panel in the dashboard to prove the incidents and novel pattern alerts were successfully stored in AWS.
2. Log into the AWS Console and navigate to **CloudWatch -> Log groups -> `/reddragon/anomalies` -> `alerts`**. You will see the structured JSON alerts appear there (note: the AWS console can take 10 to 30 seconds to index new events).

---

## 💡 Known Limitations
1. **Window Lag**: Anomaly detection uses a rolling window (currently tuned to 20s). This means that after a traffic spike subsides, there is an inherent lag of up to 20 seconds before the system fully calculates a recovery and closes the incident. 
2. **Moto vs. Real CloudWatch**: For local CI/CD testing, we demonstrate pushes to `moto`. Please note that `moto` is a local emulator and does not enforce real CloudWatch quotas, IAM policies, or ingestion/indexing delays.
