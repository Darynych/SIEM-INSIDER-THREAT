#!/usr/bin/env python3
"""
Insider-Threat Anomaly Detector (Isolation Forest)
==================================================
Part of the SIEM insider-threat lab. It pulls Windows/AD authentication
events from Elasticsearch, builds per-user behavioural features, scores
them with an Isolation Forest, and raises an alert for the outliers by:
  (a) indexing them into `ml-insider-anomalies` (so they show in Kibana), and
  (b) POSTing them to an n8n webhook that runs the SOAR response workflow.

Run it two ways:
  python insider_threat_detector.py --mode demo            # synthetic data, no ES needed
  python insider_threat_detector.py --mode live --emit     # against your Elastic stack

Config comes from environment variables (see .env.example). It talks to
Elasticsearch over the plain REST API with `requests`, so there is no
client/stack version matching to worry about.
"""

from __future__ import annotations
import os, sys, time, argparse, datetime as dt
from typing import Any

import numpy as np
import pandas as pd
import requests
import urllib3
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# lab uses a self-signed cert -> silence the warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------------------------------------------ config
ES_URL        = os.getenv("ES_URL", "https://192.168.56.10:9200")
ES_USER       = os.getenv("ES_USER", "elastic")
ES_PASS       = os.getenv("ES_PASS", "")
ES_INDEX      = os.getenv("ES_INDEX", "logs-*")           # System integration writes here
ANOMALY_INDEX = os.getenv("ANOMALY_INDEX", "ml-insider-anomalies")
N8N_WEBHOOK   = os.getenv("N8N_WEBHOOK_URL", "")          # empty = don't POST
VERIFY_TLS    = os.getenv("VERIFY_TLS", "false").lower() == "true"

# Windows Security event IDs that carry insider-threat signal
EVENT = {
    "logon": "4624", "failed_logon": "4625", "logoff": "4634",
    "special_logon": "4672", "lockout": "4740",
    "added_global_group": "4728", "added_local_group": "4732",
    "added_universal_group": "4756", "user_created": "4720",
}
WORK_START, WORK_END = 7, 19        # 07:00-19:00 = "normal" hours

FEATURES = [
    "logon_count", "failed_count", "failed_ratio", "distinct_src_ip",
    "distinct_hosts", "off_hours_logons", "weekend_logons",
    "privilege_events", "lockouts",
]

# ------------------------------------------------------------------ ES I/O
def es_search(body: dict) -> list[dict]:
    r = requests.post(f"{ES_URL}/{ES_INDEX}/_search", auth=(ES_USER, ES_PASS),
                      json=body, verify=VERIFY_TLS, timeout=30)
    r.raise_for_status()
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]

def _dig(d: Any, *keys: str):
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d

def fetch_events(lookback_hours: int) -> pd.DataFrame:
    body = {
        "size": 10000,
        "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": [
            {"terms": {"event.code": list(EVENT.values())}},
            {"range": {"@timestamp": {"gte": f"now-{lookback_hours}h"}}},
        ]}},
        "_source": ["@timestamp", "event.code", "user.name", "source.ip",
                    "host.name", "winlog.event_data.IpAddress"],
    }
    rows = []
    for s in es_search(body):
        rows.append({
            "ts":   s.get("@timestamp"),
            "code": _dig(s, "event", "code"),
            "user": _dig(s, "user", "name"),
            "src":  _dig(s, "source", "ip") or _dig(s, "winlog", "event_data", "IpAddress"),
            "host": _dig(s, "host", "name"),
        })
    return pd.DataFrame(rows)

# ------------------------------------------------------------------ features
def build_features(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["user"] + FEATURES)
    df = df.dropna(subset=["user"]).copy()
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce", utc=True)
    df["hour"] = df["ts"].dt.hour
    df["weekday"] = df["ts"].dt.weekday
    priv = {EVENT["special_logon"], EVENT["added_global_group"],
            EVENT["added_local_group"], EVENT["added_universal_group"]}

    def agg(g: pd.DataFrame) -> pd.Series:
        logons = int((g["code"] == EVENT["logon"]).sum())
        failed = int((g["code"] == EVENT["failed_logon"]).sum())
        logon_rows = g[g["code"] == EVENT["logon"]]
        return pd.Series({
            "logon_count": logons,
            "failed_count": failed,
            "failed_ratio": round(failed / (logons + failed + 1), 4),
            "distinct_src_ip": g["src"].nunique(),
            "distinct_hosts": g["host"].nunique(),
            "off_hours_logons": int(logon_rows["hour"]
                .apply(lambda h: h < WORK_START or h >= WORK_END).sum()),
            "weekend_logons": int((logon_rows["weekday"] >= 5).sum()),
            "privilege_events": int(g["code"].isin(priv).sum()),
            "lockouts": int((g["code"] == EVENT["lockout"]).sum()),
        })

    return df.groupby("user").apply(agg).reset_index()

# ------------------------------------------------------------------ model
def score(feats: pd.DataFrame, contamination: float) -> pd.DataFrame:
    if feats.empty:
        return feats
    X = StandardScaler().fit_transform(feats[FEATURES].fillna(0).to_numpy())
    model = IsolationForest(n_estimators=200, contamination=contamination,
                            random_state=42)
    model.fit(X)
    feats = feats.copy()
    feats["anomaly_score"] = (-model.score_samples(X)).round(4)   # higher = worse
    feats["is_anomaly"] = model.predict(X) == -1
    return feats.sort_values("anomaly_score", ascending=False)

# ------------------------------------------------------------------ alerting
def emit(row: pd.Series):
    alert = {
        "@timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "rule": "ml_isolation_forest_insider",
        "severity": "high" if row["anomaly_score"] > 0.65 else "medium",
        "user": row["user"],
        "anomaly_score": float(row["anomaly_score"]),
        "features": {f: float(row[f]) for f in FEATURES},
    }
    try:                                                    # 1) show it in Kibana
        requests.post(f"{ES_URL}/{ANOMALY_INDEX}/_doc", auth=(ES_USER, ES_PASS),
                      json=alert, verify=VERIFY_TLS, timeout=15).raise_for_status()
    except Exception as e:
        print(f"  ! could not index anomaly: {e}", file=sys.stderr)
    if N8N_WEBHOOK:                                          # 2) hand off to n8n SOAR
        try:
            requests.post(N8N_WEBHOOK, json=alert, timeout=15).raise_for_status()
        except Exception as e:
            print(f"  ! could not POST to n8n: {e}", file=sys.stderr)
    print(f"  ALERT  user={alert['user']:<16} score={alert['anomaly_score']:.3f} "
          f"sev={alert['severity']}")

# ------------------------------------------------------------------ runners
def report(scored: pd.DataFrame, emit_alerts: bool):
    print(scored[["user"] + FEATURES + ["anomaly_score", "is_anomaly"]]
          .to_string(index=False))
    if emit_alerts:
        for _, row in scored[scored["is_anomaly"]].iterrows():
            emit(row)

def run_live(lookback_hours: int, contamination: float, emit_alerts: bool):
    print(f"[{dt.datetime.now():%H:%M:%S}] pulling last {lookback_hours}h of auth events...")
    feats = build_features(fetch_events(lookback_hours))
    if feats.empty:
        print("  no user auth events in window (is Windows shipping Security logs yet?)")
        return
    report(score(feats, contamination), emit_alerts)

def run_demo(contamination: float, emit_alerts: bool):
    """Synthetic data so you can see the model work before AD logs are flowing."""
    rng = np.random.default_rng(7)
    rows = [dict(user=f"user{i:02d}",
                 logon_count=int(rng.integers(5, 40)), failed_count=int(rng.integers(0, 3)),
                 distinct_src_ip=int(rng.integers(1, 3)), distinct_hosts=int(rng.integers(1, 3)),
                 off_hours_logons=int(rng.integers(0, 2)), weekend_logons=int(rng.integers(0, 2)),
                 privilege_events=int(rng.integers(0, 1)), lockouts=0) for i in range(28)]
    rows += [   # three planted "insiders"
        dict(user="svc_backup", logon_count=6, failed_count=1, distinct_src_ip=1,
             distinct_hosts=9, off_hours_logons=6, weekend_logons=4, privilege_events=5, lockouts=0),
        dict(user="j.doe", logon_count=3, failed_count=41, distinct_src_ip=1,
             distinct_hosts=1, off_hours_logons=3, weekend_logons=0, privilege_events=0, lockouts=2),
        dict(user="admin_tmp", logon_count=2, failed_count=0, distinct_src_ip=4,
             distinct_hosts=6, off_hours_logons=2, weekend_logons=1, privilege_events=3, lockouts=0),
    ]
    feats = pd.DataFrame(rows)
    feats["failed_ratio"] = (feats["failed_count"] /
                             (feats["logon_count"] + feats["failed_count"] + 1)).round(4)
    report(score(feats[["user"] + FEATURES], contamination), emit_alerts)

# ------------------------------------------------------------------ cli
def main():
    p = argparse.ArgumentParser(description="Insider-threat Isolation Forest detector")
    p.add_argument("--mode", choices=["demo", "live"], default="demo")
    p.add_argument("--lookback-hours", type=int, default=24)
    p.add_argument("--contamination", type=float, default=0.1,
                   help="expected fraction of anomalous users (0-0.5)")
    p.add_argument("--loop", action="store_true", help="run forever")
    p.add_argument("--interval", type=int, default=300, help="seconds between loops")
    p.add_argument("--emit", action="store_true",
                   help="actually raise alerts (index + n8n); off by default")
    a = p.parse_args()

    def cycle():
        (run_demo if a.mode == "demo" else run_live)(
            *( (a.contamination, a.emit) if a.mode == "demo"
               else (a.lookback_hours, a.contamination, a.emit) ))

    cycle()
    while a.loop:
        time.sleep(a.interval)
        cycle()

if __name__ == "__main__":
    main()
