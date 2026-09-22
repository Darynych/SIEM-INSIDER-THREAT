# ML Insider-Threat Detector (Isolation Forest)

Unsupervised anomaly detection over Active Directory / Windows authentication
behaviour. It reads events from Elasticsearch, scores each user with an
**Isolation Forest**, and hands the outliers to the n8n SOAR workflow for response.

```
Elasticsearch (auth events)  ->  per-user features  ->  Isolation Forest
        -> anomalies  ->  ml-insider-anomalies index (Kibana)  +  n8n webhook (response)
```

## Why Isolation Forest
Insider threats are rare and unlabelled, so a supervised classifier has nothing
to learn from. Isolation Forest is unsupervised: it isolates points that are
"few and different", which is exactly what an insider looks like against a
baseline of normal users — no labelled attack data required.

## Features (per user, over a lookback window)
| Feature | Signal |
|---|---|
| `logon_count`, `failed_count`, `failed_ratio` | brute force / password spray |
| `distinct_src_ip`, `distinct_hosts` | lateral movement / credential sharing |
| `off_hours_logons`, `weekend_logons` | out-of-pattern access |
| `privilege_events` | 4672 / group-add (privilege abuse) |
| `lockouts` | 4740 (repeated bad auth) |

Event IDs used: 4624, 4625, 4634, 4672, 4740, 4728, 4732, 4756, 4720.

## Run it

```bash
pip install -r requirements.txt

# 1) See it work right now on synthetic data (no Elasticsearch needed):
python insider_threat_detector.py --mode demo

# 2) Against your live stack once Windows Security logs are flowing:
cp .env.example .env         # then edit ES_PASS etc.  (or export the vars)
set -a; . ./.env; set +a
python insider_threat_detector.py --mode live --lookback-hours 24 --emit

# 3) Run continuously (every 5 min) as the detection loop:
python insider_threat_detector.py --mode live --loop --interval 300 --emit
```

`--emit` writes each anomaly to the `ml-insider-anomalies` index **and** POSTs it
to `N8N_WEBHOOK_URL`. Without `--emit` it just prints the scored table (safe dry run).

## Wire it to Kibana + n8n
- **Kibana:** create a data view for `ml-insider-anomalies` to chart anomalies over
  time and pivot by user.
- **n8n:** set `N8N_WEBHOOK_URL` to your workflow's webhook. Each POST body is:
  `{ "@timestamp", "rule", "severity", "user", "anomaly_score", "features": {...} }`.

## Tuning
- `--contamination` = expected fraction of anomalous users (start 0.1, lower it as
  your baseline grows).
- Widen `--lookback-hours` so each user has enough history to build a stable baseline.

## Notes / next steps
- Lab scale pulls up to 10k events per run; for volume, push the feature
  aggregation into an Elasticsearch composite aggregation instead of pandas.
- The model is fit fresh each run (fine for a lab). For production, persist a
  baseline model (`joblib`) and only *score* new windows against it.
- Lab only — uses `VERIFY_TLS=false` for the self-signed cert.
