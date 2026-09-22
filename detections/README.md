# Detection Rules (detection-as-code)

Six custom Elastic Security rules for the insider-threat lab, version-controlled as
`insider-threat-rules.ndjson` so they can be reviewed, diffed, and re-imported.

## The rules

| Rule | Type | Signal | Event IDs | Needs AD DC? |
|---|---|---|---|---|
| Excessive Failed Logons (Brute Force / Spray) | threshold (≥8 / 5 min per user) | brute force / password spray | 4625 | no |
| Account Lockout | query | repeated bad auth | 4740 | no |
| Successful Logon After Repeated Failures | eql sequence | brute force that *succeeded* | 4625 → 4624 | no |
| Windows Security Log Cleared | query | anti-forensics / evasion | 1102 | no |
| User Added to Privileged Group | query | privilege escalation | 4728 / 4732 / 4756 | **yes** |
| New User Account Created | query | rogue-account persistence | 4720 | **yes** |

All rules are `"enabled": false` on import — review them, then switch on.

## Prerequisites
- Windows Security logs must be flowing into `logs-*` (Elastic Agent **System** + **Windows** integrations on the endpoints).
- The two "Needs AD DC" rules only produce events once the **Active Directory Domain Controller** is built and auditing (roadmap Day 1).
- Rules query `index: ["logs-*"]` and group on ECS `user.name`. If your failed-logon events carry the target account under `winlog.event_data.TargetUserName` instead, edit that field in the rule.

## Import them (fastest)
The file is in this repo on your Windows host, and you import through the Kibana UI in your browser (same machine), so it's right there to pick:

1. Kibana → **Security → Rules → Detection rules (SIEM)**.
2. Top-right **Import rules** → choose `detections/insider-threat-rules.ndjson` → **Import**.
3. They land **disabled**. Open each, sanity-check the query against your data in the rule preview, then **Enable**.

## Or create one by hand (the brute-force rule, to learn the flow)
Security → Rules → **Create new rule** → **Threshold** →
- Index: `logs-*`
- Custom query: `event.code:"4625"`
- Group by: `user.name`, Threshold: `8`
- Schedule: run every `5m`, look back `6m`
- Severity `High`, Risk score `73` → Create & enable.

## Wire an alert to n8n (the SOAR hand-off)
1. Kibana → **Stack Management → Connectors → Create connector → Webhook** → method `POST`, URL = your n8n webhook, no auth (lab). Save.
2. Edit a rule → **Actions** → add that Webhook connector → run **On each rule execution** (or per time frame) → paste a JSON body, e.g.:
   ```json
   { "rule": "{{context.rule.name}}", "severity": "{{context.rule.severity}}",
     "user": "{{context.alerts.0.user.name}}", "host": "{{context.alerts.0.host.name}}",
     "source_ip": "{{context.alerts.0.source.ip}}", "count": "{{context.alerts.0.kibana.alert.threshold_result.count}}" }
   ```
3. Now a rule hit POSTs straight into the n8n workflow, which runs enrich → alert → approval → disable AD user.

The same Isolation Forest anomalies (from `../ml/`) hit a second n8n webhook, so both detection paths converge on one response workflow.
