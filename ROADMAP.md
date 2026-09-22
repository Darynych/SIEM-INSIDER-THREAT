# SIEM Insider‑Threat Detection — Build Roadmap

**Stack:** Elastic (Elasticsearch + Kibana) SIEM · Active Directory · Sysmon · Isolation Forest (ML) · **n8n** (SOAR / automation)
**Lab:** Local VirtualBox · **End goal:** full active response (detect → alert → case → auto‑disable the AD user) · **Mode:** few‑day sprint, MVP‑first.

> **Start here (first 30 min):** create a Windows Server VM and promote it to a Domain Controller (Day 1, Step 1). Everything else hangs off having AD in place.

---

## 0. The final goal — what "done" looks like

```
Windows Server (Active Directory DC) ─┐
Windows 10/11 client (domain-joined)  ├─ Elastic Agent + Sysmon ─┐
Ubuntu server                        ─┘   (auth / logon / process)│
                                                                  ▼
                                         Elasticsearch + Kibana  (SIEM)
                                         • dashboards • detection rules
                                                    │
                       ┌──── Elastic detection rule │ Isolation Forest scores
                       │      fires (Webhook action) │ user behaviour → flags anomaly
                       └───────────────┬─────────────┘
                                       ▼  (HTTP webhook)
                                  n8n workflow   ← the automation centrepiece (your "SOAR")
                enrich → dedupe → alert (Slack/email) → open a case → approval gate →
                                       → disable AD user  (+ optional: isolate host)
```

**The story you're telling a hiring manager:** *"I built a detection‑and‑response pipeline. Windows/AD and Linux telemetry lands in an Elastic SIEM; insider‑threat behaviour is caught two ways — hand‑written detection rules and an Isolation Forest ML model; and a modern automation platform (n8n) runs the response: it enriches the alert, notifies the SOC, opens a case, waits for an analyst's approval, and then disables the offending Active Directory account."* That is exactly what a real SOC does.

---

## 1. Tooling — why n8n, and where Ansible actually fits

These are **three different jobs**, not competitors. Confusing them is the most common mistake, so nail the vocabulary — it makes your README sound senior:

| Layer | Job | Tools |
|---|---|---|
| **Provisioning / config** | Build & configure the machines reproducibly | **Ansible**, Terraform, or a setup script |
| **Detection** | Collect telemetry, spot bad behaviour | **Elastic** (rules + dashboards) + **Isolation Forest** |
| **Response / orchestration (SOAR)** | React to a detection automatically | **n8n**, Shuffle, Tines, Cortex XSOAR |

**Ansible isn't "old."** Red Hat's Ansible Automation Platform runs in huge enterprises. It's just doing the *provisioning* job — it can't "react to an alert." So it belongs at the **end** of this project (Day 4, optional) to make the lab rebuildable, not as the automation brain.

**"What do big companies use NOW?"** Dedicated SOAR platforms: **Cortex XSOAR** (Palo Alto), **Splunk SOAR**, **Google SecOps SOAR**, and the newer API‑first ones **Tines** and **Torq**. n8n is a *general* automation platform (not security‑specific), but it's modern, API‑first, self‑hostable and increasingly used — a great, very demonstrable pick for a portfolio. The closest open‑source "true SOAR" is **Shuffle**.

➡️ **Decision: build it in n8n** (you'll learn the SOAR concepts and it demos beautifully), and name‑drop Shuffle / XSOAR in the README to show you understand the landscape.

---

## 2. Where you are vs. what's missing

| Component | Status |
|---|---|
| Elasticsearch + Kibana | ✅ Have |
| Windows host → Elastic | ✅ Have |
| Ubuntu server → Elastic | ✅ Have |
| Isolation Forest ML | ✅ Have (needs wiring to live data + n8n) |
| **Active Directory (DC + users/OUs)** | ❌ Missing — **do first** |
| **AD/Sysmon audit logging into Elastic** | ❌ Missing |
| **Detection rules for insider scenarios** | ❌ Missing |
| **n8n installed + response workflow** | ❌ Missing |
| Docs / README / diagram / demo | ❌ Missing |

AD is the missing brick that turns "log monitoring" into an **insider‑threat** project: it gives you *identities* and the auth events insiders generate — odd‑hour logons, privilege changes, dormant‑account use, mass access.

---

## 3. The sprint principle — one thin slice before breadth

Do **not** build every detection, then all the ML, then all the automation. Build **one complete vertical slice first**:

> **one detection → Elastic webhook → n8n → Slack alert → disable the AD user**

Once that works end‑to‑end you have a *demoable project* and a proven pipeline. Then you widen it (more detections, the ML path, enrichment, cases, approval gate). This is the fastest route to "it works," and it's how you avoid a half‑built mess if you run out of time.

---

## 4. The plan, day by day

### Day 1 — Active Directory + get its logs into Elastic

**Goal:** a working domain, realistic identities, auditing on, AD + Sysmon logs flowing into Kibana.

1. **New VM:** Windows Server 2022 (2 vCPU, 4 GB RAM). Set a static IP; make the DC its own DNS server.
2. **Promote to Domain Controller:** add the *Active Directory Domain Services* role → promote to a new forest, e.g. `lab.local`.
3. **Create realistic content:** a few OUs (`HR`, `IT`, `Finance`), ~8–10 users, a couple of groups incl. `Domain Admins`. This is what your detections and ML will watch.
4. **Domain‑join** your existing Windows client to `lab.local` (so its logons authenticate through the DC and generate 4624/4768 events).
5. **Turn on auditing** via *Group Policy → Advanced Audit Policy Configuration* on the DC (see the table in §5). This is the step people forget — without it AD is quiet.
6. **Install Sysmon** on the DC and the Windows client (use a curated config such as SwiftOnSecurity or Olaf Hartong's modular one) for rich process/network events.
7. **Ship the logs:** in Kibana **Fleet**, enroll an **Elastic Agent** on the DC (you already have Fleet if your Windows host reports in). Add the **System** integration (Security/System/Application channels) and the **Windows** integration (Sysmon, PowerShell). Confirm events land in **Discover**.

**Definition of done:** you can search `event.code: "4624"` and `winlog.channel: "Microsoft-Windows-Sysmon/Operational"` in Kibana and see live events from the DC and client.

### Day 2 — The thin end‑to‑end slice

**Goal:** prove the whole pipeline with **one** detection that reaches n8n and disables a user.

1. **Install n8n** (Docker is easiest — one container). Run it on the Ubuntu server or the host to save RAM. Get the editor open on `http://<host>:5678`.
2. **Build the smallest workflow:** `Webhook (trigger)` → `Slack/Email (send)`. Copy the webhook's *test URL*.
3. **Create one Elastic detection rule** in *Kibana → Security → Rules*, e.g. **"Brute force: ≥ 8 failed logons (4625) for one user in 5 minutes."** Add a **Webhook connector** as the rule's action, pointed at your n8n webhook URL; send the alert fields as JSON.
4. **Trigger it for real:** on the client, fail a domain login 8+ times. Watch the alert fire → Elastic POSTs to n8n → Slack message appears. 🎉 Pipeline proven.
5. **Add the response node:** append an `SSH` node (to the DC, running PowerShell `Disable-ADAccount -Identity <sam>`) **or** the community **LDAP node** (set the account's `userAccountControl` disable bit). Use a **dedicated least‑privilege service account** that can only disable users in your lab OU.

**Definition of done:** one real failed‑logon burst automatically posts to Slack **and** disables that AD account. Record a screen capture here — this clip is your project's money shot.

### Day 3 — Breadth: more detections, the ML path, enrichment, cases, approval gate

**Goal:** turn the slice into a believable insider‑threat system.

1. **Add 4–6 detection rules** covering the scenarios in §5 (off‑hours logon, added to Domain Admins, new account created, account lockout, log cleared, dormant‑account logon).
2. **Wire the Isolation Forest to live data:** a small Python service that (a) queries Elasticsearch for per‑user behaviour features (logons/hour, distinct hosts, failed‑logon ratio, off‑hours count, privilege events), (b) scores them with your model, (c) POSTs any anomaly to a **second n8n webhook** (and optionally writes it back to an `insider-anomalies` index so it shows in Kibana). Run it on a schedule (cron / a loop).
3. **Enrich in n8n:** add `HTTP Request` nodes for IP reputation (AbuseIPDB / VirusTotal) and an `LDAP`/lookup node to pull the user's group membership and last logon.
4. **Add case management:** simplest is to append a row to a Google Sheet or index a doc into a `cases-*` index; nicer is the **TheHive** node. This gives you an audit trail.
5. **Add a human approval gate** before the destructive action: an n8n `Wait` (resume‑on‑webhook) or a Slack "Approve / Deny" button. *This is a senior touch — real SOAR keeps a human in the loop for account disable.*

**Definition of done:** both trigger paths (rules **and** ML) flow through one enrichment→alert→case→approval→respond workflow.

### Day 4 — Portfolio polish + push to GitHub

**Goal:** make it *look* as good as it works. A recruiter spends 60 seconds — the README and the demo GIF do the talking.

1. **Architecture diagram** (draw.io / Excalidraw) — export a PNG to `docs/`.
2. **Screenshots:** the Kibana dashboard, a detection rule, the n8n canvas, a Slack alert, the disabled account.
3. **Demo GIF:** the Day‑2 clip — trigger → alert → auto‑disable.
4. **Detection‑as‑code:** export your rules (`.ndjson`) and the n8n workflow (`.json`) into the repo.
5. **Write the README** (structure in §8) and **push** (each portfolio project = its own repo).
6. *(Optional, for the "reproducible" wow):* an Ansible playbook or setup script under `provisioning/` that stands the lab back up.

**Definition of done:** the repo is public, the README leads with the diagram + GIF, and someone could understand the whole project without running it.

---

## 5. Reference — AD auditing & the detections it enables

**Enable these subcategories** (GPO → *Advanced Audit Policy Configuration*, on the Default Domain Controllers Policy), Success **and** Failure:

| Category | Subcategory | Gives you |
|---|---|---|
| Account Logon | Credential Validation; Kerberos Auth/Service Ticket | 4776, 4768, 4769, 4771 |
| Logon/Logoff | Logon; Logoff; Account Lockout; Special Logon | 4624, 4625, 4634/4647, 4740, 4672 |
| Account Management | User Account Mgmt; Security Group Mgmt | 4720, 4722, 4725, 4726, 4738, 4728, 4732, 4756 |
| DS Access | Directory Service Changes | 5136 |
| Detailed Tracking | Process Creation (+ command line) | 4688 |

**Insider‑threat detections to build (map signal → event):**

| Scenario | Signal | Key events |
|---|---|---|
| Brute force / password spray | many failed logons | 4625, 4771 |
| Account lockout | repeated bad passwords | 4740 |
| Off‑hours logon | logon outside 07:00–19:00 | 4624 (+ time filter) |
| Privilege escalation | added to admin group | 4728, 4732, 4756 |
| Rogue account created | new/enabled account | 4720, 4722 |
| Dormant account use | logon by long‑idle user | 4624 (+ baseline) |
| Special/admin logon | privileged rights assigned | 4672 |
| Anti‑forensics | security log cleared | 1102 |
| Suspicious process | process create on host | Sysmon 1 / 4688 |

---

## 6. n8n response workflow — node by node

1. **Webhook** (trigger) — receives alert JSON from the Elastic connector; a second Webhook receives the ML service's anomalies.
2. **Edit Fields (Set)** — normalise to one schema: `user, host, src_ip, rule, severity, time`.
3. **HTTP Request** — enrich `src_ip` (AbuseIPDB / VirusTotal).
4. **LDAP / lookup** — pull the user's groups, enabled status, last logon.
5. **IF** — severity/confidence threshold (only escalate high‑confidence).
6. **Dedupe** — check the case store for an open case on this user; skip if present.
7. **Slack / Email** — notify the SOC channel with the enriched summary.
8. **Create case** — TheHive node **or** Google Sheet row **or** index into `cases-*`.
9. **Approval gate** — `Wait` (resume on webhook) or Slack Approve/Deny button.
10. **SSH → DC** — on approval: `Disable-ADAccount -Identity <sam>` (or LDAP node sets the disable bit).
11. **(Optional) Isolate host** — Elastic Defend isolate action via the Kibana API.
12. **Update case → "contained"** and post confirmation to Slack.

---

## 7. Active response — do it safely (lab notes)

- **Approval gate on by default.** Auto‑disable with no human is flashy but reckless; the gate is the *mature* choice and a great talking point.
- **Least‑privilege service account** — rights to disable users **only** in your lab OU. Never a Domain Admin token in n8n.
- **Dry‑run switch** — a workflow variable that logs "would disable X" instead of doing it, for testing.
- **Lab only.** Say so in the README. Never point this at production identities.

---

## 8. Portfolio polish — README structure

1. **Title + one‑liner** — "Insider‑threat detection & automated response lab (Elastic SIEM + AD + ML + n8n SOAR)."
2. **Architecture diagram** (PNG).
3. **What it detects** — the scenario table.
4. **How it works** — the detection → SOAR flow, with the **demo GIF**.
5. **The ML** — features, why Isolation Forest, how it's wired.
6. **The automation** — n8n workflow screenshot + what each stage does.
7. **Tech stack** — and one line placing n8n next to XSOAR/Shuffle.
8. **Reproduce it** — setup steps (or the provisioning playbook).
9. **Lessons learned / next steps.**
10. **Disclaimer** — lab environment.

---

## 9. Suggested repo layout

```
siem-insider-threat/
├─ README.md
├─ ROADMAP.md
├─ docs/            architecture.png · screenshots/ · demo.gif
├─ detections/      exported Elastic rules (.ndjson)
├─ ml/              isolation_forest.py · features.md · requirements.txt
├─ n8n/             insider-threat-workflow.json
├─ sysmon/          sysmonconfig.xml
├─ gpo/             audit-policy.md  (the settings you enabled)
└─ provisioning/    optional: ansible/ or setup scripts
```

---

## 10. RAM budget (VirtualBox, one PC)

DC ≈ 4 GB · Windows client ≈ 4 GB · Ubuntu (ELK) ≈ 4–6 GB · n8n (Docker) ≈ 0.5–1 GB. On 16 GB you're fine if you cap Elasticsearch heap (`-Xms1g -Xmx1g` for a lab) and run n8n on the Ubuntu box rather than a 4th VM. On 8 GB, run the client only when you need to generate events.

---

## References
- Elastic — Webhook connector & action: https://www.elastic.co/guide/en/kibana/current/webhook-action-type.html
- Elastic — System integration: https://www.elastic.co/docs/reference/integrations/system
- Elastic — Windows integration (Sysmon/PowerShell): https://www.elastic.co/docs/reference/integrations/windows
- n8n — Elastic Security + Kibana: https://n8n.io/integrations/elastic-security/and/kibana/
- n8n — LDAP / Active Directory community node: https://github.com/Joffcom/n8n-nodes-ldap
- n8n — Execute Command node: https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.executecommand
