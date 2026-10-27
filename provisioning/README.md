# Provisioning — Active Directory lab (`lab.local`)

These scripts build the AD side of the lab, run in this order. Each one stops on the first error.

| # | Script | Where | What it does |
|---|---|---|---|
| 1 | `01-create-dc-vm.ps1` | **Host** | Creates the `DC01` VirtualBox VM (2 vCPU / 4 GB / 60 GB, NAT + host-only) and installs Windows Server 2025 unattended |
| 2 | `02-promote-dc.ps1` | DC01 | Static IP `192.168.56.20`, UK time zone, installs AD DS + DNS, promotes the new forest `lab.local` (reboots) |
| 3 | `03-populate-ad.ps1` | DC01 | OUs, 9 users, groups, the least-privilege `svc_n8n` responder account, OpenSSH, DNS forwarders |
| 4 | `04-audit-policy.ps1` | DC01 + client | Advanced Audit policy, command-line logging, lockout policy |
| 5 | `05-sysmon-and-agent.ps1` | DC01 + client | Sysmon (SwiftOnSecurity config) + Elastic Agent enrolled into Fleet |
| 6 | `06-join-client.ps1` | Client (WinDev2407Eval) | Points DNS at the DC and joins `lab.local` as `WS01` |
| 7 | `07-simulate-insider.ps1` | DC01 | Generates attack events: `BruteForce`, `Lockout`, `PrivEsc`, `RogueAccount`, `LogClear` |

To get the scripts into DC01, use the shared clipboard, or add a VirtualBox shared folder pointing at this repo.
Run each script from an **elevated** PowerShell, and first run `Set-ExecutionPolicy -Scope Process Bypass`.

## Network

| Machine | Lab IP (host-only) | Role |
|---|---|---|
| Host (your laptop) | 192.168.56.1 | Kibana in the browser, n8n (if run on the host) |
| siem server | 192.168.56.10 | Elasticsearch, Kibana, Fleet Server |
| **DC01** | **192.168.56.20** | Domain controller + DNS for `lab.local` |
| WS01 (WinDev2407Eval) | 192.168.56.30 (static: host-only DHCP gave it no address) | Domain-joined client |

RAM: SIEM 11 GB + DC 4 GB + client 8 GB ≈ 23 GB of your 32 GB. If things get slow, lower the client to 4 GB.

## Directory layout

```
lab.local
└─ OU=Lab
   ├─ HR               a.smith, b.jones
   ├─ Finance          c.brown, d.wilson, j.doe   ← the "insider"
   ├─ IT               e.taylor, f.khan, old.contractor (dormant)
   ├─ ServiceAccounts  svc_backup, svc_n8n
   ├─ Groups           GG-HR, GG-Finance, GG-IT, Finance-Share-RW
   └─ Computers        joined workstations
```

## Why `svc_n8n` can't do much (talk about this in your report)

- `svc_n8n` has one delegated permission: read/write `userAccountControl` on **user objects inside `OU=Lab`**. That is enough for `Disable-ADAccount` and nothing else.
- Privileged accounts (Domain Admins, etc.) are protected by **AdminSDHolder**, so the responder **can't disable an admin**, even if a spoofed alert names one.
- The n8n workflow only accepts plain sAMAccountNames (`^[A-Za-z0-9._-]{1,20}$`) before building the PowerShell command. This blocks command injection from a crafted alert.
- sshd on the DC only accepts connections from `192.168.56.0/24`.

> ⚠️ AdminSDHolder also applies to any account that was **ever** in Domain Admins. That's why the `PrivEsc` simulation uses `f.khan` and not `j.doe`. Keep `j.doe` for the disable demo.

## Demo run (end-to-end)

1. In n8n, keep `dry_run = true` in **Normalize** and activate the workflow.
2. On DC01, run `.\07-simulate-insider.ps1 -Scenario BruteForce`, which sends 9 failed logons for `j.doe`.
3. The Elastic rule "Excessive Failed Logons" fires and POSTs to n8n. Slack then gets an alert with **Approve / Deny** links.
4. Click **Approve**. You get "DRY RUN – would disable j.doe".
5. Set `dry_run = false` and repeat. `j.doe` is now disabled (`Get-ADUser j.doe` shows `Enabled: False`). Re-enable it with `Enable-ADAccount j.doe`.

## Troubleshooting

- **Unattended install fails or the VM boots to an empty disk:** VirtualBox 7.0.10 is older than Server 2025. Install manually from the ISO already attached to the VM: pick *Standard Evaluation (Desktop Experience)*, then continue with script 02. Updating VirtualBox to 7.1+ also fixes it.
- **Client can't find the domain:** both NICs on the client need DNS `192.168.56.20`. Check with `nslookup lab.local`.
- **n8n SSH login as `svc_n8n` is rejected:** on DC01, open Event Viewer → Security → 4625 and read the *Failure Reason*. Test by hand from the SIEM server with `ssh 'lab\svc_n8n'@192.168.56.20`.
- **SSH works but you get "Insufficient access rights":** the target is outside `OU=Lab` or is a protected (ex-)admin. This is working as designed.
