# n8n SOAR Workflow — Insider-Threat Response

The automation "brain". A webhook receives an alert (from an Elastic detection rule
**or** the ML detector), and n8n runs the response:

```
Webhook  ->  Normalize  ->  High severity?  --yes-->  Enrich source IP (ip-api)
                                   |                        ->  Notify SOC (Slack)
                                   |                        ->  Disable AD user (SSH to the DC)
                                   +--no--> (drop / log only)
```

`insider-threat-workflow.json` is importable. Nodes use only built-in n8n node types.

## 1. Stand up n8n (Docker)
On the SIEM server (or any lab host with Docker):
```bash
sudo docker run -d --name n8n --restart unless-stopped \
  -p 5678:5678 -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n
```
No Docker? `sudo apt install -y docker.io` first, or run `npx n8n` (needs Node 18+).
Then open `http://<host>:5678`, create the owner account.

## 2. Import the workflow
n8n editor -> top-right **⋮ menu -> Import from File** -> pick `insider-threat-workflow.json`.

## 3. Configure the three external touch-points
- **Notify SOC (Slack):** replace the URL in that node with your Slack **Incoming Webhook**
  URL (Slack -> Apps -> Incoming Webhooks). Prefer email? Swap it for the Send Email node.
- **Disable AD user (SSH):** add an **SSH credential** on that node pointing at your Domain
  Controller (with OpenSSH for Windows + a least-privilege service account that can only
  disable users in your lab OU). No DC yet? Just **disable this node** for now — the rest runs.
- **Enrich source IP:** works as-is (ip-api.com, free, no key).

Then click **Active** (top-right) and copy the **Production URL** of the Webhook node —
it looks like `http://<host>:5678/webhook/insider-threat`.

## 4. Point your detections at it
- **Elastic rules:** Kibana -> Stack Management -> Connectors -> **Webhook** -> paste that
  Production URL. Add it as an **Action** on each rule (body template is in
  `../detections/README.md`).
- **ML detector:** set `N8N_WEBHOOK_URL` to the same URL and run with `--emit`
  (see `../ml/README.md`).

## 5. Test it right now (no real data needed)
With the workflow **Active**:
```bash
curl -X POST http://<host>:5678/webhook/insider-threat \
  -H "Content-Type: application/json" \
  -d '{"user":"j.doe","host":"WIN-CLIENT","source_ip":"8.8.8.8","rule":"Excessive Failed Logons","severity":"high"}'
```
Watch it run in **Executions** — it should enrich the IP and fire the Slack message. (While
building, use the **Test** button + the `…/webhook-test/insider-threat` URL instead.)

## Safety (lab)
- The `severity == high` gate keeps low-signal alerts from triggering a disable.
- **Add a manual-approval step** (an `Approval`/`Wait` node) before the SSH disable for a
  human-in-the-loop — the mature SOAR pattern, and a great thing to show in the demo.
- Least-privilege service account; never point this at production identities.
