# SecureNet AI — Enterprise Network Intrusion Detection & Active Prevention System (NIDS/NIPS)

**Real-Time Packet Ingress • Zero-Mock Architecture • Kernel Firewall Active Defense**

SecureNet AI is an operational, real-time NIDS/NIPS and host firewall management appliance designed for enterprise Security Operations Centers (SOC) and rigorous academic defense evaluations.

> **CRITICAL CORE PRINCIPLE: ZERO MOCK DATA**  
> The system starts with strictly **0 packets** and **0 threats**. There are **no** simulated loops, **no** `random.randint()` generators, and **no** fake background tickers. The dashboard only populates when real physical network frames arrive over the network card and are captured by promiscuous sockets.

---

## The Three Golden Rules of Portable Packet Sniffers

When presenting or running on a partner's machine, following these three rules guarantees zero setup crashes:

### 1. Dynamic Network Interface Auto-Detection
Network interface names are never identical across machines (e.g. `Wi-Fi`, `Ethernet 2`, `enp3s0`). SecureNet AI never hardcodes interface names. On startup, the backend automatically scans working adapters and presents a foolproof prompt:
```text
Starting SecureNet AI Backend...

Scanning network interfaces...
Found active interfaces:
 [1] Wi-Fi (IP: 192.168.1.15)
 [2] Loopback Pseudo-Interface (IP: 127.0.0.1)

Enter the number of the interface to monitor [default: 1]:
```

### 2. Elevated Administrator Privileges
Operating systems forbid standard user processes from listening to promiscuous raw network sockets.
- **Windows:** Open Command Prompt or PowerShell as **Administrator**.
- **Linux:** Run with `sudo python3 main.py`.

### 3. Packet Capture Driver on Windows
- **Linux:** Raw socket capture is native in the Linux kernel (`AF_PACKET`).
- **Windows:** Install [Npcap](https://npcap.com/) (installed in "WinPcap API-compatible Mode"). SecureNet AI also includes native Windows promiscuous raw socket fallback (`SIO_RCVALL`) for zero-dependency packet ingestion.

---

## Live Demonstration Guide for Examiners & Presentations

### Presentation Setup
1. Connect both laptops (Defender Laptop A and Attacker Laptop B) to the **same Wi-Fi network** or mobile hotspot.
2. Verify the local IP of Laptop A (e.g. `192.168.1.15`).
3. Start the SecureNet AI backend on Laptop A as Administrator. Select `[1]` (Wi-Fi).
4. Launch the frontend dashboard on Laptop A (`http://localhost:5173`).
5. **Show the examiner that the dashboard starts completely clean: 0 Packets, 0 Threats, 0 PPS.**

---

### Demonstration Method 1: The "Live Fire" Attacker Terminal
*Best for showing the real-time Threat Detection and Active Kernel Firewall.*

Open a raw terminal on Attacker Laptop B (or a second terminal window on the same machine):

#### 1. SQL Injection Live Attack:
```bash
curl "http://<PARTNER_IP>:8000/login?user=admin' UNION SELECT null, username, password FROM users--"
```
**What Happens Live:**
1. The packet physically hits Laptop A's NIC.
2. Scapy promiscuous socket intercepts the raw frame.
3. The SQLi signature (`UNION SELECT`) is matched.
4. The dashboard flashes red, the right-side **Threat Alert Toast** pops up with "Critical SQL Injection Triggered", and the Severity chart increments.
5. The Active Defense engine instantly executes the OS kernel command:
   ```cmd
   netsh advfirewall firewall add rule name="SecureNet_Block_<ATTACKER_IP>" dir=in action=block remoteip=<ATTACKER_IP>
   ```
6. **The Proof:** Laptop B executes the `curl` command a second time. **The command simply hangs and times out** because the OS firewall is actively dropping all packets from that IP!

#### 2. Cross-Site Scripting (XSS) Live Attack:
```bash
curl "http://<PARTNER_IP>:8000/api/data?search=<script>alert('XSS_BREACH')</script>"
```
**What Happens Live:**
- The XSS script tag is detected, the dashboard alerts the operator, and the offending IP is blocked.

#### 3. Deep Packet Dissection (DPI):
- Click on the threat row in the dashboard to open the **Deep Packet Inspection Modal**.
- Show the examiner the genuine Layer 3/4 5-Tuple, Wireshark-style Hex Dump octets, and Layer 7 ASCII decoded payload.

---

### Demonstration Method 2: High-Speed Traffic Blast & Scale Testing
*Best for showing dashboard responsiveness and high-throughput handling.*

When asked: *"Can this handle high packet volume or DDoS scale?"*:
Run the included traffic generator utility from Laptop B or terminal:

```bash
cd backend
python traffic_replay.py --blast 1000 --pps 200 --target <PARTNER_IP>
```
**What Happens Live:**
- 1,000 real physical UDP packets are blasted to the target NIC at 200 packets/sec.
- The **Real-Time Packets Per Second (PPS)** chart spikes instantly to reflect the real socket throughput.
- The **Inbound vs Outbound Bandwidth** chart plots real throughput based on frame lengths.
- The **Network Protocol Distribution** donut chart dynamically calculates protocol ratios.

---

## Role-Based Access Control (RBAC) Credentials

| Persona | Username | Password | Privileges |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `admin123` | Full control (Real-time DPI, Policy configuration, Simulation/Real firewall toggle, Approvals, Rollback, Topology editor, PDF/CSV reports, Audit logs) |
| **Security Analyst**| `analyst` | `analyst123` | Real-time DPI, Threat investigation, AI host analysis, Manual action proposals, SIEM reports, Read-only topology |
| **Standard Employee**| `employee`| `employee123`| Read-only sanitized dashboard (payloads redacted), topology read-only; firewall, response execution, and reports hidden |

---

## AI Behavioral Anomaly Detection & Threat Scoring

### 1. Machine Learning Component (`IsolationForest`)
SecureNet AI pairs deterministic signature-based detection with an unsupervised **Isolation Forest** behavioral model.
- **Features Extracted (10 Network-Flow Metrics):**
  1. `conn_count` (Connection frequency)
  2. `unique_dst_ports` (Port diversity / port sweep indicator)
  3. `unique_dst_ips` (Host fan-out / horizontal reconnaissance)
  4. `total_bytes` (Volumetric transmission magnitude)
  5. `avg_bytes_per_pkt` (Packet size anomalies / exfiltration)
  6. `outbound_ratio` (Egress vs ingress imbalance)
  7. `tcp_syn_ratio` (Half-open SYN scanning ratio)
  8. `sensitive_port_ratio` (Access targeting database/SSH/RDP ports)
  9. `dns_query_ratio` (DGA and DNS tunneling indicators)
  10. `payload_entropy` (Shannon entropy in bits/char for encrypted/obfuscated payload detection)

- **Offline Training & Validation Pipeline:**
  ```powershell
  cd backend
  python train_ai_model.py
  ```
  Artifacts generated:
  - Model: `backend/models_store/isolation_forest_v1.joblib`
  - Metadata & Evaluation: `backend/models_store/model_metadata.json`
  - Validation metrics: 95.33% normal baseline retention, 4.67% false positive rate, 100% holdout anomaly recall.

### 2. Multi-Factor Risk Scoring Engine
Risk scores are calculated dynamically on a calibrated 0–100 scale:
$$\text{Score} = \min(100, [0.40 \times \text{Severity} + 0.25 \times \text{Confidence} + 0.20 \times \text{AI Anomaly} + 0.15 \times \text{Recurrence}] \times \text{Asset Multiplier})$$
- **Risk Bands:**
  - `0 – 29`: Low
  - `30 – 49`: Moderate
  - `50 – 69`: Elevated
  - `70 – 89`: High
  - `90 – 100`: Critical
- **Critical Asset Multipliers:** Gateway routers (`1.25x`), Core Database Clusters (`1.35x`), Perimeter Firewalls (`1.30x`).

---

## NIDS Telemetry Ingestion (Suricata EVE JSON)

The backend provides direct ingestion endpoints for structured NIDS sensors:
- **Batch Event Ingestion:** `POST /api/nids/events/ingest`
- **Multi-line EVE JSON Upload:** `POST /api/nids/eve/upload` (supports uploading standard `eve.json` files)
- **Sensor Status & Health:** `GET /api/nids/sensor/status`

Supported event types include `alert`, `flow`, `anomaly`, `dns`, and `http`. Telemetry is validated, deduplicated, normalized, stored in PostgreSQL/SQLite, and broadcast to the frontend in real time.

---

## Automated Response Centre & Safety Guardrails

- **Simulation Mode by Default:** All automated responses initialize in safe simulation mode (`simulation_mode: true`). Actions are recorded in the SOC ledger without executing kernel-level firewall drops.
- **Real Kernel Firewall Toggle:** Real enforcement (`netsh` on Windows / `iptables` on Linux) requires explicit administrative toggle (`real_enforcement_authorized: true`).
- **Protected Allowlists:** Loopback addresses (`127.0.0.1`), configured gateways (`192.168.1.1`), internal DNS (`8.8.8.8`, `1.1.1.1`), and critical servers are protected from automated blocking.
- **TTL Expiration & Rollback:** Actions can have configurable time-to-live (e.g. 15m, 1h). A background daemon automatically expires restrictions, and administrators can click **Rollback / Unblock** at any time.

---

## Automated Testing Suite

Run the full automated test suite covering EVE JSON parsing, deterministic rule classification, AI feature extraction, risk scoring, response policies, and RBAC:
```powershell
cd backend
pytest tests/test_nids_and_response.py -v
```

---

## Quick Start Instructions

### 1. Start the Backend Server
```powershell
cd backend
python main.py
```
- Select interface `[1]` (Wi-Fi or primary LAN).
- Backend runs on `http://0.0.0.0:8000`.

### 2. Start the Frontend Dashboard
```powershell
cd frontend
npm run dev
```
- Frontend runs on `http://localhost:5173`.
- Open in browser, select **Alex Vance (Administrator)** to auto-fill credentials, and log in.
