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
| **Administrator** | `admin` | `admin123` | Full control (Real-time DPI, Firewall block/unblock, Topology editor, PDF reports) |
| **Security Analyst**| `analyst` | `analyst123` | Real-time DPI, authorized firewall management, reports, read-only surveillance topology |
| **Standard Employee**| `employee`| `employee123`| Read-only sanitized dashboard (payloads redacted), topology read-only, firewall & reports hidden |

---

## Quick Start Instructions

### 1. Start the Backend Server
```powershell
cd securenet-ai\backend
python main.py
```
- Select interface `[1]` (Wi-Fi or primary LAN).
- Backend runs on `http://0.0.0.0:8000`.

### 2. Start the Frontend Dashboard
```powershell
cd securenet-ai\frontend
npm run dev
```
- Frontend runs on `http://localhost:5173`.
- Open in browser, select **Alex Vance (Administrator)** to auto-fill credentials, and log in.
