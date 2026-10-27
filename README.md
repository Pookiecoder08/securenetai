# SecureNet AI — Enterprise Hybrid Cloud-Local SOC Platform

**Production NIDS/NIPS • Zero-Mock Architecture • Kernel Firewall Active Defense**

SecureNet AI is a hybrid cloud-local Network Intrusion Detection & Prevention System (NIDS/NIPS). It bridges a cloud-deployed React/Vite security operations center on **Vercel**, authentication and state persistence on **Supabase**, and a local hardware packet inspection sensor and kernel firewall agent running on the operator's PC exposed via **Ngrok**.

---

## 1. System Architecture

```
 ┌─────────────────────────────────────────────────────────────┐
 │                 Vercel Cloud Deployment                     │
 │              React 18 + Vite SOC Dashboard                  │
 └──────────────┬───────────────────────────────┬──────────────┘
                │ (1) Supabase GoTrue Auth      │ (2) HTTPS / WSS via Ngrok
                ▼                               ▼
 ┌───────────────────────────────┐     ┌──────────────────────────────────────────────────┐
 │        Supabase Cloud         │     │         Local Host (Sensor & Active Defense)     │
 │  - PostgreSQL Database        │     │  - FastAPI Sensor Daemon (0.0.0.0:8000)          │
 │  - GoTrue JWT Engine          │◄────┤  - Scapy Promiscuous Sniffer (Raw Socket Engine) │
 │  - Session & Role Metadata    │ (3) │  - Kernel Firewall Controller (netsh / iptables) │
 └───────────────────────────────┘     │  - Ngrok Ingress Tunnel (ngrok http 8000)        │
                                       └──────────────────────────────────────────────────┘
```

1. **Frontend (Vercel):** Single-page SOC application connecting to Supabase for authentication and streaming live network frames, alerts, and topology state via the Ngrok tunnel.
2. **Database & Auth (Supabase):** PostgreSQL database storing topology architecture, firewall rules, and audit logs. GoTrue issues HS256 JWTs verifying operator identity.
3. **Local Sensor Agent (PC):** Runs natively with administrative privileges to bind promiscuous sockets, dissect live packets, execute kernel firewall drops, and authenticate incoming commands using the Supabase JWT secret.

---

## 2. Operator Access Credentials

Authentication is strictly enforced via Supabase GoTrue. Log in using the credentials below:

| Role | Operator Identifier | Passkey | Access Permissions |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@securenet.ai` | `admin123` | Full control: Firewall ACL enforcement, Network Topology canvas, DPI inspector, SIEM reports |
| **Analyst** | `analyst@securenet.ai` | `analyst123` | Security operations: Packet analysis, Threat monitoring, Firewall rules, Incident investigation |
| **Employee** | `employee@securenet.ai` | `employee123` | Read-only viewer: Sanitized operational telemetry with redacted payload bytes |

---

## 3. Supabase Configuration (Database & GoTrue Auth)

### Step 1: Create a Supabase Project & Retrieve Credentials
1. Navigate to [supabase.com](https://supabase.com) and create a new project. During creation, save your **Database Password** (or reset it in settings if forgotten).
2. Retrieve your project strings using either of the two methods in the new UI:

#### Method A: The Top Header "Connect" Button (Quickest Method)
- At the top of your Supabase dashboard (next to your project name), click the **Connect** button to open the connection modal:
  - **For Frontend (`VITE_SUPABASE_URL` & `VITE_SUPABASE_ANON_KEY`):**
    - Click **App Frameworks** (or select **React / Vite**).
    - Copy the **Project URL** (`https://[project-ref].supabase.co`).
    - Copy the **Anon / Publishable Key** (`eyJhbGci...` or `sb_publishable_...`).
  - **For Backend Database (`DATABASE_URL`):**
    - Click the **ORMs** or **Database** tab -> choose **URI**.
    - Select **Session Pooler** (Port `6543`).
    - Copy the URI string: `postgresql://postgres.[project-ref]:[YOUR-PASSWORD]@aws-0-[region].pooler.supabase.com:6543/postgres`
    - Replace `[YOUR-PASSWORD]` with your actual database password.

#### Method B: Project Settings (Gear ⚙️ Icon in Left Sidebar)
- **Database Connection String (`DATABASE_URL`):**
  - Click ⚙️ **Project Settings** (gear icon at the bottom of the left sidebar).
  - Select **Database** from the settings menu.
  - Under **Connection parameters / Connection string**, select the **URI** tab.
  - Select mode: **Session** (port `6543`).
  - *(If you forgot your password)*: Scroll down on this same page to **Database password** and click **Reset database password**.
- **API Keys & URL (`VITE_SUPABASE_URL` & `VITE_SUPABASE_ANON_KEY`):**
  - In ⚙️ **Project Settings**, select **API** (or **API Keys** / **Data API**).
  - Under **Project URL**, copy the URL (`https://[project-ref].supabase.co`).
  - Under **Project API keys**, copy the key labeled `anon` `public` (or `Publishable key`).
- **Backend JWT Secret (`SUPABASE_JWT_SECRET`):**
  - In ⚙️ **Project Settings**, select **JWT Keys** (or scroll to **JWT Settings** under **API**).
  - Copy the **JWT Secret** string.

### Step 2: Execute Database DDL Schema
Open the **SQL Editor** in your Supabase dashboard and run the following script to create all required tables:

```sql
-- 1. Topology Architecture State
CREATE TABLE IF NOT EXISTS topology_state (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL DEFAULT 'default',
    nodes_json TEXT NOT NULL,
    edges_json TEXT NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

-- 2. Audit Trail Ledger
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    actor VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(128),
    details TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'SUCCESS'
);

-- 3. Kernel Firewall Rule Store
CREATE TABLE IF NOT EXISTS firewall_rules (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason VARCHAR(255) NOT NULL,
    blocked_by VARCHAR(64) NOT NULL DEFAULT 'AUTOMATED_NIPS',
    timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- 4. Ingress Packet Telemetry
CREATE TABLE IF NOT EXISTS packet_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(16) NOT NULL,
    is_threat BOOLEAN NOT NULL DEFAULT FALSE,
    threat_type VARCHAR(64),
    payload_sample TEXT
);

-- 5. Threat Detections
CREATE TABLE IF NOT EXISTS threat_detections (
    id SERIAL PRIMARY KEY,
    event_id INTEGER,
    timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(16) NOT NULL,
    attack_category VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    confidence INTEGER NOT NULL,
    evidence TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'NEW',
    assigned_to VARCHAR(64),
    notes TEXT
);

-- 6. Response Actions & Policies
CREATE TABLE IF NOT EXISTS response_policies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    description VARCHAR(255),
    min_risk_score INTEGER NOT NULL,
    severity_threshold VARCHAR(16) NOT NULL,
    action_type VARCHAR(32) NOT NULL DEFAULT 'RECOMMEND',
    duration_seconds INTEGER NOT NULL DEFAULT 3600,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    allowlist_ips TEXT NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS response_actions (
    id SERIAL PRIMARY KEY,
    risk_assessment_id INTEGER,
    threat_id INTEGER,
    target_ip VARCHAR(45) NOT NULL,
    action_type VARCHAR(32) NOT NULL DEFAULT 'BLOCK',
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING_APPROVAL',
    is_simulated BOOLEAN NOT NULL DEFAULT TRUE,
    reason VARCHAR(255) NOT NULL,
    initiated_by VARCHAR(64) NOT NULL DEFAULT 'POLICY_ENGINE',
    policy_name VARCHAR(64),
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    executed_at TIMESTAMP WITHOUT TIME ZONE,
    expires_at TIMESTAMP WITHOUT TIME ZONE,
    reversed_at TIMESTAMP WITHOUT TIME ZONE,
    reversed_by VARCHAR(64),
    execution_output TEXT
);

-- 7. System Runtime Configuration
CREATE TABLE IF NOT EXISTS system_configs (
    id SERIAL PRIMARY KEY,
    key VARCHAR(64) UNIQUE NOT NULL,
    value TEXT NOT NULL,
    description VARCHAR(255),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

-- 8. Operator Accounts (Sync & Legacy Fallback)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL DEFAULT '',
    role VARCHAR(32) NOT NULL DEFAULT 'admin'
);

-- Seed Initial Default Network Topology
INSERT INTO topology_state (name, nodes_json, edges_json, updated_at)
VALUES (
    'default',
    '[{"id":"gateway-1","type":"customNode","position":{"x":100,"y":180},"data":{"label":"Gateway Edge Router","category":"router","ip":"198.51.100.1","status":"online","description":"Border BGP / Edge Routing Gateway"}},{"id":"firewall-1","type":"customNode","position":{"x":360,"y":180},"data":{"label":"Next-Gen Firewall (NGFW)","category":"firewall","ip":"10.0.0.1","status":"active","description":"Kernel Packet Filter & Active Defense Controller"}},{"id":"sensor-1","type":"customNode","position":{"x":620,"y":60},"data":{"label":"SecureNet NIDS Sensor","category":"sensor","ip":"10.0.0.50","status":"monitoring","description":"Promiscuous DPI & Threat Signature Analyzer"}},{"id":"web-1","type":"customNode","position":{"x":620,"y":280},"data":{"label":"Web Application Cluster","category":"server","ip":"10.0.1.10","status":"online","description":"Production HTTP/HTTPS Web Services"}},{"id":"db-1","type":"customNode","position":{"x":880,"y":280},"data":{"label":"Core Database Cluster","category":"database","ip":"10.0.2.20","status":"online","description":"Enterprise Relational Database (SQL)"}}]',
    '[{"id":"e1-2","source":"gateway-1","target":"firewall-1","animated":true,"label":"WAN Uplink"},{"id":"e2-3","source":"firewall-1","target":"sensor-1","animated":true,"label":"Mirror/TAP Port"},{"id":"e2-4","source":"firewall-1","target":"web-1","animated":false,"label":"DMZ Traffic"},{"id":"e4-5","source":"web-1","target":"db-1","animated":false,"label":"Internal Query Bus"}]',
    NOW()
)
ON CONFLICT DO NOTHING;
```

### Step 3: Create Operator Users in Supabase
In the Supabase Dashboard, navigate to **Authentication -> Users** and click **Add User -> Create User**:

1. **Admin Operator:**
   - Email: `admin@securenet.ai`
   - Password: `admin123`
   - Auto Confirm User: **Checked**
   - User Metadata (JSON): `{"role": "admin", "username": "admin"}`
2. **Analyst Operator:**
   - Email: `analyst@securenet.ai`
   - Password: `analyst123`
   - Auto Confirm User: **Checked**
   - User Metadata (JSON): `{"role": "analyst", "username": "analyst"}`
3. **Employee Operator:**
   - Email: `employee@securenet.ai`
   - Password: `employee123`
   - Auto Confirm User: **Checked**
   - User Metadata (JSON): `{"role": "employee", "username": "employee"}`

### Step 4: Summary Mapping of Supabase Strings to Environment Variables

| Variable Name | Found In Supabase UI | Where To Configure | Example Format |
| :--- | :--- | :--- | :--- |
| **`VITE_SUPABASE_URL`** | Top "Connect" button -> App Frameworks<br>*or* ⚙️ **Project Settings -> API -> Project URL** | `frontend/.env`<br>Vercel Environment Variables | `https://[ref].supabase.co` |
| **`VITE_SUPABASE_ANON_KEY`** | Top "Connect" button -> App Frameworks<br>*or* ⚙️ **Project Settings -> API -> anon public key** | `frontend/.env`<br>Vercel Environment Variables | `eyJhbGciOiJIUzI1NiIsIn...` or `sb_publishable_...` |
| **`DATABASE_URL`** | Top "Connect" button -> ORMs (URI)<br>*or* ⚙️ **Project Settings -> Database -> URI** | `backend/.env` | `postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres` |
| **`SUPABASE_JWT_SECRET`** | ⚙️ **Project Settings -> JWT Keys**<br>*or* ⚙️ **Project Settings -> API -> JWT Settings** | `backend/.env` | `super-secret-jwt-token-string...` |

---

## 4. Local Sensor Agent & Ngrok Deployment (Local PC)

The local Python agent acts as the NIDS sensor and active firewall controller.

### Step 1: Install Dependencies
Open an elevated terminal (**Run as Administrator** on Windows, or `sudo` on Linux):

```bash
cd backend
python -m venv venv
.\venv\Scripts\activate   # Linux: source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Configure `backend/.env`
Create a `.env` file inside `backend/`:

```env
# Supabase JWT Secret (Used to verify operator JWT tokens)
SUPABASE_JWT_SECRET=your_supabase_jwt_secret_here

# Supabase PostgreSQL Connection Pooler URL
DATABASE_URL=postgresql://postgres.yourprojectref:YourPassword@aws-0-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require

# Scapy Network Interface Index (Leave empty to auto-bind active LAN/Wi-Fi)
SECURENET_IFACE=1
CAPTURE_FILTER_MODE=soc_filtered

# Active Defense Boundaries
SIMULATION_MODE=false
REAL_FIREWALL_ENFORCEMENT_AUTHORIZED=true
ALLOWLIST_IPS=127.0.0.1,10.0.0.1,192.168.1.1,8.8.8.8,1.1.1.1,10.0.0.50
```

### Step 3: Start the Backend Daemon
Run the Python engine:

```bash
python main.py
```
*The engine auto-detects the active network adapter, sets `scapy.config.conf.iface`, and binds to `0.0.0.0:8000` without blocking terminal prompts.*

### Step 4: Expose the Sensor via Ngrok (For Cloud Vercel Access)

If `ngrok` is not installed on your system yet, install it using either method:
- **Option A (Winget - Fastest):** Run `winget install ngrok.ngrok` in PowerShell, then restart your terminal.
- **Option B (Direct Download):** Download the Windows 64-bit zip from [ngrok.com/download](https://ngrok.com/download) and place `ngrok.exe` in your `backend/` folder.

Next, authenticate ngrok with your free account token (from [dashboard.ngrok.com](https://dashboard.ngrok.com/get-started/your-authtoken)):
```bash
ngrok config add-authtoken <YOUR_AUTHTOKEN>
```

In a second terminal window, launch the tunnel:
```bash
ngrok http 8000
# Or if ngrok.exe is placed in the backend folder:
.\ngrok.exe http 8000
```
Note the generated HTTPS Forwarding URL (e.g., `https://abc1234.ngrok-free.app`). This is your `VITE_SENSOR_API_URL`.

*(Note: If you are running both frontend and backend locally for development, you can simply set `VITE_SENSOR_API_URL=http://localhost:8000` in `frontend/.env` without needing Ngrok).*

---

## 5. Vercel Frontend Deployment

Deploy the React/Vite dashboard to Vercel:

### Step 1: Import Project into Vercel
1. Push your repository to GitHub or GitLab.
2. In the Vercel dashboard, click **Add New... -> Project** and import the repository.
3. Set **Root Directory** to `frontend`.
4. Build settings are auto-detected (`npm run build`, output: `dist`).

### Step 2: Set Environment Variables
In the Vercel deployment configuration, add the following Environment Variables:

| Variable | Value | Description |
| :--- | :--- | :--- |
| `VITE_SUPABASE_URL` | `https://your-project.supabase.co` | Your Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | `eyJhbGciOi...` | Supabase public anonymous API key |
| `VITE_SENSOR_API_URL` | `https://your-tunnel.ngrok-free.app` | Ngrok HTTPS URL pointing to local PC |

> **Dynamic WebSocket Routing:** The frontend utility ([frontend/src/utils/api.js](file:///c:/Users/Administrator/Desktop/securenetai_new/frontend/src/utils/api.js)) automatically converts `https://...` from `VITE_SENSOR_API_URL` into `wss://...` for live packet telemetry streams, passing the operator's Supabase JWT Bearer token in query parameters.

### Step 3: Deploy & Launch
Click **Deploy**. Once built, open your Vercel deployment URL (e.g. `https://securenet-ai.vercel.app`), log in using the Admin credentials, and monitor your local network in real-time.

---

## 6. Live Fire Testing & Attack Demonstrations

Verify the real-time intrusion detection and active kernel drop pipeline:

### 1. SQL Injection (SQLi) Live Fire Attack
Execute from any remote device or terminal:
```bash
curl "http://<LOCAL_PC_IP>:8000/login?user=admin' UNION SELECT null, username, password FROM users--"
```
- Intercepted by Scapy promiscuous socket.
- SQLi signature triggered (`UNION SELECT`).
- OS Kernel command executed:
  ```cmd
  netsh advfirewall firewall add rule name="SecureNet_Block_<ATTACKER_IP>" dir=in action=block remoteip=<ATTACKER_IP>
  ```
- Subsequent `curl` requests from the attacker will hang and time out.

### 2. Cross-Site Scripting (XSS) Attack
```bash
curl "http://<LOCAL_PC_IP>:8000/api/search?q=<script>alert('XSS_ATTACK')</script>"
```
- High-severity XSS signature triggers.
- Live event pops up in Threat Monitor and records in Supabase `threat_detections`.

### 3. High-Throughput Traffic Blast Testing
```bash
python traffic_replay.py --blast 500 --pps 100 --target 127.0.0.1
```
- Tests real-time packet processing throughput without mock timers or simulated data.
- The UI rolling throughput and protocol donut update strictly upon real WebSocket packet events.
