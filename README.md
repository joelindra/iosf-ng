# IOSF-NG (iOS Mobile Security & API Testing Framework)
**Next-Generation iOS Application & API Penetration Testing Console**  
*Created By Anonre*

---

```text
 ___ ___  ___  ___       _  _  ___ 
|_ _/ _ \/ __|| __|     | \| |/ __|
 | | (_) \__ \| _|  --- | .` | (_ |
|___\___/|___/|_|       |_|\_|\___|

Created By Anonre
iOS Mobile Security & API Testing Framework (Next-Gen)
Inspired by Recon-ng | Non-Jailbreak & Jailbroken iOS Support
```

**IOSF-NG** is an end-to-end iOS application security testing framework designed for professional mobile penetration testers, security researchers, and red teams. Inspired by the interactive workflow of `recon-ng` and `metasploit`, it unifies **USB device inspection**, **Burp Suite CA installation**, **dynamic Frida 17+ SSL Pinning Bypass (with anti-debugging bypass)**, **in-process TLS plaintext capture**, and automated **OWASP Mobile & API Security Top 10 auditing**.

---

## ⚡ Core Features

- **Interactive Recon-ng Style Shell**: Intuitive command console with shortcut aliases (`apps`, `bp`, `ca`, `cap`, `audit`, `rep`).
- **Universal iOS SSL Pinning Bypass (Frida 17+)**:
  - Hooks Apple's `Security.framework` (`SecTrustEvaluateWithError`, `SecTrustEvaluate`, `SecTrustGetTrustResult`).
  - Hooks Apple's `libboringssl.dylib` (`SSL_set_custom_verify` custom callback replacer).
  - Multi-connection deduplication to prevent callback replacement collisions.
- **Anti-Debugging / Kernel Protection Bypass**:
  - Automatically recovers from iOS kernel `(os/kern) failure` / `PT_DENY_ATTACH` (e.g., TikTok, banking apps) via automatic **Early Spawn Instrumentation**.
- **Automated Root CA Profile Generation**:
  - Generates `.mobileconfig` profiles installing Root CA certificates directly to the iOS Keychain.
  - Automatically omits restricted MDM payloads (`com.apple.proxy.http.global`) to ensure 100% compatibility with standard, non-supervised iPhones.
- **Plaintext BoringSSL TLS Interception**:
  - Hooks `SSL_read` and `SSL_write` to capture raw HTTP/HTTPS traffic directly in memory into an SQLite database.
- **OWASP API Security Top 10 Engine**:
  - Analyzes recorded traffic against API1:2023 (BOLA), API2:2023 (Broken Auth), API3:2023 (BOPLA), token leakage, and sensitive header exposures.
- **Automated Executive & Technical Reports**:
  - Compiles interactive HTML and executive PDF assessment reports with one command.

---

## 🛠️ Requirements & Prerequisites

1. **Host Computer (Windows / macOS / Linux)**:
   - Python 3.10+
   - USB cable connecting to the iOS device
   - iTunes / Apple Mobile Device Support (Windows) or native usbmuxd (macOS/Linux)
   - Burp Suite Professional / Community Edition
2. **iOS Device (Physical iPhone / iPad)**:
   - Compatible with iOS 12.0 up to iOS 17.x
   - Supports both non-jailbroken (via injected gadget/developer profile) and jailbroken devices (via `frida-server`)
   - Unlocked screen with **"Trust This Computer"** accepted

---

## 🚀 Installation & Setup

1. **Clone or Download the Repository**:
   ```bash
   git clone https://github.com/your-repo/iosf-ng.git
   cd iosf-ng
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *(Or install core dependencies manually: `pip install frida rich click cryptography pymobiledevice3 weasyprint pygments`)*

---

## 📖 End-to-End Workflow Guide

### Step 1: Launch the Console
Launch the unified entrypoint:
```bash
python main.py
```
You will be greeted with the banner, connected USB device status, and the interactive prompt:
```text
Status: Device: iPhone (iPhone10,6, iOS 16.7.16) | Session: default | Proxy: 10.136.83.113:8080

iosf-ng $ 
```

---

### Step 2: Device & Application Enumeration
1. **Verify USB Connection**:
   ```text
   iosf-ng $ devices
   ```
   Displays device name, hardware model, iOS version, connection type, and UDID.

2. **List Applications**:
   ```text
   iosf-ng $ apps
   ```
   *Alias:* `ls`  
   Scans the device and prints an organized table showing:
   - Index number (`#`)
   - Display Name
   - Bundle Identifier
   - Process Status (`RUNNING (PID)` or `Stopped`)

---

### Step 3: Setup Burp Suite Proxy & Root CA
To route device traffic into Burp Suite without SSL untrusted errors:
```text
iosf-ng $ proxy
```
*Alias:* `ca`

1. **In Burp Suite**:
   - Go to **Proxy > Proxy settings > Proxy listeners**.
   - Edit listener port `8080` and set **Bind to address** to **All interfaces**.
2. **In IOSF-NG**:
   - The tool generates a custom `.mobileconfig` Root CA profile and launches a temporary local web server with a QR Code.
   - On the iPhone: Scan QR Code or open Safari and download the profile.
   - Go to iPhone **Settings > General > VPN & Device Management** and tap **Install**.
   - Go to iPhone **Settings > General > About > Certificate Trust Settings** and toggle **Full Trust for Root Certificates** ON.
3. **Configure Wi-Fi Proxy on iPhone**:
   - Go to **Settings > Wi-Fi** > tap **(i)** on the connected network.
   - Scroll down to **Configure Proxy > Manual**.
   - Set **Server** to your computer LAN IP (e.g. `10.136.83.113`) and **Port** to `8080`.

---

### Step 4: Bypass SSL Pinning Live
When opening mobile applications with custom certificate validation or BoringSSL pinning, HTTPS requests often fail or do not reach Burp Suite.

Run the bypass directly using index number, name, or bundle ID:
```text
iosf-ng $ bypass 6
```
*Or with application name / bundle ID:*
```text
iosf-ng $ bypass MyTsel
iosf-ng $ bypass com.ss.iphone.ugc.Ame
```

#### How the Bypass Works Internally:
- **Attach Strategy**: If the app is running normally, `iosf-ng` attaches to its PID and injects the TLS validation hooks.
- **Auto-Spawn Strategy (Anti-Debugging / PT_DENY_ATTACH)**: If the app employs kernel anti-attach protections (e.g., TikTok returning `(os/kern) failure`), `iosf-ng` automatically catches the exception, restarts the process in **Spawn Mode**, and injects Frida hooks into memory before the app's `main()` executes.
- **Hooked Layers**:
  - `SecTrustEvaluateWithError` (iOS 12+)
  - `SecTrustEvaluate` & `SecTrustGetTrustResult`
  - `libboringssl.dylib` -> `SSL_set_custom_verify`

*Press `Ctrl+C` at any time to detach cleanly.*

---

### Step 5: Plaintext TLS Capture & Storage (Optional)
If you want `iosf-ng` to capture and record the plaintext traffic directly to its internal SQLite database without external proxies:
```text
iosf-ng $ intercept
```
*Alias:* `cap`  
Hooks BoringSSL's `SSL_read` and `SSL_write` to stream unencrypted HTTP requests and responses directly into `sessions/<session_name>/traffic.db`.

---

### Step 6: Automated OWASP API Top 10 Audit
Scan the recorded traffic for vulnerabilities:
```text
iosf-ng $ scan
```
*Alias:* `audit`  
Choose between:
- **[1] Passive Mode**: Analyzes authorization header structures, exposed JWTs, sensitive data exposure, and security header misconfigurations.
- **[2] Active Mode**: Replays and mutates live requests to detect Broken Object Level Authorization (BOLA), rate limit absence, and parameter tampering.

---

### Step 7: Generate Assessment Reports
Generate comprehensive HTML and PDF reports:
```text
iosf-ng $ report
```
*Alias:* `rep`  
Compiles all findings, severity levels, CVSS scores, remediation recommendations, and request/response evidence into `sessions/<session_name>/reports/`. The HTML report opens automatically in your default browser.

---

## ⌨️ Command Reference Table

| Command | Shortcut | Syntax Example | Description |
|---|:---:|---|---|
| `help` | `?` | `help` | Display command help and usage instructions |
| `devices` | `dev` | `devices` | Inspect attached iOS physical devices via usbmux |
| `apps` | `ls` | `apps` | List all applications with live PIDs and bundle IDs |
| `bypass` | `bp` | `bypass 6` / `bp MyTsel` | Live Frida SSL Pinning bypass (Attach / Spawn) |
| `proxy` | `ca` | `proxy` | Setup Burp Suite Root CA profile & QR Code server |
| `intercept`| `cap` | `intercept` | Record plaintext BoringSSL TLS traffic to DB |
| `scan` | `audit` | `scan` | Run OWASP API Security Top 10 audit rules |
| `report` | `rep` | `report html,pdf` | Compile professional HTML and PDF reports |
| `set` | `set` | `set target <bundle_id>` | Configure workspace variables (`target`, `proxy_host`, `proxy_port`, `session`) |
| `show` | `info` | `show` | Display current workspace configuration parameters |
| `clear` | `cls` | `clear` | Clear the terminal screen and reprint banner |
| `exit` | `quit` | `exit` / `q` | Exit the framework console |

---

## 🔒 Legal & Responsible Use Notice

> **DISCLAIMER:**  
> This tool is developed strictly for **authorized security testing, research, and educational purposes**. Penetration testing on applications or devices without explicit, written permission from the asset owner is strictly prohibited and illegal. All sessions are logged with timestamps.
