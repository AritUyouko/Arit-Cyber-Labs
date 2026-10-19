# CyBlack Internship — Threat Identification & Passive Security Evaluation

**Author:** Arit Uyouko · Junior Penetration Tester Candidate
**Scope:** Malware hash analysis + passive OSINT security posture review of a client domain (anonymized here as `target.example`)

## Overview

Two-part practical task mirroring real analyst work: triage a known threat fast, and quietly profile a target before acting.

1. **Malware Hash Analysis** — identify what a suspicious SHA-256 hash represents: the threat, its behavior, its impact.
2. **Passive Security Evaluation** — assess `target.example`'s external security posture using open-source intel only, no direct interaction.

---

## Part 1: Malware Hash Analysis

**SHA-256 hash submitted:** `f02ce710874cd773c3c32730dc2536d14f4e419bf828d4a27664a24af5d4484f`

| Metric | Value |
|--------|-------|
| VirusTotal detections | 39 / 63 vendors flagged malicious |
| Community reputation score | -14 |
| First seen | Nov 2025 |

**Verdict:** Confirmed malicious — Mirai botnet family, Condi subvariant.

### What this file actually is

- **Family:** Mirai botnet family — subvariant Condi (also tracked as Gafgyt, Polar.ppc.elf)
- **Build:** ELF 32-bit executable, PowerPC architecture — PowerPC is common in embedded/IoT hardware (routers, cameras, medical devices), not desktop PCs
- **Target:** Routers & IoT devices

**Key indicators of compromise (IOCs):**

| Type | Value |
|------|-------|
| File paths | `/tmp/condi`, `/var/con` |
| Process names | `condi`, `zxcr9999`, `watchdog` |
| Network behavior | Outbound SSDP M-SEARCH (device discovery) |
| Downloader pattern | `wget http://%s/%s/%s -O %s` |
| Alt. file names | `Polar.ppc.elf`, `jmivg.exe` |

### How the infection spreads

1. **Deploy** — delivered via default/brute-forced credentials or known firmware flaws
2. **Clear the field** — scans `/proc` and kills competing malware processes on the device
3. **Fetch payloads** — pulls additional payloads via `wget`, `curl`, `tftp`
4. **Propagate** — scans the local network via SSDP to find and infect new devices
5. **Recruit** — the device joins the botnet, used as a DDoS amplification node

Devices on the same network are also at risk of lateral spread once one device is infected.

### Impact & mitigation

**Healthcare sector risk:** PowerPC is common in embedded medical equipment, making healthcare a plausible target — infusion pumps, patient monitors, EHR access, emergency response systems, and connected diagnostic equipment could all be disrupted.

**Mitigations:**
- Change default credentials on IoT/network devices
- Disable unused services (Telnet, FTP, remote management)
- Apply firmware patches regularly
- Segment the network to limit lateral movement
- Deploy SIEM/EDR detection rules using the hash + IOCs above

---

## Part 2: Passive Security Evaluation — target.example

Acting as a Junior Cyber Consultant, performed a passive, non-intrusive external security posture review for an educational consultancy client — no active scanning or direct interaction with their systems.

**Tools used:**
- Qualys SSL Labs — TLS/SSL configuration grading
- MXToolbox — mail & DNS record checks
- DNSDumpster — DNS history & subdomain discovery
- WHOIS — domain registration lookup

*Why passive? Direct scanning could tip off the target — passive recon stays invisible while still surfacing real risk.*

### DNS & Infrastructure findings

| Finding | Detail |
|---------|--------|
| A records | CDN-fronted (Cloudflare) |
| Nameserver | Cloudflare DNS hosting confirmed |
| DMARC | Present — email spoofing protection in place |
| Subdomain found | One additional subdomain resolving to the same origin |
| Registrant | Redacted via registrar privacy service |

**⚠ Origin IP leaked:** found via DNS history despite Cloudflare being in front — anyone with this IP could bypass Cloudflare entirely and hit the origin server directly.

**⚠ FTP exposed:** Pure-FTPd running and visible on the origin IP — unencrypted protocol, directly reachable.

### TLS/SSL configuration

| Metric | Value |
|--------|-------|
| Overall grade | B (capped due to deprecated protocol support) |
| Protocols supported | TLS 1.0, 1.1 (deprecated), 1.2, 1.3 |
| Industry standard | TLS 1.2 minimum; 1.3 recommended (NIST SP 800-52r2) |
| Public key | EC 256-bit (ECDSA) — meets current standards |
| Certificate issuer | Google Trust Services — trusted by all major browsers |
| Validity period | 90-day cert (best practice) |
| DNS CAA record | Not configured — any CA can issue certs for this domain |

### Recommendations

1. **TLS 1.0/1.1 still enabled** → disable at server/CDN level, enforce TLS 1.2 minimum to reach an A grade
2. **Origin IP leaked via DNS history** → apply firewall rules to block direct IP access, clean historical DNS records
3. **FTP exposed on origin IP** → disable Pure-FTPd if unused, replace with SFTP/FTPS if file transfer is required
4. **DNS CAA record not configured** → add a CAA record restricting certificate issuance to the intended CA only

---

## Key Takeaways

- A known threat like Condi/Mirai can be triaged fast using existing intel — the SHA-256 hash and IOCs are ready to deploy as SIEM/EDR detection rules.
- Passive recon builds a real risk picture without alerting the target — here it surfaced a leaked origin IP and exposed FTP service, both immediately actionable.
- Both tasks reflect the same core analyst skill: identify, contextualize, and recommend — without ever overstepping scope.
