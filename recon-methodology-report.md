# Cloud Security Assessment — Reconnaissance & Asset Identification

**Author:** Arit Uyouko
**Environment:** Kali Linux VM

> **Note:** This was a reconnaissance exercise performed as part of coursework. Specific subdomains, IP ranges, and target identity have been redacted before publishing, since this data describes real third-party infrastructure. The methodology and findings structure are preserved for portfolio purposes.

## 1. Executive Summary

This report details the reconnaissance phase of a security assessment against an authorized training target. Both passive and active reconnaissance were performed to identify the digital footprint and potential attack surface. Key findings included multiple staging environments and several open ports managed through a reverse proxy/CDN.

## 2. Part A — Passive Reconnaissance (OSINT)

Passive reconnaissance gathers information without direct interaction with target servers, minimizing detection risk and adhering to ethical engagement protocols.

**Tool used:** `amass enum -d <redacted-target-domain>`

| # | Finding type | Confidence | Sensitivity |
|---|--------------|-----------|-------------|
| 1 | Public-facing subdomain | High | PUBLIC |
| 2 | Public-facing subdomain | High | PUBLIC |
| 3 | Public-facing subdomain | High | PUBLIC |
| 4 | Staging/internal subdomain | High | INTERNAL |
| 5 | Public-facing subdomain | High | PUBLIC |
| 6 | Internal/product subdomain | High | INTERNAL |
| 7 | Engineering subdomain | High | INTERNAL |
| 8 | Staging subdomain | High | INTERNAL |

*(8 subdomains discovered total — 4 public, 4 flagged internal/staging)*

## 3. Part B — Active Scanning

Active scanning involved direct probes to identify open ports and running services.

**Tool used:** `nmap -sV <redacted-target-domain>`

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 25/tcp | smtp? | Unrecognized | Potential mail relay |
| 80/tcp | http | CDN/reverse proxy | Standard web traffic |
| 443/tcp | ssl/http | CDN/reverse proxy | Secure web traffic |
| 8080/tcp | http | CDN/reverse proxy | Alternate web port |
| 8443/tcp | ssl/http | CDN/reverse proxy | Alternate secure port |

## 4. Part C — Prioritization & Risk Assessment

Top five assets identified as high-priority for further testing, based on potential impact and exposure:

1. **Port 25 (SMTP) — unrecognized version.** *High risk.* Could be a legacy mail server; if vulnerable, exploitable for mail relaying or internal spoofing.
2. **A staging subdomain.** *High risk.* Staging environments often have relaxed security controls and may contain debug logs or hardcoded test credentials.
3. **Port 8080 (HTTP).** *Medium risk.* Alternate web ports are frequently used for admin interfaces or internal tools that may be less hardened than primary services.
4. **An engineering subdomain.** *Medium risk.* Likely hosts technical documentation or dev tools — access could expose system architecture blueprints.
5. **A second staging/connect subdomain.** *Medium risk.* Non-production environments are often precursors to breaching the production network via lateral movement.

## 5. Data Flow Diagram

A Level-0 context diagram illustrating data movement between external users, the web application interface, and backend data stores was produced as part of this assessment (not included here).

## 6. Conclusion & Reflection

The reconnaissance phase successfully mapped the external attack surface. The primary challenge was the CDN/reverse proxy layer, which masks the true origin IP address and version details of the web servers. Future testing should focus on authorized proxy-bypass techniques or authenticated testing on the identified staging subdomains.
