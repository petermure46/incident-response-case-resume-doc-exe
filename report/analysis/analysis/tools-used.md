# 🧰 Tools Used in the Investigation

This document outlines the tools, platforms, and utilities used throughout the incident response and forensic analysis process.

---

## 🔍 Memory Analysis

### 🔸 Volatility Framework
- Used to extract running processes, open network connections, and analyze injected memory pages.
- Helped identify `powershell.exe`, `sshd.exe`, and `svchost.exe` behaviors.

---

## 🔬 Malware Detection

### 🔸 VirusTotal
- The `resume.doc.exe` file was submitted to VirusTotal.
- Detected as malicious by 67 out of 75 vendors.
- Identified as Metasploit/Shelma Trojan variant.

---

## 🧠 Registry & Persistence Analysis

### 🔸 Manual Inspection
- Analyzed system registry hives and NTUSER.DAT
- Located persistence keys, altered cert stores, and shell entries

### 🔸 PowerShell Forensics
- Traced execution paths and registry modifications
- Identified scripts that manipulated trusted certificates and autostart mechanisms

---

## 📦 File and Metadata Examination

### 🔸 NTUSER.DAT
- Investigated user's recent activity and personalized settings
- Detected cross-VM shared folder exposure

### 🔸 EXIF Data (optional)
- Highlighted risk of geolocation leakage via image metadata

---

## 🔗 Network & Remote Control Analysis

### 🔸 Volatility + Netstat
- Detected open ports and listening services
- Observed Plink SSH backdoor on port `12345`

---

## 🧾 Supporting Tools

- **Uploadfiles.io** — Original hosting site of malicious file
- **Plink.exe** — Used by attacker for SSH tunneling
- **Registry Viewer / Windows Tools** — (for manual key inspection)

---

## 🧠 Summary

The combination of memory analysis, registry forensics, malware classification, and script tracing allowed for a comprehensive understanding of the infection chain and system compromise. These tools reflect a standard DFIR (Digital Forensics & Incident Response) methodology.
