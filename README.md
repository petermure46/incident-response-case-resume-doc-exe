# 🛡️ Incident Response: Trojan Resume.doc.exe Attack

This project documents a real-world incident response and forensic analysis of a malware attack involving a malicious file disguised as a resume document. The file `resume.doc.exe` tricked a user into executing it, leading to a full system compromise.

---

## 🧪 Summary

- **Attack Vector**: Malicious executable downloaded from `uploadfiles.io`
- **Malware Type**: Metasploit/Shelma Trojan
- **Detection**: Flagged by 67/75 VirusTotal vendors
- **Persistence**: Registry changes, PowerShell abuse, certificate injection, DLL modification
- **Impact**: Remote access setup, data exfiltration, privacy violation, potential lateral movement

---

## 📁 Project Structure

| Folder         | Description                                      |
|----------------|--------------------------------------------------|
| `report/`      | Original redacted PDF forensic report            |
| `analysis/`    | Breakdowns of infection stages and behaviors     |
| `images/`      | Screenshots and visual evidence (optional)       |
| `tools-used.md`| List of tools used during the investigation      |

---

## 🔧 Tools & Techniques

- **Volatility** — Memory forensics
- **VirusTotal** — Malware classification
- **Registry Analysis** — Persistence detection
- **PowerShell Analysis** — Script and remote control behavior
- **Manual Investigation** — File metadata, NTUSER.DAT, network traces

---

## 🧠 Key Findings

- PowerShell is used to alter the registry, launch payloads, and control the system
- Remote SSH connections enabled using Plink and SSH executables
- NTUSER.DAT shared across VM network folders exposed additional data
- Critical DLLs like `crypt32.dll` were tampered with to ensure stealth
- Certificates were manipulated to establish trusted malicious communication

---

## ⚠️ Disclaimer

This case is a redacted, educational example of an actual forensic investigation. It contains no confidential or proprietary data. Use it to learn, demonstrate, or build your cybersecurity portfolio.

---


