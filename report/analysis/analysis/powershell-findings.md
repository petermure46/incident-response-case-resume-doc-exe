# 🧪 PowerShell Findings

PowerShell was a central tool used by the attacker during the infection and persistence phases. Here's a breakdown of how it was exploited:

---

## 📌 1. Script Execution

- Multiple `powershell.exe` processes were observed in memory.
- Volatility showed that these processes accessed key system files and directories.
- The scripts were used to download payloads, change system settings, and maintain access.

---

## 🔐 2. Registry Manipulation

PowerShell modified registry hives:

- `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CRYPT32`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SYSTEMCERTIFICATES\CA`
- User profile keys under `HKEY_USERS\S-1-5-21-...`

These changes allowed the malware to:
- Start on boot
- Maintain trust (via fake certs)
- Hijack system behavior

---

## 📊 3. Accessed System Counters and Events

- `windows_shell_global_counters` accessed to monitor system performance.
- Manipulated semaphores and Windows Events to synchronize or hide activity.
- Used Explorer descriptors, possibly to alter how folders and files appeared.

---

## 🧬 4. Code Injection

PowerShell processes had memory pages in the `PAGE_EXECUTE_READWRITE` state:

- Enabled execution of injected code
- Allowed attacker to load and run shellcode without writing it to disk (fileless)

---

## 🧾 5. User-Level Targeting

- Accessed user-specific keys for settings and recent activity
- Likely used to steal profile data or maintain user-specific persistence

---

### 🧠 Summary

The PowerShell abuse in this case demonstrates:
- A multi-stage infection chain
- Fileless attack methods
- Deep registry persistence
- Trusted system process hijacking

Security teams should monitor PowerShell activity closely and restrict script execution where possible.
