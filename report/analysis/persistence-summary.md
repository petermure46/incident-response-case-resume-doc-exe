# 🧠 Persistence Mechanism Summary

This section analyzes how the malware maintained access and control over the compromised system.

## 🔑 Registry Modifications

The malware altered several registry paths to ensure execution after reboot:

- `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CRYPT32`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SYSTEMCERTIFICATES\CA`
- `HKEY_USERS\S-1-5-21-...` → User-specific persistence

These were manipulated via malicious PowerShell scripts that injected values or created startup keys.

## 📜 PowerShell Execution

PowerShell was used extensively for payload execution and persistence:

- Scripts accessed certificate stores
- Registry keys were altered to bypass security
- Multiple instances of `powershell.exe` were launched to monitor or reinitialize the attack

## 🧬 DLL Injection

System DLLs like `crypt32.dll` and `winspipe.dll` were modified:

- These may have been injected with shellcode
- Malicious behavior triggered during normal Windows operations

## 🧾 Certificate Manipulation

Certificates were added or replaced to create trust for malicious communication:

- Allowed attacker to spoof secure connections
- Could bypass encrypted channel inspections

## 🔁 Plink & SSH

Backdoor created using:

- `plink.exe` opened port `12345`
- `sshd.exe` and `ssh.exe` used to allow remote shell access

---

Together, these mechanisms ensured continuous attacker presence, even after reboots or user intervention.
