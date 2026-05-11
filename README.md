## ProcessCredentialScanner
*A Node.js tool that scans Windows process memory for cleartext credentials and secrets — useful for assessing whether an application leaks sensitive data in memory.*

Originally based on [EdgeSavedPasswordsDumper](https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper), which demonstrated that Edge stores saved credentials in cleartext in process memory. This tool generalises that technique to any running process.

---

## Requirements
- Windows (uses Win32 `ReadProcessMemory` / `VirtualQueryEx`)
- Node.js 12+
- Administrator rights (required to open and read memory of processes owned by other users)

## Usage

```
npm install
node index.js
```

The tool lists all running processes. Enter a number or partial name to select a target, then it scans every readable memory region of that process and reports any matches.

## Detected patterns

| Pattern | Description | Precision |
|---|---|---|
| `browser_memory` | Chromium-family in-memory credential layout | High |
| `http_basic_authentication_header` | `Authorization: Basic <base64>` headers | Medium |
| `http_bearer_authentication_header` | `Authorization: Bearer <token>` headers | Medium |
| `mongodb_connection_string` | `mongodb[+srv]://user:pass@host/db` | High |
| `mysql_connection_url` | `mysql://user:pass@host/db` | High |
| `postgres_connection_string` | `postgres[ql]://user:pass@host/db` | High |
| `rsa_private_key` | `-----BEGIN RSA PRIVATE KEY-----` blocks | High |
| `ec_private_key` | `-----BEGIN EC PRIVATE KEY-----` blocks | High |
| `generic_private_key` | `-----BEGIN PRIVATE KEY-----` (PKCS#8) blocks | High |
| `openssh_private_key` | `-----BEGIN OPENSSH PRIVATE KEY-----` blocks | High |
| `pgp_private_key` | `-----BEGIN PGP PRIVATE KEY BLOCK-----` blocks | High |
| `form_encoded` | URL-encoded `username=X&password=Y` submissions | Medium |
| `json_password` | `"password":"..."` JSON fields | Medium |
| `kv_password` | `password = ...` / `passwd: ...` key-value pairs | Medium |

Each match is printed with its pattern label. Private key blocks are truncated in output but fully deduplicated internally.

## Notes
- Requires elevation; exits immediately if not running as Administrator.
- Skips memory regions larger than 256 MB to avoid OOM.
- Results are deduplicated across all PIDs of the selected process.
- Pattern quality varies by application — connection string and PEM patterns are high-precision; `kv_password` and `form_encoded` may produce noise against unknown targets and may need regex tuning.
