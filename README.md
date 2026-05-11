## EdgeSavedPasswordsDumper
*A Node.js port of [EdgeSavedPasswordsDumper](https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper) — demonstrates that Edge stores saved credentials in cleartext in process memory.*

Whenever a user stores credentials in Edge (via the built-in password manager), all credentials are stored in plaintext in the parent Edge process memory. On shared systems (e.g. terminal servers) an attacker with admin rights can read them across all logged-on and disconnected users. Microsoft considers this behaviour by design.

**For educational and research purposes only.**

---

## Requirements
- Edge 147.0.3912.98 or older
- Node.js 12+
- Administrator rights (required to open and read memory of processes owned by other users)

## Usage

```
npm install
node index.js
```
