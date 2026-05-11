## EdgeSavedPasswordsDumper
*A small educational tool demonstrating that Edge stores credentials in cleartext in process memory.*

> **Note:** This is a Node.js port of the original C# tool by [L1v1ng0ffTh3L4N](https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper).

---

## Overview
This project demonstrates that Edge stores credentials in cleartext in memory. It is intended for **educational and research purposes only**, especially for understanding memory inspection, credential handling, and security design differences across software.

The Node.js version uses `ffi-napi` to call the same Win32 APIs (`OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`) as the original, and PowerShell for WMI process enumeration.

---

## Purpose
This tool was created to show that whenever a user stores credentials in Edge (using the Microsoft Password Manager feature, e.g. Autofill), ALL credentials are stored in plaintext in the parent Edge process memory. This is obviously problematic in a shared environment (e.g. on a terminal servers) as an attacker can access **all** Edge processes for **all** logged on and disconnected users, and dump their saved credentials.
Microsoft has said that this is "by design" and thus won't fix this.
The tool is meant to support learning, responsible disclosure, and security awareness — not misuse.

---

## Disclaimer
This software is provided **strictly for educational use**.

By using this project, you agree that:
- You are solely responsible for how you use this code  
- You will not use it to violate privacy, security policies, or any applicable laws  
- The author provides **no warranty** of any kind  
- The author **cannot be held liable** for any misuse, damage, or consequences resulting from this software  

You accept full responsibility for ensuring your actions comply with all legal and ethical requirements.

---

## Features
- Demonstrates that Edge stores saved credentials in clear text in memory
- Node.js with native Win32 bindings via `ffi-napi`

---

## Requirements
- Edge 147.0.3912.98 or older
- Node.js 12+
- Administrator rights (to be able to read other users' Edge process memory)

## Installation

```
npm install
node index.js
```