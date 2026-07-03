# Process Injection Detection Lab — A Defender's View of Windows Process Injection

A hands-on lab using standard Windows tooling (Sysinternals + Sysmon) to observe
what process injection looks like from a defender's seat, and to write a
detection for it. The goal isn't to build anything malicious — it's to
understand the telemetry injection leaves behind, since that telemetry is
exactly what EDR and game anti-cheat both rely on to catch it.

---

## Project at a Glance

| | |
|---|---|
| **Tools Used** | Sysinternals Suite (Process Explorer, Process Monitor, VMMap) · Sysmon · Windows Event Viewer |
| **Platform** | Windows 10/11 VM (isolated, snapshotted) |
| **Frameworks** | MITRE ATT&CK — T1055 (Process Injection) and sub-techniques |
| **Detection Languages** | Splunk SPL, KQL (Sentinel/Defender) |
| **Security Focus** | Process/thread telemetry · Windows API abuse · EDR-style detection engineering |

## Why This Exists

External game cheats — and a large share of commodity malware — work by
reaching into another process's memory: reading it for a wallhack, writing to
it for an aimbot, or injecting code so their logic runs inside the target.
From the operating system's point of view those are all the same handful of
primitives: open a handle to a process, allocate memory in it, write to it,
and start a thread. This lab is about learning to spot exactly that sequence,
and about being honest with myself about where that visibility runs out.

**What this lab deliberately does not do:** it doesn't write, ship, or run
cheat code or a working injector. Everything here observes legitimate Windows
behavior (Process Explorer, a debugger, Sysmon's own event stream) and the
traces injection would leave in that same telemetry. A detection write-up is
more useful — and more honest — than a how-to-cheat, and it's the skill an
anti-cheat or EDR team actually hires for.

---

## Lab Setup

1. **VM.** Windows 10 or 11 in VirtualBox, VMware, or Hyper-V. Snapshot it
   clean before touching anything, so the environment can be rolled back.
2. **Sysinternals Suite** — [learn.microsoft.com/sysinternals](https://learn.microsoft.com/sysinternals).
   Used here: Process Explorer (`procexp`), Process Monitor (`procmon`), VMMap.
3. **Sysmon** — also Sysinternals, and the important one. It writes rich
   process/thread events to the Windows event log, which is the closest free
   equivalent to what an EDR agent sees.

Install from an admin PowerShell prompt:

```powershell
# from the folder where you unzipped Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

`sysmonconfig.xml` in this repo is scoped narrowly on purpose — it only turns
on the event types this lab cares about (Process Create, Image Load,
CreateRemoteThread, ProcessAccess), so the Operational log stays readable
while learning what each field means. It is not a general-purpose Sysmon
config; for production use, layer in something like the SwiftOnSecurity or
Olaf Hartong configs.

To update a running install with a new config: `.\Sysmon64.exe -c sysmonconfig.xml`

---

## Part 1 — Know What "Normal" Looks Like

You can't spot abnormal until you've stared at normal. Open Process Explorer
as admin.

1. Find a well-behaved process — `notepad.exe` is perfect. Launch it, locate
   it in Process Explorer.
2. Right-click → Properties. Walk through:
   - **Threads** — how many, and what their start addresses point to (all
     inside known modules like `ntdll.dll`, `kernel32.dll`).
   - **Handles** (`View → Lower Pane View → Handles`) — Notepad on its own
     doesn't hold an open handle to other user processes.
   - **Image** — verify the signature (Notepad is Microsoft-signed).
3. Screenshot this as your baseline — `01-notepad-baseline.png`.

**The takeaway:** a normal process's threads start inside its own loaded
modules, and it generally doesn't hold `PROCESS_VM_WRITE` /
`PROCESS_CREATE_THREAD` handles to unrelated processes. Injection breaks both
of those assumptions.

---

## Part 2 — The Anatomy of Classic Injection (On Paper)

The classic `CreateRemoteThread` injection chain, and the ATT&CK sub-technique
each step maps to under **T1055 — Process Injection**:

| Step | Windows API | What it does | MITRE ATT&CK |
|---|---|---|---|
| 1 | `OpenProcess` | Obtain a handle to the target with write/execute rights | T1055 (parent technique — this is the enabling primitive for all sub-techniques below) |
| 2 | `VirtualAllocEx` | Allocate memory inside the target process | T1055.001 — Dynamic-link Library Injection *(when the allocation will hold a DLL path)*, or T1055.002 — Portable Executable Injection *(when it holds shellcode/a PE image)* |
| 3 | `WriteProcessMemory` | Write the payload (or a DLL path) into that memory | Same sub-technique as step 2 |
| 4a | `CreateRemoteThread` | Start a new thread in the target running the payload | T1055.001 / T1055.002 |
| 4b | `QueueUserAPC` (as an alternative to 4a) | Queue the payload to run next time a target thread enters an alertable wait | T1055.004 — Asynchronous Procedure Call |
| 4c | `SetThreadContext` + `ResumeThread` (as an alternative to 4a) | Hijack an existing, already-running thread's execution rather than create a new one | T1055.003 — Thread Execution Hijacking |

**The defender's insight:** steps 1–4 are individually legal Windows API
calls — plenty of legitimate software calls `OpenProcess` or
`WriteProcessMemory`. What's rare is the *combination*: one process opening a
cross-process handle with write+execute rights and then starting or
redirecting a thread in another process. That combination, not any single
call, is the detection.

---

## Part 3 — Watch the Telemetry with Sysmon

Now generate benign cross-process activity and see how Sysmon records it, so
the real events are recognizable later.

A safe, built-in way to create legitimate cross-process access is a debugger.
Attaching a debugger opens a handle to another process with strong rights —
the same class of handle injection needs — with no malware involved.

1. Install Sysmon with `sysmonconfig.xml` from this repo (see Lab Setup above).
2. Open Event Viewer → `Applications and Services Logs → Microsoft → Windows
   → Sysmon → Operational`.
3. Trigger benign cross-process access: attach WinDbg or the Visual Studio
   debugger to a process you started, or use Process Explorer's Suspend /
   inspect actions on a process you own. Watch for **Event ID 10
   (ProcessAccess)**.
4. Screenshot an Event ID 10 record — `02-sysmon-event10.png`. In your notes,
   call out three fields specifically:
   - **SourceImage** — who reached in
   - **TargetImage** — who got reached into
   - **GrantedAccess** — the rights mask requested; this is the field that
     matters most

**The takeaway:** `GrantedAccess` is the signal. A mask that includes
`PROCESS_VM_WRITE (0x20)` + `PROCESS_CREATE_THREAD (0x02)` on a target the
source has no legitimate business writing to is the high-value flag.

---

## Part 4 — The Detection

Full writeup with the plain-English rule, the allowlist, and the reasoning
behind both is in [`detections/rule-notes.md`](detections/rule-notes.md).
Queries: [`detections/query.spl`](detections/query.spl) (Splunk) and
[`detections/query.kql`](detections/query.kql) (Sentinel/Defender for
Endpoint).

Short version: alert on Sysmon Event ID 10 where `GrantedAccess` includes both
`VM_WRITE` and `CREATE_THREAD`, excluding known-good source/target pairs
(debuggers, AV/EDR engines, backup agents). Optionally correlate with an
Event ID 8 (`CreateRemoteThread`) from the same source→target pair within a
short window for a much stronger signal.

**Honest limit, stated up front:** an attacker who requests only the minimal
rights needed — or who uses APC injection / thread hijacking instead of
`CreateRemoteThread` — can produce a `GrantedAccess` mask that never trips this
rule, and neither T1055.003 nor T1055.004 ever fire Event ID 8 at all. This
catches noisy, off-the-shelf injection. It is not a general solution, and the
full limitations section in `rule-notes.md` says so explicitly rather than
overselling the coverage.

---

## Part 5 — Tying This to Anti-Cheat

External game cheats read and write game process memory using the exact same
`OpenProcess` + `WriteProcessMemory` primitives observed in this lab — a
wallhack is a read, an aimbot or full code-injection cheat is a write, and
both start with the same `OpenProcess` call this detection watches for.

Anti-cheat systems monitor for exactly these handle opens against the game
process, which is why the `GrantedAccess` mask matters as much in a game
client as it does in an EDR: a mask that includes `VM_WRITE` from a process
that isn't the game's own overlay, launcher, or a small set of known-good
tools is the same red flag either way.

**Kernel-mode anti-cheat exists precisely because this kind of user-mode
detection can be evaded.** Everything in this lab watches events surfaced
through a user-mode-visible log (Sysmon's own driver reports up through a
channel that, at sufficient privilege, can be tampered with or blinded before
it ever writes an event). A kernel driver gets ahead of that by intercepting
the same `NtOpenProcess` / `NtWriteVirtualMemory` calls at a level the
attacker can't unhook without their own kernel access — trading a large
attack surface and real privacy/trust concerns for visibility that's much
harder to blind. That trade-off, not "kernel mode is inherently better," is
the actual argument for it.

---

## Repo Structure

```
process-injection-detection-lab/
├── README.md                 # this write-up
├── sysmonconfig.xml           # the Sysmon config used in Part 3
├── detections/
│   ├── rule-notes.md          # plain-English rule, allowlist, and limitations
│   ├── query.spl              # Splunk SPL detection
│   └── query.kql              # Sentinel/Defender KQL detection
└── screenshots/                # populated when the lab is run on a VM (see below)
```

## Status / Deliverable Checklist

- [x] Injection chain explained, mapped to MITRE T1055 and its sub-techniques
- [x] Sysmon config authored (Event IDs 1, 7, 8, 10) with rationale for each mask
- [x] Detection rule written, with an explicit allowlist and honest limitations
- [x] Splunk SPL and KQL (Sentinel/Defender) query variants
- [x] Anti-cheat tie-in section
- [ ] Clean VM spun up, snapshot taken
- [ ] Baseline screenshots of a normal process (`01-notepad-baseline.png`)
- [ ] Sysmon Event ID 10 captured on the VM (`02-sysmon-event10.png`)

The last three items require an actual Windows VM run, which is why
`screenshots/` is currently just tracked as an empty directory — the
write-up, config, and detections above are the reusable artifact; the
screenshots are the part that has to come from actually running it.
