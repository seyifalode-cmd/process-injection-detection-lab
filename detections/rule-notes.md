# Detection Rule — Cross-Process Injection Handles

## Plain-English rule

> Alert when a Sysmon Event ID 10 (ProcessAccess) shows a **SourceImage** opening
> a handle to an unrelated **TargetImage**, where **GrantedAccess** includes both
> `PROCESS_VM_WRITE` (0x0020) and `PROCESS_CREATE_THREAD` (0x0002) — the two
> rights that turn a handle from "can inspect" into "can inject and execute."
> Suppress the alert when the SourceImage/TargetImage pair is on the allowlist
> below. Optionally raise severity if the same SourceImage → TargetImage pair is
> immediately followed by an Event ID 8 (CreateRemoteThread) within a short
> window (a few seconds) — that combination is much harder to explain away as
> benign.

## Why these two rights specifically

`OpenProcess` can legitimately be called with almost any combination of rights —
`PROCESS_QUERY_INFORMATION` alone covers most monitoring tools. What's rare is a
handle that combines:

- `PROCESS_VM_OPERATION` (0x0008) + `PROCESS_VM_WRITE` (0x0020) — "I intend to
  change this process's memory," and
- `PROCESS_CREATE_THREAD` (0x0002) — "I intend to make it run something."

Debuggers request similar masks (often `PROCESS_ALL_ACCESS`), which is exactly
why they show up in this data and exactly why they need an allowlist entry
instead of a code change to the rule.

## Allowlist (known-good pairs)

| SourceImage | Why it's noisy | Notes |
|---|---|---|
| `vsjitdebugger.exe`, `devenv.exe`, `windbg.exe`, `x64dbg.exe`, `x32dbg.exe` | Debuggers legitimately need `PROCESS_ALL_ACCESS` on their target | Scope the allow to a specific SourceImage, never a blanket "debuggers" wildcard — an attacker can rename a payload to `windbg.exe` |
| AV/EDR engine processes (e.g. `MsMpEng.exe`, vendor-specific) | Security products inject scanning hooks / inline hooks into every process | Get the exact binary path + hash from your vendor's docs, don't allowlist by name alone |
| Backup/imaging agents (e.g. VSS writers, `vssvc.exe` interactions) | Some backup agents inspect process memory for open-file consistency | Verify against your organization's approved software list |
| `procexp.exe`, `procexp64.exe` (Process Explorer) | "Suspend," "Kill," and handle inspection all open elevated handles | Expected in this lab — this is what you'll see in Part 3 |

Allowlist by **full image path + code-signing thumbprint**, not just filename.
Filename-only allowlisting is trivially defeated by an attacker naming their
injector `windbg.exe` and dropping it next to the real one.

## Splunk (SPL)

See [`query.spl`](query.spl).

## Elastic/Sentinel (KQL)

See [`query.kql`](query.kql).

## Honest limitations

- **Minimal-rights injection evades this.** An attacker doesn't need
  `PROCESS_ALL_ACCESS`. `OpenProcess` with exactly `PROCESS_VM_WRITE |
  PROCESS_VM_OPERATION` plus a separate call path for execution (e.g.
  `QueueUserAPC` on a handle opened with only `PROCESS_VM_WRITE |
  PROCESS_QUERY_LIMITED_INFORMATION`, or hijacking an existing thread with
  `SetThreadContext` instead of creating a new one) can stay under a
  narrowly-scoped GrantedAccess rule. This detection catches noisy, off-the-shelf
  injection techniques — not a tuned, minimal-footprint one.
- **No Event ID 8 doesn't mean no injection.** APC injection and thread
  hijacking never call `CreateRemoteThread`, so they never fire Event 8 at all.
  The ProcessAccess (Event 10) rule is the one doing real work here; Event 8 is
  a bonus signal when it does show up.
- **Reflective/manual-mapped DLL injection** avoids the loader entirely, so the
  ImageLoad (Event 7) rule in `sysmonconfig.xml` won't see anything — there's no
  `LoadLibrary` call to trace. That technique is really a job for memory
  scanning (VAD walking, `PAGE_EXECUTE_READWRITE` region hunting), which is
  outside what Sysmon's event stream can tell you.
- **Allowlists rot.** Every entry above needs periodic review — a debugger
  version bump, a new AV build, or an attacker impersonating an allowlisted
  binary name all break the assumption the allowlist is built on.
- **This is user-mode telemetry.** Sysmon itself runs as a driver but reports
  through a user-mode-visible event log; a sufficiently privileged attacker
  (or one with a kernel driver of their own) can tamper with or blind Sysmon
  before it logs anything. See the anti-cheat section in the main
  [README](../README.md) for why this exact limitation is why kernel-mode
  anti-cheat and EDR exist.
