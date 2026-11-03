# Handoff: running and triaging Windows 10 passes

For whoever runs the corpus on genuine Windows 10 22H2 x64 and reports back. Real Windows 10 is the authority: a
failure on Windows 10 means the expectation is wrong (fix or demote the test); a failure on another implementation
of Winsock/AFD means that implementation differs (which is the point of the corpus).

## Prerequisites

- Build host: Linux (or any host) with mingw-w64 (`x86_64-w64-mingw32-gcc`), GNU make, Python 3.
- Target: a disposable Windows 10 22H2 x64 (build 19045) installation with an interactive desktop, a local
  Administrator account logged on, loopback only (127.0.0.1 and ::1), no external network, no DNS beyond the hosts
  file. Use a throwaway guest: the `dx_*` areas change the Winsock catalogs, and a crashed run could leave entries.
- Python is only needed on the build host (packaging, result parsing). Nothing but the exes is needed in the guest
  for a manual run; the unattended payload also uses PowerShell.

## Build

    make clean && make -j8      # must finish with zero errors; build/<area>.exe for every area
    python3 tools/gen_docs.py   # optional: refresh counts in README.md / COVERAGE.md

## Procedure

Three passes per release of the corpus, in this order.

1. **adm**: the elevated Administrator token the session logs on with. Every non-dx area.
2. **std**: a real local standard user (the payload creates one inside the guest at run time; if that fails the
   runner falls back to a restricted-admin token and says so with `WS2T stdkind restricted-admin`). The elevated-only
   tests (raw sockets, provider and service operations) skip; everything else must give the same results as adm.
3. **dx**: the guarded areas (`dx_*`), elevated only, on a guest you are willing to discard.

### Unattended (payload) mode

    python3 tools/win10_pack.py <payload_dir> --all --mode both --timeout 300     # adm + std, all non-dx areas
    python3 tools/win10_pack.py <payload_dir> --exes dx_provider_catalog,dx_gap_01 --mode adm --destructive
    python3 tools/win10_pack.py <payload_dir> --exes afd_poll_events --filter apev_ --full   # filter / RUN lines

The payload directory contains `bin/` (the selected exes plus two helpers: an identity probe and a
run-as-standard-user launcher), `list.txt`, `runner.ps1` and `run.cmd`. Hand it to whatever starts a fresh Windows 10
guest and runs `run.cmd` at logon with the guest serial port captured to a file. `run.cmd` configures COM1, runs the
selected exes one by one in each mode with a per-exe timeout, and frames every output line with the prefix `WS2T `.
The payload's exit code is 0 only when the runner reached `WS2T done`; a failing or timed-out test does not change
it. Keep each payload under about ten minutes (split large sets across payloads); one pass over all non-dx areas in
both modes fits in a handful of payloads.

Parse the captured log:

    python3 tools/win10_results.py serial.log                 # table: one row per (mode, exe)
    python3 tools/win10_results.py serial.log --tests         # one row per test: OK / FAIL / SKIP
    python3 tools/win10_results.py serial.log --failures      # the FAIL and SKIP detail lines
    python3 tools/win10_results.py serial.log --format json -o run.json

Row status: `OK` (SUMMARY seen, exit 0 or 1), `TIMEOUT` (killed by the runner), `NOSUMMARY` (crash), `HANG` (log stops
while the exe runs), `MISSING` (not in the payload). The tool exits 0 only when the run finished and every exe is `OK`.

### Manual mode

Copy `build\*.exe` into a scratch directory in the guest and run `tools\run_all.bat` (add `/destructive` for dx) or
a single `build\<area>.exe [filter]`. `python tools\summarize.py results --failures` aggregates the output files.

## Results to keep

Commit only sanitized summaries under `results/win10/<mode>/`: `summary.tsv` (the table from `win10_results.py`)
and `failures.tsv` (area, then the FAIL or SKIP line). Never commit raw serial logs: they contain boot noise, host
details and timing. Seconds columns are informational and may be left as `-`.

## Triage

Always re-run a failing area alone with its failing test name as the filter before concluding anything.

| Symptom | Likely cause | Action |
|---|---|---|
| Same check fails every run on Windows 10 | wrong expectation | Fix to the observed value if the behavior is a stable contract; otherwise demote to `t_note()` |
| Fails in only one run, passes alone | race, or a timing/ordering assumption | Make the test wait on the condition (bounded) instead of a fixed delay; if the outcome is legitimately racy accept both and keep the check count fixed |
| Output differs between two runs | printed variable data (port, address, handle, time) | Remove it; print relations only |
| `TIMEOUT` / `HANG` | an unbounded wait, or a blocked call nobody releases | Find the test from the last `RUN` line, add a bounded wait or a watchdog that closes the socket |
| `NOSUMMARY` | crash (access violation from a bad pointer) | Garbage non-NULL pointers are forbidden; use NULL or valid memory |
| Passes in adm, fails in std | missing privilege check | Add an elevation skip with a reason |
| Fails only under an emulator | emulator difference | Not a defect of the test |
| Different on another Windows 10 build | version-dependent | Demote to `t_note()` with the build number |

Determinism is mandatory: three consecutive runs of an area on fresh guests must give byte-identical per-test results
and printed lines.

## Slow areas

On Windows 10 a refused loopback connect takes about two seconds (the stack retries the SYN), so `x_stress_soak_bounded`
(about 175 s per mode) and `x_select_poll_matrix` (about 250 s per mode) are the longest areas; run each in a payload of
its own, or with `--timeout 450`, and keep payloads under about ten minutes.

## Expected conditional skips

These repeat identically in every run and are not failures:

- IPX/SPX not installed (`lift_05`)
- event-object mode only (`lift_07`, two cases)
- QoS error-path and service-configuration cases (`qos_misc_apis`); the service-configuration ones belong to a
  guarded area
- std mode only: raw sockets (`x_raw_icmp_elevated` and the raw columns of the sweeps), SIO_RCVALL, and provider and
  service operations that need an elevated token
- server-SKU-only behavior is skipped on client SKUs (an `NOTE` or `SKIP` names it)
- IPv6 loopback absent: tests print `SKIP no IPv6 loopback`
- std mode only: one `x_af_unix_deep` case that needs the symbolic-link privilege (error 1314)
- adm mode only: eight `x_raw_icmp_elevated` cases that test the refusal path of a non-elevated token

A new skip that is not in this list, or a skip that disappears, is a result worth reporting.

## Cleanup of the dx areas

The guarded areas sweep their own leftovers before and after every test, and everything they create carries a GUID
whose first field is `77733274` (the ASCII bytes "ws2t"). If a run was killed in the middle, either discard the guest
(preferred) or remove leftovers from an elevated prompt:

    :: list entries; anything with a ws2t-prefixed provider id is ours
    netsh winsock show catalog
    :: remove a leftover protocol entry by its catalog id
    netsh winsock remove provider <catalog-id>
    :: reset everything to defaults if the catalog looks damaged (reboot afterwards)
    netsh winsock reset

Name-space providers and service classes that are left behind are removed by re-running the same dx exe, which sweeps
before it starts; the guest's `ws2t` scratch directory (`C:\ws2t`) and the standard user created by the runner
(account name beginning `ws2t`) are removed by discarding the guest, or by hand:

    net user ws2tstd /delete
    rmdir /s /q C:\ws2t

## What to report back

1. Environment: OS build, SKU, whether IPv6 loopback and IPX were present, modes run, corpus commit.
2. Per mode: the summary table (tests, failed, skipped, checks pass/fail, status per area).
3. Every FAIL with area, test, `file:line expr (detail)`, whether it reproduces alone, and your triage verdict from the
   table above (wrong expectation / race / printed variable data / environment).
4. Every skip, grouped, and whether it is in the expected list.
5. Determinism: which areas were run more than once and whether the outputs matched byte for byte.
6. Any `NOTE` lines that look like they should be hard checks, or hard checks you think are version dependent.
7. Anything left on the guest after the dx pass.
