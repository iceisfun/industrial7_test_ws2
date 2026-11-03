# Windows 10 Winsock conformance corpus

A public, black-box conformance corpus for the Windows 10 22H2 x64 Winsock stack:

- `ws2_32.dll` (195 exports), `mswsock.dll` (63) and `wsock32.dll` (75, 71 of them forwarders)
- the AFD kernel contract those DLLs ride on: `\Device\Afd` reached through `NtCreateFile` and
  `NtDeviceIoControlFile`, written down as a specification in `docs/AFD_CONTRACT.md`
- the Winsock provider SPI (WSP / NSP), the `mswsock` provider start-up, the name-resolution providers
  and AF_UNIX

The authority is a genuine Windows 10 22H2 installation. Every hard check records what that system does; behavior
that depends on version, SKU or hardware, or that has not been verified, is only logged with `t_note()`.
Valid negative tests (exact return value plus `WSAGetLastError` or NTSTATUS for bad parameters, wrong state, wrong
socket type, buffer-size protocols) are the most valuable kind and make up most of the corpus.

## Method: LoadLibrary, GetProcAddress, call

The DLLs under test are never linked. Each test loads a module with `LoadLibrary`, resolves entry points with
`GetProcAddress` and calls through the resulting pointer:

    U(Name)                  /* pointer typed from the SDK prototype of Name */
    UIN("mswsock.dll", Name) /* same, but pinned to one module (matters for forwarders) */
    UN(Name)                 /* for exports missing from the SDK headers, after UDECL(...) */

Modules searched by `U()`: ws2_32.dll mswsock.dll wsock32.dll ntdll.dll kernel32.dll. The AFD tests reach the driver
through `NtCreateFile` / `NtDeviceIoControlFile` / `NtReadFile` / `NtWriteFile` / `NtCancelIoFile` resolved from
ntdll the same way. Control codes, structure layouts and NTSTATUS values are written out in each area's own header.

## Areas

Counts: tests are the registered tests in each built exe; checks are the number of assertions executed, measured
on Windows 10 22H2 (all 75 areas have a recorded run; the dx_* areas were run elevated only; see `results/win10/README.txt` for what was and was not verified). `COVERAGE.md` has the per-export coverage and the exact
AFD control-code status sweep.

<!-- AREAS -->
| Area | Tests | Checks (measured) | Measures |
|---|---:|---:|---|
| `address_conversion` | 472 | 10662 | WSAAddressToString / WSAStringToAddress, inet_*, htons family, getnameinfo literals |
| `af_unix` | 486 | 2322 | AF_UNIX stream sockets: readiness, overlapped I/O, name rules |
| `afd_bind_listen_accept` | 203 | 3190 | AFD bind, start-listen, wait-for-listen, accept, defer-accept, unbind contract |
| `afd_close_cleanup` | 378 | 17070 | AFD endpoint close, duplicate, share, cancel, completion port and file-information behaviour |
| `afd_connect_send_recv` | 208 | 2196 | AFD connect, send, receive, datagram, partial disconnect and completion delivery |
| `afd_endpoint_create` | 469 | 1221 | NtCreateFile on the AFD device: open packet, extended attribute and status tables |
| `afd_info_options` | 379 | 18796 | AFD information classes, connect/disconnect data and options, the full control-code sweep |
| `afd_poll_events` | 96 | 2917 | AFD poll: event bits, masks, timeouts, carrier kinds, close and cancel semantics |
| `async_select_messages` | 197 | 1998 | WSAAsyncSelect / WSAAsyncGetXByY message delivery |
| `bind_listen_accept` | 351 | 1857 | accept / WSAAccept error ladder, address-length protocol, non-blocking behaviour |
| `connect_paths` | 189 | 923 | connect / WSAConnect argument validation and check order |
| `core_smoke` | 3 | 4 | load-resolve-invoke smoke test |
| `dx_gap_00` | 8 | 38 | guarded: persisted 32-bit name-space order writer |
| `dx_gap_01` | 40 | 206 | guarded: provider and name-space catalog writers with throwaway identities |
| `dx_gap_02` | 8 | 13 | guarded: service class install/remove with a throwaway id |
| `dx_gap_04` | 5 | 6 | guarded: mswsock proxy-service start/stop pair |
| `dx_gap_05` | 6 | 55 | guarded: SAN helper-registration control codes on ordinary endpoints |
| `dx_provider_catalog` | 247 | 1625 | guarded: install, update, reorder, remove a throwaway base provider |
| `dx_qos_misc_apis` | 9 | 67 | guarded: provider catalog and QoS-related writers, restore checked |
| `event_select_enum` | 200 | 979 | WSAEventSelect / WSAEnumNetworkEvents |
| `gap_00` | 9 | 22 | WSCWriteNameSpaceOrder32 failure paths |
| `gap_01` | 236 | 1184 | provider-catalog writers that must fail without changing anything |
| `gap_02` | 180 | 948 | GetAddrInfoEx A/W, SetAddrInfoEx, GetNameInfoW, WSAStringToAddressW, WSAGetQOSByName |
| `gap_03` | 85 | 1710 | GetAcceptExSockaddrs pointer/length arithmetic |
| `gap_04` | 108 | 13557 | non-public mswsock exports: presence, ordinals, aliasing, forwarders |
| `gap_05` | 137 | 2911 | connect/disconnect data and option control codes, one literal code per row |
| `getaddrinfo_family` | 610 | 8793 | GetAddrInfoEx family: cancel, overlapped result, free |
| `ioctl_basic` | 194 | 10052 | SIO_ADDRESS_LIST_CHANGE and related change-notification lifetimes |
| `ioctl_extension_functions` | 226 | 1679 | ConnectEx, DisconnectEx, AcceptEx via looked-up extension pointers |
| `ipv6_dualstack_multicast` | 178 | 989 | ancillary data, dual-stack and multicast over WSARecvMsg/WSASendMsg |
| `legacy_name_services` | 472 | 2245 | WSAGetServiceClassNameByClassId and legacy service-class lookups |
| `lift_00` | 53 | 921 | AFD poll and device-open contract |
| `lift_01` | 63 | 1025 | AFD contract on loopback sockets |
| `lift_02` | 59 | 3431 | WSAAddressToStringA/W |
| `lift_03` | 83 | 615 | getaddrinfo / freeaddrinfo argument and literal parsing |
| `lift_04` | 98 | 1517 | multi-threaded loopback echo scenarios |
| `lift_05` | 101 | 842 | WSARecvMsg with control data |
| `lift_06` | 99 | 1050 | accept / WSAAccept alertable wait, condition function, close wake-up |
| `lift_07` | 135 | 1609 | FD_ACCEPT notification via event object and window message |
| `lift_08` | 80 | 974 | AcceptEx / GetAcceptExSockaddrs validation |
| `lift_09` | 82 | 537 | SIO_ADDRESS_LIST_CHANGE by blocking mode and overlapped form |
| `lift_10` | 69 | 598 | SIO_ADDRESS_LIST_QUERY |
| `lift_11` | 71 | 493 | AF_UNIX bind-length rules, connect, accept |
| `mswsock_acceptex_transmit` | 163 | 1189 | AcceptEx and TransmitFile/TransmitPackets, direct and via pointer |
| `nsp_lookup_service` | 137 | 586 | WSALookupServiceBegin/Next/End argument and handle lifecycle |
| `protocol_catalog` | 341 | 2124 | catalog enumeration, WSAProviderConfigChange, sockets from catalog entries |
| `qos_misc_apis` | 212 | 628 | event objects, per-thread error slot, QoS and misc APIs |
| `select_poll` | 231 | 6790 | fd_set layout, FD_* macros, __WSAFDIsSet, select, WSAPoll |
| `socket_create` | 307 | 11370 | socket / WSASocket creation matrix and the NT object behind a socket |
| `socket_handle_semantics` | 277 | 1303 | file-style I/O, inheritance and handle interactions with socket state |
| `sockopt_protocol_level` | 346 | 3981 | IP/IPv6/TCP/UDP level options, dual-stack and packet-info |
| `sockopt_socket_level` | 322 | 5193 | SOL_SOCKET get/setsockopt validation order and error codes |
| `startup_cleanup` | 379 | 692 | WSAStartup/WSACleanup reference counting and not-initialised errors |
| `stress_bounds` | 84 | 585 | bounded churn: many sockets, many connections |
| `tcp_stream_io` | 184 | 1801 | send/recv on loopback TCP: zero-length, partial, shutdown |
| `threading_and_races` | 157 | 1010 | closing a socket under a blocked call in another thread |
| `udp_datagram_io` | 165 | 1290 | UDP loopback datagram boundaries, ordering, truncation |
| `wsa_overlapped_io` | 170 | 2219 | overlapped I/O, cancellation and close with requests outstanding |
| `wsock32_forwarders` | 560 | 1924 | wsock32 export table and forwarder targets |
| `wsp_spi_mswsock` | 471 | 2292 | mswsock legacy name-service API and SPI entry points |
| `x_acceptex_fixture` | 191 | 1787 | AcceptEx buffer layout, argument and state error table, cancel |
| `x_af_unix_deep` | 471 | 2486 | AF_UNIX creation matrix, options, wrong-state errors, name shapes |
| `x_ancillary_providers` | 183 | 6963 | ancillary data and provider-level options across socket types |
| `x_child_process_inherit` | 199 | 798 | WSADuplicateSocket blob edge cases and inheritance into children |
| `x_dualstack_scope_matrix` | 167 | 3883 | bind matrix over socket flavours and address kinds |
| `x_error_mapping` | 724 | 1572 | WSA error to NTSTATUS to Win32 error mapping tables |
| `x_getaddrinfoex_async` | 170 | 4462 | GetAddrInfoEx synchronous front end: timeout, overlapped, cancel rules |
| `x_ioctl_sweep` | 236 | 2022692 | state-aware WSAIoctl and option sweeps (TCP, UDP, raw, AF_UNIX) |
| `x_overlapped_matrix` | 122 | 6537 | overlapped request edge cases: cancel with nothing pending, reuse, results |
| `x_raw_icmp_elevated` | 227 | 1773 | raw / ICMP sockets, SIO_RCVALL, scatter/gather (elevated only) |
| `x_registered_io` | 143 | 1780 | RIO extension: argument validation before queuing |
| `x_select_poll_matrix` | 120 | 3267 | select and WSAPoll with odd sets and arrays |
| `x_stress_soak_bounded` | 203 | 945 | 200-connection accept soaks with connector threads |
| `x_tcp_info_fastopen` | 202 | 5167 | TCP bind-conflict matrix, SIO_TCP_INFO, fast open |
| `x_udp_coalescing_msg` | 134 | 8633 | WSARecvMsg/WSASendMsg call contract, UDP connreset, coalescing |
| **total (75 areas)** | **15380** | **2241569** | checks are measured on Windows 10 22H2 for the areas run so far |
<!-- /AREAS -->

Prefixes: `afd_*` drive the device directly; `dx_*` are guarded areas that change system state (see Safety);
`x_*`, `gap_*` and `lift_*` are expansion and gap-fill areas for the same surfaces; the rest are named for the API
family they measure.

## Safety

- Network: loopback only (127.0.0.1, ::1). Listeners bind port 0 and use the ephemeral port the stack returns; no
  fixed ports, no non-loopback destinations, no name-server dependence (name tests use literals and the hosts file).
  Anything needing external connectivity or a real DNS server is a conditional skip with a stated reason.
- Deterministic output: ports, OS-chosen addresses, handles, timings and process ids are never printed.
- Bounded: every wait is a few seconds at most, every socket is closed, every thread is joined, scratch files live
  in a per-process temp directory that is removed at exit.
- Persistent state: only the `dx_*` areas change it (Winsock provider catalogs, name-space providers, service
  classes). They use throwaway GUIDs whose first field is a fixed marker, sweep leftovers of a crashed earlier run
  before and after each test, restore everything they touch, and skip unless the token is elevated. The runner
  refuses `dx_*` exes unless `--destructive` is given. Run them only on a disposable machine.
- No firewall changes, no listening on non-loopback, no sends to non-loopback.

## Build

Cross-compile on Linux with mingw-w64:

    make -j8            # builds build/<area>.exe for every directory under tests/
    make clean

Quick validation (compile, hang and crash checking only) can be done under a headless compatibility layer with the
runner script in `tools/`. A check that fails only under such a layer is not evidence the test is wrong; Windows 10 is the authority.

## Run on Windows 10

Copy `build/*.exe` to the machine and run:

    build\<area>.exe [name-filter]    # one area; optional substring filter on test names
    tools\run_all.bat                 # every non-dx area, results\<area>.txt
    tools\run_all.bat /destructive    # also the dx_* areas (disposable machine only)
    python tools\summarize.py results [--failures]

Output lines: `RUN <test>`, `OK` / `FAIL` / `SKIP`, `  FAIL file:line expr (detail)` per failed check, `NOTE`
for observed version-dependent behavior, and a final `SUMMARY tests= failed= skipped= checks_pass= checks_fail=`.
The exit code is 1 if any test failed. Tests that need a second process re-launch the exe (`--child <name>`).

For unattended passes in a throwaway guest (elevated Administrator and a real standard user, per-area timeouts,
framed log capture over a serial port) use the payload tools:

    python tools/win10_pack.py <payload_dir> --all --mode both     # build a payload from build/
    python tools/win10_results.py <serial.log> --failures          # parse the captured log

See `HANDOFF.md` for the complete procedure, triage rules and cleanup.

## Layout

    common/            harness (t.h, t.c), module list
    tests/<area>/      one exe per directory, many small TEST()s, header comment says what is measured
    tools/             build, packaging, results parsing, coverage and doc generation
    docs/AFD_CONTRACT.md   the AFD device contract as established by the tests
    COVERAGE.md        export coverage and the AFD control-code sweep (generated by tools/gen_docs.py)
    HANDOFF.md         how to run and triage Windows 10 passes
    results/           sanitized per-area summaries only, never raw logs

`tools/gen_docs.py` regenerates `COVERAGE.md` and the areas table above after tests are added.
