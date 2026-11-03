#!/usr/bin/env python3
"""Regenerate COVERAGE.md and the areas table inside README.md.
usage: gen_docs.py            (run from anywhere; needs build/*.exe from `make`, and tools/coverage.py)
Test counts come from the registration symbols in the built exes (so macro-generated tests are counted);
check counts come from the newest results/win10/adm/summary.tsv when present (measured), and are shown as '-'
for areas that have not been run there. The AFD ioctl table is parsed from tests/afd_info_options/sweep.c."""
import glob, os, re, subprocess, sys, csv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NM = os.environ.get("NM", "x86_64-w64-mingw32-nm")

DESC = {
 "address_conversion": "WSAAddressToString / WSAStringToAddress, inet_*, htons family, getnameinfo literals",
 "af_unix": "AF_UNIX stream sockets: readiness, overlapped I/O, name rules",
 "afd_bind_listen_accept": "AFD bind, start-listen, wait-for-listen, accept, defer-accept, unbind contract",
 "afd_close_cleanup": "AFD endpoint close, duplicate, share, cancel, completion port and file-information behaviour",
 "afd_connect_send_recv": "AFD connect, send, receive, datagram, partial disconnect and completion delivery",
 "afd_endpoint_create": "NtCreateFile on the AFD device: open packet, extended attribute and status tables",
 "afd_info_options": "AFD information classes, connect/disconnect data and options, the full control-code sweep",
 "afd_poll_events": "AFD poll: event bits, masks, timeouts, carrier kinds, close and cancel semantics",
 "async_select_messages": "WSAAsyncSelect / WSAAsyncGetXByY message delivery",
 "bind_listen_accept": "accept / WSAAccept error ladder, address-length protocol, non-blocking behaviour",
 "connect_paths": "connect / WSAConnect argument validation and check order",
 "core_smoke": "load-resolve-invoke smoke test",
 "dx_gap_00": "guarded: persisted 32-bit name-space order writer",
 "dx_gap_01": "guarded: provider and name-space catalog writers with throwaway identities",
 "dx_gap_02": "guarded: service class install/remove with a throwaway id",
 "dx_gap_04": "guarded: mswsock proxy-service start/stop pair",
 "dx_gap_05": "guarded: SAN helper-registration control codes on ordinary endpoints",
 "dx_provider_catalog": "guarded: install, update, reorder, remove a throwaway base provider",
 "dx_qos_misc_apis": "guarded: provider catalog and QoS-related writers, restore checked",
 "event_select_enum": "WSAEventSelect / WSAEnumNetworkEvents",
 "gap_00": "WSCWriteNameSpaceOrder32 failure paths",
 "gap_01": "provider-catalog writers that must fail without changing anything",
 "gap_02": "GetAddrInfoEx A/W, SetAddrInfoEx, GetNameInfoW, WSAStringToAddressW, WSAGetQOSByName",
 "gap_03": "GetAcceptExSockaddrs pointer/length arithmetic",
 "gap_04": "non-public mswsock exports: presence, ordinals, aliasing, forwarders",
 "gap_05": "connect/disconnect data and option control codes, one literal code per row",
 "getaddrinfo_family": "GetAddrInfoEx family: cancel, overlapped result, free",
 "ioctl_basic": "SIO_ADDRESS_LIST_CHANGE and related change-notification lifetimes",
 "ioctl_extension_functions": "ConnectEx, DisconnectEx, AcceptEx via looked-up extension pointers",
 "ipv6_dualstack_multicast": "ancillary data, dual-stack and multicast over WSARecvMsg/WSASendMsg",
 "legacy_name_services": "WSAGetServiceClassNameByClassId and legacy service-class lookups",
 "lift_00": "AFD poll and device-open contract",
 "lift_01": "AFD contract on loopback sockets",
 "lift_02": "WSAAddressToStringA/W",
 "lift_03": "getaddrinfo / freeaddrinfo argument and literal parsing",
 "lift_04": "multi-threaded loopback echo scenarios",
 "lift_05": "WSARecvMsg with control data",
 "lift_06": "accept / WSAAccept alertable wait, condition function, close wake-up",
 "lift_07": "FD_ACCEPT notification via event object and window message",
 "lift_08": "AcceptEx / GetAcceptExSockaddrs validation",
 "lift_09": "SIO_ADDRESS_LIST_CHANGE by blocking mode and overlapped form",
 "lift_10": "SIO_ADDRESS_LIST_QUERY",
 "lift_11": "AF_UNIX bind-length rules, connect, accept",
 "mswsock_acceptex_transmit": "AcceptEx and TransmitFile/TransmitPackets, direct and via pointer",
 "nsp_lookup_service": "WSALookupServiceBegin/Next/End argument and handle lifecycle",
 "protocol_catalog": "catalog enumeration, WSAProviderConfigChange, sockets from catalog entries",
 "qos_misc_apis": "event objects, per-thread error slot, QoS and misc APIs",
 "select_poll": "fd_set layout, FD_* macros, __WSAFDIsSet, select, WSAPoll",
 "socket_create": "socket / WSASocket creation matrix and the NT object behind a socket",
 "socket_handle_semantics": "file-style I/O, inheritance and handle interactions with socket state",
 "sockopt_protocol_level": "IP/IPv6/TCP/UDP level options, dual-stack and packet-info",
 "sockopt_socket_level": "SOL_SOCKET get/setsockopt validation order and error codes",
 "startup_cleanup": "WSAStartup/WSACleanup reference counting and not-initialised errors",
 "stress_bounds": "bounded churn: many sockets, many connections",
 "tcp_stream_io": "send/recv on loopback TCP: zero-length, partial, shutdown",
 "threading_and_races": "closing a socket under a blocked call in another thread",
 "udp_datagram_io": "UDP loopback datagram boundaries, ordering, truncation",
 "wsa_overlapped_io": "overlapped I/O, cancellation and close with requests outstanding",
 "wsock32_forwarders": "wsock32 export table and forwarder targets",
 "wsp_spi_mswsock": "mswsock legacy name-service API and SPI entry points",
 "x_acceptex_fixture": "AcceptEx buffer layout, argument and state error table, cancel",
 "x_af_unix_deep": "AF_UNIX creation matrix, options, wrong-state errors, name shapes",
 "x_ancillary_providers": "ancillary data and provider-level options across socket types",
 "x_child_process_inherit": "WSADuplicateSocket blob edge cases and inheritance into children",
 "x_dualstack_scope_matrix": "bind matrix over socket flavours and address kinds",
 "x_error_mapping": "WSA error to NTSTATUS to Win32 error mapping tables",
 "x_getaddrinfoex_async": "GetAddrInfoEx synchronous front end: timeout, overlapped, cancel rules",
 "x_ioctl_sweep": "state-aware WSAIoctl and option sweeps (TCP, UDP, raw, AF_UNIX)",
 "x_overlapped_matrix": "overlapped request edge cases: cancel with nothing pending, reuse, results",
 "x_raw_icmp_elevated": "raw / ICMP sockets, SIO_RCVALL, scatter/gather (elevated only)",
 "x_registered_io": "RIO extension: argument validation before queuing",
 "x_select_poll_matrix": "select and WSAPoll with odd sets and arrays",
 "x_stress_soak_bounded": "200-connection accept soaks with connector threads",
 "x_tcp_info_fastopen": "TCP bind-conflict matrix, SIO_TCP_INFO, fast open",
 "x_udp_coalescing_msg": "WSARecvMsg/WSASendMsg call contract, UDP connreset, coalescing",
}

def areas():
    return sorted(os.path.basename(d.rstrip("/")) for d in glob.glob(os.path.join(ROOT, "tests", "*/")))

def test_count(a):
    exe = os.path.join(ROOT, "build", a + ".exe")
    if not os.path.exists(exe): return None
    out = subprocess.run([NM, exe], capture_output=True, text=True).stdout
    return len(re.findall(r" t reg_", out))

def static_checks(a):
    n = 0
    for f in glob.glob(os.path.join(ROOT, "tests", a, "*.[ch]")):
        n += len(re.findall(r"\b(?:CHECK|CHECKF|EXPECT_[A-Z]+|[A-Z]+_EQ|CHECK_[A-Z]+|EXPECT_FAIL)\s*\(", open(f, errors="replace").read()))
    return n

def measured():
    p = os.path.join(ROOT, "results", "win10", "adm", "summary.tsv")
    m = {}
    if os.path.exists(p):
        for r in csv.DictReader(open(p), delimiter="\t"):
            m[r["exe"]] = (int(r["tests"]), int(r["checks_pass"]) + int(r["checks_fail"]))
    return m

def afd_rows():
    src = open(os.path.join(ROOT, "tests", "afd_info_options", "sweep.c")).read()
    return re.findall(r'X\((\w+),\s*(0x[0-9a-f]+)((?:,\s*"[^"]*"){7})\)', src)

LETTERS = [("S","STATUS_SUCCESS"),("P","STATUS_INVALID_PARAMETER (0xC000000D)"),("D","STATUS_INVALID_DEVICE_REQUEST (0xC0000010)"),
 ("T","STATUS_BUFFER_TOO_SMALL (0xC0000023)"),("C","STATUS_INVALID_CONNECTION (0xC0000140)"),("O","STATUS_BUFFER_OVERFLOW (0x80000005)"),
 ("V","STATUS_ACCESS_VIOLATION (0xC0000005)"),("H","STATUS_INVALID_HANDLE (0xC0000008)"),("A","STATUS_INVALID_ADDRESS_COMPONENT (0xC0000207)"),
 ("B","STATUS_ADDRESS_ALREADY_ASSOCIATED (0xC0000238)"),("N","STATUS_NOT_SUPPORTED (0xC00000BB)"),("2","0xC00000F0 (invalid parameter, variant 2)"),
 ("X","0xC000023B"),("W","request stays pending (test cancels it)"),("Q","STATUS_SUCCESS or STATUS_INVALID_DEVICE_REQUEST")]

def main():
    ar = areas(); meas = measured()
    cov = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "coverage.py"), ROOT], capture_output=True, text=True).stdout.splitlines()[0]
    unc = [l.strip() for l in open(os.path.join(ROOT, "tools", "uncovered.txt")) if l.strip()]
    rows = []; tt = tc = 0
    for a in ar:
        t = test_count(a)
        if t is None: t = 0
        mt = meas.get(a)
        chk = mt[1] if mt else None
        tt += t; tc += chk or 0
        rows.append((a, t, chk, DESC.get(a, "")))
    table = ["| Area | Tests | Checks (measured) | Measures |", "|---|---:|---:|---|"]
    for a, t, c, d in rows:
        table.append(f"| `{a}` | {t} | {c if c is not None else '-'} | {d} |")
    table.append(f"| **total ({len(rows)} areas)** | **{tt}** | **{tc}** | checks are measured on Windows 10 22H2 for the areas run so far |")
    tbl = "\n".join(table)

    # README table between markers
    rp = os.path.join(ROOT, "README.md"); r = open(rp).read()
    r = re.sub(r"(<!-- AREAS -->).*?(<!-- /AREAS -->)", lambda m: m.group(1) + "\n" + tbl + "\n" + m.group(2), r, flags=re.S)
    open(rp, "w").write(r)

    o = ["# Coverage", "", "Generated by `tools/gen_docs.py`; do not edit by hand.", "",
         "## Exports", "", f"`tools/coverage.py` reports: {cov}.", "",
         "An export counts as *called* when a test resolves it through the loader and invokes it. The list covers the named exports of "
         "ws2_32.dll, mswsock.dll and wsock32.dll (a name present in several modules counts once); wsock32 forwarders are checked in the "
         "`wsock32_forwarders` area.", "",
         "Exports not yet called by any test (mostly the transport helper entry points exported by mswsock for the TCP/IP helper DLLs):", ""]
    o += [f"- `{u}`" for u in unc]
    o += ["", "## Tests per area", "", tbl, "",
          "Test counts are the number of registered tests in each built exe. Check counts are the pass+fail totals from the most recent "
          "recorded Windows 10 run (`results/win10/adm/summary.tsv`); areas added after that run show `-` until they are run.", ""]
    rowsA = afd_rows()
    o += ["## AFD control-code sweep", "",
          f"`afd_info_options` (`aio_sweep_*`) sends each of the {len(rowsA)} control codes the AFD device registers "
          "(function numbers 0x12003 .. 0x12123, device type 0x12) to a fresh endpoint of seven kinds in six request shapes, and compares the "
          "NTSTATUS with the table below, measured on Windows 10 22H2.", "",
          "Kinds, in column order: **tcp**, **udp**, **raw**, **tcp-bound**, **tcp-listening**, **udp-bound**, **tcp-connected**. "
          "Each cell is six letters, one per request shape:", "",
          "| Shape | Input | Output |", "|---|---|---|",
          "| 0 | none | none |", "| 1 | 16 zero bytes | 16 bytes |", "| 2 | 64 zero bytes | 64 bytes |",
          "| 3 | 256 zero bytes | none |", "| 4 | none | 256 bytes |", "| 5 | 4 zero bytes | 4 bytes |", "",
          "Letters:", ""]
    o += [f"- `{l}` {d}" for l, d in LETTERS]
    o += ["", "| Code | Name | tcp | udp | raw | tcp-bound | tcp-listen | udp-bound | tcp-conn |", "|---|---|---|---|---|---|---|---|---|"]
    for name, code, cells in rowsA:
        cs = re.findall(r'"([^"]*)"', cells)
        o.append(f"| `{code}` | {name} | " + " | ".join(f"`{c}`" for c in cs) + " |")
    o += ["", "Beyond the table the sweep also asserts: the table has exactly 73 slots; codes are strictly increasing; any other function "
          "number, method-bit variant, device type, or slot alias is refused; the same results hold on synchronous handles, without an event "
          "object, and for IPv6 sockets.", ""]
    open(os.path.join(ROOT, "COVERAGE.md"), "w").write("\n".join(o))
    print(f"{len(ar)} areas, {tt} tests, {tc} measured checks, {len(rowsA)} ioctl rows")

main()
