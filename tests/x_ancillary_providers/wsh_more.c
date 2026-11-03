/* Second pass over the helper DLLs and the legacy front: further parser spellings of the three string-to-address
 * routines (bare numbers, octal and hexadecimal parts, port syntax, scope ids, ignored Bluetooth ports), the address
 * classes of the whole loopback block and of the special IPv6 forms, and the structure of the export tables
 * (exact name counts, the forwarder targets and ordinals of the legacy socket library, and the entry points it keeps
 * for itself). Every row was observed on Windows 10; nothing is resolved or sent. */
#include "anc.h"

/* ---- the PE export directory of a loaded module ---- */
typedef struct { BYTE *base; IMAGE_EXPORT_DIRECTORY *dir; DWORD dir_rva, dir_size; DWORD *fn, *nm; WORD *ord; } pe_exports;

static int pe_open(pe_exports *e, HMODULE m) {
    BYTE *b = (BYTE *)m; IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)b; IMAGE_NT_HEADERS64 *nt;
    memset(e, 0, sizeof *e);
    if (d->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (IMAGE_NT_HEADERS64 *)(b + d->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || !nt->OptionalHeader.DataDirectory[0].VirtualAddress) return 0;
    e->base = b; e->dir_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress; e->dir_size = nt->OptionalHeader.DataDirectory[0].Size;
    e->dir = (IMAGE_EXPORT_DIRECTORY *)(b + e->dir_rva);
    e->fn = (DWORD *)(b + e->dir->AddressOfFunctions); e->nm = (DWORD *)(b + e->dir->AddressOfNames); e->ord = (WORD *)(b + e->dir->AddressOfNameOrdinals);
    return 1;
}
/* index of a named export, or -1 */
static int pe_find(const pe_exports *e, const char *name) {
    for (DWORD i = 0; i < e->dir->NumberOfNames; i++) if (!strcmp((const char *)(e->base + e->nm[i]), name)) return (int)i;
    return -1;
}
static int pe_is_fwd(const pe_exports *e, int idx) { DWORD rva = e->fn[e->ord[idx]]; return rva >= e->dir_rva && rva < e->dir_rva + e->dir_size; }
static const char *pe_fwd(const pe_exports *e, int idx) { return (const char *)(e->base + e->fn[e->ord[idx]]); }

/* ---- exact export tables ---- */
static const char *const m_wshtcpip[] = { "WSHOpenSocket", "WSHOpenSocket2", "WSHGetSockaddrType", "WSHGetWildcardSockaddr", "WSHGetBroadcastSockaddr",
    "WSHGetSocketInformation", "WSHSetSocketInformation", "WSHEnumProtocols", "WSHNotify", "WSHGetProviderGuid", "WSHAddressToString", "WSHStringToAddress",
    "WSHIoctl", "WSHJoinLeaf", "WSHGetWinsockMapping", "WSHGetWSAProtocolInfo" };
static const char *const m_wship6[] = { "WSHOpenSocket", "WSHOpenSocket2", "WSHGetSockaddrType", "WSHGetWildcardSockaddr", "WSHGetSocketInformation",
    "WSHSetSocketInformation", "WSHEnumProtocols", "WSHNotify", "WSHGetProviderGuid", "WSHAddressToString", "WSHStringToAddress", "WSHIoctl", "WSHJoinLeaf",
    "WSHGetWinsockMapping", "WSHGetWSAProtocolInfo" };
static const char *const m_wshbth[] = { "WSHOpenSocket", "WSHOpenSocket2", "WSHGetSockaddrType", "WSHGetWildcardSockaddr", "WSHGetBroadcastSockaddr",
    "WSHGetSocketInformation", "WSHSetSocketInformation", "WSHEnumProtocols", "WSHNotify", "WSHGetProviderGuid", "WSHAddressToString", "WSHStringToAddress",
    "WSHIoctl", "WSHJoinLeaf", "WSHGetWinsockMapping", "WSHGetWSAProtocolInfo", "NSPStartup" };
static const char *const m_winrnr[] = { "NSPStartup", "InstallNTDSProvider", "RemoveNTDSProvider" };
static const char *const m_napinsp[] = { "NSPStartup", "DllMain" };
static const char *const m_pnrpnsp[] = { "NSPStartup" };
static const char *const m_nlaapi[] = { "LANIdFreeCollection", "LANIdRetrieveCollection", "NSPStartup", "NlaAddToPluginRequests", "NlaAddToTypeSet", "NlaAnd",
    "NlaCloseQuery", "NlaComposeNetSignature", "NlaCreateFilter", "NlaCreatePluginRequests", "NlaCreateTypeSet", "NlaDecomposeNetSignature", "NlaDeleteDataSet",
    "NlaDeleteFilter", "NlaDeletePluginRequests", "NlaDeleteTypeSet", "NlaEqual", "NlaEqualNetSignatures", "NlaGetCaptivePortalHosts", "NlaGetInternetCapability",
    "NlaGetIntranetCapability", "NlaIndicateReprobe", "NlaNotEqual", "NlaOpenQuery", "NlaOr", "NlaQueryNetData", "NlaQueryNetDataEx", "NlaQueryNetSignatures",
    "NlaRefreshQuery", "NlaRegisterQuery" };
static const char *const m_rasadhlp[] = { "AcsHlpNbConnection", "WSAttemptAutodialAddr", "WSAttemptAutodialName", "WSNoteSuccessfulHostentLookup" };

typedef struct { const char *dll; const char *const *names; DWORD n; } exact_tab;
#define XT(d, a) { d, a, (DWORD)ANC_N(a) }
static const exact_tab exact[] = { XT("wshtcpip.dll", m_wshtcpip), XT("wship6.dll", m_wship6), XT("wshbth.dll", m_wshbth), XT("winrnr.dll", m_winrnr),
    XT("napinsp.dll", m_napinsp), XT("pnrpnsp.dll", m_pnrpnsp), XT("nlaapi.dll", m_nlaapi), XT("rasadhlp.dll", m_rasadhlp) };

/* Each module exports exactly its documented names: no extra names, no unnamed ordinals, no forwarders, and the ordinals
 * follow the alphabetical order of the names (the linker's order) starting at one. */
TEST(exp_ancillary_tables_are_exact) {
    for (size_t k = 0; k < ANC_N(exact); k++) {
        HMODULE m = t_module(exact[k].dll); pe_exports e;
        if (!m) { t_note("%s absent, row skipped", exact[k].dll); continue; }
        if (!pe_open(&e, m)) { CHECKF(0, "%s has no export directory", exact[k].dll); continue; }
        CHECKF(e.dir->NumberOfNames == exact[k].n, "%s: %lu names want %lu", exact[k].dll, e.dir->NumberOfNames, exact[k].n);
        CHECKF(e.dir->NumberOfFunctions == exact[k].n, "%s: %lu functions want %lu", exact[k].dll, e.dir->NumberOfFunctions, exact[k].n);
        CHECKF(e.dir->Base == 1, "%s: ordinal base %lu", exact[k].dll, e.dir->Base);
        for (DWORD i = 0; i < exact[k].n; i++) {
            int ix = pe_find(&e, exact[k].names[i]);
            CHECKF(ix >= 0, "%s lacks %s", exact[k].dll, exact[k].names[i]);
            if (ix >= 0) CHECKF(!pe_is_fwd(&e, ix), "%s!%s is a forwarder", exact[k].dll, exact[k].names[i]);
        }
        /* every name in the table is one of the expected ones */
        for (DWORD i = 0; i < e.dir->NumberOfNames; i++) {
            const char *nm = (const char *)(e.base + e.nm[i]); int found = 0;
            for (DWORD j = 0; j < exact[k].n; j++) if (!strcmp(nm, exact[k].names[j])) found = 1;
            CHECKF(found, "%s exports the unexpected name %s", exact[k].dll, nm);
        }
    }
}

/* ---- the legacy socket library: forwarders and ordinals ---- */
typedef struct { const char *name; WORD ord; const char *fwd; } wsock_row;   /* fwd NULL: implemented in the module itself */
static const wsock_row wsock_rows[] = {
    { "accept", 1, "ws2_32.accept" }, { "bind", 2, "ws2_32.bind" }, { "closesocket", 3, "ws2_32.closesocket" }, { "connect", 4, "ws2_32.connect" },
    { "getpeername", 5, "ws2_32.getpeername" }, { "getsockname", 6, "ws2_32.getsockname" }, { "getsockopt", 7, NULL }, { "htonl", 8, "ws2_32.htonl" },
    { "htons", 9, "ws2_32.htons" }, { "inet_addr", 10, "ws2_32.inet_addr" }, { "inet_ntoa", 11, "ws2_32.inet_ntoa" }, { "ioctlsocket", 12, "ws2_32.ioctlsocket" },
    { "listen", 13, "ws2_32.listen" }, { "ntohl", 14, "ws2_32.ntohl" }, { "ntohs", 15, "ws2_32.ntohs" }, { "recv", 16, NULL }, { "recvfrom", 17, NULL },
    { "select", 18, "ws2_32.select" }, { "send", 19, "ws2_32.send" }, { "sendto", 20, "ws2_32.sendto" }, { "setsockopt", 21, NULL },
    { "shutdown", 22, "ws2_32.shutdown" }, { "socket", 23, "ws2_32.socket" }, { "MigrateWinsockConfiguration", 24, "MSWSOCK.MigrateWinsockConfiguration" },
    { "gethostbyaddr", 51, "ws2_32.gethostbyaddr" }, { "gethostbyname", 52, "ws2_32.gethostbyname" }, { "getprotobyname", 53, "ws2_32.getprotobyname" },
    { "getprotobynumber", 54, "ws2_32.getprotobynumber" }, { "getservbyname", 55, "ws2_32.getservbyname" }, { "getservbyport", 56, "ws2_32.getservbyport" },
    { "gethostname", 57, "ws2_32.gethostname" }, { "WSAAsyncSelect", 101, "ws2_32.WSAAsyncSelect" }, { "WSAAsyncGetHostByAddr", 102, "ws2_32.WSAAsyncGetHostByAddr" },
    { "WSAAsyncGetHostByName", 103, "ws2_32.WSAAsyncGetHostByName" }, { "WSAAsyncGetProtoByNumber", 104, "ws2_32.WSAAsyncGetProtoByNumber" },
    { "WSAAsyncGetProtoByName", 105, "ws2_32.WSAAsyncGetProtoByName" }, { "WSAAsyncGetServByPort", 106, "ws2_32.WSAAsyncGetServByPort" },
    { "WSAAsyncGetServByName", 107, "ws2_32.WSAAsyncGetServByName" }, { "WSACancelAsyncRequest", 108, "ws2_32.WSACancelAsyncRequest" },
    { "WSASetBlockingHook", 109, "ws2_32.WSASetBlockingHook" }, { "WSAUnhookBlockingHook", 110, "ws2_32.WSAUnhookBlockingHook" },
    { "WSAGetLastError", 111, "ws2_32.WSAGetLastError" }, { "WSASetLastError", 112, "ws2_32.WSASetLastError" }, { "WSACancelBlockingCall", 113, "ws2_32.WSACancelBlockingCall" },
    { "WSAIsBlocking", 114, "ws2_32.WSAIsBlocking" }, { "WSAStartup", 115, "ws2_32.WSAStartup" }, { "WSACleanup", 116, "ws2_32.WSACleanup" },
    { "__WSAFDIsSet", 151, "ws2_32.__WSAFDIsSet" }, { "WEP", 500, "ws2_32.WEP" }, { "WSApSetPostRoutine", 1000, "ws2_32.WSApSetPostRoutine" },
    { "inet_network", 1100, "MSWSOCK.inet_network" }, { "getnetbyname", 1101, "MSWSOCK.getnetbyname" }, { "rcmd", 1102, "MSWSOCK.rcmd" },
    { "rexec", 1103, "MSWSOCK.rexec" }, { "rresvport", 1104, "MSWSOCK.rresvport" }, { "sethostname", 1105, "MSWSOCK.sethostname" },
    { "dn_expand", 1106, "MSWSOCK.dn_expand" }, { "WSARecvEx", 1107, "MSWSOCK.WSARecvEx" }, { "s_perror", 1108, "MSWSOCK.s_perror" },
    { "GetAddressByNameA", 1109, "MSWSOCK.GetAddressByNameA" }, { "GetAddressByNameW", 1110, "MSWSOCK.GetAddressByNameW" },
    { "EnumProtocolsA", 1111, "MSWSOCK.EnumProtocolsA" }, { "EnumProtocolsW", 1112, "MSWSOCK.EnumProtocolsW" },
    { "GetTypeByNameA", 1113, "MSWSOCK.GetTypeByNameA" }, { "GetTypeByNameW", 1114, "MSWSOCK.GetTypeByNameW" },
    { "GetNameByTypeA", 1115, "MSWSOCK.GetNameByTypeA" }, { "GetNameByTypeW", 1116, "MSWSOCK.GetNameByTypeW" },
    { "SetServiceA", 1117, "MSWSOCK.SetServiceA" }, { "SetServiceW", 1118, "MSWSOCK.SetServiceW" }, { "GetServiceA", 1119, "MSWSOCK.GetServiceA" },
    { "GetServiceW", 1120, "MSWSOCK.GetServiceW" }, { "NPLoadNameSpaces", 1130, "MSWSOCK.NPLoadNameSpaces" }, { "TransmitFile", 1140, "MSWSOCK.TransmitFile" },
    { "AcceptEx", 1141, "MSWSOCK.AcceptEx" }, { "GetAcceptExSockaddrs", 1142, "MSWSOCK.GetAcceptExSockaddrs" },
};

TEST(wsock32_table_has_75_named_entries_and_no_unnamed_ones) {
    HMODULE m = t_module("wsock32.dll"); pe_exports e;
    if (!m) { t_skip("wsock32.dll is not present"); return; }
    CHECK(pe_open(&e, m));
    CHECK(ANC_N(wsock_rows) == 75);
    CHECK(e.dir->NumberOfNames == 75);
    CHECK(e.dir->Base == 1);
    /* the table spans ordinals 1..1142 with holes; exactly 75 slots are used */
    CHECK(e.dir->NumberOfFunctions == 1142);
    DWORD used = 0; for (DWORD i = 0; i < e.dir->NumberOfFunctions; i++) if (e.fn[i]) used++;
    CHECKF(used == 75, "%lu used slots", used);
}

TEST(wsock32_ordinals_and_forwarder_targets) {
    HMODULE m = t_module("wsock32.dll"); pe_exports e;
    if (!m) { t_skip("wsock32.dll is not present"); return; }
    if (!pe_open(&e, m)) { CHECK(0); return; }
    DWORD nfwd = 0, nlocal = 0;
    for (size_t i = 0; i < ANC_N(wsock_rows); i++) {
        int ix = pe_find(&e, wsock_rows[i].name);
        CHECKF(ix >= 0, "wsock32 lacks %s", wsock_rows[i].name);
        if (ix < 0) continue;
        CHECKF(e.ord[ix] + e.dir->Base == wsock_rows[i].ord, "%s: ordinal %lu want %u", wsock_rows[i].name, e.ord[ix] + e.dir->Base, wsock_rows[i].ord);
        if (pe_is_fwd(&e, ix)) {
            nfwd++;
            CHECKF(wsock_rows[i].fwd && !_stricmp(pe_fwd(&e, ix), wsock_rows[i].fwd), "%s forwards to '%s'", wsock_rows[i].name, pe_fwd(&e, ix));
        } else {
            nlocal++;
            CHECKF(wsock_rows[i].fwd == NULL, "%s is implemented in the module but should forward to %s", wsock_rows[i].name, wsock_rows[i].fwd ? wsock_rows[i].fwd : "?");
        }
    }
    CHECK(nfwd == 71); CHECK(nlocal == 4);
}

/* A forwarded name resolves to the very function of the module it forwards to; the four local entries are the legacy
 * wrappers and differ from the ws2_32 functions of the same name. */
TEST(wsock32_forwarded_names_resolve_to_the_target_module) {
    HMODULE w = t_module("wsock32.dll"), s = t_module("ws2_32.dll"), ms = t_module("mswsock.dll");
    if (!w || !s) { t_skip("wsock32 or ws2_32 not present"); return; }
    for (size_t i = 0; i < ANC_N(wsock_rows); i++) {
        FARPROC a = GetProcAddress(w, wsock_rows[i].name);
        if (!wsock_rows[i].fwd) {
            FARPROC b = GetProcAddress(s, wsock_rows[i].name);
            CHECKF(a != NULL && b != NULL && a != b, "wsock32!%s is not the ws2_32 function", wsock_rows[i].name);
        } else if (!_strnicmp(wsock_rows[i].fwd, "ws2_32.", 7)) {
            CHECKF(a == GetProcAddress(s, wsock_rows[i].fwd + 7), "wsock32!%s differs from ws2_32", wsock_rows[i].name);
        } else if (ms) {
            CHECKF(a == GetProcAddress(ms, wsock_rows[i].fwd + 8), "wsock32!%s differs from mswsock", wsock_rows[i].name);
        }
    }
}

/* Lookup by ordinal reaches the same entry as lookup by name. */
TEST(wsock32_ordinal_lookup_matches_name_lookup) {
    HMODULE w = t_module("wsock32.dll");
    if (!w) { t_skip("wsock32.dll is not present"); return; }
    for (size_t i = 0; i < ANC_N(wsock_rows); i++)
        CHECKF(GetProcAddress(w, (LPCSTR)(ULONG_PTR)wsock_rows[i].ord) == GetProcAddress(w, wsock_rows[i].name), "ordinal %u vs %s", wsock_rows[i].ord, wsock_rows[i].name);
    /* ordinals in the gaps are not exported */
    static const WORD holes[] = { 25, 50, 58, 100, 117, 150, 152, 499, 501, 999, 1001, 1099, 1121, 1129, 1131, 1139, 1143 };
    for (size_t i = 0; i < ANC_N(holes); i++) { SET_ERR(0); CHECKF(GetProcAddress(w, (LPCSTR)(ULONG_PTR)holes[i]) == NULL, "ordinal %u resolves", holes[i]); EXPECT_ERR(ERROR_INVALID_ORDINAL); }
}

/* ---- IPv4 parser: more spellings ---- */
static SOCKADDR_IN m4(ULONG a, unsigned port) { SOCKADDR_IN s; memset(&s, 0, sizeof s); s.sin_family = AF_INET; s.sin_addr.s_addr = a; s.sin_port = htons(port); return s; }
static SOCKADDR_IN6 m6(const BYTE *a16, unsigned port, ULONG scope) { SOCKADDR_IN6 s; memset(&s, 0, sizeof s); s.sin6_family = AF_INET6; s.sin6_port = htons(port); s.sin6_scope_id = scope; if (a16) memcpy(&s.sin6_addr, a16, 16); return s; }

static INT s2a_rc(const anc_wsh *h, const WCHAR *s, int fam, void *out, DWORD *len) { return h->StringToAddress((LPWSTR)s, fam, NULL, (LPSOCKADDR)out, len); }

/* inet_addr-style numeric forms: fewer than four parts, hexadecimal and octal parts, a single 32-bit number. */
TEST(s2a_ipv4_numeric_forms_wshtcpip) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    static const struct { const WCHAR *s; ULONG addr; } rows[] = {
        { L"127.1", 0x0100007f }, { L"0x7f.1", 0x0100007f }, { L"0x7f.0.0.1", 0x0100007f }, { L"2130706433", 0x0100007f },
        { L"017.0.0.1", 0x0100000f }, { L"1.2", 0x02000001 }, { L"1", 0x01000000 }, { L"0", 0 }, { L"00.00.00.00", 0 },
        { L"4294967295", 0xffffffff }, { L"0xffffffff", 0xffffffff }, { L"1.65535", 0xffff0001 }, { L"1.65536", 0x00000101 } };
    for (size_t i = 0; i < ANC_N(rows); i++) {
        BYTE buf[64]; DWORD len = 40; memset(buf, ANC_FILL, sizeof buf);
        INT r = s2a_rc(&h, rows[i].s, 2, buf, &len);
        CHECKF(r == 0 && len == 16, "'%ls': rc %d len %lu", rows[i].s, r, len);
        SOCKADDR_IN w = m4(rows[i].addr, 0);
        CHECKF(!memcmp(buf, &w, 16), "'%ls': wrong bytes", rows[i].s);
    }
}

TEST(s2a_ipv4_ports_and_more_rejections_wshtcpip) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    BYTE buf[64]; DWORD len = 40; SOCKADDR_IN w;
    /* the highest port is accepted; port zero spelled out, an out-of-range, signed, padded or empty port is not */
    len = 40; CHECK(s2a_rc(&h, L"1.2.3.4:65535", 2, buf, &len) == 0); w = m4(0x04030201, 65535); CHECK(!memcmp(buf, &w, 16));
    len = 40; CHECK(s2a_rc(&h, L"1.2.3.4:1", 2, buf, &len) == 0); w = m4(0x04030201, 1); CHECK(!memcmp(buf, &w, 16));
    static const WCHAR *bad[] = { L"1.2.3.4:0", L"1.2.3.4:65536", L"1.2.3.4:abc", L"1.2.3.4:080", L"1.2.3.4:-1", L"1.2.3.4:+1", L"1.2.3.4:1:2", L"1.2.3.4:",
        L"1.2.3.4.", L".1.2.3", L"1..2.3", L"1.2.3.4\t", L"\t1.2.3.4", L"1.2.3.4:80 ", L"1.2.3.256", L"255.255.255.256", L"1.2.3.4/8", L"1.2.3.4%1",
        L"4294967296", L"1.2.0x10000", L"[1.2.3.4]", L"[1.2.3.4]:80", L"localhost" };
    for (size_t i = 0; i < ANC_N(bad); i++) { len = 40; INT r = s2a_rc(&h, bad[i], 2, buf, &len); CHECKF(r == E_INVAL, "'%ls': rc %d", bad[i], r); }
}

/* ---- IPv6 parser: more spellings ---- */
TEST(s2a_ipv6_more_spellings_wship6) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    BYTE loop[16] = { 0 }; loop[15] = 1;
    BYTE one[16] = { 0, 1 };
    BYTE abcd[16] = { 0 }; abcd[14] = 0xab; abcd[15] = 0xcd;
    BYTE v4c[16] = { 0 }; v4c[12] = 1; v4c[13] = 2; v4c[14] = 3; v4c[15] = 4;
    BYTE hx[16] = { 0 }; hx[13] = 1; hx[14] = 0; hx[15] = 0x80;   /* ::1:80 is the two groups 1 and 0x80, not an address with a port */
    BYTE seven[16] = { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0 };
    SOCKADDR_IN6 w;
    struct { const WCHAR *s; const BYTE *a; unsigned port; ULONG scope; } rows[] = {
        { L"::1%0", loop, 0, 0 }, { L"[::1]:0", loop, 0, 0 }, { L"[::1]:", loop, 0, 0 }, { L"[::1]:65535", loop, 65535, 0 },
        { L"[::1%5]", loop, 0, 5 }, { L"::1%4294967295", loop, 0, 0xffffffffu }, { L"1::", one, 0, 0 }, { L"::ABCD", abcd, 0, 0 }, { L"::abcd", abcd, 0, 0 },
        { L"0:0:0:0:0:0:1.2.3.4", v4c, 0, 0 }, { L"::1.2.3.4", v4c, 0, 0 }, { L"1:2:3:4:5:6:7::", seven, 0, 0 }, { L"::1:80", hx, 0, 0 },
        { L"0:0:0:0:0:0:0:1", loop, 0, 0 } };
    for (size_t i = 0; i < ANC_N(rows); i++) {
        BYTE buf[64]; DWORD len = 40; memset(buf, ANC_FILL, sizeof buf);
        INT r = s2a_rc(&h, rows[i].s, 23, buf, &len);
        CHECKF(r == 0 && len == 28, "'%ls': rc %d len %lu", rows[i].s, r, len);
        w = m6(rows[i].a, rows[i].port, rows[i].scope);
        CHECKF(!memcmp(buf, &w, 28), "'%ls': wrong bytes", rows[i].s);
    }
}

TEST(s2a_ipv6_more_rejections_wship6) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    static const WCHAR *bad[] = { L"fe80::1%abc", L"fe80::1%eth0", L"::ffff:1.2.3", L"::1%4294967296", L"%5", L"::1%", L"[::1]:80:90", L"[::1] :80", L" ::1", L"::1 ",
        L"::FFFF:A.B.C.D", L"::2:3:4:5:6:7:8", L"1:2:3:4:5:6:7:8::", L"12345::1", L"[::1]:+80", L"[::1]:080", L"[::1]:65536", L"[]", L"[]:80", L"::1%5:80", L"::1.2.3.4.5" };
    BYTE buf[64]; DWORD len;
    for (size_t i = 0; i < ANC_N(bad); i++) { len = 40; INT r = s2a_rc(&h, bad[i], 23, buf, &len); CHECKF(r == E_INVAL, "'%ls': rc %d", bad[i], r); }
}

/* ---- Bluetooth parser: the port suffix is accepted and discarded ---- */
TEST(s2a_bluetooth_port_suffix_is_discarded_wshbth) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    anc_sockaddr_bth w; memset(&w, 0, sizeof w); w.family = 32; w.bt_addr = 0x112233445566ULL;
    static const WCHAR *same[] = { L"(11:22:33:44:55:66):5", L"(11:22:33:44:55:66):", L"(11:22:33:44:55:66):70000", L"(11:22:33:44:55:66):-1" };
    for (size_t i = 0; i < ANC_N(same); i++) {
        BYTE buf[64]; DWORD len = 40; memset(buf, ANC_FILL, sizeof buf);
        INT r = s2a_rc(&h, same[i], 32, buf, &len);
        CHECKF(r == 0 && len == 30 && !memcmp(buf, &w, 30), "'%ls': rc %d len %lu", same[i], r, len);
    }
    /* a group may be one digit */
    w.bt_addr = 0x010203040506ULL;
    BYTE buf[64]; DWORD len = 40; memset(buf, ANC_FILL, sizeof buf);
    CHECK(s2a_rc(&h, L"(1:2:3:4:5:6)", 32, buf, &len) == 0 && len == 30 && !memcmp(buf, &w, 30));
    len = 40; CHECK(s2a_rc(&h, L"( 11:22:33:44:55:66)", 32, buf, &len) == E_INVAL);
}

/* ---- address classes: the whole loopback block, special IPv6 forms ---- */
static void cls(const anc_wsh *h, const void *sa, DWORD len, DWORD a, DWORD p, const char *what) {
    anc_sockaddr_info o = { ANC_SENT, ANC_SENT };
    INT r = h->GetSockaddrType((PSOCKADDR)sa, len, &o);
    CHECKF(r == 0 && o.AddressInfo == a && o.EndpointInfo == p, "%s: rc %d class %lu/%lu want %lu/%lu", what, r, o.AddressInfo, o.EndpointInfo, a, p);
}

TEST(sat_v4_loopback_block_and_neighbours) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    static const struct { BYTE a[4]; DWORD cls; const char *n; } rows[] = {
        { { 127, 0, 0, 1 }, ADDR_LOOPBACK, "127.0.0.1" }, { { 127, 0, 0, 2 }, ADDR_LOOPBACK, "127.0.0.2" }, { { 127, 255, 255, 255 }, ADDR_LOOPBACK, "127.255.255.255" },
        { { 127, 0, 0, 0 }, ADDR_LOOPBACK, "127.0.0.0" }, { { 127, 1, 2, 3 }, ADDR_LOOPBACK, "127.1.2.3" },
        { { 126, 255, 255, 255 }, ADDR_NORMAL, "126.255.255.255" }, { { 128, 0, 0, 0 }, ADDR_NORMAL, "128.0.0.0" }, { { 0, 0, 0, 127 }, ADDR_NORMAL, "0.0.0.127" },
        { { 0, 0, 0, 1 }, ADDR_NORMAL, "0.0.0.1" }, { { 224, 0, 0, 1 }, ADDR_NORMAL, "224.0.0.1" }, { { 239, 255, 255, 255 }, ADDR_NORMAL, "239.255.255.255" },
        { { 240, 0, 0, 1 }, ADDR_NORMAL, "240.0.0.1" }, { { 255, 255, 255, 254 }, ADDR_NORMAL, "255.255.255.254" }, { { 255, 0, 0, 0 }, ADDR_NORMAL, "255.0.0.0" },
        { { 169, 254, 0, 1 }, ADDR_NORMAL, "169.254.0.1" }, { { 192, 168, 255, 255 }, ADDR_NORMAL, "192.168.255.255" }, { { 10, 0, 0, 1 }, ADDR_NORMAL, "10.0.0.1" } };
    for (size_t i = 0; i < ANC_N(rows); i++) { SOCKADDR_IN a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; memcpy(&a.sin_addr, rows[i].a, 4); a.sin_port = htons(5000); cls(&h, &a, 16, rows[i].cls, PORT_NORMAL, rows[i].n); }
}

TEST(sat_v4_port_boundaries) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    static const struct { unsigned p; DWORD c; } rows[] = { { 0, PORT_WILDCARD }, { 1, PORT_RESERVED }, { 255, PORT_RESERVED }, { 256, PORT_RESERVED }, { 1023, PORT_RESERVED },
        { 1024, PORT_RESERVED }, { 1999, PORT_RESERVED }, { 2000, PORT_NORMAL }, { 49151, PORT_NORMAL }, { 49152, PORT_NORMAL }, { 65535, PORT_NORMAL } };
    for (size_t i = 0; i < ANC_N(rows); i++) { SOCKADDR_IN a = m4(0, rows[i].p); char w[24]; sprintf(w, "port %u", rows[i].p); cls(&h, &a, 16, ADDR_WILDCARD, rows[i].c, w); }
}

TEST(sat_v6_special_forms_are_ordinary_addresses) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    BYTE rows[][16] = {
        { 0xff, 1 }, { 0xfe, 0xc0 }, { 0xfe, 0x80, [15] = 1 }, { 0x20, 0x01 }, { [10] = 0xff, [11] = 0xff }, { [10] = 0xff, [11] = 0xff, 127, 0, 0, 1 },
        { [14] = 1 }, { [0] = 1, [15] = 1 }, { 0xff, 2, [15] = 1 }, { [10] = 0xff, [11] = 0xff, 255, 255, 255, 255 }, { [10] = 0xff, [11] = 0xff, 0, 0, 0, 0 } };
    for (size_t i = 0; i < ANC_N(rows); i++) { SOCKADDR_IN6 a = m6(rows[i], 5000, 0); char w[16]; sprintf(w, "form %zu", i); cls(&h, &a, 28, ADDR_NORMAL, PORT_NORMAL, w); }
    /* only the all-zero address is the wildcard and only ::1 is loopback, whatever the port */
    BYTE z[16] = { 0 }, l[16] = { 0 }; l[15] = 1; SOCKADDR_IN6 a;
    a = m6(z, 49152, 0); cls(&h, &a, 28, ADDR_WILDCARD, PORT_NORMAL, ":: high port");
    a = m6(l, 1, 0);     cls(&h, &a, 28, ADDR_LOOPBACK, PORT_RESERVED, "::1 low port");
}
