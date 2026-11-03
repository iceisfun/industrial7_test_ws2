/* Module and export inventory of the ancillary Winsock modules: the three helper DLLs (wshtcpip, wship6, wshbth),
 * the name-space providers (winrnr, napinsp, pnrpnsp, nlaapi), the autodial helper (rasadhlp) and the legacy
 * wsock32 front. Each module is loaded read-only; a module that is absent is a conditional skip.
 * Measures: which names every module exports (and which it does not), and that the export tables resolve to
 * distinct code addresses where the contract says they are different entry points. */
#include "anc.h"

typedef struct { const char *dll; const char *const *names; size_t n; } modtab;

static const char *const x_wshtcpip[] = { "WSHOpenSocket", "WSHOpenSocket2", "WSHGetSockaddrType", "WSHGetWildcardSockaddr",
    "WSHGetBroadcastSockaddr", "WSHGetSocketInformation", "WSHSetSocketInformation", "WSHEnumProtocols", "WSHNotify",
    "WSHGetProviderGuid", "WSHAddressToString", "WSHStringToAddress", "WSHIoctl", "WSHJoinLeaf", "WSHGetWinsockMapping",
    "WSHGetWSAProtocolInfo" };
static const char *const x_wship6[] = { "WSHOpenSocket", "WSHOpenSocket2", "WSHGetSockaddrType", "WSHGetWildcardSockaddr",
    "WSHGetSocketInformation", "WSHSetSocketInformation", "WSHEnumProtocols", "WSHNotify", "WSHGetProviderGuid",
    "WSHAddressToString", "WSHStringToAddress", "WSHIoctl", "WSHJoinLeaf", "WSHGetWinsockMapping", "WSHGetWSAProtocolInfo" };
static const char *const x_wshbth[] = { "WSHOpenSocket", "WSHOpenSocket2", "WSHGetSockaddrType", "WSHGetWildcardSockaddr",
    "WSHGetBroadcastSockaddr", "WSHGetSocketInformation", "WSHSetSocketInformation", "WSHEnumProtocols", "WSHNotify",
    "WSHGetProviderGuid", "WSHAddressToString", "WSHStringToAddress", "WSHIoctl", "WSHJoinLeaf", "WSHGetWinsockMapping",
    "WSHGetWSAProtocolInfo", "NSPStartup" };
static const char *const x_winrnr[] = { "NSPStartup", "InstallNTDSProvider", "RemoveNTDSProvider" };
static const char *const x_napinsp[] = { "NSPStartup", "DllMain" };
static const char *const x_pnrpnsp[] = { "NSPStartup" };
static const char *const x_nlaapi[] = { "LANIdFreeCollection", "LANIdRetrieveCollection", "NSPStartup", "NlaAddToPluginRequests",
    "NlaAddToTypeSet", "NlaAnd", "NlaCloseQuery", "NlaComposeNetSignature", "NlaCreateFilter", "NlaCreatePluginRequests",
    "NlaCreateTypeSet", "NlaDecomposeNetSignature", "NlaDeleteDataSet", "NlaDeleteFilter", "NlaDeletePluginRequests",
    "NlaDeleteTypeSet", "NlaEqual", "NlaEqualNetSignatures", "NlaGetCaptivePortalHosts", "NlaGetInternetCapability",
    "NlaGetIntranetCapability", "NlaIndicateReprobe", "NlaNotEqual", "NlaOpenQuery", "NlaOr", "NlaQueryNetData",
    "NlaQueryNetDataEx", "NlaQueryNetSignatures", "NlaRefreshQuery", "NlaRegisterQuery" };
static const char *const x_rasadhlp[] = { "AcsHlpNbConnection", "WSAttemptAutodialAddr", "WSAttemptAutodialName", "WSNoteSuccessfulHostentLookup" };

#define MT(d, a) { d, a, ANC_N(a) }
static const modtab tabs[] = { MT("wshtcpip.dll", x_wshtcpip), MT("wship6.dll", x_wship6), MT("wshbth.dll", x_wshbth),
    MT("winrnr.dll", x_winrnr), MT("napinsp.dll", x_napinsp), MT("pnrpnsp.dll", x_pnrpnsp), MT("nlaapi.dll", x_nlaapi),
    MT("rasadhlp.dll", x_rasadhlp) };

static void check_exports(const modtab *m) {
    HMODULE h = t_module(m->dll);
    if (!h) { t_skip("%s is not present on this system", m->dll); return; }
    for (size_t i = 0; i < m->n; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(h, m->names[i]) != NULL, "%s does not export %s", m->dll, m->names[i]);
    }
}

TEST(mod_wshtcpip_exports) { check_exports(&tabs[0]); }
TEST(mod_wship6_exports) { check_exports(&tabs[1]); }
TEST(mod_wshbth_exports) { check_exports(&tabs[2]); }
TEST(mod_winrnr_exports) { check_exports(&tabs[3]); }
TEST(mod_napinsp_exports) { check_exports(&tabs[4]); }
TEST(mod_pnrpnsp_exports) { check_exports(&tabs[5]); }
TEST(mod_nlaapi_exports) { check_exports(&tabs[6]); }
TEST(mod_rasadhlp_exports) { check_exports(&tabs[7]); }

/* Names that a module does not export must fail with ERROR_PROC_NOT_FOUND. */
static const struct { const char *dll, *name; } absent[] = {
    { "wship6.dll", "WSHGetBroadcastSockaddr" },      /* IPv6 has no broadcast */
    { "wship6.dll", "NSPStartup" }, { "wshtcpip.dll", "NSPStartup" },
    { "wshtcpip.dll", "WSHGetBroadcastSockaddr_" }, { "wshbth.dll", "WSHJoinLeaf2" },
    { "winrnr.dll", "WSHOpenSocket2" }, { "napinsp.dll", "NSPCleanup" }, { "pnrpnsp.dll", "NSPCleanup" },
    { "nlaapi.dll", "NlaOpenQuery2" }, { "nlaapi.dll", "WSHOpenSocket" }, { "rasadhlp.dll", "WSAttemptAutodial" },
    { "rasadhlp.dll", "NSPStartup" }, { "wshbth.dll", "NlaAnd" }, { "napinsp.dll", "WSHOpenSocket2" },
};
TEST(mod_absent_names_fail_with_proc_not_found) {
    for (size_t i = 0; i < ANC_N(absent); i++) {
        HMODULE h = t_module(absent[i].dll);
        if (!h) { t_note("%s absent, row skipped", absent[i].dll); continue; }
        SET_ERR(0);
        CHECKF(GetProcAddress(h, absent[i].name) == NULL, "%s!%s unexpectedly exported", absent[i].dll, absent[i].name);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}

/* In the helper DLLs the two open entry points are distinct functions; same for the two enumeration styles. */
static void distinct_entries(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    FARPROC p[] = { (FARPROC)h.OpenSocket, (FARPROC)h.OpenSocket2, (FARPROC)h.GetSockaddrType, (FARPROC)h.GetWildcardSockaddr,
        (FARPROC)h.GetSocketInformation, (FARPROC)h.SetSocketInformation, (FARPROC)h.EnumProtocols, (FARPROC)h.Notify,
        (FARPROC)h.GetProviderGuid, (FARPROC)h.AddressToString, (FARPROC)h.StringToAddress, (FARPROC)h.GetWinsockMapping };
    for (size_t i = 0; i < ANC_N(p); i++) {
        CHECKF(p[i] != NULL, "%s: export %zu missing", hi->dll, i);
        for (size_t j = i + 1; j < ANC_N(p); j++) CHECKF(p[i] != p[j] || p[i] == NULL, "%s: exports %zu and %zu are one entry", hi->dll, i, j);
    }
    /* every resolved address lies inside the module image */
    for (size_t i = 0; i < ANC_N(p); i++) CHECK((BYTE *)p[i] > (BYTE *)h.mod && (BYTE *)p[i] < (BYTE *)h.mod + 0x100000);
}
H3(mod_entries_distinct, distinct_entries)

/* The optional broadcast entry exists in the IPv4 and Bluetooth helpers only. */
TEST(mod_broadcast_entry_by_helper) {
    anc_wsh t, v, b;
    int have_t = anc_load_wsh(&t, "wshtcpip.dll"), have_v = anc_load_wsh(&v, "wship6.dll"), have_b = anc_load_wsh(&b, "wshbth.dll");
    if (have_t) CHECK(t.GetBroadcastSockaddr != NULL);
    if (have_v) CHECK(v.GetBroadcastSockaddr == NULL);
    if (have_b) CHECK(b.GetBroadcastSockaddr != NULL);
    if (!have_t && !have_v && !have_b) t_skip("no helper DLL present");
}

/* wsock32 exports: the 75 documented names (71 of them forward to ws2_32). */
static const char *const wsock32_names[] = {
 "AcceptEx", "EnumProtocolsA", "EnumProtocolsW", "GetAcceptExSockaddrs", "GetAddressByNameA", "GetAddressByNameW", "GetNameByTypeA",
 "GetNameByTypeW", "GetServiceA", "GetServiceW", "GetTypeByNameA", "GetTypeByNameW", "MigrateWinsockConfiguration", "NPLoadNameSpaces",
 "SetServiceA", "SetServiceW", "TransmitFile", "WEP", "WSAAsyncGetHostByAddr", "WSAAsyncGetHostByName", "WSAAsyncGetProtoByName",
 "WSAAsyncGetProtoByNumber", "WSAAsyncGetServByName", "WSAAsyncGetServByPort", "WSAAsyncSelect", "WSACancelAsyncRequest",
 "WSACancelBlockingCall", "WSACleanup", "WSAGetLastError", "WSAIsBlocking", "WSARecvEx", "WSASetBlockingHook", "WSASetLastError",
 "WSAStartup", "WSAUnhookBlockingHook", "WSApSetPostRoutine", "__WSAFDIsSet", "accept", "bind", "closesocket", "connect", "dn_expand",
 "gethostbyaddr", "gethostbyname", "gethostname", "getnetbyname", "getpeername", "getprotobyname", "getprotobynumber", "getservbyname",
 "getservbyport", "getsockname", "getsockopt", "htonl", "htons", "inet_addr", "inet_network", "inet_ntoa", "ioctlsocket", "listen",
 "ntohl", "ntohs", "rcmd", "recv", "recvfrom", "rexec", "rresvport", "s_perror", "select", "send", "sendto", "sethostname",
 "setsockopt", "shutdown", "socket" };
TEST(mod_wsock32_export_names) {
    HMODULE h = t_module("wsock32.dll");
    if (!h) { t_skip("wsock32.dll is not present"); return; }
    for (size_t i = 0; i < ANC_N(wsock32_names); i++) CHECKF(GetProcAddress(h, wsock32_names[i]) != NULL, "wsock32 lacks %s", wsock32_names[i]);
    CHECK(ANC_N(wsock32_names) == 75);
}
TEST(mod_wsock32_does_not_export_ws2_only_names) {
    static const char *const no[] = { "WSASocketW", "WSAIoctl", "getaddrinfo", "WSAPoll", "WSAEnumProtocolsW", "inet_ntop", "freeaddrinfo", "WSASend" };
    HMODULE h = t_module("wsock32.dll");
    if (!h) { t_skip("wsock32.dll is not present"); return; }
    for (size_t i = 0; i < ANC_N(no); i++) { SET_ERR(0); CHECKF(GetProcAddress(h, no[i]) == NULL, "wsock32 exports %s", no[i]); EXPECT_ERR(ERROR_PROC_NOT_FOUND); }
}
