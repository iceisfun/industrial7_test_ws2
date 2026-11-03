/* wsock32.dll export table, read both through GetProcAddress and straight out of the loaded image.
 *
 * Measures, for each of the 75 named exports: that it resolves by name, that the ordinal slot of the
 * export directory names the documented ordinal and that GetProcAddress by ordinal returns the same code
 * address, and where it lands: 71 entries are forwarders (to ws2_32 or mswsock; the directory entry holds a
 * "module.name" string and the resolved address equals the target module's export), while getsockopt,
 * recv, recvfrom and setsockopt are implemented inside wsock32 itself. It also pins the directory shape
 * (base, name count, sorted names, no stray exports) and that ws2_32-only names are absent. */
#include "wf.h"
#include "wf_table.h"

typedef struct {
    const BYTE *base;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_EXPORT_DIRECTORY *dir;
    DWORD dir_rva, dir_size;
} pe_t;

static int pe_open(pe_t *p, const char *dll) {
    HMODULE m = t_module(dll);
    const IMAGE_DOS_HEADER *dos;
    if (!m) return 0;
    p->base = (const BYTE *)m;
    dos = (const IMAGE_DOS_HEADER *)p->base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    p->nt = (const IMAGE_NT_HEADERS64 *)(p->base + dos->e_lfanew);
    if (p->nt->Signature != IMAGE_NT_SIGNATURE || p->nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
    p->dir_rva  = p->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    p->dir_size = p->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!p->dir_rva) return 0;
    p->dir = (const IMAGE_EXPORT_DIRECTORY *)(p->base + p->dir_rva);
    return 1;
}

#define PE_NAMES(p)  ((const DWORD *)((p)->base + (p)->dir->AddressOfNames))
#define PE_ORDS(p)   ((const WORD *)((p)->base + (p)->dir->AddressOfNameOrdinals))
#define PE_FUNCS(p)  ((const DWORD *)((p)->base + (p)->dir->AddressOfFunctions))

/* Find a name in the directory; fills the ordinal (with base applied) and the raw function RVA. */
static int pe_find(const pe_t *p, const char *name, unsigned *ord, DWORD *rva) {
    DWORD i;
    for (i = 0; i < p->dir->NumberOfNames; i++) {
        if (!strcmp((const char *)(p->base + PE_NAMES(p)[i]), name)) {
            unsigned idx = PE_ORDS(p)[i];
            *ord = idx + p->dir->Base;
            *rva = PE_FUNCS(p)[idx];
            return 1;
        }
    }
    return 0;
}
static int pe_is_fwd(const pe_t *p, DWORD rva) { return rva >= p->dir_rva && rva < p->dir_rva + p->dir_size; }

static int in_table(unsigned ord) {
#define X(n, o, fm, fn) if ((unsigned)(o) == ord) return 1;
    WF_EXPORTS(X)
#undef X
    return 0;
}

/* ----- per-export checks -------------------------------------------------------------------------------- */
static void chk_by_name(const char *n) {
    HMODULE m = t_module("wsock32.dll");
    REQUIRE(m);
    SET_ERR(0);
    CHECK(GetProcAddress(m, n) != NULL);
}
static void chk_ordinal(const char *n, unsigned ord) {
    pe_t p; unsigned o = 0; DWORD rva = 0; FARPROC byn, byo;
    HMODULE m = t_module("wsock32.dll");
    REQUIRE(m);
    if (!pe_open(&p, "wsock32.dll")) { CHECK(0); return; }
    CHECK(pe_find(&p, n, &o, &rva));
    WEQ(o, ord);
    byn = GetProcAddress(m, n);
    byo = GetProcAddress(m, (LPCSTR)(ULONG_PTR)ord);
    CHECK(byn != NULL);
    CHECK(byo == byn);
}
static void chk_target(const char *n, const char *fm, const char *fn) {
    pe_t p; unsigned o = 0; DWORD rva = 0; HMODULE m = t_module("wsock32.dll"); FARPROC mine;
    REQUIRE(m);
    if (!pe_open(&p, "wsock32.dll") || !pe_find(&p, n, &o, &rva)) { CHECK(0); return; }
    mine = GetProcAddress(m, n);
    if (fm) {
        char want[96];
        FARPROC tgt;
        CHECK(pe_is_fwd(&p, rva));
        if (pe_is_fwd(&p, rva)) {
            snprintf(want, sizeof want, "%s.%s", fm, fn);
            CHECKF(!lstrcmpiA((const char *)(p.base + rva), want), "forwarder string \"%s\"", (const char *)(p.base + rva));
        }
        tgt = t_proc_in(fm, fn);
        CHECK(tgt != NULL);
        CHECK(mine == tgt);
        /* a forwarder's resolved address is never inside wsock32 itself */
        CHECK((const BYTE *)mine < p.base || (const BYTE *)mine >= p.base + p.nt->OptionalHeader.SizeOfImage);
    } else {
        FARPROC other = t_proc_in("ws2_32.dll", n);
        const BYTE *a = (const BYTE *)mine;
        WORD i; int exec = 0;
        const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(p.nt);
        CHECK(!pe_is_fwd(&p, rva));
        CHECK(a == p.base + rva);
        for (i = 0; i < p.nt->FileHeader.NumberOfSections; i++)
            if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
                exec = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        CHECK(exec);
        CHECK(other != NULL);          /* ws2_32 has a function of that name... */
        CHECK(other != mine);          /* ...but wsock32 does not forward to it */
    }
}

#define X(n, o, fm, fn) \
    TEST(wsock32_exp_##n##_by_name) { chk_by_name(#n); } \
    TEST(wsock32_exp_##n##_ordinal) { chk_ordinal(#n, o); } \
    TEST(wsock32_exp_##n##_target) { chk_target(#n, fm, fn); }
WF_EXPORTS(X)
#undef X

/* ----- directory shape ---------------------------------------------------------------------------------- */
TEST(wsock32_dir_basic_shape) {
    pe_t p;
    CHECK(pe_open(&p, "wsock32.dll"));
    if (!p.dir) return;
    WEQ(p.nt->FileHeader.Machine, IMAGE_FILE_MACHINE_AMD64);
    CHECK(p.nt->FileHeader.Characteristics & IMAGE_FILE_DLL);
    WEQ(p.dir->Base, 1);
    WEQ(p.dir->NumberOfNames, 75);
    WEQ(p.dir->NumberOfFunctions, 1142);
}
TEST(wsock32_dir_module_name) {
    pe_t p;
    if (!pe_open(&p, "wsock32.dll")) { CHECK(0); return; }
    CHECK(!lstrcmpiA((const char *)(p.base + p.dir->Name), "wsock32.dll"));
}
TEST(wsock32_dir_names_sorted_ascending) {
    pe_t p; DWORD i; int bad = 0;
    if (!pe_open(&p, "wsock32.dll")) { CHECK(0); return; }
    for (i = 1; i < p.dir->NumberOfNames; i++)
        if (strcmp((const char *)(p.base + PE_NAMES(&p)[i - 1]), (const char *)(p.base + PE_NAMES(&p)[i])) >= 0) bad++;
    WEQ(bad, 0);
}
TEST(wsock32_dir_forwarder_count) {
    pe_t p; DWORD i; int fwd = 0, own = 0;
    if (!pe_open(&p, "wsock32.dll")) { CHECK(0); return; }
    for (i = 0; i < p.dir->NumberOfFunctions; i++) {
        DWORD r = PE_FUNCS(&p)[i];
        if (!r) continue;
        if (pe_is_fwd(&p, r)) fwd++; else own++;
    }
    WEQ(fwd, 71);
    WEQ(own, 4);
}
TEST(wsock32_dir_no_unnamed_exports) {
    /* every populated slot of the function table has a name: 75 populated slots == 75 names */
    pe_t p; DWORD i; int populated = 0;
    if (!pe_open(&p, "wsock32.dll")) { CHECK(0); return; }
    for (i = 0; i < p.dir->NumberOfFunctions; i++) if (PE_FUNCS(&p)[i]) populated++;
    WEQ(populated, p.dir->NumberOfNames);
}
TEST(wsock32_dir_forwarder_modules_only_two) {
    pe_t p; DWORD i; int ws2 = 0, msw = 0, other = 0;
    if (!pe_open(&p, "wsock32.dll")) { CHECK(0); return; }
    for (i = 0; i < p.dir->NumberOfFunctions; i++) {
        DWORD r = PE_FUNCS(&p)[i];
        const char *s;
        if (!r || !pe_is_fwd(&p, r)) continue;
        s = (const char *)(p.base + r);
        if (!_strnicmp(s, "ws2_32.", 7)) ws2++;
        else if (!_strnicmp(s, "mswsock.", 8)) msw++;
        else other++;
    }
    WEQ(other, 0);
    WEQ(ws2, 45);
    WEQ(msw, 26);
}

/* ----- lookups that must fail ---------------------------------------------------------------------------- */
TEST(wsock32_ordinal_gaps_do_not_resolve) {
    HMODULE m = t_module("wsock32.dll");
    unsigned o, bad = 0;
    REQUIRE(m);
    for (o = 1; o <= 1142; o++) {
        FARPROC f;
        if (in_table(o)) continue;
        f = GetProcAddress(m, (LPCSTR)(ULONG_PTR)o);
        if (f) bad++;
    }
    WEQ(bad, 0);
}
TEST(wsock32_every_listed_ordinal_resolves) {
    HMODULE m = t_module("wsock32.dll");
    unsigned o, bad = 0, seen = 0;
    REQUIRE(m);
    for (o = 1; o <= 1142; o++) {
        if (!in_table(o)) continue;
        seen++;
        if (!GetProcAddress(m, (LPCSTR)(ULONG_PTR)o)) bad++;
    }
    WEQ(seen, 75);
    WEQ(bad, 0);
}
TEST(wsock32_ordinal_zero_and_beyond_do_not_resolve) {
    HMODULE m = t_module("wsock32.dll");
    REQUIRE(m);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)0) == NULL);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)1143) == NULL);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)2000) == NULL);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)0xffff) == NULL);
}
TEST(wsock32_name_lookup_is_case_sensitive) {
    HMODULE m = t_module("wsock32.dll");
    static const char *bad[] = { "Accept", "ACCEPT", "wsastartup", "WSASTARTUP", "Closesocket", "ACCEPTEX", "inet_NTOA", "Htons" };
    unsigned i;
    REQUIRE(m);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(m, bad[i]) == NULL, "%s resolved", bad[i]);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}
TEST(wsock32_decorated_and_qualified_names_do_not_resolve) {
    HMODULE m = t_module("wsock32.dll");
    static const char *bad[] = { "_accept", "accept@12", "_accept@12", "ws2_32.accept", "wsock32.accept", "mswsock.AcceptEx", "?accept", "#1", "" };
    unsigned i;
    REQUIRE(m);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(m, bad[i]) == NULL, "'%s' resolved", bad[i]);
    }
}
TEST(wsock32_missing_name_sets_proc_not_found) {
    HMODULE m = t_module("wsock32.dll");
    REQUIRE(m);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "NoSuchWsock32Export") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(wsock32_missing_ordinal_error_code) {
    HMODULE m = t_module("wsock32.dll");
    REQUIRE(m);
    SET_ERR(0);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)25) == NULL);
    EXPECT_ERR(ERROR_INVALID_ORDINAL);
}

/* Names ws2_32 exports that wsock32 does not carry. */
static const char *const ws2_only[] = {
    "WSASocketA", "WSASocketW", "WSAConnect", "WSAAccept", "WSASend", "WSASendTo", "WSASendDisconnect", "WSARecv",
    "WSARecvFrom", "WSARecvDisconnect", "WSAIoctl", "WSAEventSelect", "WSACreateEvent", "WSACloseEvent", "WSASetEvent",
    "WSAResetEvent", "WSAWaitForMultipleEvents", "WSAEnumNetworkEvents", "WSAGetOverlappedResult", "WSADuplicateSocketA",
    "WSADuplicateSocketW", "WSAEnumProtocolsA", "WSAEnumProtocolsW", "WSAStringToAddressA", "WSAStringToAddressW",
    "WSAAddressToStringA", "WSAAddressToStringW", "getaddrinfo", "freeaddrinfo", "getnameinfo", "GetAddrInfoW",
    "FreeAddrInfoW", "GetNameInfoW", "InetPtonW", "InetNtopW", "inet_pton", "inet_ntop", "WSAHtons", "WSAHtonl",
    "WSANtohs", "WSANtohl", "WSAPoll", "WSALookupServiceBeginA", "WSALookupServiceBeginW", "WSALookupServiceNextA", "WSALookupServiceNextW",
    "WSALookupServiceEnd", "WSCEnumProtocols", "WSCGetProviderPath", "WSCInstallProvider", "WSCDeinstallProvider",
    "WSASetServiceA", "WSASetServiceW", "WSAInstallServiceClassA", "WSAInstallServiceClassW", "WSARemoveServiceClass",
    "WSAGetServiceClassInfoA", "WSAGetServiceClassInfoW", "WSAEnumNameSpaceProvidersA", "WSAEnumNameSpaceProvidersW",
    "WSAGetServiceClassNameByClassIdA", "WSAGetServiceClassNameByClassIdW", "WSAProviderConfigChange", "WSAJoinLeaf",
    "WSAGetQOSByName", "WSAAddressToStringW", "WSAConnectByNameA", "WSAConnectByNameW", "WSAConnectByList",
    "WSANSPIoctl", "WSAGetOverlappedResult", "WSAInstallServiceClassA", "WSCEnableNSProvider", "WSCWriteProviderOrder"
};
TEST(wsock32_ws2_only_names_absent) {
    HMODULE m = t_module("wsock32.dll");
    unsigned i, present = 0;
    REQUIRE(m);
    for (i = 0; i < sizeof ws2_only / sizeof ws2_only[0]; i++) {
        SET_ERR(0);
        if (GetProcAddress(m, ws2_only[i])) { present++; t_note("unexpected wsock32 export %s", ws2_only[i]); }
    }
    WEQ(present, 0);
}
TEST(wsock32_ws2_only_names_exist_in_ws2_32) {
    /* sanity of the list above: each is a real ws2_32 export, so the absence test means something */
    HMODULE m = t_module("ws2_32.dll");
    unsigned i, missing = 0;
    REQUIRE(m);
    for (i = 0; i < sizeof ws2_only / sizeof ws2_only[0]; i++) {
        if (!GetProcAddress(m, ws2_only[i])) { missing++; t_note("not in ws2_32: %s", ws2_only[i]); }
    }
    WEQ(missing, 0);
}
TEST(wsock32_mswsock_only_names_absent) {
    HMODULE m = t_module("wsock32.dll");
    static const char *bad[] = { "WSPStartup", "NSPStartup", "WSARecvMsg", "AcceptExW", "DisconnectEx", "ConnectEx",
                                 "TransmitPackets", "StartWsdpService", "SetServiceExA", "SetServiceExW", "GetServiceExA" };
    unsigned i;
    REQUIRE(m);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) CHECKF(GetProcAddress(m, bad[i]) == NULL, "%s resolved", bad[i]);
}
TEST(wsock32_wsa_prefixed_names_present_are_only_the_old_set) {
    pe_t p; DWORD i; unsigned wsa = 0;
    if (!pe_open(&p, "wsock32.dll")) { CHECK(0); return; }
    for (i = 0; i < p.dir->NumberOfNames; i++) {
        const char *s = (const char *)(p.base + PE_NAMES(&p)[i]);
        if (!strncmp(s, "WSA", 3) || !strncmp(s, "WSC", 3)) wsa++;
    }
    /* the old Winsock 1.1 set: async, blocking, last-error, startup/cleanup, plus WSARecvEx and the post routine */
    WEQ(wsa, 18);
}

/* ----- cross-module identity ----------------------------------------------------------------------------- */
TEST(wsock32_forwarders_not_equal_to_wrong_module) {
    /* a ws2_32 forwarder must not accidentally equal the mswsock one of the same name, and vice versa */
    FARPROC a = t_proc_in("wsock32.dll", "WSAStartup"), b = t_proc_in("mswsock.dll", "WSAStartup");
    CHECK(a != NULL);
    CHECK(b == NULL || a != b);
    CHECK(t_proc_in("wsock32.dll", "AcceptEx") != t_proc_in("ws2_32.dll", "WSAAccept"));
}
TEST(wsock32_acceptex_family_matches_mswsock_exports) {
    static const char *n[] = { "AcceptEx", "GetAcceptExSockaddrs", "TransmitFile" };
    unsigned i;
    for (i = 0; i < 3; i++) {
        FARPROC a = t_proc_in("wsock32.dll", n[i]), b = t_proc_in("mswsock.dll", n[i]);
        CHECKF(a != NULL && a == b, "%s", n[i]);
    }
}
TEST(wsock32_ws2_32_not_exporting_the_mswsock_legacy_names) {
    static const char *n[] = { "EnumProtocolsA", "EnumProtocolsW", "GetAddressByNameA", "GetAddressByNameW", "GetNameByTypeA",
                               "GetNameByTypeW", "GetTypeByNameA", "GetTypeByNameW", "GetServiceA", "GetServiceW",
                               "SetServiceA", "SetServiceW", "NPLoadNameSpaces", "inet_network", "getnetbyname", "rcmd",
                               "rexec", "rresvport", "sethostname", "dn_expand", "WSARecvEx", "s_perror",
                               "MigrateWinsockConfiguration", "TransmitFile", "AcceptEx", "GetAcceptExSockaddrs" };
    unsigned i, bad = 0;
    for (i = 0; i < sizeof n / sizeof n[0]; i++) if (t_proc_in("ws2_32.dll", n[i])) { bad++; t_note("ws2_32 exports %s", n[i]); }
    WEQ(bad, 0);
}
TEST(wsock32_mswsock_alias_exports_share_one_body) {
    /* rcmd, rexec and rresvport are three names for one function body in mswsock */
    FARPROC a = t_proc_in("wsock32.dll", "rcmd"), b = t_proc_in("wsock32.dll", "rexec"), c = t_proc_in("wsock32.dll", "rresvport");
    CHECK(a != NULL);
    CHECK(a == b);
    CHECK(b == c);
}
TEST(wsock32_distinct_stub_bodies) {
    FARPROC g = t_proc_in("wsock32.dll", "getnetbyname"), s = t_proc_in("wsock32.dll", "sethostname"), r = t_proc_in("wsock32.dll", "rcmd");
    CHECK(g && s && r);
    CHECK(g != s);
    CHECK(g != r);
    CHECK(s != r);
}

/* ----- loading behaviour (fresh process) ----------------------------------------------------------------- */
CHILD(wf_load_only_wsock32) {
    HMODULE m;
    if (GetModuleHandleA("wsock32.dll") != NULL) return 1;
    m = LoadLibraryA("wsock32.dll");
    if (!m) return 2;
    if (GetModuleHandleA("ws2_32.dll") == NULL) return 3;    /* wsock32 imports ws2_32 */
    if (!GetProcAddress(m, "accept")) return 4;
    if (GetModuleHandleA("ws2_32.dll") == NULL) return 5;
    if (GetProcAddress(m, "AcceptEx") == NULL) return 6;
    if (GetModuleHandleA("mswsock.dll") == NULL) return 7;   /* resolving a forwarder loads its target */
    FreeLibrary(m);
    return 0;
}
TEST(wsock32_load_pulls_in_ws2_32_and_forward_targets) { WF_RUN_CHILD("wf_load_only_wsock32", ""); }

CHILD(wf_load_no_startup_needed) {
    /* merely loading wsock32 and resolving everything does not start Winsock */
    HMODULE m = LoadLibraryA("wsock32.dll");
    int (WSAAPI *gle)(void);
    if (!m) return 1;
    gle = (int (WSAAPI *)(void))GetProcAddress(m, "WSAGetLastError");
    if (!gle) return 2;
    if (gle() != 0) return 3;
    return 0;
}
TEST(wsock32_load_leaves_wsa_error_clear) { WF_RUN_CHILD("wf_load_no_startup_needed", ""); }

TEST(wsock32_same_module_handle_each_time) {
    HMODULE a = LoadLibraryA("wsock32.dll"), b = LoadLibraryA("WSOCK32.DLL"), c = GetModuleHandleA("wsock32");
    CHECK(a != NULL);
    CHECK(a == b);
    CHECK(a == c);
    FreeLibrary(a); FreeLibrary(b);
}
