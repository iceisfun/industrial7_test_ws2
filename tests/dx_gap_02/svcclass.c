/* Registration and removal of a service class under a throwaway id, through WSAInstallServiceClassW/A,
 * WSAGetServiceClassInfoW and WSARemoveServiceClass.
 * Measures: which name spaces accept a class registration, what a refused registration reports, that a
 * refusal leaves nothing behind, and, where a registration is accepted, that the class can be read back
 * from exactly the providers that hold it and is gone after removal.
 * The tests may change the persistent service-class store, so they run only when elevated, use ids owned
 * by this corpus, and remove the class before and after every test. */
#include "dx2.h"

const GUID dx2_class_a = { 0x5d2c9a71, 0x0b3e, 0x4c58, { 0x8f, 0x14, 0xa6, 0x3d, 0x70, 0xe2, 0x19, 0x41 } };
const GUID dx2_class_b = { 0x5d2c9a71, 0x0b3e, 0x4c58, { 0x8f, 0x14, 0xa6, 0x3d, 0x70, 0xe2, 0x19, 0x42 } };

int dx2_up(void) {
    static int state;
    if (!state) {
        WSADATA d;
        state = WS(WSAStartup) && WS(WSAStartup)(MAKEWORD(2, 2), &d) == 0 ? 1 : -1;
    }
    return state == 1;
}

int dx2_elevated(void) {
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD got = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &got)) r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

void dx2_sweep(void) {
    GUID a = dx2_class_a, b = dx2_class_b;
    if (!WS(WSARemoveServiceClass)) return;
    WS(WSARemoveServiceClass)(&a);
    WS(WSARemoveServiceClass)(&b);
}

int dx2_install(const GUID *id, const WCHAR *name, DWORD ns, DWORD value) {
    WSASERVICECLASSINFOW sc; WSANSCLASSINFOW ci; static WCHAR vname[] = L"ws2tValue"; DWORD v = value;
    WCHAR nm[64];
    lstrcpynW(nm, name, 64);
    memset(&ci, 0, sizeof ci); memset(&sc, 0, sizeof sc);
    ci.lpszName = vname; ci.dwNameSpace = ns; ci.dwValueType = REG_DWORD; ci.dwValueSize = sizeof v; ci.lpValue = &v;
    sc.lpServiceClassId = (GUID *)id; sc.lpszServiceClassName = nm; sc.dwCount = 1; sc.lpClassInfos = &ci;
    W_SETERR(0);
    if (WS(WSAInstallServiceClassW)(&sc) == 0) return 0;
    return W_ERR();
}

#define SETUP() do { DX2_NEED(); DX2_ELEVATED(); if (!WS(WSAInstallServiceClassW) || !WS(WSARemoveServiceClass)) { t_skip("missing export"); return; } dx2_sweep(); } while (0)

/* Number of catalog providers that hand the class back (zeroed output buffer, as the provider contract wants). */
static int holders(const GUID *id, WSASERVICECLASSINFOW **first_out, BYTE *keep, DWORD keep_len) {
    DWORD len = 0; WSANAMESPACE_INFOW *cat; int n, i, hits = 0;
    WS(WSAEnumNameSpaceProvidersW)(&len, NULL);
    cat = (WSANAMESPACE_INFOW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len ? len : 1);
    n = WS(WSAEnumNameSpaceProvidersW)(&len, cat);
    for (i = 0; i < n; i++) {
        BYTE out[0x400] = { 0 }; DWORD l = sizeof out; GUID cls = *id;
        if (WS(WSAGetServiceClassInfoW)(&cat[i].NSProviderId, &cls, &l, (LPWSASERVICECLASSINFOW)out) == 0) {
            if (!hits && keep && l <= keep_len) { memcpy(keep, out, l); if (first_out) *first_out = (WSASERVICECLASSINFOW *)keep; }
            hits++;
        }
    }
    HeapFree(GetProcessHeap(), 0, cat);
    return hits;
}

/* Registration with the "all name spaces" selector: whatever the outcome, it must leave the store consistent. */
TEST(gap2dx_class_install_all_namespaces_outcome_is_consistent) {
    GUID id = dx2_class_a; int e;
    SETUP();
    e = dx2_install(&id, L"ws2t-dx-class-a", NS_ALL, 7);
    if (e) {
        EXPECT_EQ(holders(&id, NULL, NULL, 0), 0);          /* a refusal registered nothing anywhere */
        t_note("registration of a class for all name spaces refused");
    } else {
        CHECK(holders(&id, NULL, NULL, 0) >= 1);
    }
    dx2_sweep();
    EXPECT_EQ(holders(&id, NULL, NULL, 0), 0);               /* and the sweep removes it everywhere */
}

/* The DNS provider cannot hold classes; registering a class for its name space is refused. */
TEST(gap2dx_class_install_dns_namespace_refused) {
    GUID id = dx2_class_a, pid;
    int e, n = 0, i; WSANAMESPACE_INFOW *cat = NULL; DWORD len = 0;
    SETUP();
    WS(WSAEnumNameSpaceProvidersW)(&len, NULL);
    cat = (WSANAMESPACE_INFOW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len ? len : 1);
    n = WS(WSAEnumNameSpaceProvidersW)(&len, cat);
    for (i = 0, e = -1; i < n; i++) if (cat[i].dwNameSpace == NS_DNS && cat[i].fActive) { pid = cat[i].NSProviderId; e = 0; }
    HeapFree(GetProcessHeap(), 0, cat);
    if (e) { t_skip("no DNS provider"); return; }
    e = dx2_install(&id, L"ws2t-dx-class-a", NS_DNS, 7);
    if (e == 0) { t_note("DNS class registration unexpectedly accepted"); dx2_sweep(); CHECK(0); return; }
    EXPECT_EQ(e, 87);   /* ERROR_INVALID_PARAMETER: the registration call refuses a class for this name space */
    dx2_sweep();
}

TEST(gap2dx_class_install_ansi_refusal_leaves_nothing) {
    GUID id = dx2_class_a; WSASERVICECLASSINFOA sc; WSANSCLASSINFOA ci; static char cname[] = "ws2t-dx-class-a", vname[] = "ws2tValue";
    DWORD v = 5; int r;
    SETUP();
    memset(&ci, 0, sizeof ci); memset(&sc, 0, sizeof sc);
    ci.lpszName = vname; ci.dwNameSpace = NS_ALL; ci.dwValueType = REG_DWORD; ci.dwValueSize = sizeof v; ci.lpValue = &v;
    sc.lpServiceClassId = &id; sc.lpszServiceClassName = cname; sc.dwCount = 1; sc.lpClassInfos = &ci;
    W_SETERR(0);
    r = WS(WSAInstallServiceClassA)(&sc);
    if (r != 0) EXPECT_EQ(holders(&id, NULL, NULL, 0), 0);
    else CHECK(holders(&id, NULL, NULL, 0) >= 1);
    dx2_sweep();
    EXPECT_EQ(holders(&id, NULL, NULL, 0), 0);
}

TEST(gap2dx_class_roundtrip_when_accepted) {
    GUID id = dx2_class_a; int e; BYTE keep[0x400]; WSASERVICECLASSINFOW *sc = NULL;
    SETUP();
    e = dx2_install(&id, L"ws2t-dx-class-a", NS_ALL, 7);
    if (e) { t_skip("registration refused (%d)", e); return; }
    CHECK(holders(&id, &sc, keep, sizeof keep) >= 1);
    if (sc) {
        EXPECT_EQ(memcmp(sc->lpServiceClassId, &id, sizeof id), 0);
        EXPECT_EQ(wcscmp(sc->lpszServiceClassName, L"ws2t-dx-class-a"), 0);
        EXPECT_EQ(sc->dwCount, 1);
    }
    dx2_sweep();
}

TEST(gap2dx_class_remove_twice_second_fails_when_accepted) {
    GUID id = dx2_class_a; int e;
    SETUP();
    e = dx2_install(&id, L"ws2t-dx-class-a", NS_ALL, 7);
    if (e) { t_skip("registration refused (%d)", e); return; }
    W_SETERR(0);
    EXPECT_EQ(WS(WSARemoveServiceClass)(&id), 0);
    W_SETERR(0);
    EXPECT_EQ(WS(WSARemoveServiceClass)(&id), SOCKET_ERROR);
    EXPECT_EQ(holders(&id, NULL, NULL, 0), 0);
}

TEST(gap2dx_class_remove_unknown_id_fails) {
    GUID id = dx2_class_b;
    SETUP();
    W_SETERR(0);
    EXPECT_EQ(WS(WSARemoveServiceClass)(&id), SOCKET_ERROR);
    t_note("removal of an id never installed: error %d", W_ERR());
}

TEST(gap2dx_class_two_classes_do_not_interfere_when_accepted) {
    GUID a = dx2_class_a, b = dx2_class_b; int e1, e2;
    SETUP();
    e1 = dx2_install(&a, L"ws2t-dx-class-a", NS_ALL, 1);
    e2 = dx2_install(&b, L"ws2t-dx-class-b", NS_ALL, 2);
    if (e1 || e2) { t_skip("registration refused (%d, %d)", e1, e2); dx2_sweep(); return; }
    WS(WSARemoveServiceClass)(&a);
    EXPECT_EQ(holders(&a, NULL, NULL, 0), 0);
    CHECK(holders(&b, NULL, NULL, 0) >= 1);
    dx2_sweep();
}
