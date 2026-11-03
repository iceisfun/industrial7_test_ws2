/* Calls made in a process that never ran WSAStartup, for the name-space, address-info and connection
 * exports of this area. Each row runs in a fresh child process (no start-up has happened there) and
 * checks the return value, the error the call leaves behind, and whether the argument checks that precede
 * the per-process initialisation happen first or second.
 * Why the expectations hold: the exports consult the per-process start-up state before touching their
 * arguments, except where noted (the service-class getter, the service-registration entry points and the
 * ANSI lookup-begin entry point look at their arguments first). */
#include "g2.h"

static struct { const char *name; int (*fn)(void); } g_rows[64];
static int g_nrows;

CHILD(g2pre) {
    int i;
    if (argc < 2) return 99;
    for (i = 0; i < g_nrows; i++)
        if (!strcmp(g_rows[i].name, argv[1])) return g_rows[i].fn();
    return 98;
}

/* A row is a child-side function returning 0 (all as expected) or the number of the first failing step. */
#define PRE(n) \
    static int pre_##n(void); \
    static void __attribute__((constructor)) preg_##n(void) { g_rows[g_nrows].name = #n; g_rows[g_nrows++].fn = pre_##n; } \
    TEST(gap2_pre_##n) { DWORD rc = t_run_child("g2pre", #n, 30000); \
        CHECKF(rc == 0, "child step %lu failed (0xdead0000 = spawn failure, 0xdead0001 = timeout)", (unsigned long)rc); } \
    static int pre_##n(void)
#define STEP(cond, n) do { if (!(cond)) return (n); } while (0)

#define E_(code) (WS(WSAGetLastError)() == (code))

PRE(remove_service_class_valid_guid) {
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } };
    WS(WSASetLastError)(0);
    STEP(WS(WSARemoveServiceClass)(&g) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
/* The start-up check precedes the NULL check here (the argument check is made afterwards). */
PRE(remove_service_class_null_guid) {
    WS(WSASetLastError)(0);
    STEP(WS(WSARemoveServiceClass)(NULL) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
/* The getter checks its four pointers first, so NULL gives WSAEINVAL even without start-up. */
PRE(get_class_info_w_null_checked_first) {
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } }; DWORD len = 0x100; BYTE out[0x100];
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetServiceClassInfoW)(NULL, &g, &len, (LPWSASERVICECLASSINFOW)out) == SOCKET_ERROR, 1);
    STEP(E_(GE_INVAL), 2);
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetServiceClassInfoW)(&g, &g, NULL, (LPWSASERVICECLASSINFOW)out) == SOCKET_ERROR, 3);
    STEP(E_(GE_INVAL), 4);
    return 0;
}
PRE(get_class_info_w_valid_args) {
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } }; DWORD len = 0x100; BYTE out[0x100];
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetServiceClassInfoW)(&g, &g, &len, (LPWSASERVICECLASSINFOW)out) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(get_class_info_a_null_checked_first) {
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } }; DWORD len = 0x100; BYTE out[0x100];
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetServiceClassInfoA)(&g, NULL, &len, (LPWSASERVICECLASSINFOA)out) == SOCKET_ERROR, 1);
    STEP(E_(GE_INVAL), 2);
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetServiceClassInfoA)(&g, &g, &len, NULL) == SOCKET_ERROR, 3);
    STEP(E_(GE_INVAL), 4);
    return 0;
}
PRE(get_class_info_a_valid_args) {
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } }; DWORD len = 0x100; BYTE out[0x100];
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetServiceClassInfoA)(&g, &g, &len, (LPWSASERVICECLASSINFOA)out) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(class_name_by_id_w) {
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } }; DWORD len = 64; WCHAR name[32];
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetServiceClassNameByClassIdW)(&g, name, &len) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    STEP(len == 64, 3);   /* untouched */
    return 0;
}
PRE(class_name_by_id_a) {
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } }; DWORD len = 32; char name[32];
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetServiceClassNameByClassIdA)(&g, name, &len) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    STEP(len == 32, 3);
    return 0;
}
PRE(set_service_w_null_checked_first) {
    WS(WSASetLastError)(0);
    STEP(WS(WSASetServiceW)(NULL, RNRSERVICE_REGISTER, 0) == SOCKET_ERROR, 1);
    STEP(E_(GE_FAULT), 2);
    return 0;
}
PRE(set_service_w_valid_query) {
    WSAQUERYSETW qs; static WCHAR nm[] = L"ws2t-throwaway-service";
    g2_qs_w(&qs, nm, &g2_guid_throwaway, 0x7e57);
    WS(WSASetLastError)(0);
    STEP(WS(WSASetServiceW)(&qs, RNRSERVICE_REGISTER, 0) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(set_service_a_null_checked_first) {
    WS(WSASetLastError)(0);
    STEP(WS(WSASetServiceA)(NULL, RNRSERVICE_REGISTER, 0) == SOCKET_ERROR, 1);
    STEP(E_(GE_FAULT), 2);
    return 0;
}
PRE(set_service_a_valid_query) {
    WSAQUERYSETA qs; static char nm[] = "ws2t-throwaway-service";
    g2_qs_a(&qs, nm, &g2_guid_throwaway, 0x7e57);
    WS(WSASetLastError)(0);
    STEP(WS(WSASetServiceA)(&qs, RNRSERVICE_REGISTER, 0) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(lookup_begin_w) {
    WSAQUERYSETW qs; static WCHAR nm[] = L"localhost"; HANDLE h = (HANDLE)(ULONG_PTR)0x1234;
    g2_qs_w(&qs, nm, &g2_svc_addr_by_name, NS_ALL);
    WS(WSASetLastError)(0);
    STEP(WS(WSALookupServiceBeginW)(&qs, 0, &h) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    STEP(h == (HANDLE)(ULONG_PTR)0x1234, 3);   /* the out-parameter is not written on this failure */
    return 0;
}
PRE(lookup_begin_a) {
    WSAQUERYSETA qs; static char nm[] = "localhost"; HANDLE h = (HANDLE)(ULONG_PTR)0x1234;
    g2_qs_a(&qs, nm, &g2_svc_addr_by_name, NS_ALL);
    WS(WSASetLastError)(0);
    STEP(WS(WSALookupServiceBeginA)(&qs, 0, &h) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    STEP(h == (HANDLE)(ULONG_PTR)0x1234, 3);
    return 0;
}
PRE(lookup_next_w_null_handle) {
    DWORD len = 0x200; BYTE buf[0x200];
    WS(WSASetLastError)(0);
    STEP(WS(WSALookupServiceNextW)(NULL, 0, &len, (LPWSAQUERYSETW)buf) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(lookup_next_a_null_handle) {
    DWORD len = 0x200; BYTE buf[0x200];
    WS(WSASetLastError)(0);
    STEP(WS(WSALookupServiceNextA)(NULL, 0, &len, (LPWSAQUERYSETA)buf) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(lookup_end_null_handle) {
    WS(WSASetLastError)(0);
    STEP(WS(WSALookupServiceEnd)(NULL) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(enum_providers_a) {
    DWORD len = 0;
    WS(WSASetLastError)(0);
    STEP(WS(WSAEnumNameSpaceProvidersA)(&len, NULL) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    STEP(len == 0, 3);   /* no size reported */
    return 0;
}
PRE(enum_providers_ex_a) {
    DWORD len = 0;
    WS(WSASetLastError)(0);
    STEP(WS(WSAEnumNameSpaceProvidersExA)(&len, NULL) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    STEP(len == 0, 3);
    return 0;
}
PRE(enum_providers_ex_w) {
    DWORD len = 0;
    WS(WSASetLastError)(0);
    STEP(WS(WSAEnumNameSpaceProvidersExW)(&len, NULL) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    STEP(len == 0, 3);
    return 0;
}
/* The QOS-by-name call reports failure as FALSE (not SOCKET_ERROR). */
PRE(get_qos_by_name) {
    WSABUF nm; QOS q; memset(&q, 0, sizeof q); nm.len = 0; nm.buf = NULL;
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetQOSByName)(INVALID_SOCKET, &nm, &q) == FALSE, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
/* The address-info calls return the error number itself and also leave it as the last error. */
PRE(get_addr_info_ex_a) {
    ADDRINFOEXA *res = (ADDRINFOEXA *)(ULONG_PTR)0x1234; int r;
    WS(WSASetLastError)(0);
    r = WS(GetAddrInfoExA)("127.0.0.1", NULL, NS_DNS, NULL, NULL, &res, NULL, NULL, NULL, NULL);
    STEP(r == GE_NOTINIT, 1);
    STEP(E_(GE_NOTINIT), 2);
    STEP(res == (ADDRINFOEXA *)(ULONG_PTR)0x1234, 3);   /* result pointer not cleared before the check */
    return 0;
}
PRE(set_addr_info_ex_w) {
    SOCKET_ADDRESS sa; struct sockaddr_in a; INT r;
    g2_loop4(&a, 0); sa.lpSockaddr = (LPSOCKADDR)&a; sa.iSockaddrLength = sizeof a;
    r = WS(SetAddrInfoExW)(L"ws2t-host", NULL, &sa, 1, NULL, 0, NS_DNS, NULL, NULL, NULL, NULL, NULL);
    STEP(r == GE_NOTINIT, 1);
    return 0;
}
PRE(set_addr_info_ex_a) {
    SOCKET_ADDRESS sa; struct sockaddr_in a; INT r;
    g2_loop4(&a, 0); sa.lpSockaddr = (LPSOCKADDR)&a; sa.iSockaddrLength = sizeof a;
    r = WS(SetAddrInfoExA)("ws2t-host", NULL, &sa, 1, NULL, 0, NS_DNS, NULL, NULL, NULL, NULL, NULL);
    STEP(r == GE_NOTINIT, 1);
    return 0;
}
PRE(get_name_info_w) {
    struct sockaddr_in a; WCHAR host[64]; int r;
    g2_loop4(&a, 0);
    WS(WSASetLastError)(0);
    r = WS(GetNameInfoW)((SOCKADDR *)&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST);
    STEP(r == GE_NOTINIT, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(string_to_address_w) {
    struct sockaddr_in a; INT len = sizeof a;
    WS(WSASetLastError)(0);
    STEP(WS(WSAStringToAddressW)((LPWSTR)L"127.0.0.1", AF_INET, NULL, (LPSOCKADDR)&a, &len) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(accept_ex) {
    DWORD got = 0; OVERLAPPED ov; BYTE buf[64];
    memset(&ov, 0, sizeof ov);
    WS(WSASetLastError)(0);
    STEP(MS(AcceptEx)(INVALID_SOCKET, INVALID_SOCKET, buf, 0, 32, 32, &got, &ov) == FALSE, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(wsa_connect) {
    struct sockaddr_in a; g2_loop4(&a, 0x5000);
    WS(WSASetLastError)(0);
    STEP(WS(WSAConnect)(INVALID_SOCKET, (SOCKADDR *)&a, sizeof a, NULL, NULL, NULL, NULL) == SOCKET_ERROR, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(connect_by_list) {
    WS(WSASetLastError)(0);
    STEP(WS(WSAConnectByList)(INVALID_SOCKET, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == FALSE, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
PRE(connect_by_name_w) {
    WS(WSASetLastError)(0);
    STEP(WS(WSAConnectByNameW)(INVALID_SOCKET, (LPWSTR)L"127.0.0.1", (LPWSTR)L"80", NULL, NULL, NULL, NULL, NULL, NULL) == FALSE, 1);
    STEP(E_(GE_NOTINIT), 2);
    return 0;
}
/* The provider entry point initialises the library itself, so it works without any start-up. */
PRE(mswsock_nspstartup_works_without_start) {
    typedef INT (WSAAPI *st_fn)(LPGUID, LPNSP_ROUTINE);
    typedef INT (WSAAPI *cl_fn)(LPGUID);
    st_fn st = (st_fn)t_proc_in("mswsock.dll", "NSPStartup");
    GUID id = g2_guid_throwaway; NSP_ROUTINE rt;
    if (!st || t_is_wine()) return 0;
    memset(&rt, 0, sizeof rt); rt.cbSize = sizeof rt;
    SetLastError(0);
    STEP(st(&id, &rt) == 0, 1);
    STEP(rt.NSPCleanup != NULL, 2);
    STEP(((cl_fn)rt.NSPCleanup)(&id) == 0, 3);
    return 0;
}

/* ---- after the last cleanup the same refusals apply as before the first start-up ---- */

CHILD(g2cleanup) {
    WSADATA d; DWORD len; GUID g = g2_guid_throwaway; int step = 0;
    struct sockaddr_in a; INT alen = sizeof a; WCHAR host[32]; WSABUF nm; QOS q; char t[] = "x"; DWORD blen = 0x100; BYTE out[0x100] = { 0 };
    WSAQUERYSETW qs; static WCHAR nmw[] = L"ws2t"; HANDLE h = NULL; ADDRINFOEXA *res = NULL;
    g2_loop4(&a, 0);
    memset(&q, 0, sizeof q); nm.buf = t; nm.len = 1;
    g2_qs_w(&qs, nmw, &g2_guid_throwaway, 0x7e57);
    if (WS(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 90;
    if (WS(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 91;
    WS(WSACleanup)();                       /* one of two starts released: still usable */
    len = 0;
    STEP(WS(WSAEnumNameSpaceProvidersA)(&len, NULL) == SOCKET_ERROR && E_(GE_FAULT) && len > 0, 1);
    WS(WSACleanup)();                       /* the last one */
    len = 0; WS(WSASetLastError)(0);
    STEP(WS(WSAEnumNameSpaceProvidersA)(&len, NULL) == SOCKET_ERROR && E_(GE_NOTINIT), 2);
    WS(WSASetLastError)(0);
    STEP(WS(WSAEnumNameSpaceProvidersExW)(&len, NULL) == SOCKET_ERROR && E_(GE_NOTINIT), 3);
    WS(WSASetLastError)(0);
    STEP(WS(GetNameInfoW)((SOCKADDR *)&a, sizeof a, host, 32, NULL, 0, NI_NUMERICHOST) == GE_NOTINIT && E_(GE_NOTINIT), 4);
    WS(WSASetLastError)(0);
    STEP(WS(WSAStringToAddressW)((LPWSTR)L"127.0.0.1", AF_INET, NULL, (LPSOCKADDR)&a, &alen) == SOCKET_ERROR && E_(GE_NOTINIT), 5);
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetQOSByName)(INVALID_SOCKET, &nm, &q) == FALSE && E_(GE_NOTINIT), 6);
    WS(WSASetLastError)(0);
    STEP(WS(WSALookupServiceBeginW)(&qs, 0, &h) == SOCKET_ERROR && E_(GE_NOTINIT), 7);
    WS(WSASetLastError)(0);
    STEP(WS(WSAGetServiceClassInfoW)(&g, &g, &blen, (LPWSASERVICECLASSINFOW)out) == SOCKET_ERROR && E_(GE_NOTINIT), 8);
    WS(WSASetLastError)(0);
    STEP(WS(WSARemoveServiceClass)(&g) == SOCKET_ERROR && E_(GE_NOTINIT), 9);
    WS(WSASetLastError)(0);
    STEP(WS(WSASetServiceW)(&qs, RNRSERVICE_REGISTER, 0) == SOCKET_ERROR && E_(GE_NOTINIT), 10);
    WS(WSASetLastError)(0);
    STEP(WS(GetAddrInfoExA)("127.0.0.1", NULL, NS_DNS, NULL, NULL, &res, NULL, NULL, NULL, NULL) == GE_NOTINIT, 11);
    WS(WSASetLastError)(0);
    STEP(WS(WSACleanup)() == SOCKET_ERROR && E_(GE_NOTINIT), 12);   /* a further cleanup is refused too */
    return 0;
}
TEST(gap2_pre_after_last_cleanup_everything_is_refused) {
    DWORD rc = t_run_child("g2cleanup", "", 30000);
    CHECKF(rc == 0, "child step %lu failed", (unsigned long)rc);
}
