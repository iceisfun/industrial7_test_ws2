/* Further lookup-API edges: handle ownership across threads, many simultaneous handles,
 * name-space ids that no catalog entry serves, output monotonicity in the requested fields,
 * case independence of loopback names, service-registration operations against the DNS entry,
 * and direct calls into the DNS provider's routines for loopback names. */
#include "nsp.h"

static WCHAR wlh[] = L"localhost";

TEST(lm_end_null_handle_is_invalid_handle) {
    REQUIRE(W_END); NSP_NEED();
    W_SETERR(0);
    EXPECT_EQ(W_END(NULL), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_BADHANDLE);
}

TEST(lm_namespaces_missing_from_catalog_report_service_not_found) {
    static const DWORD nss[] = { NS_TCPIP_LOCAL, NS_TCPIP_HOSTS, NS_NETBT, 0x7e57, 0x7fffffff };
    size_t i;
    REQUIRE(W_BEGIN_W); NSP_NEED();
    for (i = 0; i < NSP_N(nss); i++) {
        WSAQUERYSETW qs; HANDLE h = (HANDLE)(ULONG_PTR)1;
        nsp_query_w(&qs, wlh, &nsp_svcid_addr_by_name, nss[i]);
        W_SETERR(0);
        CHECKF(W_BEGIN_W(&qs, LUP_RETURN_NAME, &h) == SOCKET_ERROR, "name space %lu accepted", (unsigned long)nss[i]);
        CHECKF(W_ERR() == (int)E_SVC_NOTFOUND, "name space %lu: error %d", (unsigned long)nss[i], W_ERR());
        CHECKF(h == NULL, "name space %lu: handle not cleared", (unsigned long)nss[i]);
    }
}

TEST(lm_ansi_begin_unknown_namespace_and_context) {
    WSAQUERYSETA qs; HANDLE h = (HANDLE)(ULONG_PTR)1; char nm[] = "localhost", ctx[] = "somewhere";
    REQUIRE(W_BEGIN_A); NSP_NEED();
    nsp_query_a(&qs, nm, &nsp_svcid_addr_by_name, 0x7e57);
    W_SETERR(0);
    EXPECT_EQ(W_BEGIN_A(&qs, LUP_RETURN_NAME, &h), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_SVC_NOTFOUND);
    h = NULL;
    nsp_query_a(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
    qs.lpszContext = ctx;
    W_SETERR(0);
    EXPECT_EQ(W_BEGIN_A(&qs, LUP_RETURN_NAME, &h), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_NODATA);
}

TEST(lm_required_size_grows_with_requested_fields) {
    static const DWORD flag_sets[] = { 0, LUP_RETURN_NAME, LUP_RETURN_NAME | LUP_RETURN_ADDR };
    DWORD sizes[3] = {0}; size_t i;
    REQUIRE(W_BEGIN_W); REQUIRE(W_NEXT_W); REQUIRE(W_END); NSP_NEED();
    for (i = 0; i < NSP_N(flag_sets); i++) {
        WSAQUERYSETW qs; HANDLE h = NULL;
        nsp_query_w(&qs, wlh, &nsp_svcid_addr_by_name, NS_DNS);
        if (W_BEGIN_W(&qs, flag_sets[i], &h) != 0) { t_skip("begin failed"); return; }
        W_NEXT_W(h, 0, &sizes[i], NULL);
        W_END(h);
    }
    CHECK(sizes[0] >= NSP_SZ_QS_W);
    CHECK(sizes[1] >= sizes[0]);
    CHECK(sizes[2] > sizes[1]);
}

TEST(lm_loopback_name_case_does_not_change_address_count) {
    static WCHAR lower[] = L"localhost", upper[] = L"LOCALHOST";
    WSAQUERYSETW qs; int a, b, e1, e2;
    REQUIRE(W_BEGIN_W); NSP_NEED();
    nsp_query_w(&qs, lower, &nsp_svcid_addr_by_name, NS_DNS);
    a = nsp_count_w(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &e1, &e2);
    nsp_query_w(&qs, upper, &nsp_svcid_addr_by_name, NS_DNS);
    b = nsp_count_w(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &e1, &e2);
    CHECK(a >= 1);
    EXPECT_EQ(a, b);
}

TEST(lm_many_simultaneous_handles) {
    enum { N = 24 };
    HANDLE h[N]; int i, opened = 0;
    WSAQUERYSETW qs;
    REQUIRE(W_BEGIN_W); REQUIRE(W_END); NSP_NEED();
    nsp_query_w(&qs, wlh, &nsp_svcid_addr_by_name, NS_DNS);
    for (i = 0; i < N; i++) {
        h[i] = NULL;
        if (W_BEGIN_W(&qs, LUP_RETURN_NAME, &h[i]) == 0) opened++;
        else CHECKF(0, "handle %d: begin failed (%d)", i, W_ERR());
    }
    for (i = 0; i < N; i++) for (int j = i + 1; j < N; j++) if (h[i] && h[i] == h[j]) CHECKF(0, "handles %d and %d equal", i, j);
    for (i = 0; i < N; i++) if (h[i]) EXPECT_EQ(W_END(h[i]), 0);
    EXPECT_EQ(opened, N);
}

typedef struct { HANDLE h; int next_err; } xthread;
static DWORD WINAPI thread_next(LPVOID p) {
    xthread *x = (xthread *)p; nsp_buf b = {0};
    x->next_err = nsp_next_w(x->h, 0, &b, NULL);
    nsp_buf_free(&b);
    return 0;
}

TEST(lm_handle_usable_from_another_thread) {
    HANDLE h = NULL, th; xthread x; WSAQUERYSETW qs; DWORD id;
    REQUIRE(W_BEGIN_W); REQUIRE(W_END); NSP_NEED();
    nsp_query_w(&qs, wlh, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_W(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h) != 0) { t_skip("begin failed"); return; }
    x.h = h; x.next_err = -2;
    th = CreateThread(NULL, 0, thread_next, &x, 0, &id);
    if (!th) { W_END(h); t_skip("no thread"); return; }
    if (WaitForSingleObject(th, 10000) != WAIT_OBJECT_0) { CHECKF(0, "worker did not finish"); TerminateThread(th, 1); CloseHandle(th); return; }
    CloseHandle(th);
    EXPECT_EQ(x.next_err, 0);
    EXPECT_EQ(W_END(h), 0);     /* the creating thread may end it */
}

/* ---- WSASetService against the DNS entry: every operation is refused the same way ---- */

TEST(lm_set_service_dns_all_operations_not_supported) {
    static const WSAESETSERVICEOP ops[] = { RNRSERVICE_REGISTER, RNRSERVICE_DEREGISTER, RNRSERVICE_DELETE };
    size_t i; GUID id; typeof(&WSASetServiceW) set = UIN("ws2_32.dll", WSASetServiceW);
    REQUIRE(set); NSP_NEED();
    if (!nsp_provider_for(NS_DNS, &id)) { t_skip("no DNS provider in the catalog"); return; }
    for (i = 0; i < NSP_N(ops); i++) {
        WSAQUERYSETW qs; WCHAR nm[] = L"ws2t-throwaway-service";
        nsp_query_w(&qs, nm, &nsp_guid_throwaway, NS_DNS);
        W_SETERR(0);
        CHECKF(set(&qs, ops[i], 0) == SOCKET_ERROR, "op %zu accepted", i);
        CHECKF(W_ERR() == ERROR_NOT_SUPPORTED, "op %zu error %d", i, W_ERR());
    }
}

TEST(lm_get_class_info_ansi_matches_wide_for_unregistered_provider) {
    typeof(&WSAGetServiceClassInfoA) ga = UIN("ws2_32.dll", WSAGetServiceClassInfoA);
    typeof(&WSAGetServiceClassInfoW) gw = UIN("ws2_32.dll", WSAGetServiceClassInfoW);
    GUID prov = nsp_guid_throwaway, cls = nsp_guid_throwaway; DWORD l1 = 0x100, l2 = 0x100; BYTE o1[0x100] = {0}, o2[0x100] = {0};
    int e1, e2;
    REQUIRE(ga); REQUIRE(gw); NSP_NEED();
    W_SETERR(0); EXPECT_EQ(gw(&prov, &cls, &l1, (LPWSASERVICECLASSINFOW)o1), SOCKET_ERROR); e1 = W_ERR();
    W_SETERR(0); EXPECT_EQ(ga(&prov, &cls, &l2, (LPWSASERVICECLASSINFOA)o2), SOCKET_ERROR); e2 = W_ERR();
    EXPECT_EQ(e1, e2);
}

/* ---- the DNS provider's own routines on loopback names ---- */

typedef INT (WSAAPI *nspstartup_fn2)(LPGUID, LPNSP_ROUTINE);

typedef struct { NSP_ROUTINE rt; GUID id; int ok; } dns2;

static int dns2_open(dns2 *d) {
    nspstartup_fn2 st = (nspstartup_fn2)t_proc_in("mswsock.dll", "NSPStartup");
    memset(d, 0, sizeof *d);
    if (!st || !nsp_up() || !nsp_provider_for(NS_DNS, &d->id)) return 0;
    d->rt.cbSize = sizeof d->rt;
    if (st(&d->id, &d->rt) != 0) return 0;
    d->ok = 1;
    return 1;
}

static HANDLE dns2_begin(dns2 *d, LPWSTR name, const GUID *cls, DWORD flags) {
    WSAQUERYSETW qs; HANDLE h = NULL;
    nsp_query_w(&qs, name, cls, NS_DNS);
    return d->rt.NSPLookupServiceBegin(&d->id, &qs, NULL, flags, &h) == 0 ? h : NULL;
}

TEST(lm_dns_provider_numeric_ipv4_loopback_direct) {
    dns2 d; HANDLE h; DWORD len = 0; BYTE *buf; WCHAR nm[] = L"127.0.0.1";
    if (!dns2_open(&d)) { t_skip("DNS provider not available"); return; }
    h = dns2_begin(&d, nm, &nsp_svcid_addr_by_name, LUP_RETURN_NAME | LUP_RETURN_ADDR);
    CHECK(h != NULL);
    if (h) {
        d.rt.NSPLookupServiceNext(h, 0, &len, NULL);
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len ? len : 1);
        if (buf) {
            DWORD l = len; WSAQUERYSETW *r = (WSAQUERYSETW *)buf; int n = 0;
            EXPECT_EQ(d.rt.NSPLookupServiceNext(h, 0, &l, r), 0);
            CHECK(r->lpcsaBuffer && r->dwNumberOfCsAddrs >= 1);
            if (r->lpcsaBuffer) CHECK(nsp_csaddrs_loopback(r->lpcsaBuffer, r->dwNumberOfCsAddrs, &n));
            HeapFree(GetProcessHeap(), 0, buf);
        }
        d.rt.NSPLookupServiceEnd(h);
    }
    d.rt.NSPCleanup(&d.id);
}

TEST(lm_dns_provider_two_handles_are_independent) {
    dns2 d; HANDLE a, b; BYTE buf[0x400]; DWORD len;
    if (!dns2_open(&d)) { t_skip("DNS provider not available"); return; }
    a = dns2_begin(&d, wlh, &nsp_svcid_addr_by_name, LUP_RETURN_NAME);
    b = dns2_begin(&d, wlh, &nsp_svcid_addr_by_name, LUP_RETURN_NAME);
    CHECK(a && b);
    if (a && b) {
        CHECK(a != b);
        len = sizeof buf;
        EXPECT_EQ(d.rt.NSPLookupServiceNext(a, 0, &len, (WSAQUERYSETW *)buf), 0);
        len = sizeof buf;
        EXPECT_EQ(d.rt.NSPLookupServiceNext(b, 0, &len, (WSAQUERYSETW *)buf), 0);
    }
    if (a) d.rt.NSPLookupServiceEnd(a);
    if (b) d.rt.NSPLookupServiceEnd(b);
    d.rt.NSPCleanup(&d.id);
}

TEST(lm_dns_provider_restart_after_cleanup) {
    dns2 d; nspstartup_fn2 st = (nspstartup_fn2)t_proc_in("mswsock.dll", "NSPStartup"); NSP_ROUTINE rt;
    if (!dns2_open(&d)) { t_skip("DNS provider not available"); return; }
    EXPECT_EQ(d.rt.NSPCleanup(&d.id), 0);
    memset(&rt, 0, sizeof rt); rt.cbSize = sizeof rt;
    EXPECT_EQ(st(&d.id, &rt), 0);
    CHECK(rt.NSPLookupServiceBegin != NULL);
    rt.NSPCleanup(&d.id);
}
