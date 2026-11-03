/* Result content of WSALookupService* for loopback names in the DNS name space.
 * Measures: which output fields each LUP_RETURN_* flag controls, the fixed header fields of a
 * result (dwSize, dwNameSpace), loopback-only addresses for the built-in loopback names,
 * W/A parity, name-space and provider selection, and the invalid-flag errors of Next.
 * Counts of addresses and the exact instance names are machine data and are only logged. */
#include "nsp.h"

static WCHAR wlocalhost[] = L"localhost";

/* Run one lookup on `name` and keep the first result in b. Returns 0 when a result arrived,
 * otherwise the Begin or Next error (Begin errors are or'ed with 0x10000). */
static int first_result(LPWSTR name, const GUID *cls, DWORD ns, DWORD flags, nsp_buf *b, int *total) {
    WSAQUERYSETW qs; HANDLE h = NULL; int e, n = 0;
    nsp_query_w(&qs, name, cls, ns);
    if (total) *total = 0;
    if (W_BEGIN_W(&qs, flags, &h) != 0) return 0x10000 | W_ERR();
    e = nsp_next_w(h, 0, b, NULL);
    if (e == 0) {
        n = 1;
        {   /* drain the rest without keeping it */
            nsp_buf extra = {0}; int guard = 0;
            while (guard++ < 32 && nsp_next_w(h, 0, &extra, NULL) == 0) n++;
            nsp_buf_free(&extra);
        }
    }
    if (total) *total = n;
    W_END(h);
    return e;
}

#define NEED_RESULT(name, cls, ns, flags, b, total) \
    do { int e_ = first_result(name, cls, ns, flags, &b, &total); \
         if (e_) { nsp_buf_free(&b); t_skip("lookup not available here (code 0x%x)", e_); return; } } while (0)

/* ---- the localhost family ---- */

static const struct { LPWSTR name; const char *what; } loop_names[] = {
    { L"localhost", "lower case" }, { L"LOCALHOST", "upper case" }, { L"LocalHost", "mixed case" },
    { L"localhost.", "trailing dot" },
};

TEST(lr_localhost_spellings_resolve_to_loopback_only) {
    size_t i; NSP_NEED(); REQUIRE(W_BEGIN_W);
    for (i = 0; i < NSP_N(loop_names); i++) {
        nsp_buf b = {0}; int total = 0, e;
        WCHAR copy[32];
        lstrcpyW(copy, loop_names[i].name);
        e = first_result(copy, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_ADDR, &b, &total);
        CHECKF(e == 0, "%s: lookup failed (0x%x)", loop_names[i].what, e);
        if (e == 0) {
            WSAQUERYSETW *r = (WSAQUERYSETW *)b.p; int n = 0;
            CHECKF(r->dwNumberOfCsAddrs >= 1 && r->lpcsaBuffer, "%s: no addresses", loop_names[i].what);
            if (r->lpcsaBuffer) {
                CHECKF(nsp_csaddrs_loopback(r->lpcsaBuffer, r->dwNumberOfCsAddrs, &n) && n >= 1, "%s: non-loopback address", loop_names[i].what);
            }
        }
        nsp_buf_free(&b);
    }
}

TEST(lr_loopback_keyword_logged) {
    /* The provider short-cuts both "localhost" and "loopback" without a network query; whether
     * the second is answered for this service class is recorded, not asserted. */
    nsp_buf b = {0}; int total; WCHAR nm[] = L"loopback";
    int e;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    e = first_result(nm, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_ADDR, &b, &total);
    EXPECT_EQ(e, 0);
    CHECK(total >= 1);
    nsp_buf_free(&b);
}

TEST(lr_numeric_ipv4_loopback_resolves_to_itself) {
    nsp_buf b = {0}; int total, e, n = 0; WCHAR nm[] = L"127.0.0.1";
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    e = first_result(nm, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_ADDR, &b, &total);
    EXPECT_EQ(e, 0);
    if (e == 0) {
        WSAQUERYSETW *r = (WSAQUERYSETW *)b.p;
        CHECK(r->dwNumberOfCsAddrs >= 1 && r->lpcsaBuffer);
        if (r->lpcsaBuffer) {
            CHECK(nsp_csaddrs_loopback(r->lpcsaBuffer, r->dwNumberOfCsAddrs, &n) && n >= 1);
            CHECK(r->lpcsaBuffer[0].RemoteAddr.lpSockaddr && r->lpcsaBuffer[0].RemoteAddr.lpSockaddr->sa_family == AF_INET);
        }
    }
    nsp_buf_free(&b);
}

TEST(lr_numeric_ipv6_loopback_logged) {
    nsp_buf b = {0}; int total, e; WCHAR nm[] = L"::1";
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    e = first_result(nm, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_ADDR, &b, &total);
    t_note("numeric ::1 through the name-by-address class: code 0x%x results %d", e, total);
    nsp_buf_free(&b);
}

TEST(lr_address_by_string_class_numeric_loopback) {
    nsp_buf b = {0}; int total, e; WCHAR nm[] = L"127.0.0.1";
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    e = first_result(nm, &nsp_svcid_addr_by_string, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_ADDR, &b, &total);
    EXPECT_EQ(e, 0);
    CHECK(total >= 1);
    nsp_buf_free(&b);
}

/* ---- header fields of a result ---- */

TEST(lr_result_header_size_and_namespace) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME, b, total);
    {   WSAQUERYSETW *r = (WSAQUERYSETW *)b.p;
        EXPECT_EQ(r->dwSize, NSP_SZ_QS_W);     /* the fixed part of the set; strings and arrays follow it */
        EXPECT_EQ(r->dwNameSpace, NS_DNS);     /* set from the catalog entry that answered */
    }
    nsp_buf_free(&b);
}

TEST(lr_result_blob_pointers_lie_inside_buffer) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_ADDR, b, total);
    {   WSAQUERYSETW *r = (WSAQUERYSETW *)b.p; BYTE *lo = b.p, *hi = b.p + b.cap;
        if (r->lpszServiceInstanceName) CHECK((BYTE *)r->lpszServiceInstanceName >= lo && (BYTE *)r->lpszServiceInstanceName < hi);
        if (r->lpcsaBuffer) CHECK((BYTE *)r->lpcsaBuffer >= lo && (BYTE *)r->lpcsaBuffer < hi);
    }
    nsp_buf_free(&b);
}

TEST(lr_return_name_fills_instance_name) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME, b, total);
    {   WSAQUERYSETW *r = (WSAQUERYSETW *)b.p;
        CHECK(r->lpszServiceInstanceName != NULL);
        if (r->lpszServiceInstanceName) CHECK(r->lpszServiceInstanceName[0] != 0);
        t_note("instance name length %d", r->lpszServiceInstanceName ? lstrlenW(r->lpszServiceInstanceName) : -1);
    }
    nsp_buf_free(&b);
}

TEST(lr_without_return_name_no_instance_name_logged) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_ADDR, b, total);
    CHECK(((WSAQUERYSETW *)b.p)->lpszServiceInstanceName == NULL);   /* only what was asked for is returned */
    nsp_buf_free(&b);
}

TEST(lr_return_addr_fills_csaddr_array) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_ADDR, b, total);
    {   WSAQUERYSETW *r = (WSAQUERYSETW *)b.p; DWORD i;
        CHECK(r->dwNumberOfCsAddrs >= 1);
        CHECK(r->lpcsaBuffer != NULL);
        t_note("csaddr count for localhost: %lu", (unsigned long)r->dwNumberOfCsAddrs);
        for (i = 0; r->lpcsaBuffer && i < r->dwNumberOfCsAddrs; i++) {
            const SOCKET_ADDRESS *sa = &r->lpcsaBuffer[i].RemoteAddr;
            CHECK(sa->lpSockaddr != NULL);
            if (!sa->lpSockaddr) continue;
            if (sa->lpSockaddr->sa_family == AF_INET) EXPECT_EQ(sa->iSockaddrLength, sizeof(SOCKADDR_IN));
            else if (sa->lpSockaddr->sa_family == AF_INET6) EXPECT_EQ(sa->iSockaddrLength, sizeof(SOCKADDR_IN6));
            else CHECKF(0, "unexpected family %d", sa->lpSockaddr->sa_family);
        }
    }
    nsp_buf_free(&b);
}

TEST(lr_without_return_addr_no_csaddr_logged) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME, b, total);
    EXPECT_EQ(((WSAQUERYSETW *)b.p)->dwNumberOfCsAddrs, 0);
    CHECK(((WSAQUERYSETW *)b.p)->lpcsaBuffer == NULL);
    nsp_buf_free(&b);
}

TEST(lr_return_type_echoes_service_class) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_TYPE, b, total);
    {   WSAQUERYSETW *r = (WSAQUERYSETW *)b.p;
        CHECK(r->lpServiceClassId != NULL);
        if (r->lpServiceClassId) CHECK(IsEqualGUID(r->lpServiceClassId, &nsp_svcid_addr_by_name));
    }
    nsp_buf_free(&b);
}

TEST(lr_return_blob_supplies_blob) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_BLOB, b, total);
    {   WSAQUERYSETW *r = (WSAQUERYSETW *)b.p;
        CHECK(r->lpBlob != NULL);
        if (r->lpBlob) { CHECK(r->lpBlob->cbSize > 0); CHECK(r->lpBlob->pBlobData != NULL); }
    }
    nsp_buf_free(&b);
}

TEST(lr_return_all_is_accepted) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_ALL, b, total);
    {   WSAQUERYSETW *r = (WSAQUERYSETW *)b.p;
        CHECK(r->lpszServiceInstanceName != NULL);
        CHECK(r->lpcsaBuffer != NULL);
        CHECK(r->lpServiceClassId != NULL);
    }
    nsp_buf_free(&b);
}

TEST(lr_return_all_with_deep_is_accepted) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_ALL | LUP_DEEP, b, total);
    nsp_buf_free(&b);
}

TEST(lr_zero_flags_begin_is_accepted) {
    WSAQUERYSETW qs; HANDLE h = NULL;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    EXPECT_EQ(W_BEGIN_W(&qs, 0, &h), 0);
    if (h) W_END(h);
}

TEST(lr_second_next_after_single_result_is_no_more) {
    WSAQUERYSETW qs; HANDLE h = NULL; nsp_buf b = {0}; int e;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_W(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h) != 0) { t_skip("begin failed"); return; }
    /* One host with no aliases is one result; the next call ends the enumeration. */
    EXPECT_EQ(nsp_next_w(h, 0, &b, NULL), 0);
    e = nsp_next_w(h, 0, &b, NULL);
    EXPECT_EQ(e, E_NO_MORE);
    nsp_buf_free(&b);
    W_END(h);
}

TEST(lr_next_first_call_small_buffer_needs_growth) {
    WSAQUERYSETW qs; HANDLE h = NULL; nsp_buf b = {0}; BYTE tiny[0x78]; DWORD len = sizeof tiny;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_W(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h) != 0) { t_skip("begin failed"); return; }
    /* The fixed part alone is not enough once a name and addresses are requested. */
    W_SETERR(0);
    EXPECT_EQ(W_NEXT_W(h, 0, &len, (WSAQUERYSETW *)tiny), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_FAULT);
    CHECK(len > NSP_SZ_QS_W);
    nsp_buf_free(&b);
    W_END(h);
}

TEST(lr_required_size_grows_with_requested_fields) {
    HANDLE h1 = NULL, h2 = NULL; WSAQUERYSETW qs; DWORD l1 = 0, l2 = 0;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_W(&qs, 0, &h1) != 0) { t_skip("begin failed"); return; }
    if (W_BEGIN_W(&qs, LUP_RETURN_ALL, &h2) != 0) { W_END(h1); t_skip("begin failed"); return; }
    EXPECT_EQ(W_NEXT_W(h1, 0, &l1, NULL), SOCKET_ERROR);
    EXPECT_EQ(W_NEXT_W(h2, 0, &l2, NULL), SOCKET_ERROR);
    CHECK(l2 > l1);
    W_END(h1); W_END(h2);
}

/* ---- invalid flags on Next ---- */

/* Unsupported flag bits on Next are refused as an invalid parameter (each on its own fresh handle). */
static const struct { DWORD flags; int err; } next_bad_flags[] = {
    { LUP_CONTAINERS | LUP_NOCONTAINERS, (int)E_BADPARAM },
    { 0x4000, (int)E_BADPARAM }, { 0x10000, (int)E_BADPARAM }, { 0x40000, (int)E_BADPARAM },
    { 0x80000, (int)E_BADPARAM }, { 0x04000000, (int)E_BADPARAM }, { 0x20000000, (int)E_BADPARAM },
};

TEST(lr_next_rejects_unsupported_flags) {
    size_t i; WSAQUERYSETW qs;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    for (i = 0; i < NSP_N(next_bad_flags); i++) {
        HANDLE h = NULL; BYTE buf[512]; DWORD len = sizeof buf;
        if (W_BEGIN_W(&qs, LUP_RETURN_NAME, &h) != 0) { t_skip("begin failed"); return; }
        W_SETERR(0);
        CHECKF(W_NEXT_W(h, next_bad_flags[i].flags, &len, (WSAQUERYSETW *)buf) == SOCKET_ERROR, "flags 0x%lx accepted", (unsigned long)next_bad_flags[i].flags);
        CHECKF(W_ERR() == next_bad_flags[i].err, "flags 0x%lx: error %d want %d", (unsigned long)next_bad_flags[i].flags, W_ERR(), next_bad_flags[i].err);
        W_END(h);
    }
}

TEST(lr_next_refused_flags_end_the_enumeration) {
    /* A Next refused for its flags still spends the pending result: the following valid call
     * finds the enumeration finished. */
    static const DWORD bad[] = { LUP_CONTAINERS | LUP_NOCONTAINERS, 0x4000 };
    size_t i; WSAQUERYSETW qs;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    for (i = 0; i < NSP_N(bad); i++) {
        HANDLE h; nsp_buf b = {0}; BYTE buf[512]; DWORD len = sizeof buf;
        if (W_BEGIN_W(&qs, LUP_RETURN_NAME, &h) != 0) { t_skip("begin failed"); return; }
        EXPECT_EQ(W_NEXT_W(h, bad[i], &len, (WSAQUERYSETW *)buf), SOCKET_ERROR);
        EXPECT_EQ(nsp_next_w(h, 0, &b, NULL), E_NO_MORE);
        nsp_buf_free(&b);
        W_END(h);
    }
}

/* ---- name-space and provider selection ---- */

TEST(lr_unknown_namespace_is_service_not_found) {
    WSAQUERYSETW qs; HANDLE h = (HANDLE)(ULONG_PTR)1;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, 0x7e57);
    W_SETERR(0);
    EXPECT_EQ(W_BEGIN_W(&qs, LUP_RETURN_NAME, &h), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_SVC_NOTFOUND);
    EXPECT_EQ(h, NULL);
}

TEST(lr_unknown_provider_id_fails_begin) {
    WSAQUERYSETW qs; HANDLE h = (HANDLE)(ULONG_PTR)1;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    qs.lpNSProviderId = (GUID *)&nsp_guid_throwaway;
    W_SETERR(0);
    EXPECT_EQ(W_BEGIN_W(&qs, LUP_RETURN_NAME, &h), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_INVAL);
    EXPECT_EQ(h, NULL);
}

TEST(lr_dns_provider_id_selects_the_provider) {
    WSAQUERYSETW qs; HANDLE h = NULL; GUID id;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    if (!nsp_provider_for(NS_DNS, &id)) { t_skip("no DNS provider in the catalog"); return; }
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    qs.lpNSProviderId = &id;
    EXPECT_EQ(W_BEGIN_W(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h), 0);
    if (h) W_END(h);
}

TEST(lr_provider_id_alone_without_namespace_selects_the_provider) {
    WSAQUERYSETW qs; HANDLE h = NULL; GUID id;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    if (!nsp_provider_for(NS_DNS, &id)) { t_skip("no DNS provider in the catalog"); return; }
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_ALL);
    qs.lpNSProviderId = &id;
    EXPECT_EQ(W_BEGIN_W(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h), 0);
    if (h) W_END(h);
}

TEST(lr_ns_all_localhost_resolves) {
    nsp_buf b = {0}; int total;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_ALL, LUP_RETURN_NAME | LUP_RETURN_ADDR, b, total);
    {   WSAQUERYSETW *r = (WSAQUERYSETW *)b.p; int n = 0;
        CHECK(r->lpcsaBuffer && nsp_csaddrs_loopback(r->lpcsaBuffer, r->dwNumberOfCsAddrs, &n));
        t_note("NS_ALL result served by name space %lu", (unsigned long)r->dwNameSpace);
    }
    nsp_buf_free(&b);
}

TEST(lr_result_provider_id_matches_catalog_when_reported) {
    nsp_buf b = {0}; int total; GUID id;
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    if (!nsp_provider_for(NS_DNS, &id)) { t_skip("no DNS provider in the catalog"); return; }
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME, b, total);
    {   WSAQUERYSETW *r = (WSAQUERYSETW *)b.p;
        if (r->lpNSProviderId) CHECK(IsEqualGUID(r->lpNSProviderId, &id));
        else t_note("result carries no provider id");
    }
    nsp_buf_free(&b);
}

TEST(lr_other_namespaces_logged) {
    static const DWORD nss[] = { NS_TCPIP_HOSTS, NS_TCPIP_LOCAL, NS_NETBT, NS_NLA, NS_NTDS, NS_PNRPNAME, NS_BTH };
    size_t i; NSP_NEED(); REQUIRE(W_BEGIN_W);
    for (i = 0; i < NSP_N(nss); i++) {
        int eb = 0, el = 0, n;
        WSAQUERYSETW qs; WCHAR nm[] = L"localhost";
        nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, nss[i]);
        n = nsp_count_w(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &eb, &el);
        t_note("name space %lu: results %d begin error %d last error %d", (unsigned long)nss[i], n, eb, el);
    }
}

/* ---- W/A parity and independence ---- */

TEST(lr_ansi_and_wide_agree_on_address_count) {
    WSAQUERYSETA qa; HANDLE ha = NULL; nsp_buf bw = {0}, ba = {0}; int total, e; char nm[] = "localhost";
    NSP_NEED(); REQUIRE(W_BEGIN_A); REQUIRE(W_END);
    NEED_RESULT(wlocalhost, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_ADDR, bw, total);
    nsp_query_a(&qa, nm, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_A(&qa, LUP_RETURN_NAME | LUP_RETURN_ADDR, &ha) != 0) { nsp_buf_free(&bw); t_skip("A begin failed"); return; }
    e = nsp_next_a(ha, 0, &ba, NULL);
    EXPECT_EQ(e, 0);
    if (e == 0) {
        WSAQUERYSETA *a = (WSAQUERYSETA *)ba.p; WSAQUERYSETW *w = (WSAQUERYSETW *)bw.p;
        EXPECT_EQ(a->dwNumberOfCsAddrs, w->dwNumberOfCsAddrs);
        EXPECT_EQ(a->dwNameSpace, w->dwNameSpace);
        if (a->lpszServiceInstanceName && w->lpszServiceInstanceName) {
            WCHAR wide[260];
            MultiByteToWideChar(CP_ACP, 0, a->lpszServiceInstanceName, -1, wide, 260);
            CHECK(!lstrcmpiW(wide, w->lpszServiceInstanceName));
        }
    }
    nsp_buf_free(&bw); nsp_buf_free(&ba);
    W_END(ha);
}

TEST(lr_ansi_next_after_exhaustion_is_no_more) {
    WSAQUERYSETA qa; HANDLE ha = NULL; nsp_buf b = {0}; int e, guard = 0; char nm[] = "localhost";
    NSP_NEED(); REQUIRE(W_BEGIN_A); REQUIRE(W_END);
    nsp_query_a(&qa, nm, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_A(&qa, LUP_RETURN_NAME, &ha) != 0) { t_skip("A begin failed"); return; }
    while (guard++ < 32 && (e = nsp_next_a(ha, 0, &b, NULL)) == 0) {}
    EXPECT_EQ(e, E_NO_MORE);
    nsp_buf_free(&b);
    W_END(ha);
}

TEST(lr_two_handles_enumerate_independently) {
    WSAQUERYSETW qs; HANDLE a = NULL, c = NULL; nsp_buf ba = {0}, bc = {0};
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_W(&qs, LUP_RETURN_NAME, &a) != 0 || W_BEGIN_W(&qs, LUP_RETURN_NAME, &c) != 0) { t_skip("begin failed"); if (a) W_END(a); return; }
    EXPECT_EQ(nsp_next_w(a, 0, &ba, NULL), 0);
    EXPECT_EQ(nsp_next_w(a, 0, &ba, NULL), E_NO_MORE);
    EXPECT_EQ(nsp_next_w(c, 0, &bc, NULL), 0);   /* the second handle is untouched by the first */
    nsp_buf_free(&ba); nsp_buf_free(&bc);
    W_END(a); W_END(c);
}

TEST(lr_end_one_handle_leaves_other_usable) {
    WSAQUERYSETW qs; HANDLE a = NULL, c = NULL; nsp_buf b = {0};
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_W(&qs, LUP_RETURN_NAME, &a) != 0 || W_BEGIN_W(&qs, LUP_RETURN_NAME, &c) != 0) { t_skip("begin failed"); if (a) W_END(a); return; }
    EXPECT_EQ(W_END(a), 0);
    EXPECT_EQ(nsp_next_w(c, 0, &b, NULL), 0);
    nsp_buf_free(&b);
    W_END(c);
}

TEST(lr_query_set_is_not_modified_by_begin) {
    WSAQUERYSETW qs, before; HANDLE h = NULL;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    qs.dwNumberOfCsAddrs = 3; qs.lpcsaBuffer = (CSADDR_INFO *)(ULONG_PTR)0x10; qs.dwOutputFlags = 7;
    before = qs;
    W_BEGIN_W(&qs, LUP_RETURN_NAME, &h);
    /* Begin parks and restores the fields it must not look at (address buffer fields). */
    CHECK(!memcmp(&before, &qs, sizeof qs));
    if (h) W_END(h);
}

TEST(lr_repeated_begin_end_cycles) {
    int i; WSAQUERYSETW qs;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, wlocalhost, &nsp_svcid_addr_by_name, NS_DNS);
    for (i = 0; i < 20; i++) {
        HANDLE h = NULL;
        if (W_BEGIN_W(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h) != 0) { CHECKF(0, "cycle %d begin failed (%d)", i, W_ERR()); break; }
        CHECK(W_END(h) == 0);
    }
}

/* ---- the local host and services: environment-shaped, logged only ---- */

TEST(lr_empty_name_hostname_class_logged) {
    nsp_buf b = {0}; int total, e; WCHAR nm[] = L"";
    NSP_NEED(); REQUIRE(W_BEGIN_W);
    e = first_result(nm, &nsp_svcid_hostname, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_ADDR, &b, &total);
    t_note("hostname class with empty name: code 0x%x results %d", e, total);
    nsp_buf_free(&b);
}

TEST(lr_machine_name_logged) {
    nsp_buf b = {0}; int total, e; char host[256]; WCHAR wide[256];
    typeof(&gethostname) gh = UIN("ws2_32.dll", gethostname);
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(gh);
    if (gh(host, sizeof host) != 0) { t_skip("gethostname failed"); return; }
    MultiByteToWideChar(CP_ACP, 0, host, -1, wide, 256);
    e = first_result(wide, &nsp_svcid_addr_by_name, NS_DNS, LUP_RETURN_NAME | LUP_RETURN_ADDR, &b, &total);
    t_note("machine name lookup: code 0x%x results %d", e, total);
    if (e == 0) {
        WSAQUERYSETW *r = (WSAQUERYSETW *)b.p; int n = 0;
        t_note("machine name addresses all loopback: %d", r->lpcsaBuffer ? nsp_csaddrs_loopback(r->lpcsaBuffer, r->dwNumberOfCsAddrs, &n) : -1);
    }
    nsp_buf_free(&b);
}

TEST(lr_service_by_name_http_logged) {
    WSAQUERYSETW qs; HANDLE h = NULL; WCHAR nm[] = L"http"; AFPROTOCOLS ap = { AF_INET, IPPROTO_TCP }; nsp_buf b = {0}; int e;
    NSP_NEED(); REQUIRE(W_BEGIN_W); REQUIRE(W_END);
    nsp_query_w(&qs, nm, &nsp_svcid_service_by_name, NS_DNS);
    qs.lpafpProtocols = &ap; qs.dwNumberOfProtocols = 1;
    if (W_BEGIN_W(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h) != 0) { t_note("service-by-name begin error %d", W_ERR()); return; }
    e = nsp_next_w(h, 0, &b, NULL);
    t_note("service-by-name http: next code %d", e);
    if (e == 0) {
        WSAQUERYSETW *r = (WSAQUERYSETW *)b.p;
        if (r->lpcsaBuffer && r->dwNumberOfCsAddrs && r->lpcsaBuffer[0].LocalAddr.lpSockaddr && r->lpcsaBuffer[0].LocalAddr.lpSockaddr->sa_family == AF_INET)
            t_note("service-by-name port: %u", (unsigned)(((((SOCKADDR_IN *)r->lpcsaBuffer[0].LocalAddr.lpSockaddr)->sin_port) >> 8) | ((((SOCKADDR_IN *)r->lpcsaBuffer[0].LocalAddr.lpSockaddr)->sin_port & 0xff) << 8)));
    }
    nsp_buf_free(&b);
    W_END(h);
}
