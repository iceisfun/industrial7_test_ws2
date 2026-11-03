/* WSALookupServiceBeginA / WSALookupServiceNextA specifics that the wide forms do not share.
 * Measures: the three members of the caller's ANSI query set that the Begin entry point zeroes before it does
 * anything else (so they are cleared even when the call fails), that every other member is left alone,
 * and that results delivered through the ANSI Next call are narrow strings placed inside the caller's
 * buffer behind a fixed-size header.
 * Why: the ANSI Begin entry point clears comment, address count and output flags of the caller's structure
 * first, then converts a private wide copy; the ANSI Next entry point converts a wide result into the
 * caller's buffer. */
#include "g2.h"

#define LUP_ALL_RETURNS (LUP_RETURN_NAME | LUP_RETURN_ADDR | LUP_RETURN_TYPE)

static void dirty_a(WSAQUERYSETA *qs, char *comment, LPSTR name, const GUID *cls, DWORD ns) {
    g2_qs_a(qs, name, cls, ns);
    qs->lpszComment = comment;
    qs->dwNumberOfCsAddrs = 7;
    qs->dwOutputFlags = 0x55;
}

TEST(gap2_lookup_begin_a_clears_comment_count_and_flags_on_success) {
    WSAQUERYSETA qs; char nm[] = "localhost", cm[] = "ws2t-comment"; HANDLE h = NULL; int r;
    G2_NEED();
    dirty_a(&qs, cm, nm, &g2_svc_addr_by_name, NS_ALL);
    r = WS(WSALookupServiceBeginA)(&qs, LUP_RETURN_NAME, &h);
    CHECKF(r == 0, "begin returned %d (error %d)", r, W_ERR());
    CHECK(qs.lpszComment == NULL);
    EXPECT_EQ(qs.dwNumberOfCsAddrs, 0);
    EXPECT_EQ(qs.dwOutputFlags, 0);
    if (r == 0) WS(WSALookupServiceEnd)(h);
}

TEST(gap2_lookup_begin_a_clears_comment_count_and_flags_on_failure) {
    WSAQUERYSETA qs; char nm[] = "localhost", cm[] = "ws2t-comment"; HANDLE h = (HANDLE)(ULONG_PTR)1; int r;
    G2_NEED();
    dirty_a(&qs, cm, nm, &g2_svc_addr_by_name, 0x7e57);       /* no provider serves this name space */
    W_SETERR(0);
    r = WS(WSALookupServiceBeginA)(&qs, LUP_RETURN_NAME, &h);
    EXPECT_EQ(r, SOCKET_ERROR);
    CHECK(qs.lpszComment == NULL);
    EXPECT_EQ(qs.dwNumberOfCsAddrs, 0);
    EXPECT_EQ(qs.dwOutputFlags, 0);
}

TEST(gap2_lookup_begin_a_leaves_the_other_members_alone) {
    WSAQUERYSETA qs, before; char nm[] = "localhost", cm[] = "ws2t-comment"; HANDLE h = NULL; GUID cls = g2_svc_addr_by_name;
    int r;
    G2_NEED();
    dirty_a(&qs, cm, nm, &cls, NS_ALL);
    qs.dwSize = sizeof qs;
    before = qs;
    r = WS(WSALookupServiceBeginA)(&qs, LUP_RETURN_NAME, &h);
    CHECK(qs.dwSize == before.dwSize && qs.lpszServiceInstanceName == before.lpszServiceInstanceName);
    CHECK(qs.lpServiceClassId == before.lpServiceClassId && qs.dwNameSpace == before.dwNameSpace);
    CHECK(qs.lpVersion == before.lpVersion && qs.lpNSProviderId == before.lpNSProviderId);
    CHECK(qs.lpszContext == before.lpszContext && qs.dwNumberOfProtocols == before.dwNumberOfProtocols);
    CHECK(qs.lpafpProtocols == before.lpafpProtocols && qs.lpszQueryString == before.lpszQueryString);
    CHECK(qs.lpcsaBuffer == before.lpcsaBuffer && qs.lpBlob == before.lpBlob);
    EXPECT_STR(nm, "localhost");
    EXPECT_STR(cm, "ws2t-comment");
    if (r == 0) WS(WSALookupServiceEnd)(h);
}

/* The clearing is done on the caller's structure itself, once per call, also when the call is repeated. */
TEST(gap2_lookup_begin_a_clears_again_on_a_second_call) {
    WSAQUERYSETA qs; char nm[] = "localhost", cm[] = "ws2t-comment"; HANDLE h1 = NULL, h2 = NULL; int r1, r2;
    G2_NEED();
    dirty_a(&qs, cm, nm, &g2_svc_addr_by_name, NS_ALL);
    r1 = WS(WSALookupServiceBeginA)(&qs, LUP_RETURN_NAME, &h1);
    qs.dwOutputFlags = 0x66; qs.dwNumberOfCsAddrs = 3; qs.lpszComment = cm;
    r2 = WS(WSALookupServiceBeginA)(&qs, LUP_RETURN_NAME, &h2);
    CHECK(qs.lpszComment == NULL);
    EXPECT_EQ(qs.dwNumberOfCsAddrs, 0);
    EXPECT_EQ(qs.dwOutputFlags, 0);
    if (r1 == 0) WS(WSALookupServiceEnd)(h1);
    if (r2 == 0) WS(WSALookupServiceEnd)(h2);
}

static int first_a_result(BYTE *buf, DWORD cap, DWORD flags) {
    WSAQUERYSETA qs; char nm[] = "localhost"; HANDLE h = NULL; DWORD len = cap; int r;
    g2_qs_a(&qs, nm, &g2_svc_addr_by_name, NS_ALL);
    if (WS(WSALookupServiceBeginA)(&qs, flags, &h) != 0) return -1;
    memset(buf, 0xCD, cap);
    r = WS(WSALookupServiceNextA)(h, 0, &len, (LPWSAQUERYSETA)buf);
    WS(WSALookupServiceEnd)(h);
    return r == 0 ? 0 : W_ERR();
}

TEST(gap2_lookup_next_a_header_size_is_fixed) {
    BYTE buf[2048]; int r;
    G2_NEED();
    r = first_a_result(buf, sizeof buf, LUP_ALL_RETURNS);
    if (r != 0) { t_skip("no result for the loopback name (%d)", r); return; }
    EXPECT_EQ(((WSAQUERYSETA *)buf)->dwSize, sizeof(WSAQUERYSETA));
}

TEST(gap2_lookup_next_a_name_is_narrow_and_inside_buffer) {
    BYTE buf[2048]; int r; WSAQUERYSETA *q = (WSAQUERYSETA *)buf;
    G2_NEED();
    r = first_a_result(buf, sizeof buf, LUP_ALL_RETURNS);
    if (r != 0) { t_skip("no result for the loopback name (%d)", r); return; }
    CHECK(q->lpszServiceInstanceName != NULL);
    if (q->lpszServiceInstanceName) {
        CHECK((BYTE *)q->lpszServiceInstanceName >= buf + sizeof(WSAQUERYSETA) && (BYTE *)q->lpszServiceInstanceName < buf + sizeof buf);
        CHECK(strlen(q->lpszServiceInstanceName) > 1);   /* wide text would end after its first character */
    }
}

TEST(gap2_lookup_next_a_address_array_is_aligned_and_inside_buffer) {
    BYTE buf[2048]; int r; WSAQUERYSETA *q = (WSAQUERYSETA *)buf;
    G2_NEED();
    r = first_a_result(buf, sizeof buf, LUP_ALL_RETURNS);
    if (r != 0) { t_skip("no result for the loopback name (%d)", r); return; }
    CHECK(q->dwNumberOfCsAddrs > 0 && q->lpcsaBuffer != NULL);
    if (q->lpcsaBuffer) {
        CHECK((BYTE *)q->lpcsaBuffer >= buf + sizeof(WSAQUERYSETA) && (BYTE *)q->lpcsaBuffer < buf + sizeof buf);
        EXPECT_EQ((ULONG_PTR)q->lpcsaBuffer % sizeof(void *), 0);
    }
}

TEST(gap2_lookup_next_a_without_returns_has_no_name_or_addresses) {
    BYTE buf[2048]; int r; WSAQUERYSETA *q = (WSAQUERYSETA *)buf;
    G2_NEED();
    r = first_a_result(buf, sizeof buf, 0);
    if (r != 0) { t_skip("no result without return flags (%d)", r); return; }
    CHECK(q->lpcsaBuffer == NULL);
    EXPECT_EQ(q->dwNumberOfCsAddrs, 0);
}

/* Size protocol of the ANSI form: a short buffer yields WSAEFAULT with the size, and that size works. */
TEST(gap2_lookup_next_a_reported_size_is_sufficient) {
    WSAQUERYSETA qs; char nm[] = "localhost"; HANDLE h = NULL; DWORD len = 0; BYTE *buf; int r;
    G2_NEED();
    g2_qs_a(&qs, nm, &g2_svc_addr_by_name, NS_ALL);
    if (WS(WSALookupServiceBeginA)(&qs, LUP_ALL_RETURNS, &h) != 0) { t_skip("begin failed"); return; }
    W_SETERR(0);
    r = WS(WSALookupServiceNextA)(h, 0, &len, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_FAULT);
    if (len == 0) { WS(WSALookupServiceEnd)(h); CHECK(len != 0); return; }
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    r = WS(WSALookupServiceNextA)(h, 0, &len, (LPWSAQUERYSETA)buf);
    CHECKF(r == 0, "second call with the reported size returned %d (error %d)", r, W_ERR());
    HeapFree(GetProcessHeap(), 0, buf);
    WS(WSALookupServiceEnd)(h);
}

/* Begin, ANSI form, with every present/absent mix of the string members and an unserved name space: the
 * conversion is transparent, so the outcome equals the outcome with no strings at all. */
TEST(gap2_lookup_begin_a_string_member_combinations_match_baseline) {
    int mask, base_r = 0, base_e = 0;
    G2_NEED();
    for (mask = 0; mask < 16; mask++) {
        WSAQUERYSETA qs; char n[] = "ws2t-name", c[] = "ws2t-comment", x[] = "\\", q[] = "ws2t=1"; HANDLE h = NULL; int r, e;
        g2_qs_a(&qs, (mask & 1) ? n : NULL, &g2_guid_throwaway, 0x7e57);
        qs.lpszContext = (mask & 4) ? x : NULL;
        qs.lpszQueryString = (mask & 8) ? q : NULL;
        qs.lpszComment = (mask & 2) ? c : NULL;       /* cleared by the call itself */
        W_SETERR(0);
        r = WS(WSALookupServiceBeginA)(&qs, LUP_RETURN_NAME, &h);
        e = W_ERR();
        if (r == 0) WS(WSALookupServiceEnd)(h);
        if (mask == 0) { base_r = r; base_e = e; CHECK(r == SOCKET_ERROR); }
        else CHECKF(r == base_r && e == base_e, "mask %d: r=%d err=%d, baseline r=%d err=%d", mask, r, e, base_r, base_e);
    }
}

/* A lookup aimed at one catalog provider by its id: the DNS provider answers the loopback host name, no other
 * inbox provider does. */
TEST(gap2_lookup_begin_by_provider_id_only_dns_resolves_host_names) {
    int n = 0, i; WSANAMESPACE_INFOW *c;
    G2_NEED();
    c = g2_catalog(&n);
    if (!c) { t_skip("no catalog"); return; }
    for (i = 0; i < n; i++) {
        WSAQUERYSETW qs; static WCHAR nm[] = L"localhost"; HANDLE h = NULL; int r;
        g2_qs_w(&qs, nm, &g2_svc_addr_by_name, c[i].dwNameSpace);
        qs.lpNSProviderId = &c[i].NSProviderId;
        W_SETERR(0);
        r = WS(WSALookupServiceBeginW)(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h);
        if (c[i].dwNameSpace == NS_DNS) { CHECKF(r == 0, "DNS provider refused (%d)", W_ERR()); }
        else { CHECKF(r == SOCKET_ERROR, "name space %lu accepted a host-name query", (unsigned long)c[i].dwNameSpace);
               t_note("name space %lu: error %d", (unsigned long)c[i].dwNameSpace, W_ERR()); }
        if (r == 0) WS(WSALookupServiceEnd)(h);
    }
    g2_free(c);
}
