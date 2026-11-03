/* GetAddrInfoExA, SetAddrInfoExA/W, GetNameInfoW, WSAStringToAddressW and WSAGetQOSByName.
 * Measures: argument rejection that the entry points perform themselves (asynchronous-only parameters of the
 * ANSI query, the extended-hints version field, the reserved parameters of the registration calls,
 * socket-address length and family checks of the reverse lookup), what each call returns versus what it
 * leaves as the last error, which output members are written or left alone, and how the registration
 * calls pick providers. Only numeric loopback names are resolved. */
#include "g2.h"

/* ------------------------------------------------------------------------------------------------ */
/* GetAddrInfoExA                                                                                    */
/* ------------------------------------------------------------------------------------------------ */

static int gaex_a(const char *name, DWORD ns, const ADDRINFOEXA *hints, ADDRINFOEXA **res,
                  struct timeval *tmo, OVERLAPPED *ov, LPLOOKUPSERVICE_COMPLETION_ROUTINE cr, HANDLE *h) {
    return WS(GetAddrInfoExA)(name, NULL, ns, NULL, hints, res, tmo, ov, cr, h);
}
static void completion_stub(DWORD e, DWORD b, LPWSAOVERLAPPED o) { (void)e; (void)b; (void)o; }

/* The ANSI query is synchronous only: any of the four asynchronous parameters is refused. */
TEST(gap2_addr_exa_timeout_parameter_refused) {
    struct timeval tv = { 1, 0 }; ADDRINFOEXA *res = (ADDRINFOEXA *)(ULONG_PTR)0x1; int r;
    G2_NEED();
    W_SETERR(0);
    r = gaex_a("127.0.0.1", NS_DNS, NULL, &res, &tv, NULL, NULL, NULL);
    EXPECT_EQ(r, GE_INVAL);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    EXPECT_EQ(res, NULL);
}
TEST(gap2_addr_exa_overlapped_parameter_refused) {
    OVERLAPPED ov; ADDRINFOEXA *res = (ADDRINFOEXA *)(ULONG_PTR)0x1; int r;
    G2_NEED();
    memset(&ov, 0, sizeof ov);
    W_SETERR(0);
    r = gaex_a("127.0.0.1", NS_DNS, NULL, &res, NULL, &ov, NULL, NULL);
    EXPECT_EQ(r, GE_INVAL);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    EXPECT_EQ(res, NULL);
}
TEST(gap2_addr_exa_completion_routine_parameter_refused) {
    ADDRINFOEXA *res = (ADDRINFOEXA *)(ULONG_PTR)0x1; int r;
    G2_NEED();
    W_SETERR(0);
    r = gaex_a("127.0.0.1", NS_DNS, NULL, &res, NULL, NULL, (LPLOOKUPSERVICE_COMPLETION_ROUTINE)completion_stub, NULL);
    EXPECT_EQ(r, GE_INVAL);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    EXPECT_EQ(res, NULL);
}
TEST(gap2_addr_exa_handle_parameter_refused) {
    HANDLE h = NULL; ADDRINFOEXA *res = (ADDRINFOEXA *)(ULONG_PTR)0x1; int r;
    G2_NEED();
    W_SETERR(0);
    r = gaex_a("127.0.0.1", NS_DNS, NULL, &res, NULL, NULL, NULL, &h);
    EXPECT_EQ(r, GE_INVAL);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    EXPECT_EQ(res, NULL);
    EXPECT_EQ(h, NULL);
}
TEST(gap2_addr_exa_all_async_parameters_refused_before_name_is_read) {
    /* The refusal precedes any use of the name, so even a name that would not resolve is irrelevant. */
    struct timeval tv = { 1, 0 }; ADDRINFOEXA *res = (ADDRINFOEXA *)(ULONG_PTR)0x1; int r;
    G2_NEED();
    r = gaex_a("ws2t-no-such-host.invalid", NS_DNS, NULL, &res, &tv, NULL, NULL, NULL);
    EXPECT_EQ(r, GE_INVAL);
    EXPECT_EQ(res, NULL);
}

/* Extended hints: a negative flags member announces a version-carrying structure whose version must be 2..4. */
TEST(gap2_addr_exa_extended_hints_version_table) {
    static const struct { int ver; int ok; } rows[] = {
        { 0, 0 }, { 1, 0 }, { 2, 1 }, { 3, 1 }, { 4, 1 }, { 5, 0 }, { 6, 0 }, { 0x7fffffff, 0 }, { -1, 0 },
    };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(rows); i++) {
        BYTE hints[0x80]; ADDRINFOEXA *res = NULL; int r;
        memset(hints, 0, sizeof hints);
        *(int *)(hints + 0) = (int)0x80000000;       /* extended-structure flag */
        *(int *)(hints + 4) = AF_INET;
        *(int *)(hints + 0x48) = rows[i].ver;
        W_SETERR(0);
        r = gaex_a("127.0.0.1", NS_DNS, (const ADDRINFOEXA *)hints, &res, NULL, NULL, NULL, NULL);
        if (rows[i].ok) { CHECKF(r == 0, "version %d returned %d", rows[i].ver, r); }
        else { CHECKF(r == GE_INVAL, "version %d returned %d", rows[i].ver, r); }
        CHECKF(rows[i].ok == (res != NULL), "version %d: result pointer %p", rows[i].ver, (void *)res);
        if (res) WS(FreeAddrInfoEx)(res);
    }
}

TEST(gap2_addr_exa_success_clears_last_error) {
    ADDRINFOEXA *res = NULL; int r;
    G2_NEED();
    W_SETERR(0x1234);
    r = gaex_a("127.0.0.1", NS_DNS, NULL, &res, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(W_ERR(), 0);
    if (res) WS(FreeAddrInfoEx)(res);
}

TEST(gap2_addr_exa_numeric_loopback_result_shape) {
    ADDRINFOEXA *res = NULL; int r;
    G2_NEED();
    r = gaex_a("127.0.0.1", NS_DNS, NULL, &res, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0);
    if (!res) { CHECK(res != NULL); return; }
    EXPECT_EQ(res->ai_family, AF_INET);
    EXPECT_EQ(res->ai_addrlen, sizeof(struct sockaddr_in));
    CHECK(res->ai_next == NULL);
    CHECK(res->ai_addr != NULL);
    if (res->ai_addr) EXPECT_EQ(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr, 0x0100007f);
    WS(FreeAddrInfoEx)(res);
}

TEST(gap2_addr_exa_canonical_name_is_narrow_text) {
    ADDRINFOEXA hints, *res = NULL; int r;
    G2_NEED();
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_CANONNAME | AI_NUMERICHOST;
    hints.ai_family = AF_INET;
    r = gaex_a("127.0.0.1", NS_DNS, &hints, &res, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0);
    if (!res) return;
    CHECK(res->ai_canonname != NULL);
    if (res->ai_canonname) EXPECT_STR(res->ai_canonname, "127.0.0.1");   /* narrow text, the numeric host itself */
    WS(FreeAddrInfoEx)(res);
}

TEST(gap2_addr_exa_matches_wide_on_list_length_and_order) {
    ADDRINFOEXA *a = NULL; ADDRINFOEXW *w = NULL, *wp; ADDRINFOEXA *ap; int ra, rw, na = 0, nw = 0, same = 1;
    G2_NEED();
    ra = gaex_a("localhost", NS_DNS, NULL, &a, NULL, NULL, NULL, NULL);
    rw = WS(GetAddrInfoExW)(L"localhost", NULL, NS_DNS, NULL, NULL, &w, NULL, NULL, NULL, NULL);
    CHECKF(ra == rw, "A %d W %d", ra, rw);
    if (ra == 0 && rw == 0) {
        for (ap = a, wp = w; ap || wp; ap = ap ? ap->ai_next : NULL, wp = wp ? wp->ai_next : NULL) {
            if (ap) na++;
            if (wp) nw++;
            if (ap && wp && (ap->ai_family != wp->ai_family || ap->ai_addrlen != wp->ai_addrlen)) same = 0;
        }
        CHECKF(na == nw && na > 0, "A has %d entries, W has %d", na, nw);
        CHECK(same);
    }
    if (a) WS(FreeAddrInfoEx)(a);
    if (w) WS(FreeAddrInfoExW)(w);
}

/* ------------------------------------------------------------------------------------------------ */
/* SetAddrInfoExA / SetAddrInfoExW                                                                   */
/* ------------------------------------------------------------------------------------------------ */

typedef enum { RES_TIMEOUT, RES_OVERLAPPED, RES_COMPLETION, RES_HANDLE, RES_NONE } reserved_kind;
static const char *rk_name[] = { "timeout", "overlapped", "completion routine", "handle", "none" };

static INT set_w(const WCHAR *name, const WCHAR *svc, DWORD count, DWORD ns, GUID *nspid, reserved_kind rk) {
    struct sockaddr_in a; SOCKET_ADDRESS sa; struct timeval tv = { 1, 0 }; OVERLAPPED ov; HANDLE h = NULL;
    g2_loop4(&a, 0x5000); sa.lpSockaddr = (LPSOCKADDR)&a; sa.iSockaddrLength = sizeof a;
    memset(&ov, 0, sizeof ov);
    return WS(SetAddrInfoExW)(name, svc, count ? &sa : NULL, count, NULL, 0, ns, nspid,
                              rk == RES_TIMEOUT ? &tv : NULL, rk == RES_OVERLAPPED ? &ov : NULL,
                              rk == RES_COMPLETION ? (LPLOOKUPSERVICE_COMPLETION_ROUTINE)completion_stub : NULL,
                              rk == RES_HANDLE ? &h : NULL);
}
static INT set_a(const char *name, const char *svc, DWORD count, DWORD ns, GUID *nspid, reserved_kind rk) {
    struct sockaddr_in a; SOCKET_ADDRESS sa; struct timeval tv = { 1, 0 }; OVERLAPPED ov; HANDLE h = NULL;
    g2_loop4(&a, 0x5000); sa.lpSockaddr = (LPSOCKADDR)&a; sa.iSockaddrLength = sizeof a;
    memset(&ov, 0, sizeof ov);
    return WS(SetAddrInfoExA)(name, svc, count ? &sa : NULL, count, NULL, 0, ns, nspid,
                              rk == RES_TIMEOUT ? &tv : NULL, rk == RES_OVERLAPPED ? &ov : NULL,
                              rk == RES_COMPLETION ? (LPLOOKUPSERVICE_COMPLETION_ROUTINE)completion_stub : NULL,
                              rk == RES_HANDLE ? &h : NULL);
}

/* The registration call is synchronous only; the four trailing parameters must be NULL. */
TEST(gap2_addr_setex_w_asynchronous_parameters_refused) {
    int k;
    G2_NEED();
    for (k = RES_TIMEOUT; k <= RES_HANDLE; k++) {
        INT r = set_w(L"ws2t-host", NULL, 1, 0x7e57, NULL, (reserved_kind)k);
        CHECKF(r == GE_INVAL, "%s: returned %d", rk_name[k], r);
    }
}
TEST(gap2_addr_setex_a_asynchronous_parameters_refused) {
    int k;
    G2_NEED();
    for (k = RES_TIMEOUT; k <= RES_HANDLE; k++) {
        INT r = set_a("ws2t-host", NULL, 1, 0x7e57, NULL, (reserved_kind)k);
        CHECKF(r == GE_INVAL, "%s: returned %d", rk_name[k], r);
    }
}
/* The refusal happens before any provider is chosen, so the name space does not matter. */
TEST(gap2_addr_setex_asynchronous_refusal_precedes_provider_selection) {
    static const DWORD spaces[] = { 0x7e57, NS_DNS, NS_ALL };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(spaces); i++) {
        CHECKF(set_w(L"ws2t-host", NULL, 0, spaces[i], NULL, RES_OVERLAPPED) == GE_INVAL, "W name space %lu", (unsigned long)spaces[i]);
        CHECKF(set_a("ws2t-host", NULL, 0, spaces[i], NULL, RES_HANDLE) == GE_INVAL, "A name space %lu", (unsigned long)spaces[i]);
    }
}

TEST(gap2_addr_setex_w_unserved_namespace_is_no_data) {
    DWORD counts[] = { 0, 1, 0xffffffffu };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(counts); i++) {
        INT r = set_w(L"ws2t-host", NULL, counts[i] == 0xffffffffu ? 0 : counts[i], 0x7e57, NULL, RES_NONE);
        CHECKF(r == GE_NODATA, "count %lu returned %d", (unsigned long)counts[i], r);
    }
}
TEST(gap2_addr_setex_a_unserved_namespace_is_no_data) {
    INT r;
    G2_NEED();
    r = set_a("ws2t-host", NULL, 1, 0x7e57, NULL, RES_NONE);
    EXPECT_EQ(r, GE_NODATA);
    r = set_a("ws2t-host", NULL, 0, 0x7e57, NULL, RES_NONE);
    EXPECT_EQ(r, GE_NODATA);
}
/* Counts of zero, one and "all ones" only choose the operation; the outcome through the DNS provider is the same. */
TEST(gap2_addr_setex_dns_namespace_not_supported_for_every_count) {
    static const DWORD counts[] = { 0, 1, 2 };
    int i; GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    for (i = 0; i < G2_N(counts); i++) {
        struct sockaddr_in a[2]; SOCKET_ADDRESS sa[2]; INT r;
        g2_loop4(&a[0], 0x5000); g2_loop4(&a[1], 0x5001);
        sa[0].lpSockaddr = (LPSOCKADDR)&a[0]; sa[0].iSockaddrLength = sizeof a[0];
        sa[1].lpSockaddr = (LPSOCKADDR)&a[1]; sa[1].iSockaddrLength = sizeof a[1];
        r = WS(SetAddrInfoExW)(L"ws2t-host", NULL, counts[i] ? sa : NULL, counts[i], NULL, 0, NS_DNS, NULL, NULL, NULL, NULL, NULL);
        CHECKF(r == GE_NOTSUPP32, "count %lu returned %d", (unsigned long)counts[i], r);
    }
}
TEST(gap2_addr_setex_a_dns_namespace_not_supported) {
    GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    EXPECT_EQ(set_a("ws2t-host", NULL, 1, NS_DNS, NULL, RES_NONE), GE_NOTSUPP32);
}
TEST(gap2_addr_setex_provider_id_overrides_namespace) {
    GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    EXPECT_EQ(set_w(L"ws2t-host", NULL, 1, 0x7e57, &id, RES_NONE), GE_NOTSUPP32);
    EXPECT_EQ(set_a("ws2t-host", NULL, 1, 0x7e57, &id, RES_NONE), GE_NOTSUPP32);
}
TEST(gap2_addr_setex_unserved_provider_id_is_no_data) {
    GUID ghost = g2_guid_throwaway;
    G2_NEED();
    EXPECT_EQ(set_w(L"ws2t-host", NULL, 1, NS_DNS, &ghost, RES_NONE), GE_NODATA);
    EXPECT_EQ(set_a("ws2t-host", NULL, 1, NS_DNS, &ghost, RES_NONE), GE_NODATA);
}
/* A service name is resolved to a port before the provider is chosen. */
TEST(gap2_addr_setex_numeric_and_well_known_service_names_reach_provider_selection) {
    static const WCHAR *svcs[] = { L"8080", L"0", L"65535", L"http" };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(svcs); i++) {
        INT r = set_w(L"ws2t-host", svcs[i], 1, 0x7e57, NULL, RES_NONE);
        CHECKF(r == GE_NODATA, "service %d returned %d", i, r);
    }
}
TEST(gap2_addr_setex_unknown_service_name_is_type_not_found) {
    INT r;
    G2_NEED();
    r = set_w(L"ws2t-host", L"ws2t-no-such-service", 1, 0x7e57, NULL, RES_NONE);
    EXPECT_EQ(r, 10109);   /* WSATYPE_NOT_FOUND */
}
TEST(gap2_addr_setex_a_numeric_service_name_reaches_provider_selection) {
    G2_NEED();
    EXPECT_EQ(set_a("ws2t-host", "8080", 1, 0x7e57, NULL, RES_NONE), GE_NODATA);
}

/* ------------------------------------------------------------------------------------------------ */
/* GetNameInfoW                                                                                      */
/* ------------------------------------------------------------------------------------------------ */

static void sa4(struct sockaddr_in *a, unsigned long addr_be, unsigned short port_host) {
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET; a->sin_port = (unsigned short)((port_host >> 8) | (port_host << 8)); a->sin_addr.s_addr = addr_be;
}
static void sa6(struct sockaddr_in6 *a, const BYTE *addr16, unsigned short port_host, ULONG scope) {
    memset(a, 0, sizeof *a);
    a->sin6_family = AF_INET6; a->sin6_port = (unsigned short)((port_host >> 8) | (port_host << 8));
    memcpy(&a->sin6_addr, addr16, 16); a->sin6_scope_id = scope;
}
static const BYTE v6_loop[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const BYTE v6_ll[16]   = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

static int gni(const void *sa, int len, WCHAR *host, DWORD hl, WCHAR *svc, DWORD sl, int flags) {
    return WS(GetNameInfoW)((const SOCKADDR *)sa, len, host, hl, svc, sl, flags);
}

TEST(gap2_addr_nameinfo_null_address_is_fault) {
    WCHAR host[64]; int r;
    G2_NEED();
    W_SETERR(0);
    r = gni(NULL, sizeof(struct sockaddr_in), host, 64, NULL, 0, NI_NUMERICHOST);
    EXPECT_EQ(r, GE_FAULT);
    EXPECT_EQ(W_ERR(), GE_FAULT);
}

typedef struct { int af; int len; int want; } len_row;
static const len_row len_rows[] = {
    { AF_INET, 0, GE_FAULT }, { AF_INET, 1, GE_FAULT }, { AF_INET, 8, GE_FAULT }, { AF_INET, 15, GE_FAULT }, { AF_INET, -1, GE_FAULT },
    { AF_INET6, 0, GE_FAULT }, { AF_INET6, 16, GE_FAULT }, { AF_INET6, 27, GE_FAULT }, { AF_INET6, -1, GE_FAULT },
};
TEST(gap2_addr_nameinfo_short_length_is_fault) {
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(len_rows); i++) {
        BYTE buf[sizeof(struct sockaddr_in6)]; WCHAR host[64]; int r;
        memset(buf, 0, sizeof buf);
        if (len_rows[i].af == AF_INET) sa4((struct sockaddr_in *)buf, 0x0100007f, 80);
        else sa6((struct sockaddr_in6 *)buf, v6_loop, 80, 0);
        W_SETERR(0);
        r = gni(buf, len_rows[i].len, host, 64, NULL, 0, NI_NUMERICHOST);
        CHECKF(r == len_rows[i].want, "row %d returned %d", i, r);
        CHECKF(W_ERR() == len_rows[i].want, "row %d error %d", i, W_ERR());
    }
}
TEST(gap2_addr_nameinfo_minimum_lengths_accepted) {
    struct sockaddr_in a4; struct sockaddr_in6 a6; WCHAR host[64];
    G2_NEED();
    sa4(&a4, 0x0100007f, 80); sa6(&a6, v6_loop, 80, 0);
    EXPECT_EQ(gni(&a4, 16, host, 64, NULL, 0, NI_NUMERICHOST), 0);
    EXPECT_EQ(gni(&a6, 28, host, 64, NULL, 0, NI_NUMERICHOST), 0);
}
TEST(gap2_addr_nameinfo_longer_than_needed_length_accepted) {
    BYTE buf[64]; WCHAR host[64];
    G2_NEED();
    memset(buf, 0, sizeof buf);
    sa4((struct sockaddr_in *)buf, 0x0100007f, 80);
    EXPECT_EQ(gni(buf, 64, host, 64, NULL, 0, NI_NUMERICHOST), 0);
    EXPECT_EQ(wcscmp(host, L"127.0.0.1"), 0);
}
/* The family test comes before the length test. */
TEST(gap2_addr_nameinfo_family_table) {
    static const struct { int af; int len; } rows[] = {
        { AF_UNSPEC, 28 }, { AF_UNIX, 28 }, { AF_UNIX, 0 }, { AF_IPX, 28 }, { AF_NETBIOS, 28 }, { 0x7e57, 28 }, { 0xffff, 0 },
        { AF_INET, 16 }, { AF_INET6, 28 },
    };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(rows); i++) {
        BYTE buf[sizeof(struct sockaddr_in6)]; WCHAR host[64]; int r; int ok = rows[i].af == AF_INET || rows[i].af == AF_INET6;
        memset(buf, 0, sizeof buf);
        *(USHORT *)buf = (USHORT)rows[i].af;
        if (rows[i].af == AF_INET6) memcpy(buf + 8, v6_loop, 16);
        W_SETERR(0);
        r = gni(buf, rows[i].len, host, 64, NULL, 0, NI_NUMERICHOST);
        if (ok) CHECKF(r == 0, "row %d returned %d", i, r);
        else { CHECKF(r == GE_AFNOSUPPORT, "row %d returned %d", i, r); CHECKF(W_ERR() == GE_AFNOSUPPORT, "row %d error %d", i, W_ERR()); }
    }
}
TEST(gap2_addr_nameinfo_success_clears_last_error) {
    struct sockaddr_in a; WCHAR host[64];
    G2_NEED();
    sa4(&a, 0x0100007f, 80);
    W_SETERR(0x4321);
    EXPECT_EQ(gni(&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST), 0);
    EXPECT_EQ(W_ERR(), 0);
}
TEST(gap2_addr_nameinfo_no_outputs_requested_succeeds) {
    struct sockaddr_in a;
    G2_NEED();
    sa4(&a, 0x0100007f, 80);
    W_SETERR(0x4321);
    EXPECT_EQ(gni(&a, sizeof a, NULL, 0, NULL, 0, 0), 0);
    EXPECT_EQ(W_ERR(), 0);
}
TEST(gap2_addr_nameinfo_null_buffers_ignore_their_lengths) {
    struct sockaddr_in a;
    G2_NEED();
    sa4(&a, 0x0100007f, 80);
    EXPECT_EQ(gni(&a, sizeof a, NULL, 64, NULL, 64, NI_NUMERICHOST | NI_NUMERICSERV), 0);
}
TEST(gap2_addr_nameinfo_numeric_host_has_no_port) {
    struct sockaddr_in a; WCHAR host[64];
    G2_NEED();
    sa4(&a, 0x0100007f, 8080);
    EXPECT_EQ(gni(&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST), 0);
    EXPECT_EQ(wcscmp(host, L"127.0.0.1"), 0);
}
TEST(gap2_addr_nameinfo_numeric_host_v6_loopback_and_scope) {
    struct sockaddr_in6 a; WCHAR host[64];
    G2_NEED();
    sa6(&a, v6_loop, 80, 0);
    EXPECT_EQ(gni(&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST), 0);
    EXPECT_EQ(wcscmp(host, L"::1"), 0);
    sa6(&a, v6_ll, 80, 0);
    EXPECT_EQ(gni(&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST), 0);
    EXPECT_EQ(wcscmp(host, L"fe80::1"), 0);
    sa6(&a, v6_ll, 80, 5);
    EXPECT_EQ(gni(&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST), 0);
    EXPECT_EQ(wcscmp(host, L"fe80::1%5"), 0);
}
TEST(gap2_addr_nameinfo_numeric_host_exact_and_short_buffers) {
    struct sockaddr_in a; WCHAR host[16]; int r;
    G2_NEED();
    sa4(&a, 0x0100007f, 80);
    r = gni(&a, sizeof a, host, 10, NULL, 0, NI_NUMERICHOST);       /* "127.0.0.1" + terminator */
    EXPECT_EQ(r, 0);
    wmemset(host, 0xCDCD, 16);
    W_SETERR(0);
    r = gni(&a, sizeof a, host, 9, NULL, 0, NI_NUMERICHOST);
    EXPECT_EQ(r, GE_FAULT);
    EXPECT_EQ(W_ERR(), GE_FAULT);
    r = gni(&a, sizeof a, host, 1, NULL, 0, NI_NUMERICHOST);
    EXPECT_EQ(r, GE_FAULT);
}
TEST(gap2_addr_nameinfo_numeric_host_wins_over_name_required) {
    struct sockaddr_in a; WCHAR host[64];
    G2_NEED();
    sa4(&a, 0x0100007f, 80);
    EXPECT_EQ(gni(&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST | NI_NAMEREQD), 0);
    EXPECT_EQ(wcscmp(host, L"127.0.0.1"), 0);
}
TEST(gap2_addr_nameinfo_unknown_flag_bits_ignored) {
    struct sockaddr_in a; WCHAR host[64];
    G2_NEED();
    sa4(&a, 0x0100007f, 80);
    EXPECT_EQ(gni(&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST | 0x100), 0);
    EXPECT_EQ(gni(&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST | 0x80000000), 0);
}
TEST(gap2_addr_nameinfo_numeric_service_values) {
    static const struct { unsigned short port; const WCHAR *want; } rows[] = {
        { 0, L"0" }, { 1, L"1" }, { 80, L"80" }, { 8080, L"8080" }, { 65535, L"65535" },
    };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(rows); i++) {
        struct sockaddr_in a; WCHAR svc[16];
        sa4(&a, 0x0100007f, rows[i].port);
        wmemset(svc, 0xCDCD, 16);
        CHECKF(gni(&a, sizeof a, NULL, 0, svc, 16, NI_NUMERICSERV) == 0, "port %u", rows[i].port);
        CHECKF(!wcscmp(svc, rows[i].want), "port %u gave a different text", rows[i].port);
    }
}
TEST(gap2_addr_nameinfo_zero_service_length_leaves_buffer) {
    struct sockaddr_in a; WCHAR svc[4]; int r;
    G2_NEED();
    sa4(&a, 0x0100007f, 80);
    wmemset(svc, 0xCDCD, 4);
    r = gni(&a, sizeof a, NULL, 0, svc, 0, NI_NUMERICSERV);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(svc[0], 0xCDCD);
}
TEST(gap2_addr_nameinfo_service_buffer_too_small) {
    struct sockaddr_in a; WCHAR svc[8]; int r;
    G2_NEED();
    sa4(&a, 0x0100007f, 8080);
    wmemset(svc, 0xCDCD, 8);
    W_SETERR(0);
    r = gni(&a, sizeof a, NULL, 0, svc, 2, NI_NUMERICSERV);
    EXPECT_EQ(r, ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(W_ERR(), ERROR_INSUFFICIENT_BUFFER);
}
TEST(gap2_addr_nameinfo_host_and_service_together) {
    struct sockaddr_in a; WCHAR host[32], svc[16];
    G2_NEED();
    sa4(&a, 0x0100007f, 443);
    EXPECT_EQ(gni(&a, sizeof a, host, 32, svc, 16, NI_NUMERICHOST | NI_NUMERICSERV), 0);
    EXPECT_EQ(wcscmp(host, L"127.0.0.1"), 0);
    EXPECT_EQ(wcscmp(svc, L"443"), 0);
}
TEST(gap2_addr_nameinfo_failure_before_service_leaves_service_buffer) {
    struct sockaddr_in a; WCHAR host[4], svc[8]; int r;
    G2_NEED();
    sa4(&a, 0x0100007f, 443);
    wmemset(svc, 0xCDCD, 8);
    r = gni(&a, sizeof a, host, 2, svc, 8, NI_NUMERICHOST | NI_NUMERICSERV);   /* host buffer too small */
    EXPECT_EQ(r, GE_FAULT);
    EXPECT_EQ(svc[0], 0xCDCD);
}

/* The service text of a port comes from the services database; ports that have no entry come back as digits. */
TEST(gap2_addr_nameinfo_service_names_for_well_known_ports) {
    static const struct { unsigned short port; int flags; const WCHAR *text; } rows[] = {
        { 80, 0, L"http" }, { 443, 0, L"https" }, { 53, NI_DGRAM, L"domain" }, { 0, 0, L"0" },
    };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(rows); i++) {
        struct sockaddr_in a; WCHAR svc[64]; int r;
        sa4(&a, 0x0100007f, rows[i].port);
        wmemset(svc, 0, 64);
        r = gni(&a, sizeof a, NULL, 0, svc, 64, rows[i].flags);
        CHECKF(r == 0, "port %u returned %d", rows[i].port, r);
        CHECKF(!wcscmp(svc, rows[i].text), "port %u gave a different text", rows[i].port);
    }
}
TEST(gap2_addr_nameinfo_numeric_service_flag_beats_the_services_database) {
    struct sockaddr_in a; WCHAR svc[16];
    G2_NEED();
    sa4(&a, 0x0100007f, 80);
    EXPECT_EQ(gni(&a, sizeof a, NULL, 0, svc, 16, NI_NUMERICSERV), 0);
    EXPECT_EQ(wcscmp(svc, L"80"), 0);
}
TEST(gap2_addr_nameinfo_numeric_ipv4_table) {
    static const struct { unsigned long be; const WCHAR *text; } rows[] = {
        { 0x00000000, L"0.0.0.0" }, { 0xffffffff, L"255.255.255.255" }, { 0x04030201, L"1.2.3.4" },
        { 0x281e140a, L"10.20.30.40" }, { 0x01ffa8c0, L"192.168.255.1" }, { 0x010000e0, L"224.0.0.1" },
        { 0x0101fea9, L"169.254.1.1" }, { 0x0100007f, L"127.0.0.1" },
    };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(rows); i++) {
        struct sockaddr_in a; WCHAR host[32];
        sa4(&a, rows[i].be, 1234);
        CHECKF(gni(&a, sizeof a, host, 32, NULL, 0, NI_NUMERICHOST) == 0, "row %d", i);
        CHECKF(!wcscmp(host, rows[i].text), "row %d text differs", i);
    }
}
TEST(gap2_addr_nameinfo_numeric_ipv6_table) {
    static const struct { BYTE a[16]; const WCHAR *text; } rows[] = {
        { { 0 }, L"::" },
        { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, L"::1" },
        { { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, L"2001:db8::1" },
        { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, L"ff02::1" },
        { { 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6 }, L"2001:db8:1:2:3:4:5:6" },
    };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(rows); i++) {
        struct sockaddr_in6 a; WCHAR host[64];
        sa6(&a, rows[i].a, 99, 0);
        CHECKF(gni(&a, sizeof a, host, 64, NULL, 0, NI_NUMERICHOST) == 0, "row %d", i);
        CHECKF(!wcscmp(host, rows[i].text), "row %d text differs", i);
    }
}
TEST(gap2_addr_nameinfo_flow_label_and_zero_bytes_are_ignored) {
    struct sockaddr_in6 a; struct sockaddr_in b; WCHAR h1[64], h2[64];
    G2_NEED();
    sa6(&a, v6_loop, 80, 0);
    a.sin6_flowinfo = 0x12345;
    EXPECT_EQ(gni(&a, sizeof a, h1, 64, NULL, 0, NI_NUMERICHOST), 0);
    EXPECT_EQ(wcscmp(h1, L"::1"), 0);
    sa4(&b, 0x0100007f, 80);
    memset(b.sin_zero, 0xAA, sizeof b.sin_zero);
    EXPECT_EQ(gni(&b, sizeof b, h2, 64, NULL, 0, NI_NUMERICHOST), 0);
    EXPECT_EQ(wcscmp(h2, L"127.0.0.1"), 0);
}
TEST(gap2_addr_nameinfo_does_not_modify_the_address) {
    struct sockaddr_in a, before; WCHAR host[32];
    G2_NEED();
    sa4(&a, 0x0100007f, 8080);
    before = a;
    gni(&a, sizeof a, host, 32, NULL, 0, NI_NUMERICHOST);
    CHECK(!memcmp(&a, &before, sizeof a));
}

/* ------------------------------------------------------------------------------------------------ */
/* WSAStringToAddressW provider selection                                                            */
/* ------------------------------------------------------------------------------------------------ */

static int first_entry_for(int af, int type, WSAPROTOCOL_INFOW *out) {
    DWORD len = 0; WSAPROTOCOL_INFOW *p; int n, i, found = 0;
    if (!g2_up()) return 0;
    WS(WSAEnumProtocolsW)(NULL, NULL, &len);
    if (!len) return 0;
    p = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, len);
    n = WS(WSAEnumProtocolsW)(NULL, p, &len);
    for (i = 0; i < n; i++)
        if (p[i].iAddressFamily == af && p[i].iSocketType == type && !found) { *out = p[i]; found = 1; }
    HeapFree(GetProcessHeap(), 0, p);
    return found;
}

/* With a protocol-info argument only its catalog entry id selects the provider; everything else in it is ignored. */
TEST(gap2_addr_s2a_protocol_info_only_catalog_id_matters) {
    WSAPROTOCOL_INFOW pi; struct sockaddr_in a; INT len = sizeof a; int r;
    G2_NEED();
    if (!first_entry_for(AF_INET, SOCK_STREAM, &pi)) { t_skip("no IPv4 stream entry"); return; }
    pi.iAddressFamily = 0x7e57; pi.iSocketType = 99; pi.iProtocol = 12345;
    memset(pi.szProtocol, 'x', sizeof pi.szProtocol);
    r = WS(WSAStringToAddressW)((LPWSTR)L"127.0.0.1:80", AF_INET, &pi, (LPSOCKADDR)&a, &len);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(a.sin_family, AF_INET);
    EXPECT_EQ(a.sin_port, 0x5000);
    EXPECT_EQ(len, sizeof a);
}
TEST(gap2_addr_s2a_protocol_info_unknown_catalog_id) {
    WSAPROTOCOL_INFOW pi; struct sockaddr_in a; INT len = sizeof a; int r;
    G2_NEED();
    memset(&pi, 0, sizeof pi);
    pi.dwCatalogEntryId = 0x7e57e57;
    W_SETERR(0);
    r = WS(WSAStringToAddressW)((LPWSTR)L"127.0.0.1", AF_INET, &pi, (LPSOCKADDR)&a, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_INVAL);
}
TEST(gap2_addr_s2a_unspecified_family_without_protocol_info_is_invalid) {
    char buf[64]; INT len = sizeof buf; int r;
    G2_NEED();
    W_SETERR(0);
    r = WS(WSAStringToAddressW)((LPWSTR)L"127.0.0.1", AF_UNSPEC, NULL, (LPSOCKADDR)buf, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_INVAL);
}

TEST(gap2_addr_s2a_unknown_family_without_protocol_info) {
    char buf[64]; INT len = sizeof buf; int r;
    G2_NEED();
    W_SETERR(0);
    r = WS(WSAStringToAddressW)((LPWSTR)L"127.0.0.1", 0x7e57, NULL, (LPSOCKADDR)buf, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_INVAL);
}

/* ------------------------------------------------------------------------------------------------ */
/* WSAGetQOSByName                                                                                   */
/* ------------------------------------------------------------------------------------------------ */

TEST(gap2_addr_qos_plain_event_handle_is_not_a_socket) {
    HANDLE ev; WSABUF nm; QOS q; BOOL r; char t[] = "x";
    G2_NEED();
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    nm.buf = t; nm.len = 1; memset(&q, 0, sizeof q);
    W_SETERR(0);
    r = WS(WSAGetQOSByName)((SOCKET)ev, &nm, &q);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_NOTSOCK);
    CloseHandle(ev);
}
TEST(gap2_addr_qos_zero_handle_is_not_a_socket) {
    WSABUF nm; QOS q; BOOL r; char t[] = "x";
    G2_NEED();
    nm.buf = t; nm.len = 1; memset(&q, 0, sizeof q);
    W_SETERR(0);
    r = WS(WSAGetQOSByName)(0, &nm, &q);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_NOTSOCK);
}
/* A socket answers any template name with the default QOS: every rate and size unspecified, best-effort
 * service in both directions, and an empty provider-specific buffer. */
static void check_default_qos(const QOS *q, const char *what) {
    const FLOWSPEC *f[2];
    int i;
    f[0] = &q->SendingFlowspec; f[1] = &q->ReceivingFlowspec;
    for (i = 0; i < 2; i++) {
        CHECKF(f[i]->TokenRate == QOS_NOT_SPECIFIED && f[i]->TokenBucketSize == QOS_NOT_SPECIFIED, "%s flowspec %d rate/bucket", what, i);
        CHECKF(f[i]->PeakBandwidth == QOS_NOT_SPECIFIED && f[i]->Latency == QOS_NOT_SPECIFIED && f[i]->DelayVariation == QOS_NOT_SPECIFIED, "%s flowspec %d bandwidth/latency", what, i);
        CHECKF(f[i]->ServiceType == SERVICETYPE_BESTEFFORT, "%s flowspec %d service type %lu", what, i, (unsigned long)f[i]->ServiceType);
        CHECKF(f[i]->MaxSduSize == QOS_NOT_SPECIFIED && f[i]->MinimumPolicedSize == QOS_NOT_SPECIFIED, "%s flowspec %d sizes", what, i);
    }
    CHECKF(q->ProviderSpecific.len == 0 && q->ProviderSpecific.buf == NULL, "%s provider-specific buffer", what);
}

TEST(gap2_addr_qos_structure_size) {
    EXPECT_EQ(sizeof(QOS), 0x50);
    EXPECT_EQ(sizeof(FLOWSPEC), 0x20);
}

TEST(gap2_addr_qos_udp_socket_default_flowspecs) {
    SOCKET s; BYTE q[0x100]; WSABUF nm; char t[] = "ws2t-template"; BOOL r;
    G2_NEED();
    s = g2_udp4();
    if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    memset(q, 0xCD, sizeof q);
    nm.buf = t; nm.len = (ULONG)strlen(t);
    W_SETERR(0);
    r = WS(WSAGetQOSByName)(s, &nm, (LPQOS)q);
    EXPECT_EQ(r, TRUE);
    EXPECT_EQ(W_ERR(), 0);
    EXPECT_EQ(q[0x50], 0xCD);          /* exactly 0x50 bytes are written */
    check_default_qos((const QOS *)q, "udp");
    g2_close(s);
}
TEST(gap2_addr_qos_stream_socket_default_flowspecs) {
    SOCKET s; BYTE q[0x100]; WSABUF nm; char t[] = "x"; BOOL r;
    G2_NEED();
    s = g2_tcp4();
    if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    memset(q, 0xCD, sizeof q);
    nm.buf = t; nm.len = 1;
    W_SETERR(0);
    r = WS(WSAGetQOSByName)(s, &nm, (LPQOS)q);
    EXPECT_EQ(r, TRUE);
    EXPECT_EQ(W_ERR(), 0);
    EXPECT_EQ(q[0x50], 0xCD);
    check_default_qos((const QOS *)q, "tcp");
    g2_close(s);
}
TEST(gap2_addr_qos_name_pointer_unused_on_plain_socket) {
    SOCKET s; BYTE q[0x100]; BOOL r;
    G2_NEED();
    s = g2_udp4();
    if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    memset(q, 0, sizeof q);
    W_SETERR(0);
    r = WS(WSAGetQOSByName)(s, NULL, (LPQOS)q);
    EXPECT_EQ(r, TRUE);
    check_default_qos((const QOS *)q, "udp, no name");
    g2_close(s);
}
TEST(gap2_addr_qos_listening_socket_default_flowspecs) {
    SOCKET s; BYTE q[0x100]; WSABUF nm; char t[] = "x"; unsigned short port; BOOL r;
    G2_NEED();
    s = g2_listen4(&port);
    if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    memset(q, 0xCD, sizeof q);
    nm.buf = t; nm.len = 1;
    r = WS(WSAGetQOSByName)(s, &nm, (LPQOS)q);
    EXPECT_EQ(r, TRUE);
    check_default_qos((const QOS *)q, "listener");
    g2_close(s);
}
TEST(gap2_addr_qos_same_defaults_on_every_call) {
    SOCKET s; BYTE q1[0x100], q2[0x100]; WSABUF nm; char t[] = "x";
    G2_NEED();
    s = g2_udp4();
    if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    memset(q1, 0, sizeof q1); memset(q2, 0xFF, sizeof q2);
    nm.buf = t; nm.len = 1;
    CHECK(WS(WSAGetQOSByName)(s, &nm, (LPQOS)q1));
    CHECK(WS(WSAGetQOSByName)(s, &nm, (LPQOS)q2));
    CHECK(!memcmp(q1, q2, 0x50));
    g2_close(s);
}

/* ------------------------------------------------------------------------------------------------ */
/* GetAddrInfoExA: name and service forms                                                            */
/* ------------------------------------------------------------------------------------------------ */

static int gaex_ns(const char *name, const char *svc, int flags, int family, int socktype, ADDRINFOEXA **res) {
    ADDRINFOEXA h;
    memset(&h, 0, sizeof h);
    h.ai_flags = flags; h.ai_family = family; h.ai_socktype = socktype;
    *res = NULL;
    return WS(GetAddrInfoExA)(name, svc, NS_DNS, NULL, &h, res, NULL, NULL, NULL, NULL);
}

TEST(gap2_addr_exa_numeric_host_with_non_numeric_name_is_not_found) {
    static const char *names[] = { "localhost", "ws2t-no-such-host.invalid", "127.0.0.1x", "1.2.3" , "256.1.1.1" };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(names); i++) {
        ADDRINFOEXA *res; int r = gaex_ns(names[i], NULL, AI_NUMERICHOST, AF_INET, SOCK_STREAM, &res);
        if (!strcmp(names[i], "1.2.3")) { t_note("short dotted form with AI_NUMERICHOST: %d", r); if (res) WS(FreeAddrInfoEx)(res); continue; }
        CHECKF(r == 11001, "%s returned %d", names[i], r);   /* WSAHOST_NOT_FOUND */
        CHECKF(res == NULL, "%s left a result", names[i]);
        CHECKF(W_ERR() == 11001, "%s last error %d", names[i], W_ERR());
    }
}
TEST(gap2_addr_exa_numeric_service_sets_the_port) {
    static const struct { const char *svc; unsigned short port; } rows[] = { { "80", 80 }, { "0", 0 }, { "65535", 65535 }, { "8080", 8080 } };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(rows); i++) {
        ADDRINFOEXA *res; int r = gaex_ns("127.0.0.1", rows[i].svc, AI_NUMERICHOST, AF_INET, SOCK_STREAM, &res);
        CHECKF(r == 0, "service %s returned %d", rows[i].svc, r);
        if (r == 0 && res && res->ai_addr) {
            unsigned short be = ((struct sockaddr_in *)res->ai_addr)->sin_port;
            CHECKF((unsigned short)((be >> 8) | (be << 8)) == rows[i].port, "service %s: port %u", rows[i].svc, (unsigned)((be >> 8) | (be << 8)));
        }
        if (res) WS(FreeAddrInfoEx)(res);
    }
}
TEST(gap2_addr_exa_null_name_passive_is_wildcard_otherwise_loopback) {
    ADDRINFOEXA *res; int r;
    G2_NEED();
    r = gaex_ns(NULL, "80", AI_PASSIVE, AF_INET, SOCK_STREAM, &res);
    EXPECT_EQ(r, 0);
    if (res && res->ai_addr) EXPECT_EQ(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr, 0);
    if (res) WS(FreeAddrInfoEx)(res);
    r = gaex_ns(NULL, "80", 0, AF_INET, SOCK_STREAM, &res);
    EXPECT_EQ(r, 0);
    if (res && res->ai_addr) EXPECT_EQ(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr, 0x0100007f);
    if (res) WS(FreeAddrInfoEx)(res);
}
TEST(gap2_addr_exa_hints_socket_type_and_protocol_are_echoed) {
    ADDRINFOEXA *res; int r;
    G2_NEED();
    r = gaex_ns("127.0.0.1", "80", AI_NUMERICHOST, AF_INET, SOCK_STREAM, &res);
    EXPECT_EQ(r, 0);
    if (res) { EXPECT_EQ(res->ai_socktype, SOCK_STREAM); EXPECT_EQ(res->ai_protocol, 0);     /* the hint's protocol (zero) is echoed, not resolved */ WS(FreeAddrInfoEx)(res); }
    r = gaex_ns("127.0.0.1", "80", AI_NUMERICHOST, AF_INET, SOCK_DGRAM, &res);
    EXPECT_EQ(r, 0);
    if (res) { EXPECT_EQ(res->ai_socktype, SOCK_DGRAM); EXPECT_EQ(res->ai_protocol, 0); WS(FreeAddrInfoEx)(res); }
}
TEST(gap2_addr_exa_family_restricts_numeric_results) {
    ADDRINFOEXA *res; int r;
    G2_NEED();
    r = gaex_ns("::1", NULL, AI_NUMERICHOST, AF_INET, SOCK_STREAM, &res);
    EXPECT_NE(r, 0);
    EXPECT_EQ(res, NULL);
    r = gaex_ns("127.0.0.1", NULL, AI_NUMERICHOST, AF_INET6, SOCK_STREAM, &res);
    EXPECT_NE(r, 0);
    EXPECT_EQ(res, NULL);
    r = gaex_ns("::1", NULL, AI_NUMERICHOST, AF_INET6, SOCK_STREAM, &res);
    EXPECT_EQ(r, 0);
    if (res) { EXPECT_EQ(res->ai_family, AF_INET6); EXPECT_EQ(res->ai_addrlen, sizeof(struct sockaddr_in6)); WS(FreeAddrInfoEx)(res); }
}
