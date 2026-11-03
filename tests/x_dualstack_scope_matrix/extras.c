/* Further dual-stack and scope-id edge cases: output-buffer protocols of the string/address converters,
 * sockaddr length rules in getnameinfo and sendto, datagram name-length rules on receive, inet_pton forms,
 * WSAAccept and AcceptEx/ConnectEx on dual-stack sockets, option-level errors for IPV6_V6ONLY, getaddrinfo
 * argument validation, UDP disconnect, and the protocol information of IPv4 and IPv6 sockets.  Loopback only. */
#include "sm.h"

/* ---- WSAStringToAddress: output-length protocol ---- */
static void s2a_len_case(const char *text, int af, int need) {
    for (int k = 0; k <= need + 4; k += 2) {
        struct sockaddr_in6 o; INT l = k; int rc;
        memset(&o, 0, sizeof o);
        rc = U(WSAStringToAddressA)((LPSTR)text, af, NULL, (struct sockaddr *)&o, &l);
        if (k < need) {
            CHECKF(rc != 0 && s_err() == WSAEFAULT, "[%s] outlen %d rc=%d err=%d", text, k, rc, s_err());
            CHECKF(l == need, "[%s] outlen %d reports %d want %d", text, k, l, need);
        } else {
            CHECKF(rc == 0, "[%s] outlen %d rc=%d err=%d", text, k, rc, s_err());
            CHECKF(l == need, "[%s] outlen %d result length %d", text, k, l);
        }
    }
}
TEST(dsm_x_str2addr_outlen_v6_text) { s2a_len_case("::1", AF_INET6, 28); }
TEST(dsm_x_str2addr_outlen_v6_scoped_text) { s2a_len_case("fe80::1%1", AF_INET6, 28); }
TEST(dsm_x_str2addr_outlen_v6_bracket_port) { s2a_len_case("[::1]:80", AF_INET6, 28); }
TEST(dsm_x_str2addr_outlen_v6_mapped) { s2a_len_case("::ffff:127.0.0.1", AF_INET6, 28); }
TEST(dsm_x_str2addr_outlen_v4_text) { s2a_len_case("127.0.0.1", AF_INET, 16); }
TEST(dsm_x_str2addr_outlen_v4_with_port) { s2a_len_case("127.0.0.1:80", AF_INET, 16); }

/* the wide entry point must agree with the ANSI one on accepted forms and on rejected forms */
TEST(dsm_x_str2addr_wide_equals_ansi_full_table) {
    static const struct { const char *t; int af; } r[] = {
        { "::1", 23 }, { "::1", 2 }, { "[::1]:80", 23 }, { "[::1%1]:80", 23 }, { "fe80::1%1", 23 }, { "fe80::1%0", 23 },
        { "fe80::1%4294967295", 23 }, { "fe80::1%4294967296", 23 }, { "fe80::1%", 23 }, { "fe80::1%abc", 23 },
        { "::ffff:1.2.3.4%1", 23 }, { "127.0.0.1", 23 }, { "127.0.0.1", 2 }, { "127.0.0.1:80", 2 }, { "127.0.0.1%1", 2 },
        { "[::1", 23 }, { "::1]", 23 }, { "[::1]:65536", 23 }, { "1::2::3", 23 }, { "::1 ", 23 }, { "", 23 }, { "", 2 },
    };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof r / sizeof *r; i++) {
        struct sockaddr_in6 a, w; INT la = sizeof a, lw = sizeof w; WCHAR wb[64]; int k, ra, rw, ea = 0, ew = 0;
        for (k = 0; r[i].t[k]; k++) wb[k] = (WCHAR)r[i].t[k];
        wb[k] = 0;
        memset(&a, 0, sizeof a); memset(&w, 0, sizeof w);
        ra = U(WSAStringToAddressA)((LPSTR)r[i].t, r[i].af, NULL, (struct sockaddr *)&a, &la); if (ra) ea = s_err();
        rw = U(WSAStringToAddressW)(wb, r[i].af, NULL, (struct sockaddr *)&w, &lw); if (rw) ew = s_err();
        CHECKF(ra == rw && ea == ew, "[%s] af=%d ansi rc=%d err=%d wide rc=%d err=%d", r[i].t, r[i].af, ra, ea, rw, ew);
        if (!ra && !rw) CHECKF(la == lw && !memcmp(&a, &w, la), "[%s] af=%d results differ", r[i].t, r[i].af);
    }
}

/* ---- WSAAddressToString: output protocol corners ---- */
TEST(dsm_x_addr2str_zero_length_buffer_reports_need) {
    struct sockaddr_in6 a; char out[8]; DWORD ol = 0; int rc;
    if (!s_up()) return;
    s_mkaddr(&a, AK_V6LOOP, 0);
    rc = U(WSAAddressToStringA)((struct sockaddr *)&a, SA6LEN, NULL, out, &ol);
    CHECK(rc != 0); CHECK(s_err() == WSAEFAULT); EXPECT_EQ(ol, 4);
    s_mkaddr(&a, AK_LL, s_h16(80)); a.sin6_scope_id = 1; ol = 0;
    rc = U(WSAAddressToStringA)((struct sockaddr *)&a, SA6LEN, NULL, out, &ol);
    CHECK(rc != 0); CHECK(s_err() == WSAEFAULT); EXPECT_EQ(ol, 15);
}
TEST(dsm_x_addr2str_unspecified_family_is_einval) {
    struct sockaddr_in6 a; char out[64]; DWORD ol = sizeof out; int rc;
    if (!s_up()) return;
    s_mkaddr(&a, AK_V6LOOP, 0); a.sin6_family = AF_UNSPEC;
    rc = U(WSAAddressToStringA)((struct sockaddr *)&a, SA6LEN, NULL, out, &ol);
    CHECK(rc != 0); CHECK(s_err() == WSAEINVAL);
}
TEST(dsm_x_addr2str_v4_name_accepts_longer_length_but_not_shorter) {
    struct sockaddr_in6 a; char out[64]; DWORD ol; int rc;
    if (!s_up()) return;
    s_mkaddr(&a, AK_V4LOOP, 0);
    ol = sizeof out; rc = U(WSAAddressToStringA)((struct sockaddr *)&a, SA6LEN, NULL, out, &ol);
    CHECK(rc == 0); EXPECT_STR(out, "127.0.0.1");
    ol = sizeof out; rc = U(WSAAddressToStringA)((struct sockaddr *)&a, SA4LEN, NULL, out, &ol);
    CHECK(rc == 0);
    ol = sizeof out; rc = U(WSAAddressToStringA)((struct sockaddr *)&a, SA4LEN - 1, NULL, out, &ol);
    CHECK(rc != 0); CHECK(s_err() == WSAEFAULT);
}
TEST(dsm_x_addr2str_wide_matches_ansi_text_and_length) {
    static const struct { int ak; unsigned port, scope; } r[] = {
        { AK_V6LOOP, 0, 0 }, { AK_V6LOOP, 80, 1 }, { AK_LL, 0, 1 }, { AK_LL, 80, 7 }, { AK_MAPLOOP, 81, 3 }, { AK_V6ANY, 0, 0 }, { AK_V4LOOP, 80, 0 },
    };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof r / sizeof *r; i++) {
        char a[32], o[128]; WCHAR w[128]; DWORD la = sizeof o, lw = 128; int len = s_mkaddr(a, r[i].ak, s_h16((unsigned short)r[i].port)), k;
        if (len == SA6LEN) ((struct sockaddr_in6 *)a)->sin6_scope_id = r[i].scope;
        CHECK(U(WSAAddressToStringA)((struct sockaddr *)a, len, NULL, o, &la) == 0);
        CHECK(U(WSAAddressToStringW)((struct sockaddr *)a, len, NULL, w, &lw) == 0);
        CHECKF(la == lw, "row %u lengths %lu vs %lu", i, la, lw);
        for (k = 0; o[k]; k++) if (w[k] != (WCHAR)o[k]) break;
        CHECKF(o[k] == 0 && w[k] == 0, "row %u texts differ", i);
        lw = la - 1;
        CHECK(U(WSAAddressToStringW)((struct sockaddr *)a, len, NULL, w, &lw) != 0); CHECK(s_err() == WSAEFAULT); EXPECT_EQ(lw, la);
    }
}

/* ---- getnameinfo: sockaddr length and family rules, buffer protocols ---- */
TEST(dsm_x_getnameinfo_v6_length_below_28_is_efault) {
    char a[32], h[80], sv[16];
    if (!s_up()) return;
    for (int l = 0; l < 28; l += 4) {
        int rc; s_mkaddr(a, AK_V6LOOP, s_h16(80));
        rc = U(getnameinfo)((struct sockaddr *)a, l, h, sizeof h, sv, sizeof sv, 0xa);
        CHECKF(rc == WSAEFAULT, "len %d rc=%d", l, rc);
    }
    s_mkaddr(a, AK_V6LOOP, s_h16(80));
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, h, sizeof h, sv, sizeof sv, 0xa) == 0);
    CHECK(U(getnameinfo)((struct sockaddr *)a, 32, h, sizeof h, sv, sizeof sv, 0xa) == 0);
}
TEST(dsm_x_getnameinfo_v4_length_rules) {
    char a[32], h[80], sv[16];
    if (!s_up()) return;
    s_mkaddr(a, AK_V4LOOP, s_h16(80));
    CHECK(U(getnameinfo)((struct sockaddr *)a, 15, h, sizeof h, sv, sizeof sv, 0xa) == WSAEFAULT);
    CHECK(U(getnameinfo)((struct sockaddr *)a, 16, h, sizeof h, sv, sizeof sv, 0xa) == 0);
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, h, sizeof h, sv, sizeof sv, 0xa) == 0);
    EXPECT_STR(h, "127.0.0.1");
}
TEST(dsm_x_getnameinfo_unspecified_family_is_eafnosupport) {
    char a[32], h[80], sv[16];
    if (!s_up()) return;
    s_mkaddr(a, AK_V6LOOP, s_h16(80)); a[0] = a[1] = 0;
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, h, sizeof h, sv, sizeof sv, 0xa) == WSAEAFNOSUPPORT);
}
TEST(dsm_x_getnameinfo_numeric_service_buffer_protocol) {
    char a[32], h[80], sv[16];
    if (!s_up()) return;
    s_mkaddr(a, AK_V6LOOP, s_h16(8080));
    memset(sv, 'x', sizeof sv);
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, h, sizeof h, sv, 4, NI_NUMERICHOST | NI_NUMERICSERV) == 122);
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, h, sizeof h, sv, 5, NI_NUMERICHOST | NI_NUMERICSERV) == 0);
    EXPECT_STR(sv, "8080");
    s_mkaddr(a, AK_V6LOOP, 0);
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, h, sizeof h, sv, 2, NI_NUMERICHOST | NI_NUMERICSERV) == 0);
    EXPECT_STR(sv, "0");
}
TEST(dsm_x_getnameinfo_omitted_buffers_are_allowed) {
    char a[32], h[80], sv[16];
    if (!s_up()) return;
    s_mkaddr(a, AK_V6LOOP, s_h16(8080));
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, h, sizeof h, NULL, 0, 0xa) == 0);
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, NULL, 0, sv, sizeof sv, 0xa) == 0);
    EXPECT_STR(sv, "8080");
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, h, 0, sv, sizeof sv, 0xa) == 0);
}
TEST(dsm_x_getnameinfo_service_names_are_informational) {
    char a[32], h[80], sv[32];
    if (!s_up()) return;
    s_mkaddr(a, AK_V6LOOP, s_h16(80));
    CHECK(U(getnameinfo)((struct sockaddr *)a, 28, h, sizeof h, sv, sizeof sv, NI_NUMERICHOST) == 0);
    t_note("port 80 resolves to a service name or digits: %s", strcmp(sv, "80") ? "name" : "digits");
}

/* ---- getaddrinfo argument validation ---- */
TEST(dsm_x_getaddrinfo_unsupported_socktype_and_family) {
    ADDRINFOA h, *res = NULL;
    if (!s_up()) return;
    memset(&h, 0, sizeof h); h.ai_family = AF_INET6; h.ai_socktype = 77; h.ai_flags = AI_NUMERICHOST;
    CHECK(U(getaddrinfo)("::1", "80", &h, &res) == WSAESOCKTNOSUPPORT);
    h.ai_socktype = 0; h.ai_family = 99;
    CHECK(U(getaddrinfo)("::1", "80", &h, &res) == WSAEAFNOSUPPORT);
}
TEST(dsm_x_getaddrinfo_numeric_serv_rejects_names) {
    ADDRINFOA h, *res = NULL;
    if (!s_up()) return;
    memset(&h, 0, sizeof h); h.ai_family = AF_INET6; h.ai_socktype = SOCK_STREAM; h.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    CHECK(U(getaddrinfo)("::1", "http", &h, &res) == WSAHOST_NOT_FOUND);
    CHECK(U(getaddrinfo)("::1", "80", &h, &res) == 0);
    if (res) { CHECK(s_h16(((struct sockaddr_in6 *)res->ai_addr)->sin6_port) == 80); U(freeaddrinfo)(res); }
}
TEST(dsm_x_getaddrinfo_no_node_no_service_is_not_found) {
    ADDRINFOA h, *res = NULL;
    if (!s_up()) return;
    memset(&h, 0, sizeof h); h.ai_family = AF_UNSPEC; h.ai_socktype = SOCK_STREAM;
    CHECK(U(getaddrinfo)(NULL, NULL, &h, &res) == WSAHOST_NOT_FOUND);
}
TEST(dsm_x_getaddrinfo_missing_service_gives_port_zero) {
    ADDRINFOA h, *res = NULL;
    if (!s_up()) return;
    memset(&h, 0, sizeof h); h.ai_family = AF_INET6; h.ai_socktype = SOCK_STREAM; h.ai_flags = AI_NUMERICHOST;
    CHECK(U(getaddrinfo)("fe80::1%1", NULL, &h, &res) == 0);
    if (res) {
        struct sockaddr_in6 *q = (struct sockaddr_in6 *)res->ai_addr;
        CHECK(q->sin6_port == 0); CHECK(q->sin6_scope_id == 1); CHECK(res->ai_next == NULL);
        U(freeaddrinfo)(res);
    }
}
TEST(dsm_x_getaddrinfo_unspecified_socktype_numeric_host_single_entry) {
    static const char *const hosts[] = { "::1", "fe80::1%1", "127.0.0.1", "::ffff:127.0.0.1" };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof hosts / sizeof *hosts; i++) {
        ADDRINFOA h, *res = NULL; int n = 0;
        memset(&h, 0, sizeof h); h.ai_family = AF_UNSPEC; h.ai_flags = AI_NUMERICHOST;
        CHECKF(U(getaddrinfo)(hosts[i], "80", &h, &res) == 0, "[%s]", hosts[i]);
        for (ADDRINFOA *p = res; p; p = p->ai_next) { n++; CHECKF(p->ai_socktype == 0 && p->ai_protocol == 0, "[%s] type %d proto %d", hosts[i], p->ai_socktype, p->ai_protocol); }
        CHECKF(n == 1, "[%s] entries %d", hosts[i], n);
        if (res) U(freeaddrinfo)(res);
    }
}
TEST(dsm_x_getaddrinfo_v4_text_with_v4mapped_flag_maps_it) {
    ADDRINFOA h, *res = NULL;
    char d[64];
    if (!s_up()) return;
    memset(&h, 0, sizeof h); h.ai_family = AF_INET6; h.ai_socktype = SOCK_STREAM; h.ai_flags = AI_V4MAPPED;
    CHECK(U(getaddrinfo)("127.0.0.1", "80", &h, &res) == 0);
    if (res) {
        s_desc(res->ai_addr, (int)res->ai_addrlen, d, sizeof d);
        EXPECT_STR(d, "v6:map:loop:scope0:len28"); CHECK(res->ai_next == NULL);
        U(freeaddrinfo)(res);
    }
    res = NULL; h.ai_flags = 0;
    CHECK(U(getaddrinfo)("127.0.0.1", "80", &h, &res) == WSAHOST_NOT_FOUND);
    res = NULL; h.ai_flags = AI_V4MAPPED;
    CHECK(U(getaddrinfo)("::1", "80", &h, &res) == 0);
    if (res) { s_desc(res->ai_addr, (int)res->ai_addrlen, d, sizeof d); EXPECT_STR(d, "v6:loop:scope0:len28"); U(freeaddrinfo)(res); }
}

/* ---- inet_pton: no scope, no brackets, family-specific ---- */
TEST(dsm_x_inet_pton_forms) {
    static const struct { const char *t; int af, rc; } r[] = {
        { "::1", 23, 1 }, { "::", 23, 1 }, { "::ffff:1.2.3.4", 23, 1 }, { "fe80::1", 23, 1 },
        { "fe80::1%1", 23, 0 }, { "fe80::1%", 23, 0 }, { "[::1]", 23, 0 }, { "::1%abc", 23, 0 }, { "1.2.3.4", 23, 0 }, { "", 23, 0 },
        { "1.2.3.4", 2, 1 }, { "::1", 2, 0 }, { "1.2.3.4:80", 2, 0 }, { "1.2.3", 2, 0 }, { "256.1.1.1", 2, 0 },
    };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof r / sizeof *r; i++) {
        unsigned char b[16];
        CHECKF(UIN("ws2_32.dll", inet_pton)(r[i].af, r[i].t, b) == r[i].rc, "[%s] af=%d", r[i].t, r[i].af);
    }
    { unsigned char b[16]; CHECK(UIN("ws2_32.dll", inet_pton)(99, "::1", b) == -1); CHECK(s_err() == WSAEAFNOSUPPORT); }
}
TEST(dsm_x_inet_pton_mapped_bytes) {
    unsigned char b[16], want[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4 };
    if (!s_up()) return;
    CHECK(UIN("ws2_32.dll", inet_pton)(AF_INET6, "::ffff:1.2.3.4", b) == 1);
    CHECK(!memcmp(b, want, 16));
}

/* ---- WSAAccept: the condition function sees the peer as the listener's family reports it ---- */
struct cond_seen { int calls; char caller[64]; DWORD calleelen; };
static int CALLBACK cond_cb(LPWSABUF caller, LPWSABUF cdata, LPQOS q1, LPQOS q2, LPWSABUF callee, LPWSABUF sdata, GROUP *g, DWORD_PTR ud) {
    struct cond_seen *c = (struct cond_seen *)ud;
    c->calls++; s_desc(caller->buf, caller->len, c->caller, sizeof c->caller); c->calleelen = callee->len;
    return CF_ACCEPT;
}
static void wsaaccept_case(int lsk, int csk, int cak, const char *want_caller, DWORD want_calleelen) {
    SOCKET l = s_mk(lsk, SOCK_STREAM), c, a; char ad[32]; int len = s_mkaddr(ad, lsk == SK_V4 ? AK_V4ANY : AK_V6ANY, 0);
    struct cond_seen seen; struct sockaddr_in6 x; int xl = sizeof x; char d[64];
    memset(&seen, 0, sizeof seen);
    CHECK(U(bind)(l, (struct sockaddr *)ad, len) == 0); CHECK(U(listen)(l, 2) == 0);
    c = s_mk(csk, SOCK_STREAM); len = s_mkaddr(ad, cak, s_port(l));
    CHECK(s_connect(c, ad, len, 3000) == 0);
    CHECK(s_readable(l, 3000));
    a = U(WSAAccept)(l, (struct sockaddr *)&x, &xl, cond_cb, (DWORD_PTR)&seen);
    CHECK(a != INVALID_SOCKET);
    EXPECT_EQ(seen.calls, 1);
    EXPECT_STR(seen.caller, want_caller);
    EXPECT_EQ(seen.calleelen, want_calleelen);
    s_desc(&x, xl, d, sizeof d); EXPECT_STR(d, want_caller);
    s_close(a); s_close(c); s_close(l);
}
TEST(dsm_x_wsaaccept_condition_v4_listener) { if (!s_up()) return; wsaaccept_case(SK_V4, SK_V4, AK_V4LOOP, "v4:loop:len16", 16); }
TEST(dsm_x_wsaaccept_condition_dual_listener_v4_client) { if (!s_up()) return; wsaaccept_case(SK_V6D, SK_V4, AK_V4LOOP, "v6:map:loop:scope0:len28", 28); }
TEST(dsm_x_wsaaccept_condition_dual_listener_v6_client) { if (!s_up()) return; wsaaccept_case(SK_V6D, SK_V6D, AK_V6LOOP, "v6:loop:scope0:len28", 28); }
TEST(dsm_x_wsaaccept_condition_v6only_listener) { if (!s_up()) return; wsaaccept_case(SK_V6O, SK_V6D, AK_V6LOOP, "v6:loop:scope0:len28", 28); }

/* ---- AcceptEx / ConnectEx on dual-stack sockets ---- */
static void *ext_fn(SOCKET s, GUID g) {
    void *f = NULL; DWORD r = 0;
    if (U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &r, NULL, NULL)) return NULL;
    return f;
}
static void acceptex_case(int lsk, int cak, int csk, const char *want) {
    GUID ga = WSAID_ACCEPTEX, gg = WSAID_GETACCEPTEXSOCKADDRS;
    SOCKET l = s_mk(lsk, SOCK_STREAM), c = s_mk(csk, SOCK_STREAM), a = s_mk(lsk, SOCK_STREAM);
    char ad[32], buf[256], d[64]; int len = s_mkaddr(ad, lsk == SK_V4 ? AK_V4ANY : AK_V6ANY, 0);
    LPFN_ACCEPTEX AE; LPFN_GETACCEPTEXSOCKADDRS GS; OVERLAPPED ov; DWORD got = 0, tr, fl; BOOL ok;
    CHECK(U(bind)(l, (struct sockaddr *)ad, len) == 0); CHECK(U(listen)(l, 2) == 0);
    AE = (LPFN_ACCEPTEX)ext_fn(l, ga); GS = (LPFN_GETACCEPTEXSOCKADDRS)ext_fn(l, gg);
    if (!AE || !GS) { t_skip("extension functions unavailable"); goto out; }
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    ok = AE(l, a, buf, 0, lsk == SK_V4 ? 32 : 44, lsk == SK_V4 ? 32 : 44, &got, &ov);
    CHECK(ok || s_err() == ERROR_IO_PENDING);
    len = s_mkaddr(ad, cak, s_port(l));
    CHECK(s_connect(c, ad, len, 3000) == 0);
    CHECK(WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0);
    CHECK(U(WSAGetOverlappedResult)(l, &ov, &tr, FALSE, &fl));
    { struct sockaddr *ls = NULL, *rs = NULL; int ll = 0, rl = 0;
      GS(buf, 0, lsk == SK_V4 ? 32 : 44, lsk == SK_V4 ? 32 : 44, &ls, &ll, &rs, &rl);
      if (ls && rs) { s_desc(ls, ll, d, sizeof d); EXPECT_STR(d, want); s_desc(rs, rl, d, sizeof d); EXPECT_STR(d, want); } else CHECK(0); }
    U(WSACloseEvent)(ov.hEvent);
out:
    s_close(a); s_close(c); s_close(l);
}
TEST(dsm_x_acceptex_v4_listener_names) { if (!s_up()) return; acceptex_case(SK_V4, AK_V4LOOP, SK_V4, "v4:loop:len16"); }
TEST(dsm_x_acceptex_dual_listener_v4_client_names_are_mapped) { if (!s_up()) return; acceptex_case(SK_V6D, AK_MAPLOOP, SK_V6D, "v6:map:loop:scope0:len28"); }
TEST(dsm_x_acceptex_v6only_listener_names) { if (!s_up()) return; acceptex_case(SK_V6O, AK_V6LOOP, SK_V6D, "v6:loop:scope0:len28"); }
TEST(dsm_x_acceptex_zero_address_space_is_efault) {
    GUID ga = WSAID_ACCEPTEX;
    for (int k = 0; k < 2; k++) {
        SOCKET l = s_mk(k ? SK_V6D : SK_V4, SOCK_STREAM), a = s_mk(k ? SK_V6D : SK_V4, SOCK_STREAM); char ad[32], buf[64];
        LPFN_ACCEPTEX AE; OVERLAPPED ov; DWORD got = 0; BOOL ok;
        if (!s_up()) return;
        CHECK(U(bind)(l, (struct sockaddr *)ad, s_mkaddr(ad, k ? AK_V6ANY : AK_V4ANY, 0)) == 0); CHECK(U(listen)(l, 2) == 0);
        AE = (LPFN_ACCEPTEX)ext_fn(l, ga);
        if (AE) {
            memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
            ok = AE(l, a, buf, 0, 0, 0, &got, &ov);
            CHECK(!ok); CHECK(s_err() == WSAEFAULT);
            U(WSACloseEvent)(ov.hEvent);
        }
        s_close(a); s_close(l);
    }
}
static void connectex_case(int csk, int cak, int want_err) {
    GUID gc = WSAID_CONNECTEX;
    int lsk = csk == SK_V4 ? SK_V4 : SK_V6D;
    SOCKET l = s_mk(lsk, SOCK_STREAM), c = s_mk(csk, SOCK_STREAM); char ad[32]; int len;
    LPFN_CONNECTEX CE; OVERLAPPED ov; DWORD tr, fl, w; BOOL ok; int e;
    CHECK(U(bind)(l, (struct sockaddr *)ad, s_mkaddr(ad, lsk == SK_V4 ? AK_V4ANY : AK_V6ANY, 0)) == 0); CHECK(U(listen)(l, 2) == 0);
    CE = (LPFN_CONNECTEX)ext_fn(c, gc);
    if (!CE) { t_skip("ConnectEx unavailable"); goto out; }
    CHECK(U(bind)(c, (struct sockaddr *)ad, s_mkaddr(ad, csk == SK_V4 ? AK_V4ANY : AK_V6ANY, 0)) == 0);
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    len = s_mkaddr(ad, cak, s_port(l));
    ok = CE(c, (struct sockaddr *)ad, len, NULL, 0, NULL, &ov);
    e = ok ? 0 : s_err();
    CHECKF(ok || e == ERROR_IO_PENDING, "%s->%s start err %d", SK_NAME[csk], AK_NAME[cak], e);
    w = WaitForSingleObject(ov.hEvent, 3000);
    CHECK(w == WAIT_OBJECT_0);
    if (w == WAIT_OBJECT_0) {
        int g = U(WSAGetOverlappedResult)(c, &ov, &tr, FALSE, &fl);
        if (want_err == 0) CHECKF(g, "%s->%s completion err %d", SK_NAME[csk], AK_NAME[cak], g ? 0 : s_err());
        else CHECKF(!g && s_err() == want_err, "%s->%s completion g=%d err=%d want %d", SK_NAME[csk], AK_NAME[cak], g, g ? 0 : s_err(), want_err);
    }
    U(WSACloseEvent)(ov.hEvent);
out:
    s_close(c); s_close(l);
}
TEST(dsm_x_connectex_dual_to_mapped_loopback)        { if (!s_up()) return; connectex_case(SK_V6D, AK_MAPLOOP, 0); }
TEST(dsm_x_connectex_dual_to_v6_loopback)            { if (!s_up()) return; connectex_case(SK_V6D, AK_V6LOOP, 0); }
TEST(dsm_x_connectex_v4_to_v4_loopback)              { if (!s_up()) return; connectex_case(SK_V4, AK_V4LOOP, 0); }
TEST(dsm_x_connectex_v6only_to_mapped_fails_at_completion) { if (!s_up()) return; connectex_case(SK_V6O, AK_MAPLOOP, WSAEADDRNOTAVAIL); }
TEST(dsm_x_connectex_dual_to_v4_name_fails_at_completion)  { if (!s_up()) return; connectex_case(SK_V6D, AK_V4LOOP, WSAEADDRNOTAVAIL); }
TEST(dsm_x_connectex_v4_to_v6_name_fails_at_completion)    { if (!s_up()) return; connectex_case(SK_V4, AK_V6LOOP, WSAEADDRNOTAVAIL); }
TEST(dsm_x_connectex_scoped_loopback_fails_at_completion)  { if (!s_up()) return; connectex_case(SK_V6D, AK_V6LOOP_SCOPE, WSAEADDRNOTAVAIL); }

/* ---- IPV6_V6ONLY option addressing errors ---- */
TEST(dsm_x_v6only_on_closed_socket_is_enotsock) {
    SOCKET s; int v, rc;
    if (!s_up()) return;
    s = s_open(AF_INET6, SOCK_STREAM); s_close(s);
    rc = s_v6only(s, 0); CHECK(rc != 0); CHECK(s_err() == WSAENOTSOCK);
    rc = s_getint(s, IPPROTO_IPV6, IPV6_V6ONLY, &v); CHECK(rc != 0); CHECK(s_err() == WSAENOTSOCK);
}
TEST(dsm_x_v6only_option_number_at_wrong_levels) {
    static const struct { int level, err; } r[] = {
        { SOL_SOCKET, WSAENOPROTOOPT }, { IPPROTO_IP, WSAENOPROTOOPT }, { IPPROTO_TCP, WSAENOPROTOOPT },
        { IPPROTO_UDP, WSAEINVAL }, { IPPROTO_ICMPV6, WSAEINVAL }, { 12345, WSAEINVAL },
    };
    SOCKET s; int v;
    if (!s_up()) return;
    s = s_mk(SK_V6D, SOCK_STREAM);   /* dual-stack, so the IP level exists */
    for (unsigned i = 0; i < sizeof r / sizeof *r; i++) {
        int rc = s_setint(s, r[i].level, IPV6_V6ONLY, 0), e = rc ? s_err() : 0;
        CHECKF(rc != 0 && e == r[i].err, "set level %d rc=%d err=%d want %d", r[i].level, rc, e, r[i].err);
        rc = s_getint(s, r[i].level, IPV6_V6ONLY, &v); e = rc ? s_err() : 0;
        CHECKF(rc != 0 && e == r[i].err, "get level %d rc=%d err=%d want %d", r[i].level, rc, e, r[i].err);
    }
    CHECK(s_getint(s, IPPROTO_IPV6, IPV6_V6ONLY, &v) == 0); EXPECT_EQ(v, 0);
    s_close(s);
    /* a V6ONLY socket has no IP level at all: set is WSAEINVAL, get is unknown option */
    s = s_mk(SK_V6O, SOCK_STREAM);
    { int rc = s_setint(s, IPPROTO_IP, IPV6_V6ONLY, 0); CHECK(rc != 0); CHECK(s_err() == WSAEINVAL); }
    { int rc = s_getint(s, IPPROTO_IP, IPV6_V6ONLY, &v); CHECK(rc != 0); CHECK(s_err() == WSAENOPROTOOPT); }
    s_close(s);
}
TEST(dsm_x_ipv6_level_unknown_option_numbers) {
    SOCKET s; int v;
    if (!s_up()) return;
    s = s_open(AF_INET6, SOCK_STREAM);
    for (int nm = 0; nm < 2; nm++) {
        int opt = nm ? 9999 : 0, rc = s_setint(s, IPPROTO_IPV6, opt, 1);
        CHECKF(rc != 0 && s_err() == WSAENOPROTOOPT, "option %d set", opt);
        rc = s_getint(s, IPPROTO_IPV6, opt, &v);
        CHECKF(rc != 0 && s_err() == WSAENOPROTOOPT, "option %d get", opt);
    }
    s_close(s);
}

/* ---- SO_PROTOCOL_INFOW describes the family of the socket ---- */
static void protoinfo_case(int sk, int ty, int af, int proto, int maxaddr) {
    SOCKET s = s_mk(sk, ty); WSAPROTOCOL_INFOW pi; int l = sizeof pi;
    memset(&pi, 0, sizeof pi);
    CHECK(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l) == 0);
    EXPECT_EQ(pi.iAddressFamily, af); EXPECT_EQ(pi.iSocketType, ty); EXPECT_EQ(pi.iProtocol, proto);
    EXPECT_EQ(pi.iMaxSockAddr, maxaddr); EXPECT_EQ(pi.iMinSockAddr, maxaddr);
    s_close(s);
}
TEST(dsm_x_protocol_info_tcp_v4)  { if (!s_up()) return; protoinfo_case(SK_V4, SOCK_STREAM, AF_INET, IPPROTO_TCP, 16); }
TEST(dsm_x_protocol_info_tcp_v6)  { if (!s_up()) return; protoinfo_case(SK_V6D, SOCK_STREAM, AF_INET6, IPPROTO_TCP, 28); }
TEST(dsm_x_protocol_info_udp_v4)  { if (!s_up()) return; protoinfo_case(SK_V4, SOCK_DGRAM, AF_INET, IPPROTO_UDP, 16); }
TEST(dsm_x_protocol_info_udp_v6)  { if (!s_up()) return; protoinfo_case(SK_V6D, SOCK_DGRAM, AF_INET6, IPPROTO_UDP, 28); }

/* ---- datagram name lengths on receive and send ---- */
static void recv_name_case(int rsk, int ssk, int tak, int need) {
    SOCKET r = s_mk(rsk, SOCK_DGRAM), s = s_mk(ssk, SOCK_DGRAM); char a[32], b[16]; int tl;
    CHECK(U(bind)(r, (struct sockaddr *)a, s_mkaddr(a, rsk == SK_V4 ? AK_V4ANY : AK_V6ANY, 0)) == 0);
    tl = s_mkaddr(a, tak, s_port(r));
    CHECK(U(sendto)(s, "abcd", 4, 0, (struct sockaddr *)a, tl) == 4);
    CHECK(s_readable(r, 3000));
    for (int fl = 0; fl < need; fl += 4) {
        struct sockaddr_in6 f; int l = fl, n;
        memset(&f, 0, sizeof f);
        n = U(recvfrom)(r, b, sizeof b, MSG_PEEK, (struct sockaddr *)&f, &l);
        CHECKF(n < 0 && s_err() == WSAEFAULT, "peek fromlen %d n=%d err=%d", fl, n, n < 0 ? s_err() : 0);
        CHECKF(l == fl, "peek fromlen %d changed to %d", fl, l);
    }
    { struct sockaddr_in6 f; int l = need, n = U(recvfrom)(r, b, sizeof b, MSG_PEEK, (struct sockaddr *)&f, &l);
      CHECKF(n == 4, "datagram was dropped by the short-name errors: n=%d err=%d", n, n < 0 ? s_err() : 0); EXPECT_EQ(l, need); }
    /* too-small data buffer: WSAEMSGSIZE, name still returned, datagram consumed */
    { struct sockaddr_in6 f; int l = need, n = U(recvfrom)(r, b, 2, 0, (struct sockaddr *)&f, &l);
      CHECK(n < 0); CHECK(s_err() == WSAEMSGSIZE); EXPECT_EQ(l, need);
      CHECK(!s_readable(r, 300)); }
    s_close(s); s_close(r);
}
TEST(dsm_x_udp_recvfrom_short_name_v4_receiver)   { if (!s_up()) return; recv_name_case(SK_V4, SK_V4, AK_V4LOOP, 16); }
TEST(dsm_x_udp_recvfrom_short_name_dual_receiver_v4_sender) { if (!s_up()) return; recv_name_case(SK_V6D, SK_V4, AK_V4LOOP, 28); }
TEST(dsm_x_udp_recvfrom_short_name_dual_receiver_v6_sender) { if (!s_up()) return; recv_name_case(SK_V6D, SK_V6D, AK_V6LOOP, 28); }
TEST(dsm_x_udp_recvfrom_short_name_v6only_receiver) { if (!s_up()) return; recv_name_case(SK_V6O, SK_V6D, AK_V6LOOP, 28); }

TEST(dsm_x_udp_sendto_length_and_scope_rules) {
    SOCKET r, s; char a[32]; unsigned short p; int n;
    if (!s_up()) return;
    r = s_mk(SK_V6D, SOCK_DGRAM); s = s_mk(SK_V6D, SOCK_DGRAM);
    CHECK(U(bind)(r, (struct sockaddr *)a, s_mkaddr(a, AK_V6ANY, 0)) == 0); p = s_port(r);
    s_mkaddr(a, AK_V6LOOP, p);
    n = U(sendto)(s, "ab", 2, 0, (struct sockaddr *)a, 16); CHECK(n < 0); CHECK(s_err() == WSAEFAULT);
    n = U(sendto)(s, "ab", 2, 0, (struct sockaddr *)a, 27); CHECK(n < 0); CHECK(s_err() == WSAEFAULT);
    n = U(sendto)(s, "ab", 2, 0, (struct sockaddr *)a, 28); CHECK(n == 2);
    CHECK(s_readable(r, 3000));
    s_mkaddr(a, AK_V6LOOP_SCOPE, p);
    n = U(sendto)(s, "ab", 2, 0, (struct sockaddr *)a, 28); CHECK(n < 0); CHECK(s_err() == WSAEADDRNOTAVAIL);
    s_mkaddr(a, AK_V6LOOP_BADSCOPE, p);
    n = U(sendto)(s, "ab", 2, 0, (struct sockaddr *)a, 28); CHECK(n < 0); CHECK(s_err() == WSAEADDRNOTAVAIL);
    s_mkaddr(a, AK_V6ANY, p);
    n = U(sendto)(s, "ab", 2, 0, (struct sockaddr *)a, 28); CHECK(n < 0); CHECK(s_err() == WSAEADDRNOTAVAIL);
    n = U(send)(s, "ab", 2, 0); CHECK(n < 0); CHECK(s_err() == WSAENOTCONN);
    s_close(s); s_close(r);
}
TEST(dsm_x_udp_connect_and_disconnect_by_unspecified_family) {
    SOCKET s; char a[32]; struct sockaddr_in6 x; int xl, rc;
    if (!s_up()) return;
    s = s_mk(SK_V6D, SOCK_DGRAM);
    CHECK(U(connect)(s, (struct sockaddr *)a, s_mkaddr(a, AK_V6LOOP, s_h16(9))) == 0);
    xl = sizeof x; CHECK(U(getpeername)(s, (struct sockaddr *)&x, &xl) == 0);
    CHECK(U(connect)(s, (struct sockaddr *)a, s_mkaddr(a, AK_MAPLOOP, s_h16(9))) == 0);   /* a connected datagram socket can re-connect */
    xl = sizeof x; CHECK(U(getpeername)(s, (struct sockaddr *)&x, &xl) == 0);
    { char d[64]; s_desc(&x, xl, d, sizeof d); EXPECT_STR(d, "v6:map:loop:scope0:len28"); }
    memset(a, 0, sizeof a);
    rc = U(connect)(s, (struct sockaddr *)a, SA6LEN); CHECK(rc == 0);
    xl = sizeof x; rc = U(getpeername)(s, (struct sockaddr *)&x, &xl);
    CHECK(rc != 0); CHECK(s_err() == WSAENOTCONN);
    s_close(s);
}

/* ---- connect(): name length and port rules ---- */
TEST(dsm_x_connect_name_length_rules) {
    static const int lens6[] = { 0, 16, 27 };
    char a[32];
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof lens6 / sizeof *lens6; i++) {
        SOCKET s = s_mk(SK_V6D, SOCK_STREAM); int rc;
        s_mkaddr(a, AK_V6LOOP, s_h16(9));
        rc = U(connect)(s, (struct sockaddr *)a, lens6[i]);
        CHECKF(rc != 0 && s_err() == WSAEFAULT, "v6 len %d rc=%d err=%d", lens6[i], rc, s_err());
        s_close(s);
    }
    for (int l = 0; l <= 15; l += 5) {
        SOCKET s = s_mk(SK_V4, SOCK_STREAM); int rc;
        s_mkaddr(a, AK_V4LOOP, s_h16(9));
        rc = U(connect)(s, (struct sockaddr *)a, l);
        CHECKF(rc != 0 && s_err() == WSAEFAULT, "v4 len %d rc=%d err=%d", l, rc, s_err());
        s_close(s);
    }
}
TEST(dsm_x_connect_port_zero_is_eaddrnotavail) {
    char a[32];
    if (!s_up()) return;
    for (int k = 0; k < 3; k++) {
        static const int ks[3] = { SK_V4, SK_V6D, SK_V6O };
        SOCKET s = s_mk(ks[k], SOCK_STREAM); int rc;
        s_mkaddr(a, ks[k] == SK_V4 ? AK_V4LOOP : AK_V6LOOP, 0);
        rc = U(connect)(s, (struct sockaddr *)a, ks[k] == SK_V4 ? SA4LEN : SA6LEN);
        CHECKF(rc != 0 && s_err() == WSAEADDRNOTAVAIL, "%s rc=%d err=%d", SK_NAME[ks[k]], rc, s_err());
        s_close(s);
    }
}

/* ---- IP_UNICAST_IF / IPV6_UNICAST_IF read length ---- */
TEST(dsm_x_unicast_if_get_length_rules) {
    static const struct { int sk, level; } r[] = { { SK_V4, IPPROTO_IP }, { SK_V6D, IPPROTO_IP }, { SK_V6D, IPPROTO_IPV6 }, { SK_V6O, IPPROTO_IPV6 } };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof r / sizeof *r; i++) {
        for (int l = 0; l <= 6; l += 2) {
            SOCKET s = s_mk(r[i].sk, SOCK_STREAM); unsigned char b[8]; int ll = l, rc;
            memset(b, 0x55, sizeof b);
            rc = U(getsockopt)(s, r[i].level, 31, (char *)b, &ll);
            if (l < 4) { CHECKF(rc != 0 && s_err() == WSAEFAULT, "%s/%d len %d rc=%d err=%d", SK_NAME[r[i].sk], r[i].level, l, rc, s_err()); EXPECT_EQ(ll, 0); }
            else { CHECKF(rc == 0, "%s/%d len %d", SK_NAME[r[i].sk], r[i].level, l); EXPECT_EQ(ll, 4); CHECK(b[4] == 0x55); }
            s_close(s);
        }
    }
}

/* ---- inet_ntop for IPv6 forms ---- */
TEST(dsm_x_inet_ntop_forms) {
    static const struct { unsigned char b[16]; const char *t; } r[] = {
        { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }, "::1" },
        { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "::" },
        { { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4 }, "::ffff:1.2.3.4" },
        { { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }, "fe80::1" },
    };
    typedef const char *(WSAAPI *ntop_t)(INT, const VOID *, PSTR, size_t);
    ntop_t f;
    if (!s_up()) return;
    f = (ntop_t)t_proc_in("ws2_32.dll", "inet_ntop");
    if (!f) { t_skip("inet_ntop unavailable"); return; }
    for (unsigned i = 0; i < sizeof r / sizeof *r; i++) {
        char o[64]; const char *p = f(AF_INET6, r[i].b, o, sizeof o);
        CHECKF(p != NULL && !strcmp(o, r[i].t), "row %u got %s", i, p ? o : "(null)");
        { char small[16]; size_t n = strlen(r[i].t);
          CHECKF(f(AF_INET6, r[i].b, small, n) == NULL && s_err() == WSAEINVAL, "row %u one short", i);
          CHECKF(f(AF_INET6, r[i].b, small, n + 1) != NULL, "row %u exact", i); }
    }
    { char o[64]; CHECK(f(99, r[0].b, o, sizeof o) == NULL); CHECK(s_err() == WSAEAFNOSUPPORT); }
}
