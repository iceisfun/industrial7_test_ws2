/* getaddrinfo family: the name "localhost" through every front end.
 *
 * Measures: the shape of a name-resolution answer that needs no network (loopback addresses only, families
 * filtered by the hint, ports from the service, socket type and protocol copied from the hint, entry sizes),
 * the effect of flags on a real name (AI_PASSIVE ignored, AI_NUMERICHOST refusing the name, AI_CANONNAME and
 * AI_FQDN giving a canonical name on the first entry only), and agreement between the four front ends. The exact
 * list length and order depend on the host configuration and are only noted. */
#include "gf.h"

static int ent_is_loopback(const struct gf_ent *e)
{
    if (e->family == AF_INET) return e->addr[4] == 127;
    if (e->family == AF_INET6) {
        int i;
        for (i = 8; i < 23; i++) if (e->addr[i]) return 0;
        return e->addr[23] == 1;
    }
    return 0;
}
static int has_addr(const struct gf_res *r, const char *want)
{
    int i;
    for (i = 0; i < r->n; i++) {
        char t[100];
        gf_fmt(&r->e[i], t, sizeof t);
        if (!strcmp(t, want)) return 1;
    }
    return 0;
}

/* Common shape checks for one answer. */
static void shape(int api, const struct gf_res *r, int family, int st, int pr, int port)
{
    int i;
    CHECKF(r->ret == 0 && r->werr == 0, "%s ret %d werr %d", gf_api_name(api), r->ret, r->werr);
    if (r->ret) return;
    CHECKF(r->n >= 1, "%s empty answer", gf_api_name(api));
    CHECKF(r->n < GF_MAXENT, "%s answer not terminated", gf_api_name(api));
    for (i = 0; i < r->n; i++) {
        const struct gf_ent *e = &r->e[i];
        CHECKF(e->family == AF_INET || e->family == AF_INET6, "%s entry %d family %d", gf_api_name(api), i, e->family);
        if (family) CHECKF(e->family == family, "%s entry %d family %d want %d", gf_api_name(api), i, e->family, family);
        CHECKF(e->addrlen == (e->family == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6)), "%s entry %d addrlen %u", gf_api_name(api), i, (unsigned)e->addrlen);
        CHECKF(e->socktype == st && e->protocol == pr, "%s entry %d type/proto %d/%d", gf_api_name(api), i, e->socktype, e->protocol);
        CHECKF(ent_is_loopback(e), "%s entry %d is not loopback", gf_api_name(api), i);
        if (port >= 0) CHECKF((int)gf_port(e) == port, "%s entry %d port %u", gf_api_name(api), i, gf_port(e));
    }
}

static void lh(int family, const char *serv, int st, int pr, int port, const char *must_have)
{
    int api;
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "localhost", serv, H(0, family, st, pr), &r);
        shape(api, &r, family, st, pr, port);
        if (!r.ret && must_have) CHECKF(has_addr(&r, must_have), "%s lacks %s", gf_api_name(api), must_have);
    }
}
#define LH_TEST(nm, fam, serv, st, pr, port, have) TEST(nm) { GFB_BEGIN(GF_ALL); lh(fam, serv, st, pr, port, have); GFB_END(); }
LH_TEST(gfl_inet_noserv,        AF_INET,  NULL, 0, 0, 0,  "127.0.0.1")
LH_TEST(gfl_inet_port80,        AF_INET,  "80", 0, 0, 80, "127.0.0.1")
LH_TEST(gfl_inet_port0,         AF_INET,  "0",  0, 0, 0,  "127.0.0.1")
LH_TEST(gfl_inet_port65535,     AF_INET,  "65535", 0, 0, 65535, "127.0.0.1")
LH_TEST(gfl_inet_stream_tcp,    AF_INET,  "8080", SOCK_STREAM, IPPROTO_TCP, 8080, "127.0.0.1")
LH_TEST(gfl_inet_dgram_udp,     AF_INET,  "8080", SOCK_DGRAM, IPPROTO_UDP, 8080, "127.0.0.1")
LH_TEST(gfl_inet_raw,           AF_INET,  "0",  SOCK_RAW, IPPROTO_ICMP, 0, "127.0.0.1")
LH_TEST(gfl_inet_stream_proto0, AF_INET,  "1",  SOCK_STREAM, 0, 1, "127.0.0.1")
LH_TEST(gfl_inet_odd_protocol,  AF_INET,  "1",  0, 253, 1, "127.0.0.1")
LH_TEST(gfl_inet6_noserv,       AF_INET6, NULL, 0, 0, 0,  "0:0:0:0:0:0:0:1")
LH_TEST(gfl_inet6_port80,       AF_INET6, "80", 0, 0, 80, "0:0:0:0:0:0:0:1")
LH_TEST(gfl_inet6_stream_tcp,   AF_INET6, "8080", SOCK_STREAM, IPPROTO_TCP, 8080, "0:0:0:0:0:0:0:1")
LH_TEST(gfl_inet6_dgram_udp,    AF_INET6, "8080", SOCK_DGRAM, IPPROTO_UDP, 8080, "0:0:0:0:0:0:0:1")
LH_TEST(gfl_unspec_noserv,      AF_UNSPEC, NULL, 0, 0, 0, "127.0.0.1")
LH_TEST(gfl_unspec_port80,      AF_UNSPEC, "80", 0, 0, 80, "127.0.0.1")
LH_TEST(gfl_unspec_stream_tcp,  AF_UNSPEC, "81", SOCK_STREAM, IPPROTO_TCP, 81, "127.0.0.1")
LH_TEST(gfl_unspec_dgram_udp,   AF_UNSPEC, "82", SOCK_DGRAM, IPPROTO_UDP, 82, "127.0.0.1")

/* AF_UNSPEC answers contain no duplicates of the same address. */
TEST(gfl_unspec_no_duplicate_addresses)
{
    int api, i, j;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "localhost", NULL, NULL, &r);
        CHECKF(r.ret == 0, "%s ret %d", gf_api_name(api), r.ret);
        for (i = 0; i < r.n; i++)
            for (j = i + 1; j < r.n; j++)
                CHECKF(!(r.e[i].family == r.e[j].family && !memcmp(r.e[i].addr + 4, r.e[j].addr + 4, 20)), "%s entries %d/%d identical", gf_api_name(api), i, j);
    }
    GFB_END();
}
/* Without a hint the entries carry socktype 0 / protocol 0 (no per-protocol expansion of the list). */
TEST(gfl_unhinted_entries_are_untyped)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "localhost", NULL, NULL, &r);
        shape(api, &r, 0, 0, 0, 0);
    }
    GFB_END();
}
/* Named service: port from the services database as the same library sees it. */
TEST(gfl_named_service_port)
{
    int api;
    GFB_BEGIN(GF_ALL);
    if (!U(getservbyname)) { t_skip("no getservbyname"); GFB_END(); return; }
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        struct gf_svc m = gf_model_service("http", SOCK_STREAM);
        gf_run(api, "localhost", "http", H(0, AF_INET, SOCK_STREAM, 0), &r);
        if (m.err) { CHECKF(r.ret == m.err, "%s ret %d", gf_api_name(api), r.ret); continue; }
        shape(api, &r, AF_INET, SOCK_STREAM, 0, (int)gf_ntohs16(m.port_be));
    }
    GFB_END();
}
/* Unknown service: the service error wins before any name work is done. */
ERR_ROW(gfl_unknown_service,       GF_ALL, "localhost", "no_such_service_zz", H(0, AF_INET, 0, 0), WSATYPE_NOT_FOUND)
ERR_ROW(gfl_numericserv_name,      GF_ALL, "localhost", "http", H(AI_NUMERICSERV, AF_INET, 0, 0), WSAHOST_NOT_FOUND)

/* ---- flags on a real name ---------------------------------------------------------------------------- */
ERR_ROW(gfl_numerichost_refuses_name,        GF_ALL, "localhost", NULL, H(AI_NUMERICHOST, 0, 0, 0), WSAHOST_NOT_FOUND)
ERR_ROW(gfl_numerichost_refuses_name_inet,   GF_ALL, "localhost", NULL, H(AI_NUMERICHOST, AF_INET, 0, 0), WSAHOST_NOT_FOUND)
ERR_ROW(gfl_numerichost_refuses_name_inet6,  GF_ALL, "localhost", NULL, H(AI_NUMERICHOST, AF_INET6, 0, 0), WSAHOST_NOT_FOUND)
ERR_ROW(gfl_numerichost_refuses_name_upper,  GF_ALL, "LOCALHOST", NULL, H(AI_NUMERICHOST, 0, 0, 0), WSAHOST_NOT_FOUND)

/* AI_PASSIVE only matters when the node is NULL. */
TEST(gfl_passive_ignored_with_name)
{
    int api, i;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "localhost", "80", H(AI_PASSIVE, AF_INET, 0, 0), &r);
        shape(api, &r, AF_INET, 0, 0, 80);
        for (i = 0; i < r.n; i++) CHECKF(r.e[i].addr[4] == 127, "%s entry %d not loopback", gf_api_name(api), i);
    }
    GFB_END();
}
TEST(gfl_flags_ignored_for_name)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "localhost", "80", H(AI_ALL | AI_NON_AUTHORITATIVE | AI_RETURN_PREFERRED_NAMES | AI_FILESERVER | AI_DISABLE_IDN_ENCODING, AF_INET, 0, 0), &r);
        shape(api, &r, AF_INET, 0, 0, 80);
    }
    GFB_END();
}
TEST(gfl_case_insensitive)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "LocalHost", NULL, H(0, AF_INET, 0, 0), &r);
        shape(api, &r, AF_INET, 0, 0, 0);
        CHECKF(has_addr(&r, "127.0.0.1"), "%s lacks 127.0.0.1", gf_api_name(api));
    }
    GFB_END();
}

/* Canonical name: present on the first entry only, absent without the flag. */
static void canon_localhost(int flags)
{
    int api;
    GF_EACH(api, GF_AW) {
        struct gf_res r;
        gf_run(api, "localhost", NULL, H(flags, 0, 0, 0), &r);
        CHECKF(r.ret == 0 && r.n >= 1, "%s ret %d", gf_api_name(api), r.ret);
        if (r.ret || r.n < 1) continue;
        CHECKF(r.e[0].has_canon && r.e[0].canon[0], "%s first entry has no canonical name", gf_api_name(api));
        CHECKF(!r.canon_after_first, "%s canonical name on a later entry", gf_api_name(api));
    }
}
TEST(gfl_canonname_first_entry_only) { GFB_BEGIN(GF_AW); canon_localhost(AI_CANONNAME); GFB_END(); }
TEST(gfl_fqdn_first_entry_only)      { GFB_BEGIN(GF_AW); canon_localhost(AI_FQDN); GFB_END(); }
TEST(gfl_canonname_inet_first_entry_only)
{
    int api;
    GFB_BEGIN(GF_AW);
    GF_EACH(api, GF_AW) {
        struct gf_res r;
        gf_run(api, "localhost", NULL, H(AI_CANONNAME, AF_INET, 0, 0), &r);
        CHECKF(r.ret == 0 && r.n >= 1 && r.e[0].has_canon && !r.canon_after_first, "%s ret %d", gf_api_name(api), r.ret);
    }
    GFB_END();
}
TEST(gfl_no_canonname_without_flag)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "localhost", NULL, NULL, &r);
        CHECKF(r.ret == 0 && r.n >= 1, "%s ret %d", gf_api_name(api), r.ret);
        CHECKF(!r.e[0].has_canon && !r.canon_after_first, "%s unexpected canonical name", gf_api_name(api));
    }
    GFB_END();
}
TEST(gfl_canon_and_fqdn_together_refused_aw)
{
    GFB_BEGIN(GF_AW);
    gf_check_err(GF_AW, "localhost", NULL, H(AI_CANONNAME | AI_FQDN, 0, 0, 0), WSAEINVAL);
    GFB_END();
}

/* ---- agreement between front ends --------------------------------------------------------------------------- */
TEST(gfl_front_ends_agree)
{
    struct gf_res a, w, xw, xa;
    int i;
    GFB_BEGIN(GF_ALL);
    gf_run(GF_A, "localhost", "80", H(0, AF_INET, SOCK_STREAM, IPPROTO_TCP), &a);
    gf_run(GF_W, "localhost", "80", H(0, AF_INET, SOCK_STREAM, IPPROTO_TCP), &w);
    gf_run(GF_XW, "localhost", "80", H(0, AF_INET, SOCK_STREAM, IPPROTO_TCP), &xw);
    if (gf_api_ok(GF_XA)) gf_run(GF_XA, "localhost", "80", H(0, AF_INET, SOCK_STREAM, IPPROTO_TCP), &xa); else xa = xw;
    EXPECT_EQ(a.n, w.n);
    EXPECT_EQ(a.n, xw.n);
    EXPECT_EQ(a.n, xa.n);
    for (i = 0; i < a.n && i < w.n && i < xw.n && i < xa.n; i++) {
        CHECK(!memcmp(a.e[i].addr, w.e[i].addr, a.e[i].addrlen));
        CHECK(!memcmp(a.e[i].addr, xw.e[i].addr, a.e[i].addrlen));
        CHECK(!memcmp(a.e[i].addr, xa.e[i].addr, a.e[i].addrlen));
    }
    GFB_END();
}
TEST(gfl_repeatable)
{
    struct gf_res first, again;
    int i;
    GFB_BEGIN(GF_W);
    gf_run(GF_W, "localhost", "80", NULL, &first);
    for (i = 0; i < 4; i++) {
        gf_run(GF_W, "localhost", "80", NULL, &again);
        EXPECT_EQ(again.n, first.n);
    }
    GFB_END();
}

/* ---- return conventions for a successful name lookup ----------------------------------------------------------------- */
TEST(gfl_success_clears_last_error)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "localhost", NULL, NULL, &r);
        CHECKF(r.ret == 0 && r.werr == 0, "%s ret %d werr %d", gf_api_name(api), r.ret, r.werr);
    }
    GFB_END();
}
/* The empty string behaves like the local machine name: it resolves, and clears the error. */
TEST(gfl_empty_node_resolves)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "", NULL, NULL, &r);
        CHECKF(r.ret == 0 && r.werr == 0 && r.n >= 1, "%s ret %d werr %d", gf_api_name(api), r.ret, r.werr);
    }
    GFB_END();
}
/* Async lookup of localhost agrees with the synchronous answer. */
TEST(gfl_async_matches_sync)
{
    ADDRINFOEXW *res = NULL, *sync = NULL, *p, *q;
    static OVERLAPPED ov;                  /* static: the library touches it again after the first completion signal */
    static const WCHAR name[] = { 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0 };
    ADDRINFOEXW hint;
    int n1 = 0, n2 = 0;
    GFB_BEGIN(GF_XW);
    memset(&hint, 0, sizeof hint);
    hint.ai_family = AF_INET;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(U(GetAddrInfoExW)(name, NULL, NS_DNS, NULL, &hint, &sync, NULL, NULL, NULL, NULL), 0);
    EXPECT_EQ(U(GetAddrInfoExW)(name, NULL, NS_DNS, NULL, &hint, &res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 10000), WAIT_OBJECT_0);
    for (p = res; p; p = p->ai_next) n1++;
    for (q = sync; q; q = q->ai_next) n2++;
    EXPECT_EQ(n1, n2);
    for (p = res, q = sync; p && q; p = p->ai_next, q = q->ai_next) {
        EXPECT_EQ(p->ai_family, q->ai_family);
        CHECK(p->ai_addrlen == q->ai_addrlen && !memcmp(p->ai_addr, q->ai_addr, p->ai_addrlen));
    }
    if (res) U(FreeAddrInfoExW)(res);
    if (sync) U(FreeAddrInfoExW)(sync);
    Sleep(200);                            /* let the library finish with the request before the event goes away */
    CloseHandle(ov.hEvent);
    GFB_END();
}
