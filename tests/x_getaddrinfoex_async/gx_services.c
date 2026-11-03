/* GetAddrInfoExW service-name resolution (pServiceName) against the stock services file, and how the two
 * selectors differ: NS_DNS validates the service, NS_ALL is lenient and falls back to port 0.
 * Numeric parsing follows a strtoul-like rule truncated to 16 bits. Destination is always 127.0.0.1. */
#include "gx.h"

#define NSALL 0
#define NSDNS 12

/* ---- named services on NS_DNS -------------------------------------------------------------------- */
/* socktype column: 1 stream only (service listed for tcp only), 2 dgram only, 0 both (entry type 0). */
static const struct { const char *svc; int port; int st; } named[] = {
    {"http", 80, 1}, {"ftp", 21, 1}, {"domain", 53, 0}, {"telnet", 23, 1}, {"smtp", 25, 1}, {"ntp", 123, 2},
    {"snmp", 161, 2}, {"echo", 7, 0}, {"https", 443, 0}, {"ssh", 22, 1}, {"ldap", 389, 1}, {"epmap", 135, 0},
    {"microsoft-ds", 445, 0}, {"HTTP", 80, 1}, {"Domain", 53, 0},
};
TEST(xsvc_named_services_dns_port_and_type)
{
    unsigned i; int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(named); i++) {
        gx_res r = gx_call("127.0.0.1", named[i].svc, ns ? NSDNS : NSALL, NULL);
        CHECKF(r.ret == 0 && r.wsa == 0, "%s ns=%d ret=%d", named[i].svc, ns, r.ret);
        if (r.ret == 0 && gx_count(r.res) == 1) {
            CHECKF(gx_port(r.res->ai_addr) == named[i].port, "%s port %d", named[i].svc, gx_port(r.res->ai_addr));
            CHECKF(r.res->ai_socktype == named[i].st, "%s socktype %d want %d", named[i].svc, r.res->ai_socktype, named[i].st);
            CHECK(GX_IS_V4(r.res, "127.0.0.1"));
        }
        gx_release(&r);
    }
    GX_END();
}
TEST(xsvc_named_service_on_localhost_both_entries)
{
    GX_BEGIN();
    gx_res r = gx_call("localhost", "http", NSDNS, NULL);
    GX_EQ(r.ret, 0);
    if (r.ret == 0) {
        GXEX *e;
        GX_EQ(gx_count(r.res), 2);
        for (e = r.res; e; e = e->ai_next) { GX_EQ(gx_port(e->ai_addr), 80); GX_EQ(e->ai_socktype, SOCK_STREAM); }
    }
    gx_release(&r);
    GX_END();
}
TEST(xsvc_null_name_named_service_gives_loopback_with_port)
{
    GX_BEGIN();
    gx_res r = gx_call(NULL, "http", NSDNS, NULL);
    GX_EQ(r.ret, 0);
    if (r.ret == 0) { GX_EQ(gx_count(r.res), 2); CHECK(!strcmp(gx_fams(r.res), "23,2")); GX_EQ(gx_port(r.res->ai_addr), 80); GX_EQ(r.res->ai_socktype, SOCK_STREAM); }
    gx_release(&r);
    GX_END();
}

/* ---- hinted socktype against the services file ---------------------------------------------------- */
/* NS_DNS: a stream-only service asked for as datagram (and the reverse) is "type not found"; a service
 * listed for both gives the port for either. NS_ALL ignores the mismatch and answers port 0. */
static const struct { const char *svc; int st; int dnsport; int dnserr; int allport; } typed[] = {
    {"http", SOCK_DGRAM, 0, WSATYPE_NOT_FOUND, 0},
    {"ftp", SOCK_DGRAM, 0, WSATYPE_NOT_FOUND, 0},
    {"http", SOCK_STREAM, 80, 0, 80},
    {"ftp", SOCK_STREAM, 21, 0, 21},
    {"domain", SOCK_STREAM, 53, 0, 53},
    {"domain", SOCK_DGRAM, 53, 0, 53},
    {"ntp", SOCK_DGRAM, 123, 0, 123},
    {"ntp", SOCK_STREAM, 0, WSATYPE_NOT_FOUND, 0},
};
TEST(xsvc_hinted_socktype_vs_services_file)
{
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(typed); i++) {
        GXEX h = gx_hint(0, 0, typed[i].st, 0);
        gx_res d = gx_call("127.0.0.1", typed[i].svc, NSDNS, &h), a = gx_call("127.0.0.1", typed[i].svc, NSALL, &h);
        if (typed[i].dnserr) { CHECKF(d.ret == typed[i].dnserr && d.wsa == typed[i].dnserr && d.res == NULL, "dns %s st=%d ret=%d", typed[i].svc, typed[i].st, d.ret); }
        else { CHECKF(d.ret == 0 && gx_port(d.res->ai_addr) == typed[i].dnsport && d.res->ai_socktype == typed[i].st, "dns %s st=%d ret=%d", typed[i].svc, typed[i].st, d.ret); }
        CHECKF(a.ret == 0, "all %s st=%d ret=%d", typed[i].svc, typed[i].st, a.ret);
        if (a.ret == 0) { GX_EQ(gx_port(a.res->ai_addr), typed[i].allport); GX_EQ(a.res->ai_socktype, typed[i].st); }
        gx_release(&d); gx_release(&a);
    }
    GX_END();
}
/* AI_NUMERICSERV forbids names: NS_DNS answers host-not-found (not a service error), NS_ALL silently uses 0. */
TEST(xsvc_numericserv_with_name_service)
{
    static const char *const svcs[] = {"http", "ftp", "domain", "HTTP", "nosuchsvc"};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(svcs); i++) {
        GXEX h = gx_hint(AI_NUMERICSERV, 0, SOCK_STREAM, 0);
        gx_res d = gx_call("127.0.0.1", svcs[i], NSDNS, &h), a = gx_call("127.0.0.1", svcs[i], NSALL, &h);
        CHECKF(d.ret == WSAHOST_NOT_FOUND && d.res == NULL, "dns %s ret=%d", svcs[i], d.ret);
        CHECKF(a.ret == 0 && gx_port(a.res->ai_addr) == 0, "all %s ret=%d", svcs[i], a.ret);
        gx_release(&d); gx_release(&a);
    }
    GX_END();
}
TEST(xsvc_numericserv_with_digits_is_fine)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_NUMERICSERV, 0, SOCK_STREAM, 0);
    gx_res d = gx_call("127.0.0.1", "8080", NSDNS, &h), a = gx_call("127.0.0.1", "8080", NSALL, &h);
    CHECK(d.ret == 0 && gx_port(d.res->ai_addr) == 8080);
    CHECK(a.ret == 0 && gx_port(a.res->ai_addr) == 8080);
    gx_release(&d); gx_release(&a);
    GX_END();
}

/* ---- numeric service strings ---------------------------------------------------------------------- */
/* port < 0: the call must fail with the table's error (NS_DNS). dnsport/allport are the observed ports. */
static const struct { const char *svc; int dnsport; int dnserr; int allport; } digits[] = {
    {"0", 0, 0, 0}, {"1", 1, 0, 1}, {"80", 80, 0, 80}, {"21", 21, 0, 21}, {"53", 53, 0, 53}, {"8080", 8080, 0, 8080},
    {"65535", 65535, 0, 65535}, {"65536", 0, 0, 0}, {"-1", 65535, 0, 65535}, {" 80", 80, 0, 80}, {"+80", 80, 0, 80},
    {"", 0, 0, 0},
    {"80 ", 0, WSATYPE_NOT_FOUND, 0}, {"0x50", 0, WSATYPE_NOT_FOUND, 0}, {"1e1", 0, WSATYPE_NOT_FOUND, 0},
    {"nosuchsvc", 0, WSATYPE_NOT_FOUND, 0},
};
TEST(xsvc_numeric_string_table)
{
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(digits); i++) {
        gx_res d = gx_call("127.0.0.1", digits[i].svc, NSDNS, NULL), a = gx_call("127.0.0.1", digits[i].svc, NSALL, NULL);
        if (digits[i].dnserr) CHECKF(d.ret == digits[i].dnserr && d.wsa == d.ret && d.res == NULL, "dns '%s' ret=%d", digits[i].svc, d.ret);
        else CHECKF(d.ret == 0 && gx_port(d.res->ai_addr) == digits[i].dnsport, "dns '%s' ret=%d port %d", digits[i].svc, d.ret, d.ret ? -1 : gx_port(d.res->ai_addr));
        CHECKF(a.ret == 0 && gx_port(a.res->ai_addr) == digits[i].allport, "all '%s' ret=%d port %d", digits[i].svc, a.ret, a.ret ? -1 : gx_port(a.res->ai_addr));
        gx_release(&d); gx_release(&a);
    }
    GX_END();
}
/* The wrap rules differ per selector for strings that are not plain digits: NS_ALL answers port 0 where
 * NS_DNS reports an error. */
TEST(xsvc_all_selector_is_lenient_for_bad_service_text)
{
    static const char *const bad[] = {"80 ", "0x50", "1e1", "nosuchsvc", "65536"};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(bad); i++) {
        gx_res a = gx_call("127.0.0.1", bad[i], NSALL, NULL);
        CHECKF(a.ret == 0 && gx_port(a.res->ai_addr) == 0, "'%s' ret=%d", bad[i], a.ret);
        gx_release(&a);
    }
    GX_END();
}
TEST(xsvc_service_only_null_name_numeric)
{
    GX_BEGIN();
    gx_res r = gx_call(NULL, "8080", NSDNS, NULL);
    GX_EQ(r.ret, 0);
    if (r.ret == 0) { GX_EQ(gx_count(r.res), 2); GX_EQ(gx_port(r.res->ai_addr), 8080); GX_EQ(gx_port(r.res->ai_next->ai_addr), 8080); }
    gx_release(&r);
    GX_END();
}
TEST(xsvc_unsupported_selector_with_service)
{
    GX_BEGIN();
    gx_res a = gx_call("127.0.0.1", "80", 15, NULL), b = gx_call("127.0.0.1", "http", 15, NULL), c = gx_call("127.0.0.1", "80", 38, NULL);
    GX_EQ(a.ret, WSASERVICE_NOT_FOUND); GX_EQ(b.ret, WSASERVICE_NOT_FOUND); GX_EQ(c.ret, WSAEINVAL);
    CHECK(a.res == NULL && b.res == NULL && c.res == NULL);
    GX_END();
}
/* ---- ANSI front end: same rows ---------------------------------------------------------------------- */
TEST(xsvc_ansi_front_end_services)
{
    static const struct { const char *svc; int port; int err; } rows[] = {
        {"http", 80, 0}, {"ftp", 21, 0}, {"domain", 53, 0}, {"8080", 8080, 0}, {"nosuchsvc", 0, WSATYPE_NOT_FOUND}, {"80 ", 0, WSATYPE_NOT_FOUND},
    };
    unsigned i;
    GX_BEGIN();
    if (!GXA() || !U(FreeAddrInfoEx)) { t_skip("no GetAddrInfoExA"); return; }
    for (i = 0; i < NARR(rows); i++) {
        GXEXA *res = NULL;
        int r = GXA()("127.0.0.1", rows[i].svc, NSDNS, NULL, NULL, (void **)&res, NULL, NULL, NULL, NULL);
        if (rows[i].err) { CHECKF(r == rows[i].err && res == NULL, "%s ret=%d", rows[i].svc, r); }
        else { CHECKF(r == 0 && res && gx_port(res->ai_addr) == rows[i].port, "%s ret=%d", rows[i].svc, r); }
        if (res) U(FreeAddrInfoEx)((PADDRINFOEXA)res);
    }
    GX_END();
}
