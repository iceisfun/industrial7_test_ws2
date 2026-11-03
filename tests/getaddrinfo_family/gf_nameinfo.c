/* getnameinfo / GetNameInfoW: address-to-text conversion.
 *
 * Measures: socket-address validation order (NULL, family, length), flag handling (NI_NUMERICHOST,
 * NI_NUMERICSERV, NI_DGRAM, NI_NAMEREQD, NI_NOFQDN, unknown bits), numeric host text for IPv4/IPv6 (scope id
 * kept, port dropped), service text (decimal, or the services-database name per protocol), the buffer-size
 * protocol of the wide call (WSAEFAULT for the host, ERROR_INSUFFICIENT_BUFFER for the service) versus the
 * ANSI call (ERROR_INSUFFICIENT_BUFFER for both, zero length meaning "size query" for a non-NULL buffer), the
 * rule that a NULL buffer or (wide call) a zero service length skips that part, and WSANOTINITIALISED.
 * Only numeric conversions are required to succeed with exact text; reverse lookups are exercised only through
 * calls that fall back to the numeric text. */
#include "gf.h"

#define GN_BEGIN() \
    do { if (!U(getnameinfo) || !U(GetNameInfoW) || !U(WSAGetLastError) || !U(WSASetLastError)) { t_skip("missing export"); return; } \
         if (gf_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define GN_END() gf_down()

static void mk4(SOCKADDR_IN *s, unsigned a, unsigned b, unsigned c, unsigned d, unsigned port)
{
    memset(s, 0, sizeof *s);
    s->sin_family = AF_INET;
    s->sin_port = (USHORT)(((port & 0xff) << 8) | (port >> 8));
    s->sin_addr.S_un.S_addr = a | b << 8 | c << 16 | (unsigned)d << 24;
}
static void mk6(SOCKADDR_IN6 *s, const unsigned short g[8], unsigned port, unsigned scope)
{
    int i;
    memset(s, 0, sizeof *s);
    s->sin6_family = AF_INET6;
    s->sin6_port = (USHORT)(((port & 0xff) << 8) | (port >> 8));
    for (i = 0; i < 8; i++) { s->sin6_addr.u.Byte[2 * i] = (UCHAR)(g[i] >> 8); s->sin6_addr.u.Byte[2 * i + 1] = (UCHAR)g[i]; }
    s->sin6_scope_id = scope;
}
static const unsigned short g_lo6[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };
static const unsigned short g_ll6[8] = { 0xfe80, 0, 0, 0, 0, 0, 0, 1 };
static const unsigned short g_doc6[8] = { 0x2001, 0xdb8, 0, 0, 0, 0, 0, 5 };
static const unsigned short g_any6[8] = { 0 };
static const unsigned short g_map6[8] = { 0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304 };

/* ---- call wrappers returning the text produced ------------------------------------------------------ */
struct gn_out { int ret, werr; char host[300], serv[100]; };
static void gn_a(const void *sa, int len, int want_host, int want_serv, int hostlen, int servlen, int flags, struct gn_out *o)
{
    memset(o, 0, sizeof *o);
    memset(o->host, 'X', sizeof o->host - 1);
    memset(o->serv, 'X', sizeof o->serv - 1);
    SETWSERR(0x1234);
    o->ret = U(getnameinfo)((const struct sockaddr *)sa, len, want_host ? o->host : NULL, hostlen, want_serv ? o->serv : NULL, servlen, flags);
    o->werr = WSERR();
}
static void gn_w(const void *sa, int len, int want_host, int want_serv, int hostlen, int servlen, int flags, struct gn_out *o)
{
    WCHAR h[300], s[100];
    size_t i;
    memset(o, 0, sizeof *o);
    for (i = 0; i < 299; i++) h[i] = 'X';
    h[299] = 0;
    for (i = 0; i < 99; i++) s[i] = 'X';
    s[99] = 0;
    SETWSERR(0x1234);
    o->ret = U(GetNameInfoW)((const SOCKADDR *)sa, len, want_host ? h : NULL, hostlen, want_serv ? s : NULL, servlen, flags);
    o->werr = WSERR();
    for (i = 0; i < 299; i++) { if (!h[i]) break; o->host[i] = h[i] < 0x80 ? (char)h[i] : '?'; }
    for (i = 0; i < 99; i++) { if (!s[i]) break; o->serv[i] = s[i] < 0x80 ? (char)s[i] : '?'; }
}
static int gn_untouched(const char *s) { return s[0] == 'X' && s[1] == 'X'; }

typedef void (*gn_fn)(const void *, int, int, int, int, int, int, struct gn_out *);
static const char *gn_name(gn_fn f) { return f == gn_a ? "getnameinfo" : "GetNameInfoW"; }

/* Numeric host + numeric service for a socket address: exact text through both calls. */
static void gn_numeric(const void *sa, int len, int flags, const char *host, const char *serv)
{
    gn_fn fns[2] = { gn_a, gn_w };
    int i;
    for (i = 0; i < 2; i++) {
        struct gn_out o;
        fns[i](sa, len, 1, 1, 256, 32, flags, &o);
        CHECKF(o.ret == 0 && o.werr == 0, "%s ret %d werr %d", gn_name(fns[i]), o.ret, o.werr);
        if (o.ret) continue;
        CHECKF(!strcmp(o.host, host), "%s host \"%s\" want \"%s\"", gn_name(fns[i]), o.host, host);
        CHECKF(!strcmp(o.serv, serv), "%s serv \"%s\" want \"%s\"", gn_name(fns[i]), o.serv, serv);
    }
}
#define NHS (NI_NUMERICHOST | NI_NUMERICSERV)

#define N4(nm, a, b, c, d, port, host, serv) \
    TEST(nm) { SOCKADDR_IN s; GN_BEGIN(); mk4(&s, a, b, c, d, port); gn_numeric(&s, sizeof s, NHS, host, serv); GN_END(); }
N4(gfi_v4_loopback_80,   127, 0, 0, 1, 80,    "127.0.0.1", "80")
N4(gfi_v4_any_0,         0, 0, 0, 0, 0,       "0.0.0.0", "0")
N4(gfi_v4_broadcast,     255, 255, 255, 255, 65535, "255.255.255.255", "65535")
N4(gfi_v4_private,       10, 20, 30, 40, 8080, "10.20.30.40", "8080")
N4(gfi_v4_port_1,        192, 0, 2, 7, 1,     "192.0.2.7", "1")
N4(gfi_v4_port_256,      192, 0, 2, 7, 256,   "192.0.2.7", "256")
N4(gfi_v4_port_443,      1, 2, 3, 4, 443,     "1.2.3.4", "443")
N4(gfi_v4_port_32768,    1, 2, 3, 4, 32768,   "1.2.3.4", "32768")
N4(gfi_v4_port_54321,    172, 16, 0, 9, 54321, "172.16.0.9", "54321")
N4(gfi_v4_port_65534,    100, 64, 1, 1, 65534, "100.64.1.1", "65534")

#define N6(nm, g, port, scope, host, serv) \
    TEST(nm) { SOCKADDR_IN6 s; GN_BEGIN(); mk6(&s, g, port, scope); gn_numeric(&s, sizeof s, NHS, host, serv); GN_END(); }
N6(gfi_v6_loopback_80,   g_lo6, 80, 0,   "::1", "80")
N6(gfi_v6_any_0,         g_any6, 0, 0,   "::", "0")
N6(gfi_v6_doc_443,       g_doc6, 443, 0, "2001:db8::5", "443")
N6(gfi_v6_linklocal_scope, g_ll6, 80, 3, "fe80::1%3", "80")
N6(gfi_v6_linklocal_scope12, g_ll6, 0, 12, "fe80::1%12", "0")
N6(gfi_v6_loopback_scope,  g_lo6, 1, 1,  "::1%1", "1")
N6(gfi_v6_mapped,        g_map6, 25, 0,  "::ffff:1.2.3.4", "25")
N6(gfi_v6_port_65535,    g_doc6, 65535, 0, "2001:db8::5", "65535")

/* flow info in a v6 address is ignored */
TEST(gfi_v6_flowinfo_ignored)
{
    SOCKADDR_IN6 s;
    GN_BEGIN();
    mk6(&s, g_doc6, 80, 0);
    s.sin6_flowinfo = 0x12345678;
    gn_numeric(&s, sizeof s, NHS, "2001:db8::5", "80");
    GN_END();
}
/* sin_zero / trailing bytes are ignored and a longer length is fine */
TEST(gfi_v4_longer_length_accepted)
{
    SOCKADDR_STORAGE ss;
    GN_BEGIN();
    memset(&ss, 0, sizeof ss);
    mk4((SOCKADDR_IN *)&ss, 9, 8, 7, 6, 99);
    gn_numeric(&ss, sizeof ss, NHS, "9.8.7.6", "99");
    gn_numeric(&ss, 28, NHS, "9.8.7.6", "99");
    gn_numeric(&ss, 17, NHS, "9.8.7.6", "99");
    GN_END();
}
TEST(gfi_v4_sin_zero_ignored)
{
    SOCKADDR_IN s;
    GN_BEGIN();
    mk4(&s, 9, 8, 7, 6, 99);
    memset(s.sin_zero, 0xaa, sizeof s.sin_zero);
    gn_numeric(&s, sizeof s, NHS, "9.8.7.6", "99");
    GN_END();
}
TEST(gfi_v6_longer_length_accepted)
{
    SOCKADDR_STORAGE ss;
    GN_BEGIN();
    memset(&ss, 0, sizeof ss);
    mk6((SOCKADDR_IN6 *)&ss, g_doc6, 99, 0);
    gn_numeric(&ss, sizeof ss, NHS, "2001:db8::5", "99");
    gn_numeric(&ss, 29, NHS, "2001:db8::5", "99");
    GN_END();
}

/* ---- socket address validation ------------------------------------------------------------------------ */
static void gn_expect_err(const void *sa, int len, int flags, int err_a, int err_w)
{
    gn_fn fns[2] = { gn_a, gn_w };
    int want[2], i;
    want[0] = err_a; want[1] = err_w;
    for (i = 0; i < 2; i++) {
        struct gn_out o;
        fns[i](sa, len, 1, 1, 256, 32, flags, &o);
        CHECKF(o.ret == want[i], "%s ret %d want %d", gn_name(fns[i]), o.ret, want[i]);
        CHECKF(o.werr == want[i], "%s werr %d want %d", gn_name(fns[i]), o.werr, want[i]);
        CHECKF(gn_untouched(o.host), "%s wrote the host buffer", gn_name(fns[i]));
        CHECKF(gn_untouched(o.serv), "%s wrote the service buffer", gn_name(fns[i]));
    }
}
TEST(gfi_null_sockaddr_is_efault)
{
    GN_BEGIN();
    gn_expect_err(NULL, 16, NHS, WSAEFAULT, WSAEFAULT);
    gn_expect_err(NULL, 0, NHS, WSAEFAULT, WSAEFAULT);
    gn_expect_err(NULL, 28, 0, WSAEFAULT, WSAEFAULT);
    GN_END();
}
#define BADFAM(nm, fam) \
    TEST(nm) { SOCKADDR_STORAGE ss; GN_BEGIN(); memset(&ss, 0, sizeof ss); ss.ss_family = (ADDRESS_FAMILY)(fam); \
        gn_expect_err(&ss, sizeof ss, NHS, WSAEAFNOSUPPORT, WSAEAFNOSUPPORT); GN_END(); }
BADFAM(gfi_family_unspec,  AF_UNSPEC)
BADFAM(gfi_family_unix,    AF_UNIX)
BADFAM(gfi_family_ipx,     AF_IPX)
BADFAM(gfi_family_netbios, AF_NETBIOS)
BADFAM(gfi_family_irda,    26)
BADFAM(gfi_family_bth,     32)
BADFAM(gfi_family_24,      24)
BADFAM(gfi_family_22,      22)
BADFAM(gfi_family_3,       3)
BADFAM(gfi_family_max,     0xffff)
/* family is judged before the length */
TEST(gfi_family_beats_length)
{
    SOCKADDR_STORAGE ss;
    GN_BEGIN();
    memset(&ss, 0, sizeof ss);
    ss.ss_family = AF_UNIX;
    gn_expect_err(&ss, 2, NHS, WSAEAFNOSUPPORT, WSAEAFNOSUPPORT);
    gn_expect_err(&ss, 0, NHS, WSAEAFNOSUPPORT, WSAEAFNOSUPPORT);
    GN_END();
}
/* too-short length for the family is WSAEFAULT */
TEST(gfi_v4_short_length)
{
    SOCKADDR_IN s;
    int len;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    for (len = 0; len < 16; len++) gn_expect_err(&s, len, NHS, WSAEFAULT, WSAEFAULT);
    GN_END();
}
TEST(gfi_v6_short_length)
{
    SOCKADDR_IN6 s;
    int len;
    GN_BEGIN();
    mk6(&s, g_doc6, 80, 0);
    for (len = 0; len < 28; len++) gn_expect_err(&s, len, NHS, WSAEFAULT, WSAEFAULT);
    GN_END();
}
TEST(gfi_negative_length_is_efault)
{
    SOCKADDR_IN s;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    gn_expect_err(&s, -1, NHS, WSAEFAULT, WSAEFAULT);
    gn_expect_err(&s, (int)0x80000000, NHS, WSAEFAULT, WSAEFAULT);
    GN_END();
}
TEST(gfi_v4_exact_length_ok)  { SOCKADDR_IN s; GN_BEGIN(); mk4(&s, 1, 2, 3, 4, 80); gn_numeric(&s, 16, NHS, "1.2.3.4", "80"); GN_END(); }
TEST(gfi_v6_exact_length_ok)  { SOCKADDR_IN6 s; GN_BEGIN(); mk6(&s, g_doc6, 80, 0); gn_numeric(&s, 28, NHS, "2001:db8::5", "80"); GN_END(); }
/* length checks are by family: a v6 address with a v4-sized length fails, a v4 address with a v6 length works */
TEST(gfi_v6_with_v4_length_fails)
{
    SOCKADDR_STORAGE ss;
    GN_BEGIN();
    memset(&ss, 0, sizeof ss);
    mk6((SOCKADDR_IN6 *)&ss, g_doc6, 80, 0);
    gn_expect_err(&ss, 16, NHS, WSAEFAULT, WSAEFAULT);
    GN_END();
}

/* ---- nothing requested ---------------------------------------------------------------------------------- */
TEST(gfi_no_buffers_succeeds)
{
    SOCKADDR_IN s;
    gn_fn fns[2] = { gn_a, gn_w };
    int i;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    for (i = 0; i < 2; i++) {
        struct gn_out o;
        fns[i](&s, sizeof s, 0, 0, 0, 0, NHS, &o);
        CHECKF(o.ret == 0 && o.werr == 0, "%s ret %d werr %d", gn_name(fns[i]), o.ret, o.werr);
    }
    GN_END();
}
TEST(gfi_no_buffers_with_lengths_succeeds)
{
    SOCKADDR_IN s;
    gn_fn fns[2] = { gn_a, gn_w };
    int i;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    for (i = 0; i < 2; i++) {
        struct gn_out o;
        fns[i](&s, sizeof s, 0, 0, 100, 100, 0, &o);
        CHECKF(o.ret == 0, "%s ret %d", gn_name(fns[i]), o.ret);
    }
    GN_END();
}
TEST(gfi_host_only)
{
    SOCKADDR_IN s;
    gn_fn fns[2] = { gn_a, gn_w };
    int i;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    for (i = 0; i < 2; i++) {
        struct gn_out o;
        fns[i](&s, sizeof s, 1, 0, 64, 0, NHS, &o);
        CHECKF(o.ret == 0 && !strcmp(o.host, "1.2.3.4"), "%s ret %d host \"%s\"", gn_name(fns[i]), o.ret, o.host);
        CHECK(gn_untouched(o.serv));
    }
    GN_END();
}
TEST(gfi_serv_only)
{
    SOCKADDR_IN s;
    gn_fn fns[2] = { gn_a, gn_w };
    int i;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    for (i = 0; i < 2; i++) {
        struct gn_out o;
        fns[i](&s, sizeof s, 0, 1, 0, 32, NHS, &o);
        CHECKF(o.ret == 0 && !strcmp(o.serv, "80"), "%s ret %d serv \"%s\"", gn_name(fns[i]), o.ret, o.serv);
        CHECK(gn_untouched(o.host));
    }
    GN_END();
}
/* wide call: a service buffer with length 0 is skipped */
TEST(gfi_w_serv_length_zero_skipped)
{
    SOCKADDR_IN s;
    struct gn_out o;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    gn_w(&s, sizeof s, 1, 1, 64, 0, NHS, &o);
    EXPECT_EQ(o.ret, 0);
    EXPECT_STR(o.host, "1.2.3.4");
    CHECK(gn_untouched(o.serv));
    GN_END();
}

/* ---- host buffer protocol --------------------------------------------------------------------------------- */
/* wide: WSAEFAULT when the buffer cannot hold text plus NUL; ANSI: ERROR_INSUFFICIENT_BUFFER */
static void host_size(const void *sa, int len, const char *text)
{
    int n = (int)strlen(text), l;
    for (l = 1; l <= n + 2; l++) {
        struct gn_out a, w;
        gn_a(sa, len, 1, 0, l, 0, NI_NUMERICHOST, &a);
        gn_w(sa, len, 1, 0, l, 0, NI_NUMERICHOST, &w);
        if (l >= n + 1) {
            CHECKF(a.ret == 0 && !strcmp(a.host, text), "ANSI len %d ret %d \"%s\"", l, a.ret, a.host);
            CHECKF(w.ret == 0 && !strcmp(w.host, text), "wide len %d ret %d \"%s\"", l, w.ret, w.host);
        } else {
            CHECKF(a.ret == ERROR_INSUFFICIENT_BUFFER, "ANSI len %d ret %d", l, a.ret);
            CHECKF(w.ret == WSAEFAULT, "wide len %d ret %d", l, w.ret);
            CHECKF(a.werr == a.ret && w.werr == w.ret, "last error %d/%d", a.werr, w.werr);
        }
    }
}
TEST(gfi_host_size_v4)       { SOCKADDR_IN s; GN_BEGIN(); mk4(&s, 127, 0, 0, 1, 0); host_size(&s, sizeof s, "127.0.0.1"); GN_END(); }
TEST(gfi_host_size_v4_short) { SOCKADDR_IN s; GN_BEGIN(); mk4(&s, 1, 2, 3, 4, 0); host_size(&s, sizeof s, "1.2.3.4"); GN_END(); }
TEST(gfi_host_size_v6_loop)  { SOCKADDR_IN6 s; GN_BEGIN(); mk6(&s, g_lo6, 0, 0); host_size(&s, sizeof s, "::1"); GN_END(); }
TEST(gfi_host_size_v6_doc)   { SOCKADDR_IN6 s; GN_BEGIN(); mk6(&s, g_doc6, 0, 0); host_size(&s, sizeof s, "2001:db8::5"); GN_END(); }
TEST(gfi_host_size_v6_scope) { SOCKADDR_IN6 s; GN_BEGIN(); mk6(&s, g_ll6, 0, 7); host_size(&s, sizeof s, "fe80::1%7"); GN_END(); }
/* zero-length host buffer */
TEST(gfi_host_length_zero_wide_efault)
{
    SOCKADDR_IN s;
    struct gn_out o;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    gn_w(&s, sizeof s, 1, 0, 0, 0, NI_NUMERICHOST, &o);
    EXPECT_EQ(o.ret, WSAEFAULT);
    CHECK(gn_untouched(o.host));
    GN_END();
}
/* ANSI: a non-NULL buffer with length 0 is a size probe that succeeds without writing */
TEST(gfi_host_length_zero_ansi_probe)
{
    SOCKADDR_IN s;
    struct gn_out o;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    gn_a(&s, sizeof s, 1, 0, 0, 0, NI_NUMERICHOST, &o);
    EXPECT_EQ(o.ret, 0);
    CHECK(gn_untouched(o.host));
    GN_END();
}
TEST(gfi_serv_length_zero_ansi_probe)
{
    SOCKADDR_IN s;
    struct gn_out o;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    gn_a(&s, sizeof s, 0, 1, 0, 0, NI_NUMERICSERV, &o);
    EXPECT_EQ(o.ret, 0);
    CHECK(gn_untouched(o.serv));
    GN_END();
}
/* a host failure leaves the service buffer alone */
TEST(gfi_host_failure_skips_service)
{
    SOCKADDR_IN s;
    struct gn_out a, w;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 80);
    gn_a(&s, sizeof s, 1, 1, 3, 32, NHS, &a);
    gn_w(&s, sizeof s, 1, 1, 3, 32, NHS, &w);
    CHECK(a.ret != 0 && w.ret != 0);
    CHECK(gn_untouched(a.serv) && gn_untouched(w.serv));
    GN_END();
}

/* ---- service buffer protocol --------------------------------------------------------------------------------- */
static void serv_size(unsigned port, const char *text)
{
    SOCKADDR_IN s;
    int n = (int)strlen(text), l;
    mk4(&s, 1, 2, 3, 4, port);
    for (l = 1; l <= n + 2; l++) {
        struct gn_out a, w;
        gn_a(&s, sizeof s, 0, 1, 0, l, NI_NUMERICSERV, &a);
        gn_w(&s, sizeof s, 0, 1, 0, l, NI_NUMERICSERV, &w);
        if (l >= n + 1) {
            CHECKF(a.ret == 0 && !strcmp(a.serv, text), "ANSI len %d ret %d \"%s\"", l, a.ret, a.serv);
            CHECKF(w.ret == 0 && !strcmp(w.serv, text), "wide len %d ret %d \"%s\"", l, w.ret, w.serv);
        } else {
            CHECKF(a.ret == ERROR_INSUFFICIENT_BUFFER, "ANSI len %d ret %d", l, a.ret);
            if (l > 0) CHECKF(w.ret == ERROR_INSUFFICIENT_BUFFER, "wide len %d ret %d", l, w.ret);
        }
    }
}
TEST(gfi_serv_size_80)    { GN_BEGIN(); serv_size(80, "80"); GN_END(); }
TEST(gfi_serv_size_0)     { GN_BEGIN(); serv_size(0, "0"); GN_END(); }
TEST(gfi_serv_size_8080)  { GN_BEGIN(); serv_size(8080, "8080"); GN_END(); }
TEST(gfi_serv_size_65535) { GN_BEGIN(); serv_size(65535, "65535"); GN_END(); }
/* a service failure still delivers the host text */
TEST(gfi_serv_failure_after_host_written)
{
    SOCKADDR_IN s;
    struct gn_out w;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 8080);
    gn_w(&s, sizeof s, 1, 1, 64, 2, NHS, &w);
    EXPECT_EQ(w.ret, ERROR_INSUFFICIENT_BUFFER);
    EXPECT_STR(w.host, "1.2.3.4");
    GN_END();
}

/* ---- flags ---------------------------------------------------------------------------------------------------- */
/* bits other than the five defined ones are ignored */
static void flag_numeric(int flags)
{
    SOCKADDR_IN s;
    mk4(&s, 5, 6, 7, 8, 9);
    gn_numeric(&s, sizeof s, flags, "5.6.7.8", "9");
}
#define FLG(nm, f) TEST(nm) { GN_BEGIN(); flag_numeric((f) | NHS); GN_END(); }
FLG(gfi_flags_none,      0)
FLG(gfi_flags_nofqdn,    NI_NOFQDN)
FLG(gfi_flags_dgram,     NI_DGRAM)
FLG(gfi_flags_nofqdn_dgram, NI_NOFQDN | NI_DGRAM)
FLG(gfi_flags_unknown_0x20,  0x20)
FLG(gfi_flags_unknown_0x100, 0x100)
FLG(gfi_flags_unknown_0x8000, 0x8000)
FLG(gfi_flags_unknown_high,  (int)0x80000000)
FLG(gfi_flags_unknown_many,  (int)0xffffffe0)
/* NUMERICHOST wins over NAMEREQD: no lookup is attempted, so no failure */
TEST(gfi_namereqd_with_numerichost_succeeds)
{
    SOCKADDR_IN s;
    GN_BEGIN();
    mk4(&s, 5, 6, 7, 8, 9);
    gn_numeric(&s, sizeof s, NI_NAMEREQD | NI_NUMERICHOST | NI_NUMERICSERV, "5.6.7.8", "9");
    GN_END();
}
TEST(gfi_namereqd_with_numerichost_v6_succeeds)
{
    SOCKADDR_IN6 s;
    GN_BEGIN();
    mk6(&s, g_doc6, 9, 0);
    gn_numeric(&s, sizeof s, NI_NAMEREQD | NI_NUMERICHOST | NI_NUMERICSERV, "2001:db8::5", "9");
    GN_END();
}
/* Without NI_NAMEREQD a failed reverse lookup falls back to the numeric text, so the call succeeds and the
 * host buffer is non-empty (the text itself depends on the machine). Loopback addresses only. */
static void lookup_fallback(const void *sa, int len)
{
    gn_fn fns[2] = { gn_a, gn_w };
    int i;
    for (i = 0; i < 2; i++) {
        struct gn_out o;
        fns[i](sa, len, 1, 0, 256, 0, 0, &o);
        CHECKF(o.ret == 0, "%s ret %d", gn_name(fns[i]), o.ret);
        CHECKF(o.host[0] != 0 && !gn_untouched(o.host), "%s empty host", gn_name(fns[i]));
    }
}
TEST(gfi_loopback_v4_reverse_or_numeric)  { SOCKADDR_IN s; GN_BEGIN(); mk4(&s, 127, 0, 0, 1, 80); lookup_fallback(&s, sizeof s); GN_END(); }
TEST(gfi_loopback_v6_reverse_or_numeric)  { SOCKADDR_IN6 s; GN_BEGIN(); mk6(&s, g_lo6, 80, 0); lookup_fallback(&s, sizeof s); GN_END(); }

/* ---- service names ----------------------------------------------------------------------------------------------- */
/* Without NI_NUMERICSERV the services database names the port per protocol; unknown ports print as decimal.
 * The expected text is derived from getservbyport on the same library. */
static void serv_name_check(unsigned port, int flags)
{
    SOCKADDR_IN s;
    gn_fn fns[2] = { gn_a, gn_w };
    const struct servent *se;
    char want[64];
    int i;
    mk4(&s, 1, 2, 3, 4, port);
    se = U(getservbyport)(s.sin_port, (flags & NI_DGRAM) ? "udp" : "tcp");
    if (se) lstrcpynA(want, se->s_name, sizeof want); else snprintf(want, sizeof want, "%u", port);
    for (i = 0; i < 2; i++) {
        struct gn_out o;
        fns[i](&s, sizeof s, 0, 1, 0, 32, flags, &o);
        CHECKF(o.ret == 0, "%s port %u ret %d", gn_name(fns[i]), port, o.ret);
        if (!o.ret) CHECKF(!strcmp(o.serv, want), "%s port %u serv \"%s\" want \"%s\"", gn_name(fns[i]), port, o.serv, want);
    }
}
#define SN(nm, port, fl) TEST(nm) { GN_BEGIN(); if (!U(getservbyport)) { t_skip("no getservbyport"); GN_END(); return; } serv_name_check(port, fl); GN_END(); }
SN(gfi_svc_tcp_80,    80, 0)
SN(gfi_svc_tcp_21,    21, 0)
SN(gfi_svc_tcp_22,    22, 0)
SN(gfi_svc_tcp_25,    25, 0)
SN(gfi_svc_tcp_443,   443, 0)
SN(gfi_svc_tcp_53,    53, 0)
SN(gfi_svc_tcp_123,   123, 0)
SN(gfi_svc_udp_53,    53, NI_DGRAM)
SN(gfi_svc_udp_123,   123, NI_DGRAM)
SN(gfi_svc_udp_67,    67, NI_DGRAM)
SN(gfi_svc_udp_161,   161, NI_DGRAM)
SN(gfi_svc_udp_80,    80, NI_DGRAM)
SN(gfi_svc_tcp_0,     0, 0)
SN(gfi_svc_tcp_54321, 54321, 0)
SN(gfi_svc_udp_54321, 54321, NI_DGRAM)
SN(gfi_svc_tcp_65535, 65535, 0)
/* NI_NUMERICSERV always prints digits, even for a registered port */
TEST(gfi_numericserv_forces_digits)
{
    GN_BEGIN();
    flag_numeric(NHS);
    {
        SOCKADDR_IN s;
        mk4(&s, 1, 2, 3, 4, 80);
        gn_numeric(&s, sizeof s, NHS, "1.2.3.4", "80");
        mk4(&s, 1, 2, 3, 4, 443);
        gn_numeric(&s, sizeof s, NHS | NI_DGRAM, "1.2.3.4", "443");
    }
    GN_END();
}
/* The port comes out in host order whatever the byte order on the wire: 0x5000 in memory is port 80 */
TEST(gfi_port_byte_order)
{
    SOCKADDR_IN s;
    GN_BEGIN();
    mk4(&s, 1, 2, 3, 4, 0);
    s.sin_port = 0x5000;
    gn_numeric(&s, sizeof s, NHS, "1.2.3.4", "80");
    s.sin_port = 0x0050;
    gn_numeric(&s, sizeof s, NHS, "1.2.3.4", "20480");
    GN_END();
}

/* ---- consistency with the wide address-to-string path --------------------------------------------------------------- */
TEST(gfi_numeric_host_matches_wsaaddresstostring)
{
    SOCKADDR_IN s4;
    SOCKADDR_IN6 s6;
    struct gn_out o;
    WCHAR buf[64];
    DWORD len;
    GN_BEGIN();
    if (!U(WSAAddressToStringW)) { t_skip("no WSAAddressToStringW"); GN_END(); return; }
    mk4(&s4, 10, 9, 8, 7, 0);
    len = 64;
    EXPECT_EQ(U(WSAAddressToStringW)((LPSOCKADDR)&s4, sizeof s4, NULL, buf, &len), 0);
    gn_w(&s4, sizeof s4, 1, 0, 64, 0, NI_NUMERICHOST, &o);
    { char t[64]; size_t i; for (i = 0; buf[i] && i < 63; i++) t[i] = (char)buf[i]; t[i] = 0; EXPECT_STR(o.host, t); }
    mk6(&s6, g_ll6, 0, 4);
    len = 64;
    EXPECT_EQ(U(WSAAddressToStringW)((LPSOCKADDR)&s6, sizeof s6, NULL, buf, &len), 0);
    gn_w(&s6, sizeof s6, 1, 0, 64, 0, NI_NUMERICHOST, &o);
    { char t[64]; size_t i; for (i = 0; buf[i] && i < 63; i++) t[i] = (char)buf[i]; t[i] = 0; EXPECT_STR(o.host, t); }
    GN_END();
}
/* The port in the socket address is not part of the host text even though the string converter would add it */
TEST(gfi_numeric_host_drops_port)
{
    SOCKADDR_IN s;
    struct gn_out o;
    GN_BEGIN();
    mk4(&s, 10, 9, 8, 7, 1234);
    gn_w(&s, sizeof s, 1, 0, 64, 0, NI_NUMERICHOST, &o);
    EXPECT_STR(o.host, "10.9.8.7");
    gn_a(&s, sizeof s, 1, 0, 64, 0, NI_NUMERICHOST, &o);
    EXPECT_STR(o.host, "10.9.8.7");
    GN_END();
}
/* the caller's socket address is not modified (the port is cleared in a private copy) */
TEST(gfi_sockaddr_not_modified)
{
    SOCKADDR_IN s, before;
    SOCKADDR_IN6 s6, before6;
    struct gn_out o;
    GN_BEGIN();
    mk4(&s, 10, 9, 8, 7, 1234);
    before = s;
    gn_w(&s, sizeof s, 1, 1, 64, 16, NHS, &o);
    CHECK(!memcmp(&s, &before, sizeof s));
    mk6(&s6, g_ll6, 1234, 2);
    before6 = s6;
    gn_w(&s6, sizeof s6, 1, 1, 64, 16, NHS, &o);
    CHECK(!memcmp(&s6, &before6, sizeof s6));
    GN_END();
}
/* repeatable */
TEST(gfi_repeatable)
{
    SOCKADDR_IN s;
    int i;
    GN_BEGIN();
    mk4(&s, 10, 9, 8, 7, 1234);
    for (i = 0; i < 5; i++) gn_numeric(&s, sizeof s, NHS, "10.9.8.7", "1234");
    GN_END();
}
/* ANSI and wide produce the same text */
TEST(gfi_ansi_wide_parity)
{
    SOCKADDR_IN6 s;
    struct gn_out a, w;
    GN_BEGIN();
    mk6(&s, g_doc6, 8443, 5);
    gn_a(&s, sizeof s, 1, 1, 100, 20, NHS, &a);
    gn_w(&s, sizeof s, 1, 1, 100, 20, NHS, &w);
    EXPECT_EQ(a.ret, w.ret);
    EXPECT_STR(a.host, w.host);
    EXPECT_STR(a.serv, w.serv);
    GN_END();
}

/* ---- before WSAStartup ------------------------------------------------------------------------------------------------ */
TEST(gfi_not_initialised_ansi)
{
    SOCKADDR_IN s;
    struct gn_out o;
    if (!U(getnameinfo) || !U(WSAGetLastError)) { t_skip("missing export"); return; }
    mk4(&s, 1, 2, 3, 4, 80);
    gn_a(&s, sizeof s, 1, 1, 64, 16, NHS, &o);
    EXPECT_EQ(o.ret, WSANOTINITIALISED);
    EXPECT_EQ(o.werr, WSANOTINITIALISED);
    CHECK(gn_untouched(o.host));
}
TEST(gfi_not_initialised_wide)
{
    SOCKADDR_IN s;
    struct gn_out o;
    if (!U(GetNameInfoW) || !U(WSAGetLastError)) { t_skip("missing export"); return; }
    mk4(&s, 1, 2, 3, 4, 80);
    gn_w(&s, sizeof s, 1, 1, 64, 16, NHS, &o);
    EXPECT_EQ(o.ret, WSANOTINITIALISED);
    EXPECT_EQ(o.werr, WSANOTINITIALISED);
}
TEST(gfi_not_initialised_getaddrinfo_family)
{
    struct gf_res r;
    int api;
    if (!U(WSAGetLastError) || !gf_have(GF_AW | GF_XW)) { t_skip("missing export"); return; }
    for (api = GF_A; api <= GF_XW; api <<= 1) {
        gf_run(api, "127.0.0.1", NULL, NULL, &r);
        CHECKF(r.ret == WSANOTINITIALISED, "%s ret %d", gf_api_name(api), r.ret);
        CHECKF(r.werr == WSANOTINITIALISED, "%s werr %d", gf_api_name(api), r.werr);
    }
}
/* the check precedes argument validation */
TEST(gfi_not_initialised_beats_null_names)
{
    struct gf_res r;
    if (!U(WSAGetLastError) || !gf_have(GF_W | GF_XW)) { t_skip("missing export"); return; }
    gf_run(GF_W, NULL, NULL, NULL, &r);
    EXPECT_EQ(r.ret, WSANOTINITIALISED);
    CHECK(r.out_null);
    gf_run(GF_XW, NULL, NULL, NULL, &r);
    EXPECT_EQ(r.ret, WSANOTINITIALISED);
}
/* after a balanced Startup/Cleanup the library is uninitialised again */
TEST(gfi_not_initialised_after_cleanup)
{
    SOCKADDR_IN s;
    struct gn_out o;
    GN_BEGIN();
    GN_END();
    mk4(&s, 1, 2, 3, 4, 80);
    gn_w(&s, sizeof s, 1, 1, 64, 16, NHS, &o);
    EXPECT_EQ(o.ret, WSANOTINITIALISED);
}
/* a nested Startup keeps it usable until the second Cleanup */
TEST(gfi_nested_startup_keeps_working)
{
    SOCKADDR_IN s;
    struct gn_out o;
    GN_BEGIN();
    gf_up();
    gf_down();
    mk4(&s, 1, 2, 3, 4, 80);
    gn_w(&s, sizeof s, 1, 1, 64, 16, NHS, &o);
    EXPECT_EQ(o.ret, 0);
    GN_END();
}
