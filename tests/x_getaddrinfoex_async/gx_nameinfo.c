/* getnameinfo / GetNameInfoW for loopback socket addresses: which flags select the numeric or the name
 * form, service-name results, exact buffer-size protocol and argument errors. The host name returned for
 * loopback is the machine's own name, so those checks are relations to GetComputerNameEx. */
#include "gx.h"

UDECL(int, GetNameInfoW_, (const SOCKADDR *sa, socklen_t len, PWCHAR host, DWORD hostlen, PWCHAR serv, DWORD servlen, INT flags));

#define NEED_NI() \
    do { if (!U(getnameinfo) || !U(WSAGetLastError) || !U(WSASetLastError)) { t_skip("missing export"); return; } \
         if (gx_up()) { t_skip("WSAStartup failed"); return; } } while (0)

static int is_machine_name(const char *s)
{
    WCHAR w[300], a[300], b[300];
    DWORD la = 300, lb = 300;
    if (!MultiByteToWideChar(CP_ACP, 0, s, -1, w, 300)) return 0;
    if (!GetComputerNameExW(ComputerNameDnsHostname, a, &la)) a[0] = 0;
    if (!GetComputerNameExW(ComputerNameDnsFullyQualified, b, &lb)) b[0] = 0;
    return !lstrcmpiW(w, a) || !lstrcmpiW(w, b);
}
static int ni4(int port, int flags, char *h, int hl, char *s, int sl)
{
    SOCKADDR_IN a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = gx_bs32(0x7f000001); a.sin_port = gx_bs16((unsigned short)port);
    SETWSERR(0x7777);
    return U(getnameinfo)((SOCKADDR *)&a, sizeof a, h, hl, s, sl, flags);
}
static int ni6(int port, int flags, char *h, int hl, char *s, int sl)
{
    SOCKADDR_IN6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; a.sin6_port = gx_bs16((unsigned short)port);
    SETWSERR(0x7777);
    return U(getnameinfo)((SOCKADDR *)&a, sizeof a, h, hl, s, sl, flags);
}

/* flags -> host form (L literal, N machine name), service form (S service name, P port number), for port 80 */
static const struct { int flags; char host; char serv; } nirows[] = {
    {0, 'N', 'S'}, {NI_NOFQDN, 'N', 'S'}, {NI_NUMERICHOST, 'L', 'S'}, {NI_NAMEREQD, 'N', 'S'}, {NI_NUMERICSERV, 'N', 'P'},
    {NI_DGRAM, 'N', 'P'}, {NI_NUMERICHOST | NI_NUMERICSERV, 'L', 'P'}, {NI_NUMERICHOST | NI_NAMEREQD, 'L', 'S'},
    {NI_NOFQDN | NI_NAMEREQD, 'N', 'S'}, {0x20, 'N', 'S'}, {0x100, 'N', 'S'}, {-1, 'L', 'P'},
};
static void ni_rows(int v6)
{
    unsigned i;
    for (i = 0; i < NARR(nirows); i++) {
        char h[300], s[40];
        int r = v6 ? ni6(80, nirows[i].flags, h, sizeof h, s, sizeof s) : ni4(80, nirows[i].flags, h, sizeof h, s, sizeof s);
        CHECKF(r == 0 && WSERR() == 0, "flags %x ret=%d wsa=%d", nirows[i].flags, r, WSERR());
        if (r) continue;
        if (nirows[i].host == 'L') EXPECT_STR(h, v6 ? "::1" : "127.0.0.1");
        else CHECKF(is_machine_name(h), "flags %x host '%s'", nirows[i].flags, h);
        EXPECT_STR(s, nirows[i].serv == 'S' ? "http" : "80");
    }
}
TEST(xni_flag_matrix_v4) { NEED_NI(); ni_rows(0); gx_down(); }
TEST(xni_flag_matrix_v6) { NEED_NI(); ni_rows(1); gx_down(); }

TEST(xni_service_names_by_port)
{
    static const struct { int port; const char *name; } sv[] = {{80, "http"}, {21, "ftp"}, {53, "domain"}, {12345, "12345"}, {0, "0"}, {65535, "65535"}};
    unsigned i;
    NEED_NI();
    for (i = 0; i < NARR(sv); i++) {
        char s[40];
        CHECKF(ni4(sv[i].port, NI_NUMERICHOST, NULL, 0, s, sizeof s) == 0, "port %d", sv[i].port);
        EXPECT_STR(s, sv[i].name);
        CHECK(ni6(sv[i].port, NI_NUMERICHOST, NULL, 0, s, sizeof s) == 0);
        EXPECT_STR(s, sv[i].name);
        CHECK(ni4(sv[i].port, NI_NUMERICSERV, NULL, 0, s, sizeof s) == 0);
        { char num[16]; snprintf(num, sizeof num, "%d", sv[i].port); EXPECT_STR(s, num); }
    }
    gx_down();
}

/* ---- buffer protocol ---------------------------------------------------------------------------------- */
/* A host buffer must hold the text plus its terminator; shorter non-zero sizes fail with
 * ERROR_INSUFFICIENT_BUFFER (122) both as return value and as WSAGetLastError; a zero size means "not wanted". */
TEST(xni_host_buffer_exact_size_numeric)
{
    int hl, r;
    NEED_NI();
    for (hl = 1; hl <= 12; hl++) {
        char h[40];
        memset(h, 'Z', sizeof h);
        r = ni4(80, NI_NUMERICHOST, h, hl, NULL, 0);
        if (hl < 10) { CHECKF(r == ERROR_INSUFFICIENT_BUFFER && WSERR() == ERROR_INSUFFICIENT_BUFFER, "hl %d ret %d", hl, r); }
        else { CHECKF(r == 0, "hl %d ret %d", hl, r); EXPECT_STR(h, "127.0.0.1"); }
    }
    for (hl = 1; hl <= 5; hl++) {
        char h[40];
        r = ni6(80, NI_NUMERICHOST, h, hl, NULL, 0);
        if (hl < 4) { CHECKF(r == ERROR_INSUFFICIENT_BUFFER, "v6 hl %d ret %d", hl, r); }
        else { CHECKF(r == 0, "v6 hl %d ret %d", hl, r); EXPECT_STR(h, "::1"); }
    }
    gx_down();
}
TEST(xni_host_buffer_exact_size_machine_name)
{
    char h[300];
    int need, hl;
    NEED_NI();
    GX_EQ(ni4(80, 0, h, sizeof h, NULL, 0), 0);
    need = (int)strlen(h) + 1;
    for (hl = 1; hl <= need + 2 && hl < 300; hl++) {
        char b[300];
        int r = ni4(80, 0, b, hl, NULL, 0);
        if (hl < need) CHECKF(r == ERROR_INSUFFICIENT_BUFFER && WSERR() == ERROR_INSUFFICIENT_BUFFER, "hl %d need %d ret %d", hl, need, r);
        else { CHECKF(r == 0, "hl %d need %d ret %d", hl, need, r); EXPECT_STR(b, h); }
    }
    gx_down();
}
TEST(xni_service_buffer_exact_size)
{
    int sl, r;
    NEED_NI();
    for (sl = 1; sl <= 8; sl++) {
        char s[40];
        r = ni4(80, NI_NUMERICHOST, NULL, 0, s, sl);
        if (sl < 5) CHECKF(r == ERROR_INSUFFICIENT_BUFFER && WSERR() == ERROR_INSUFFICIENT_BUFFER, "sl %d ret %d", sl, r);
        else { CHECKF(r == 0, "sl %d ret %d", sl, r); EXPECT_STR(s, "http"); }
        r = ni4(80, NI_NUMERICHOST | NI_NUMERICSERV, NULL, 0, s, sl);
        if (sl < 3) CHECKF(r == ERROR_INSUFFICIENT_BUFFER, "num sl %d ret %d", sl, r);
        else { CHECKF(r == 0, "num sl %d ret %d", sl, r); EXPECT_STR(s, "80"); }
    }
    gx_down();
}
TEST(xni_zero_length_buffer_means_not_wanted)
{
    char h[40], s[40];
    NEED_NI();
    memset(h, 'Z', sizeof h); memset(s, 'Z', sizeof s);
    GX_EQ(ni4(80, 0, h, 0, s, 0), 0);
    CHECK(h[0] == 'Z' && s[0] == 'Z');
    GX_EQ(ni4(80, 0, h, sizeof h, s, 0), 0);
    CHECK(h[0] != 'Z' && s[0] == 'Z');
    memset(h, 'Z', sizeof h);
    GX_EQ(ni4(80, 0, h, 0, s, sizeof s), 0);
    CHECK(h[0] == 'Z'); EXPECT_STR(s, "http");
    gx_down();
}
TEST(xni_null_buffers_are_not_wanted)
{
    char h[40], s[40];
    NEED_NI();
    GX_EQ(ni4(80, 0, NULL, 0, NULL, 0), 0);
    GX_EQ(ni4(80, 0, h, sizeof h, NULL, 0), 0);
    GX_EQ(ni4(80, 0, NULL, 0, s, sizeof s), 0);
    GX_EQ(ni4(80, 0, NULL, 40, s, sizeof s), 0);       /* a NULL host pointer wins over its length */
    EXPECT_STR(s, "http");
    gx_down();
}

/* ---- argument errors ------------------------------------------------------------------------------------ */
TEST(xni_bad_sockaddr_arguments)
{
    SOCKADDR_IN a;
    char h[40], s[40];
    int r;
    NEED_NI();
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = gx_bs32(0x7f000001);
    SETWSERR(0x7777); r = U(getnameinfo)((SOCKADDR *)&a, 8, h, 40, s, 40, 0);
    CHECKF(r == WSAEFAULT && WSERR() == WSAEFAULT, "len 8 ret %d", r);
    SETWSERR(0x7777); r = U(getnameinfo)((SOCKADDR *)&a, 0, h, 40, s, 40, 0);
    CHECKF(r == WSAEFAULT, "len 0 ret %d", r);
    SETWSERR(0x7777); r = U(getnameinfo)(NULL, 16, h, 40, s, 40, 0);
    CHECKF(r == WSAEFAULT, "NULL sa ret %d", r);
    a.sin_family = AF_UNIX;
    SETWSERR(0x7777); r = U(getnameinfo)((SOCKADDR *)&a, 16, h, 40, s, 40, 0);
    CHECKF(r == WSAEAFNOSUPPORT && WSERR() == WSAEAFNOSUPPORT, "AF_UNIX ret %d", r);
    a.sin_family = AF_UNSPEC;
    SETWSERR(0x7777); r = U(getnameinfo)((SOCKADDR *)&a, 16, h, 40, s, 40, 0);
    CHECKF(r == WSAEAFNOSUPPORT, "AF_UNSPEC ret %d", r);
    a.sin_family = 99;
    SETWSERR(0x7777); r = U(getnameinfo)((SOCKADDR *)&a, 16, h, 40, s, 40, 0);
    CHECKF(r == WSAEAFNOSUPPORT, "fam 99 ret %d", r);
    gx_down();
}
TEST(xni_v6_short_length_is_fault)
{
    SOCKADDR_IN6 a;
    char h[40];
    int r;
    NEED_NI();
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
    SETWSERR(0x7777); r = U(getnameinfo)((SOCKADDR *)&a, 16, h, 40, NULL, 0, NI_NUMERICHOST);
    CHECKF(r == WSAEFAULT, "v6 with v4 length ret %d", r);
    gx_down();
}
TEST(xni_success_clears_error_slot_and_equals_return)
{
    char h[40];
    NEED_NI();
    GX_EQ(ni4(80, NI_NUMERICHOST, h, sizeof h, NULL, 0), 0);
    GX_EQ(WSERR(), 0);
    gx_down();
}
TEST(xni_wide_front_end_matches_ansi)
{
    SOCKADDR_IN a;
    WCHAR h[300], s[40];
    GetNameInfoW__pfn w;
    NEED_NI();
    w = (GetNameInfoW__pfn)t_proc("GetNameInfoW");
    if (!w) { t_skip("no GetNameInfoW"); gx_down(); return; }
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = gx_bs32(0x7f000001); a.sin_port = gx_bs16(80);
    GX_EQ(w((SOCKADDR *)&a, sizeof a, h, 300, s, 40, NI_NUMERICHOST), 0);
    EXPECT_WSTR(h, gx_w("127.0.0.1")); EXPECT_WSTR(s, gx_w("http"));
    GX_EQ(w((SOCKADDR *)&a, sizeof a, h, 9, s, 40, NI_NUMERICHOST), WSAEFAULT);   /* the wide form reports a short host buffer as a fault */
    GX_EQ(w((SOCKADDR *)&a, sizeof a, h, 10, s, 4, NI_NUMERICHOST), ERROR_INSUFFICIENT_BUFFER);
    GX_EQ(w((SOCKADDR *)&a, sizeof a, h, 10, s, 5, NI_NUMERICHOST), 0);
    GX_EQ(w((SOCKADDR *)&a, 8, h, 10, s, 5, 0), WSAEFAULT);
    gx_down();
}
TEST(xni_name_of_loopback_equals_canonical_name_of_localhost)
{
    gx_res r;
    char h[300];
    WCHAR w[300];
    GX_BEGIN();
    if (!U(getnameinfo)) { t_skip("no getnameinfo"); return; }
    {
        GXEX hint = gx_hint(AI_CANONNAME, 0, 0, 0);
        r = gx_call("localhost", NULL, 12, &hint);
        GX_EQ(r.ret, 0);
        GX_EQ(ni4(80, 0, h, sizeof h, NULL, 0), 0);
        MultiByteToWideChar(CP_ACP, 0, h, -1, w, 300);
        if (r.ret == 0 && r.res->ai_canonname) CHECK(!lstrcmpiW(w, r.res->ai_canonname));
        gx_release(&r);
    }
    GX_END();
}
