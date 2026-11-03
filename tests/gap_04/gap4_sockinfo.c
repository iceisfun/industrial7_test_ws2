/* Per-socket option plumbing, ioctl dispatch and multipoint join of the helper entry points embedded in
 * mswsock.dll (Tcpip4_/Tcpip6_ WSHGetSocketInformation, WSHSetSocketInformation, WSHIoctl, WSHJoinLeaf).
 *
 * Measures: the single supported internal option (the helper-context option) and its length protocol for the
 * getter; WSAENOPROTOOPT for every other level/option pair on the getter and WSAEINVAL on the setter; WSHIoctl
 * refusing every control code with WSAEINVAL; and the argument validation of the multicast join, each failure
 * being WSAEINVAL before any socket call, plus the error of the underlying option call when every argument is
 * well formed but the socket handle is not a socket. */
#include "gap4.h"

#define SOL_INTERNAL_ 0xfffe
#define SO_CONTEXT_ 1
#define FILL 0xA5

static INT getinfo(g4_getinfo_fn f, PVOID ctx, INT lvl, INT opt, PCHAR buf, INT *len)
{
    return f(ctx, (SOCKET)0x1234, NULL, NULL, lvl, opt, buf, len);
}
static INT setinfo(g4_setinfo_fn f, PVOID ctx, INT lvl, INT opt, PCHAR buf, INT len)
{
    return f(ctx, (SOCKET)0x1234, NULL, NULL, lvl, opt, buf, len);
}

static void get_ctx_option(const g4_fam *fam)
{
    g4_getinfo_fn f = (g4_getinfo_fn)g4_fn(fam, "GetSocketInformation");
    PVOID ctx = (PVOID)(ULONG_PTR)fam->af; BYTE buf[32]; INT len, l; static const INT lens[] = { 8, 9, 16, 32 }; size_t i;
    REQUIRE(f);
    for (l = 0; l < 8; l++) {
        len = l; memset(buf, FILL, sizeof buf);
        CHECKF(getinfo(f, ctx, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, &len) == G4_FAULT, "%s len %d", fam->tag, l);
        CHECKF(len == l && buf[0] == FILL, "%s len %d: touched", fam->tag, l);
    }
    for (i = 0; i < G4N(lens); i++) {
        len = lens[i]; memset(buf, FILL, sizeof buf);
        CHECKF(getinfo(f, ctx, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, &len) == 0, "%s len %d", fam->tag, lens[i]);
        CHECKF(len == 8, "%s len %d: reported %d", fam->tag, lens[i], len);
        CHECKF(*(ULONG_PTR *)buf == (ULONG_PTR)ctx, "%s len %d: value", fam->tag, lens[i]);
        CHECKF(buf[8] == FILL, "%s len %d: wrote past eight bytes", fam->tag, lens[i]);
    }
}
TEST(gap4_getinfo_v4_context_option) { get_ctx_option(&g4_v4); }
TEST(gap4_getinfo_v6_context_option) { get_ctx_option(&g4_v6); }

static void get_ctx_value_is_the_argument(const g4_fam *fam)
{
    g4_getinfo_fn f = (g4_getinfo_fn)g4_fn(fam, "GetSocketInformation"); BYTE buf[16]; INT len = 8;
    static const ULONG_PTR vals[] = { 0, 1, 0x123456, 0xdeadbeef, (ULONG_PTR)-1 }; size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(vals); i++) {
        len = 8; memset(buf, FILL, sizeof buf);
        CHECKF(getinfo(f, (PVOID)vals[i], SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, &len) == 0 && *(ULONG_PTR *)buf == vals[i], "value %llx", (unsigned long long)vals[i]);
    }
}
TEST(gap4_getinfo_v4_context_value_is_not_looked_up) { get_ctx_value_is_the_argument(&g4_v4); }
TEST(gap4_getinfo_v6_context_value_is_not_looked_up) { get_ctx_value_is_the_argument(&g4_v6); }

static void get_ctx_null_buffer(const g4_fam *fam)
{
    g4_getinfo_fn f = (g4_getinfo_fn)g4_fn(fam, "GetSocketInformation"); INT len;
    REQUIRE(f);
    len = 8; EXPECT_EQ(getinfo(f, (PVOID)1, SOL_INTERNAL_, SO_CONTEXT_, NULL, &len), 0); EXPECT_EQ(len, 8);
    len = 0; EXPECT_EQ(getinfo(f, (PVOID)1, SOL_INTERNAL_, SO_CONTEXT_, NULL, &len), 0); EXPECT_EQ(len, 8);
    len = 100; EXPECT_EQ(getinfo(f, (PVOID)1, SOL_INTERNAL_, SO_CONTEXT_, NULL, &len), 0); EXPECT_EQ(len, 8);
}
TEST(gap4_getinfo_v4_null_buffer_asks_only_for_the_size) { get_ctx_null_buffer(&g4_v4); }
TEST(gap4_getinfo_v6_null_buffer_asks_only_for_the_size) { get_ctx_null_buffer(&g4_v6); }

static void get_other_options(const g4_fam *fam)
{
    g4_getinfo_fn f = (g4_getinfo_fn)g4_fn(fam, "GetSocketInformation");
    static const struct { INT lvl, opt; } rows[] = {
        { SOL_INTERNAL_, 0 }, { SOL_INTERNAL_, 2 }, { SOL_INTERNAL_, 3 }, { SOL_INTERNAL_, -1 }, { SOL_INTERNAL_, 0x1001 },
        { 0, 1 }, { 0, 0 }, { 6, 1 }, { 6, 3 }, { 17, 1 }, { 41, 1 }, { 0xffff, 1 }, { 0xffff, 0x1001 }, { 0xffff, 0x4 },
        { 0xfffd, 1 }, { 0xffff, 0 }, { -1, 1 }, { 0x10000 + SOL_INTERNAL_, 1 }, { 1, 1 }, { 0xfffe + 1, 1 },
    };
    size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(rows); i++) {
        BYTE buf[16]; INT len = 8; INT r;
        memset(buf, FILL, sizeof buf);
        r = getinfo(f, (PVOID)1, rows[i].lvl, rows[i].opt, (PCHAR)buf, &len);
        CHECKF(r == G4_NOPROTOOPT, "%s level %x opt %x: rc %d", fam->tag, rows[i].lvl, rows[i].opt, r);
        CHECKF(len == 8 && buf[0] == FILL, "%s level %x opt %x: outputs touched", fam->tag, rows[i].lvl, rows[i].opt);
    }
}
TEST(gap4_getinfo_v4_unsupported_pairs) { get_other_options(&g4_v4); }
TEST(gap4_getinfo_v6_unsupported_pairs) { get_other_options(&g4_v6); }

static void set_options(const g4_fam *fam)
{
    g4_setinfo_fn f = (g4_setinfo_fn)g4_fn(fam, "SetSocketInformation");
    static const struct { INT lvl, opt; } bad[] = {
        { SOL_INTERNAL_, 0 }, { SOL_INTERNAL_, 2 }, { SOL_INTERNAL_, -1 }, { 0, 1 }, { 6, 1 }, { 0xffff, 1 }, { 0xffff, 0x1001 },
        { 41, 1 }, { 0xfffd, 1 }, { -1, 1 }, { 0, 0 }, { 1, 1 },
    };
    BYTE buf[16] = { 0 }; size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(bad); i++)
        CHECKF(setinfo(f, (PVOID)1, bad[i].lvl, bad[i].opt, (PCHAR)buf, 8) == G4_INVAL, "%s level %x opt %x", fam->tag, bad[i].lvl, bad[i].opt);
    EXPECT_EQ(setinfo(f, (PVOID)1, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, 8), 0);
    EXPECT_EQ(setinfo(f, (PVOID)1, SOL_INTERNAL_, SO_CONTEXT_, NULL, 0), 0);
    EXPECT_EQ(setinfo(f, (PVOID)1, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, 0), 0);
    EXPECT_EQ(setinfo(f, (PVOID)1, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, 100), 0);
    EXPECT_EQ(setinfo(f, (PVOID)1, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, -5), 0);
}
TEST(gap4_setinfo_v4_option_pairs) { set_options(&g4_v4); }
TEST(gap4_setinfo_v6_option_pairs) { set_options(&g4_v6); }

/* Setting the context option does not change what the getter reports. */
TEST(gap4_setinfo_context_option_stores_nothing)
{
    g4_setinfo_fn s = (g4_setinfo_fn)g4_fn(&g4_v4, "SetSocketInformation");
    g4_getinfo_fn g = (g4_getinfo_fn)g4_fn(&g4_v4, "GetSocketInformation");
    ULONG_PTR newv = 0x5555; BYTE buf[16]; INT len = 8;
    REQUIRE(s); REQUIRE(g);
    EXPECT_EQ(setinfo(s, (PVOID)7, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)&newv, 8), 0);
    EXPECT_EQ(getinfo(g, (PVOID)7, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, &len), 0);
    CHECK(*(ULONG_PTR *)buf == 7);
}

/* ---- WSHIoctl ---- */
static void ioctl_refused(const g4_fam *fam)
{
    g4_ioctl_fn f = (g4_ioctl_fn)g4_fn(fam, "Ioctl");
    static const DWORD codes[] = { 0, 1, 0x4004667f /* FIONREAD */, 0x8004667e /* FIONBIO */, 0x98000004 /* SIO_GET_EXTENSION_FUNCTION_POINTER */,
        0x98000001, 0x98000002, 0x98000006, 0x4C000001, 0x88000004, 0xffffffffu, 0x12345678 };
    size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(codes); i++) {
        DWORD ret = 0x77; BOOL need = TRUE;
        CHECKF(f((PVOID)1, (SOCKET)0x1234, NULL, NULL, codes[i], NULL, 0, NULL, 0, &ret, NULL, NULL, &need) == G4_INVAL, "%s code %lx", fam->tag, codes[i]);
        CHECKF(ret == 0x77 && need == TRUE, "%s code %lx: outputs touched", fam->tag, codes[i]);
    }
}
TEST(gap4_ioctl_v4_refuses_every_control_code) { ioctl_refused(&g4_v4); }
TEST(gap4_ioctl_v6_refuses_every_control_code) { ioctl_refused(&g4_v6); }

/* ---- WSHJoinLeaf ---- */
typedef struct {
    PVOID ctx; SOCKET sock; PVOID leafctx; SOCKET leafsock; PSOCKADDR sa; DWORD salen; LPWSABUF cd, ce; PVOID sq, gq;
} join_args;

static INT join(g4_join_fn f, const join_args *a)
{
    return f(a->ctx, a->sock, NULL, NULL, a->leafctx, a->leafsock, a->sa, a->salen, a->cd, a->ce, a->sq, a->gq, 0);
}
static void join_base(const g4_fam *fam, join_args *a, SOCKET s, void *sa, DWORD salen)
{
    memset(a, 0, sizeof *a);
    a->ctx = (PVOID)(ULONG_PTR)fam->af; a->sock = s; a->leafctx = NULL; a->leafsock = INVALID_SOCKET;
    a->sa = (PSOCKADDR)sa; a->salen = salen;
}
static void join_rows(const g4_fam *fam)
{
    g4_join_fn f = (g4_join_fn)g4_fn(fam, "JoinLeaf");
    struct sockaddr_in a4; struct sockaddr_in6 a6; void *sa; DWORD salen;
    WSABUF nonempty, empty; BYTE dummy[8]; join_args a; int i;
    REQUIRE(f);
    memset(&a4, 0, sizeof a4); a4.sin_family = AF_INET; a4.sin_addr.s_addr = 0x010201E0u;
    memset(&a6, 0, sizeof a6); a6.sin6_family = AF_INET6; a6.sin6_addr.s6_addr[0] = 0xff; a6.sin6_addr.s6_addr[15] = 1;
    if (fam->af == AF_INET) { sa = &a4; salen = sizeof a4; } else { sa = &a6; salen = sizeof a6; }
    nonempty.len = 4; nonempty.buf = (CHAR *)dummy; empty.len = 0; empty.buf = NULL;
    memset(dummy, 0, sizeof dummy);
    /* each row breaks exactly one rule */
    for (i = 0; i < 12; i++) {
        join_base(fam, &a, (SOCKET)0x1234, sa, salen);
        switch (i) {
        case 0: a.ctx = NULL; break;
        case 1: a.sock = INVALID_SOCKET; break;
        case 2: a.leafctx = (PVOID)(ULONG_PTR)1; break;
        case 3: a.leafsock = (SOCKET)0x1234; break;
        case 4: a.leafsock = 0; break;
        case 5: a.sa = NULL; break;
        case 6: a.salen = salen - 1; break;
        case 7: a.salen = 0; break;
        case 8: a.ctx = (PVOID)(ULONG_PTR)(fam->af == AF_INET ? AF_INET6 : AF_INET); break;
        case 9: a.cd = &nonempty; break;
        case 10: a.ce = &nonempty; break;
        case 11: a.sq = dummy; break;
        }
        CHECKF(join(f, &a) == G4_INVAL, "%s row %d", fam->tag, i);
    }
    join_base(fam, &a, (SOCKET)0x1234, sa, salen); a.gq = dummy;
    CHECKF(join(f, &a) == G4_INVAL, "%s group qos", fam->tag);
    {   /* wrong family inside the address */
        struct sockaddr_in6 w6 = a6; struct sockaddr_in w4 = a4; 
        join_base(fam, &a, (SOCKET)0x1234, fam->af == AF_INET ? (void *)&a6 : (void *)&a4, fam->af == AF_INET ? sizeof a6 : sizeof a4);
        CHECKF(join(f, &a) == G4_INVAL, "%s address of the other family", fam->tag);
        w6.sin6_family = 0; w4.sin_family = 0;
        join_base(fam, &a, (SOCKET)0x1234, fam->af == AF_INET ? (void *)&w4 : (void *)&w6, salen);
        CHECKF(join(f, &a) == G4_INVAL, "%s family zero", fam->tag);
    }
}
TEST(gap4_joinleaf_v4_argument_rules) { join_rows(&g4_v4); }
TEST(gap4_joinleaf_v6_argument_rules) { join_rows(&g4_v6); }

/* Empty caller/callee data blocks do not count as data. */
static void join_empty_data(const g4_fam *fam)
{
    g4_join_fn f = (g4_join_fn)g4_fn(fam, "JoinLeaf");
    struct sockaddr_in a4; struct sockaddr_in6 a6; WSABUF empty; join_args a;
    SOCKET s;
    typedef SOCKET (WSAAPI *sock_fn)(int, int, int); typedef int (WSAAPI *close_fn)(SOCKET);
    sock_fn so = (sock_fn)t_proc_in("ws2_32.dll", "socket"); close_fn cl = (close_fn)t_proc_in("ws2_32.dll", "closesocket");
    REQUIRE(f); REQUIRE(so); REQUIRE(cl);
    if (!g4_wsa_up()) { t_skip("stack did not start"); return; }
    memset(&a4, 0, sizeof a4); a4.sin_family = AF_INET; a4.sin_addr.s_addr = 0x010201E0u;
    memset(&a6, 0, sizeof a6); a6.sin6_family = AF_INET6; a6.sin6_addr.s6_addr[0] = 0xff; a6.sin6_addr.s6_addr[15] = 1;
    empty.len = 0; empty.buf = NULL;
    /* a handle that was a socket and is closed: the option call fails with "not a socket" */
    s = so(fam->af, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) { t_skip("no datagram socket for this family"); return; }
    cl(s);
    join_base(fam, &a, s, fam->af == AF_INET ? (void *)&a4 : (void *)&a6, fam->af == AF_INET ? sizeof a4 : sizeof a6);
    a.cd = &empty; a.ce = &empty;
    EXPECT_EQ(join(f, &a), G4_NOTSOCK);
    a.cd = NULL; a.ce = NULL;
    EXPECT_EQ(join(f, &a), G4_NOTSOCK);
}
TEST(gap4_joinleaf_v4_valid_arguments_reach_the_socket_call) { join_empty_data(&g4_v4); }
TEST(gap4_joinleaf_v6_valid_arguments_reach_the_socket_call) { join_empty_data(&g4_v6); }
