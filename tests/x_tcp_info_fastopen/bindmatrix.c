/* Bind-conflict matrix for TCP on loopback: a first socket (plain, SO_REUSEADDR or SO_EXCLUSIVEADDRUSE) holds a
 * port, a second socket (same three choices) binds the same port. The outcome depends on the option pair and on
 * whether each side names the loopback address or the wildcard; listening versus merely bound makes no difference,
 * and connected sockets that merely carry the port do not block a new bind at all. Errors are WSAEADDRINUSE (10048)
 * or WSAEACCES (10013). Each cell below is a measured value. */
#include "xt.h"

enum { M_NONE, M_REUSE, M_EXCL };
static const char *const mname[3] = {"plain", "reuse", "excl"};
enum { A_LO, A_ANY };
static const char *const aname[2] = {"loopback", "wildcard"};
#define EIN WSAEADDRINUSE
#define EAC WSAEACCES

static void setmode(SOCKET s, int m)
{
    if (m == M_REUSE) xt_seti(s, SOL_SOCKET, SO_REUSEADDR, 1);
    if (m == M_EXCL) xt_seti(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
}
static int bind_to(SOCKET s, int addr, u_short port, u_short *out)
{
    struct sockaddr_in a; int l = sizeof a;
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = port;
    a.sin_addr.s_addr = addr == A_LO ? U(htonl)(INADDR_LOOPBACK) : 0;
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return U(WSAGetLastError)();
    if (out) { U(getsockname)(s, (struct sockaddr *)&a, &l); *out = a.sin_port; }
    return 0;
}
/* want[m1][m2]: error of the second bind (0 = success); the second socket then also listens, which must work */
static void run_matrix(int a1, int a2, int listening, const int want[3][3])
{
    int m1, m2;
    for (m1 = 0; m1 < 3; m1++) for (m2 = 0; m2 < 3; m2++) {
        SOCKET s1 = xt_tcp(), s2 = xt_tcp(); u_short port = 0; int e1, e2, e3 = 0;
        setmode(s1, m1);
        e1 = bind_to(s1, a1, 0, &port);
        EQ(e1, 0);
        if (listening) EQ(U(listen)(s1, 2), 0);
        setmode(s2, m2);
        e2 = bind_to(s2, a2, port, NULL);
        CHECKF(e2 == want[m1][m2], "first %s/%s %s, second %s/%s: bind err %d want %d", aname[a1], mname[m1], listening ? "listening" : "bound", aname[a2], mname[m2], e2, want[m1][m2]);
        if (e2 == 0) { e3 = U(listen)(s2, 2) ? U(WSAGetLastError)() : 0; EQ(e3, 0); }
        xt_close(s1); xt_close(s2);
    }
}
static const int mx_same[3][3]  = {{EIN, EAC, EIN}, {EIN, 0, EIN}, {EIN, EAC, EIN}};
static const int mx_wild_then_lo[3][3] = {{0, 0, 0}, {0, 0, 0}, {EAC, EAC, EAC}};
static const int mx_lo_then_wild[3][3] = {{0, 0, EIN}, {0, 0, EIN}, {0, 0, EIN}};

TEST(bindmx_loopback_then_loopback_bound) { NEED(); run_matrix(A_LO, A_LO, 0, mx_same); }
TEST(bindmx_loopback_then_loopback_listening) { NEED(); run_matrix(A_LO, A_LO, 1, mx_same); }
TEST(bindmx_wildcard_then_wildcard_bound) { NEED(); run_matrix(A_ANY, A_ANY, 0, mx_same); }
TEST(bindmx_wildcard_then_wildcard_listening) { NEED(); run_matrix(A_ANY, A_ANY, 1, mx_same); }
TEST(bindmx_wildcard_then_loopback_bound) { NEED(); run_matrix(A_ANY, A_LO, 0, mx_wild_then_lo); }
TEST(bindmx_wildcard_then_loopback_listening) { NEED(); run_matrix(A_ANY, A_LO, 1, mx_wild_then_lo); }
TEST(bindmx_loopback_then_wildcard_bound) { NEED(); run_matrix(A_LO, A_ANY, 0, mx_lo_then_wild); }
TEST(bindmx_loopback_then_wildcard_listening) { NEED(); run_matrix(A_LO, A_ANY, 1, mx_lo_then_wild); }

/* The option must be in place before bind: setting REUSEADDR after bind does not rescue a conflicting second bind. */
TEST(bindmx_reuse_set_after_bind_does_not_make_the_first_socket_shareable)
{
    SOCKET s1, s2; u_short p = 0;
    NEED();
    s1 = xt_tcp(); EQ(xt_bind_lo(s1, &p), 0);
    EQ(xt_seti(s1, SOL_SOCKET, SO_REUSEADDR, 1), 0);
    s2 = xt_tcp(); EQ(xt_seti(s2, SOL_SOCKET, SO_REUSEADDR, 1), 0);
    EQ(bind_to(s2, A_LO, p, NULL), WSAEACCES);
    xt_close(s1); xt_close(s2);
}
TEST(bindmx_second_bind_after_first_closed_succeeds_for_every_mode)
{
    int m1, m2;
    NEED();
    for (m1 = 0; m1 < 3; m1++) for (m2 = 0; m2 < 3; m2++) {
        SOCKET s1 = xt_tcp(), s2 = xt_tcp(); u_short p = 0;
        setmode(s1, m1); EQ(bind_to(s1, A_LO, 0, &p), 0); xt_close(s1);
        setmode(s2, m2);
        CHECKF(bind_to(s2, A_LO, p, NULL) == 0, "%s then %s after close", mname[m1], mname[m2]);
        xt_close(s2);
    }
}
TEST(bindmx_failed_bind_leaves_socket_usable_for_another_port)
{
    SOCKET s1 = xt_tcp(), s2 = xt_tcp(); u_short p = 0, q = 0;
    NEED();
    EQ(bind_to(s1, A_LO, 0, &p), 0);
    EQ(bind_to(s2, A_LO, p, NULL), WSAEADDRINUSE);
    EQ(bind_to(s2, A_LO, 0, &q), 0);
    CHECK(q != 0 && q != p);
    xt_close(s1); xt_close(s2);
}
TEST(bindmx_second_bind_on_the_same_socket_is_invalid)
{
    SOCKET s = xt_tcp(); u_short p = 0;
    NEED();
    EQ(bind_to(s, A_LO, 0, &p), 0);
    EQ(bind_to(s, A_LO, 0, NULL), WSAEINVAL);
    xt_close(s);
}

/* ---- connected sockets and the port they carry ------------------------------------------------------------ */
/* An accepted connection and a client's ephemeral port do not hold a bind claim of their own: once the listener is
 * gone every mode can bind the same loopback port. While the listener is open the listener's matrix applies. */
TEST(bindmx_accepted_connection_alone_does_not_block_bind)
{
    int m1, m2;
    NEED();
    for (m1 = 0; m1 < 3; m1++) for (m2 = 0; m2 < 3; m2++) {
        SOCKET lis = xt_tcp(), c = xt_tcp(), a, s2 = xt_tcp(); u_short p = 0;
        setmode(lis, m1); EQ(bind_to(lis, A_LO, 0, &p), 0); EQ(U(listen)(lis, 2), 0);
        EQ(xt_connect_lo(c, p), 0); CHECK(xt_readable(lis, 3000));
        a = xt_accept(lis); CHECK(a != INVALID_SOCKET);
        xt_close(lis);
        setmode(s2, m2);
        CHECKF(bind_to(s2, A_LO, p, NULL) == 0, "listener %s closed, connection alive, new %s bind", mname[m1], mname[m2]);
        xt_close(s2); xt_close(a); xt_close(c);
    }
}
TEST(bindmx_client_ephemeral_port_does_not_block_bind)
{
    int m;
    NEED();
    for (m = 0; m < 3; m++) {
        SOCKET c, a, l, s2; struct sockaddr_in sa; int sl = sizeof sa;
        if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
        EQ(U(getsockname)(c, (struct sockaddr *)&sa, &sl), 0);
        s2 = xt_tcp(); setmode(s2, m);
        CHECKF(bind_to(s2, A_LO, sa.sin_port, NULL) == 0, "bind onto a connected client's port, mode %s", mname[m]);
        xt_close(s2); xt_close(c); xt_close(a); xt_close(l);
    }
}
TEST(bindmx_open_listener_with_live_connection_keeps_its_matrix)
{
    int m1, m2;
    NEED();
    for (m1 = 0; m1 < 3; m1++) for (m2 = 0; m2 < 3; m2++) {
        SOCKET lis = xt_tcp(), c = xt_tcp(), a, s2 = xt_tcp(); u_short p = 0;
        setmode(lis, m1); EQ(bind_to(lis, A_LO, 0, &p), 0); EQ(U(listen)(lis, 2), 0);
        EQ(xt_connect_lo(c, p), 0); CHECK(xt_readable(lis, 3000));
        a = xt_accept(lis);
        setmode(s2, m2);
        CHECKF(bind_to(s2, A_LO, p, NULL) == mx_same[m1][m2], "open listener %s, connection alive, new %s", mname[m1], mname[m2]);
        xt_close(s2); xt_close(a); xt_close(c); xt_close(lis);
    }
}

/* ---- two shared listeners ---------------------------------------------------------------------------------- */
TEST(bindmx_shared_listeners_one_receives_each_connection)
{
    SOCKET l1 = xt_tcp(), l2 = xt_tcp(); u_short p = 0; int n1 = 0, n2 = 0, i;
    NEED();
    xt_seti(l1, SOL_SOCKET, SO_REUSEADDR, 1); xt_seti(l2, SOL_SOCKET, SO_REUSEADDR, 1);
    EQ(bind_to(l1, A_LO, 0, &p), 0); EQ(bind_to(l2, A_LO, p, NULL), 0);
    EQ(U(listen)(l1, 4), 0); EQ(U(listen)(l2, 4), 0);
    for (i = 0; i < 4; i++) {
        SOCKET c = xt_tcp(), a;
        EQ(xt_connect_lo(c, p), 0);
        /* the connection is queued on exactly one of the two listeners; wait (bounded) for either */
        { int t; for (t = 0; t < 150 && !xt_readable(l1, 0) && !xt_readable(l2, 0); t++) Sleep(20); }
        if (xt_readable(l1, 0)) { a = xt_accept(l1); n1++; xt_close(a); }
        else if (xt_readable(l2, 0)) { a = xt_accept(l2); n2++; xt_close(a); }
        xt_close(c);
    }
    EQ(n1 + n2, 4);
    xt_close(l1); xt_close(l2);
}

/* ---- IPv6 loopback: recorded matrix (printed, not asserted) ---------------------------------------------------- */
static int bind6(SOCKET s, int any, u_short port, u_short *out)
{
    struct sockaddr_in6 a; int l = sizeof a;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = port;
    if (!any) a.sin6_addr.u.Byte[15] = 1;
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return U(WSAGetLastError)();
    if (out) { U(getsockname)(s, (struct sockaddr *)&a, &l); *out = a.sin6_port; }
    return 0;
}
TEST(bindmx_ipv6_loopback_then_loopback_matrix_equals_the_ipv4_one)
{
    int m1, m2; SOCKET probe;
    NEED();
    probe = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (probe == INVALID_SOCKET) { t_skip("no IPv6"); return; }
    xt_close(probe);
    for (m1 = 0; m1 < 3; m1++) for (m2 = 0; m2 < 3; m2++) {
        SOCKET s1 = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP), s2 = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP); u_short p = 0; int e2;
        setmode(s1, m1); setmode(s2, m2);
        if (bind6(s1, 0, 0, &p)) { xt_close(s1); xt_close(s2); t_skip("no IPv6 loopback"); return; }
        e2 = bind6(s2, 0, p, NULL);
        CHECKF(e2 == mx_same[m1][m2], "::1 first %s second %s: err %d want %d", mname[m1], mname[m2], e2, mx_same[m1][m2]);
        xt_close(s1); xt_close(s2);
    }
}
