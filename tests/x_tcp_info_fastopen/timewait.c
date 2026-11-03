/* Port reuse after an orderly close on loopback. The side that closes first would normally sit in TIME_WAIT; the
 * observable question is whether a new socket can take the same local port, with and without SO_REUSEADDR and
 * SO_EXCLUSIVEADDRUSE, and whether a listener can be re-created on the port of a just-closed server. */
#include "xt.h"

static void setmode(SOCKET s, int m)
{
    if (m == 1) xt_seti(s, SOL_SOCKET, SO_REUSEADDR, 1);
    if (m == 2) xt_seti(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
}
static const char *const mname[3] = {"plain", "reuse", "excl"};
/* orderly close of both directions, first side then second; returns after both sides reached state CLOSED */
static void orderly(SOCKET first, SOCKET second)
{
    char b[4];
    U(shutdown)(first, SD_SEND);
    xt_wait_state(second, 7, 3000);
    U(recv)(second, b, 4, 0);
    U(shutdown)(second, SD_SEND);
    xt_wait_state(first, 0, 3000);
}
static int bind_port(SOCKET s, u_short port)
{
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = port; a.sin_addr.s_addr = U(htonl)(INADDR_LOOPBACK);
    return U(bind)(s, (struct sockaddr *)&a, sizeof a) ? U(WSAGetLastError)() : 0;
}

TEST(timewait_client_port_rebindable_after_client_closed_first)
{
    int m;
    NEED();
    for (m = 0; m < 3; m++) {
        SOCKET c, a, l, s2; struct sockaddr_in sa; int sl = sizeof sa; u_short cport;
        if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
        EQ(U(getsockname)(c, (struct sockaddr *)&sa, &sl), 0); cport = sa.sin_port;
        orderly(c, a);
        xt_close(c); xt_close(a);
        s2 = xt_tcp(); setmode(s2, m);
        CHECKF(bind_port(s2, cport) == 0, "mode %s", mname[m]);
        xt_close(s2); xt_close(l);
    }
}
TEST(timewait_server_port_listenable_again_after_server_closed_first)
{
    int m;
    NEED();
    for (m = 0; m < 3; m++) {
        SOCKET c, a, l, s2; struct sockaddr_in sa; int sl = sizeof sa; u_short port; int e;
        if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
        EQ(U(getsockname)(l, (struct sockaddr *)&sa, &sl), 0); port = sa.sin_port;
        xt_close(l);
        orderly(a, c);                 /* the accepted (server) side closes first */
        xt_close(a); xt_close(c);
        s2 = xt_tcp(); setmode(s2, m);
        e = bind_port(s2, port);
        CHECKF(e == 0, "mode %s bind err %d", mname[m], e);
        if (e == 0) { EQ(U(listen)(s2, 2), 0); }
        xt_close(s2);
    }
}
TEST(timewait_server_port_listenable_again_after_client_closed_first)
{
    int m;
    NEED();
    for (m = 0; m < 3; m++) {
        SOCKET c, a, l, s2; struct sockaddr_in sa; int sl = sizeof sa; u_short port; int e;
        if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
        EQ(U(getsockname)(l, (struct sockaddr *)&sa, &sl), 0); port = sa.sin_port;
        xt_close(l);
        orderly(c, a);
        xt_close(c); xt_close(a);
        s2 = xt_tcp(); setmode(s2, m);
        e = bind_port(s2, port);
        CHECKF(e == 0, "mode %s bind err %d", mname[m], e);
        if (e == 0) { EQ(U(listen)(s2, 2), 0); }
        xt_close(s2);
    }
}
TEST(timewait_new_listener_on_old_port_accepts_a_fresh_connection)
{
    SOCKET c, a, l, s2, c2, a2; struct sockaddr_in sa; int sl = sizeof sa; u_short port;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(U(getsockname)(l, (struct sockaddr *)&sa, &sl), 0); port = sa.sin_port;
    xt_close(l);
    orderly(a, c);
    xt_close(a); xt_close(c);
    s2 = xt_tcp();
    EQ(bind_port(s2, port), 0); EQ(U(listen)(s2, 2), 0);
    c2 = xt_tcp(); EQ(xt_connect_lo(c2, port), 0);
    CHECK(xt_readable(s2, 3000));
    a2 = xt_accept(s2); CHECK(a2 != INVALID_SOCKET);
    EQ(xt_send(c2, "ok", 2), 2);
    { char b[4]; EQ(xt_recv_all(a2, b, 2, 3000), 2); }
    xt_close(a2); xt_close(c2); xt_close(s2);
}
TEST(timewait_same_four_tuple_connect_is_address_in_use)
{
    int m;
    NEED();
    for (m = 0; m < 3; m++) {
        SOCKET l, c, a, c2; u_short p, q = 0; int rb, rc = 0, ec = 0;
        if (!xt_listen_lo(&l, &p, 4)) { t_skip("listener failed"); return; }
        c = xt_tcp(); xt_seti(c, SOL_SOCKET, SO_REUSEADDR, 1);
        EQ(xt_bind_lo(c, &q), 0);
        EQ(xt_connect_lo(c, p), 0); CHECK(xt_readable(l, 3000));
        a = xt_accept(l);
        orderly(c, a);                 /* c closes first: it holds the TIME_WAIT */
        xt_close(c); xt_close(a);
        c2 = xt_tcp(); setmode(c2, m);
        rb = bind_port(c2, q);
        EQ(rb, 0);
        rc = xt_connect_lo(c2, p); ec = rc ? U(WSAGetLastError)() : 0;
        CHECKF(rc == SOCKET_ERROR && ec == WSAEADDRINUSE, "mode %s: connect rc %d err %d", mname[m], rc, ec);
        xt_close(c2); xt_close(l);
    }
}
TEST(timewait_other_destination_from_the_old_port_connects)
{
    SOCKET l1, l2, c, a, c2, a2; u_short p1, p2, q = 0; int rc;
    NEED();
    if (!xt_listen_lo(&l1, &p1, 4) || !xt_listen_lo(&l2, &p2, 4)) { t_skip("listeners failed"); return; }
    c = xt_tcp(); xt_seti(c, SOL_SOCKET, SO_REUSEADDR, 1);
    EQ(xt_bind_lo(c, &q), 0);
    EQ(xt_connect_lo(c, p1), 0); CHECK(xt_readable(l1, 3000));
    a = xt_accept(l1);
    orderly(c, a); xt_close(c); xt_close(a);
    c2 = xt_tcp(); xt_seti(c2, SOL_SOCKET, SO_REUSEADDR, 1);
    EQ(bind_port(c2, q), 0);
    rc = xt_connect_lo(c2, p2);
    EQ(rc, 0);
    if (rc == 0) { CHECK(xt_readable(l2, 3000)); a2 = xt_accept(l2); xt_close(a2); }
    xt_close(c2); xt_close(l1); xt_close(l2);
}
