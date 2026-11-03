/* The AF_UNIX accept queue: how many not-yet-accepted connections a listener holds for a given listen()
 * backlog, what the connect that does not fit sees, how accept() frees room, and what unaccepted clients see
 * when the listener goes away. Connects are nonblocking so nothing waits on a full queue. */
#include "xud.h"

#define MAXC 48

struct fill { SOCKET lis; SOCKADDR_UN a; SOCKET c[MAXC]; int n; int in_progress; int failed; int first_fail_err; int all_fail_nobufs; };

static int fill_open(struct fill *f, int backlog, const char *leaf)
{
    memset(f, 0, sizeof *f);
    f->lis = x_sock();
    if (f->lis == INVALID_SOCKET) return 0;
    x_addr(&f->a, x_path(leaf));
    if (x_bind(f->lis, &f->a) || U(listen)(f->lis, backlog)) {
        t_skip("cannot listen");
        U(closesocket)(f->lis);
        DeleteFileA(f->a.sun_path);
        return 0;
    }
    f->all_fail_nobufs = 1;
    return 1;
}
/* One more nonblocking connect; records the outcome. */
static int fill_one(struct fill *f)
{
    SOCKET c = x_sock();
    int r;
    x_blocking(c, FALSE);
    f->c[f->n++] = c;
    r = x_connect(c, &f->a);
    if (r == 0) { f->in_progress++; return 0; }
    if (x_err() == WSAEWOULDBLOCK) { f->in_progress++; return 0; }
    f->failed++;
    if (!f->first_fail_err) f->first_fail_err = x_err();
    if (x_err() != WSAENOBUFS) f->all_fail_nobufs = 0;
    return x_err();
}
static void fill_close(struct fill *f)
{
    int i;
    for (i = 0; i < f->n; i++) U(closesocket)(f->c[i]);
    U(closesocket)(f->lis);
    DeleteFileA(f->a.sun_path);
}
static int drain(struct fill *f)
{
    int n = 0;
    SOCKET s;
    while (x_readable(f->lis, 300) && (s = U(accept)(f->lis, NULL, NULL)) != INVALID_SOCKET) { n++; U(closesocket)(s); }
    return n;
}

/* backlog -> number of connections the queue holds: five per backlog unit, at least five */
static void capacity(int backlog, int cap)
{
    struct fill f;
    int i, accepted;
    UP();
    if (!fill_open(&f, backlog, "bl_cap.sock")) return;
    for (i = 0; i < cap + 3; i++) fill_one(&f);
    XEQ(f.in_progress, cap);
    XEQ(f.failed, 3);
    XEQ(f.first_fail_err, WSAENOBUFS);
    CHECK(f.all_fail_nobufs);
    accepted = drain(&f);
    XEQ(accepted, cap);                                   /* the refused ones never entered the queue */
    fill_close(&f);
}
TEST(xud_backlog_0_holds_five) { capacity(0, 5); }
TEST(xud_backlog_1_holds_five) { capacity(1, 5); }
TEST(xud_backlog_2_holds_ten) { capacity(2, 10); }
TEST(xud_backlog_3_holds_fifteen) { capacity(3, 15); }
TEST(xud_backlog_4_holds_twenty) { capacity(4, 20); }
TEST(xud_backlog_5_holds_twenty_five) { capacity(5, 25); }

static void no_limit_within(int backlog, int n)
{
    struct fill f;
    int i;
    UP();
    if (!fill_open(&f, backlog, "bl_big.sock")) return;
    for (i = 0; i < n; i++) fill_one(&f);
    XEQ(f.failed, 0);
    XEQ(drain(&f), n);
    fill_close(&f);
}
TEST(xud_backlog_8_holds_forty) { no_limit_within(8, 40); }
TEST(xud_backlog_somaxconn_holds_forty) { no_limit_within(SOMAXCONN, 40); }
TEST(xud_backlog_max_int_holds_forty) { no_limit_within(0x7fffffff, 40); }
TEST(xud_backlog_negative_one_behaves_as_large_queue)
{
    struct fill f;
    int i;
    UP();
    if (!fill_open(&f, -1, "bl_neg.sock")) return;
    for (i = 0; i < 40; i++) fill_one(&f);
    XEQ(f.failed, 0);
    XEQ(f.in_progress, 40);
    drain(&f);
    fill_close(&f);
}

/* ---- the queue refills after accept ---- */
TEST(xud_backlog_accept_frees_one_slot)
{
    struct fill f;
    SOCKET s;
    int i;
    UP();
    if (!fill_open(&f, 1, "bl_slot.sock")) return;
    for (i = 0; i < 5; i++) XEQ(fill_one(&f), 0);
    XEQ(fill_one(&f), WSAENOBUFS);                        /* queue full */
    s = x_accept_wait(f.lis);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    XEQ(fill_one(&f), 0);                                 /* one slot came back */
    XEQ(fill_one(&f), WSAENOBUFS);                        /* and only one */
    drain(&f);
    fill_close(&f);
}
TEST(xud_backlog_drained_queue_accepts_again)
{
    struct fill f;
    int i, e;
    UP();
    if (!fill_open(&f, 1, "bl_again.sock")) return;
    for (i = 0; i < 7; i++) fill_one(&f);
    XEQ(drain(&f), 5);
    CHECK(x_try_connect(f.lis, f.a.sun_path, &e));
    XEQ(e, WSAEWOULDBLOCK);
    fill_close(&f);
}
TEST(xud_backlog_refused_client_socket_state)
{
    struct fill f;
    fd_set w, x;
    struct timeval tv = { 0, 100000 };
    WSAPOLLFD p;
    int i, so = -1, l = sizeof so;
    SOCKET refused;
    UP();
    if (!fill_open(&f, 1, "bl_state.sock")) return;
    for (i = 0; i < 6; i++) fill_one(&f);
    XEQ(f.failed, 1);
    refused = f.c[5];
    XEQ(U(getsockopt)(refused, SOL_SOCKET, SO_ERROR, (char *)&so, &l), 0);
    XEQ(so, 0);                                           /* synchronous failure: nothing pending */
    FD_ZERO(&w); FD_ZERO(&x); FD_SET(refused, &w); FD_SET(refused, &x);
    XEQ(U(select)(0, NULL, &w, &x, &tv), 1);
    CHECK(!x_isset(refused, &w));
    CHECK(x_isset(refused, &x));
    p.fd = refused; p.events = POLLWRNORM; p.revents = 0;
    XEQ(U(WSAPoll)(&p, 1, 100), 1);
    XEQ((unsigned short)p.revents, POLLERR | POLLHUP | POLLWRNORM);
    /* a queued (successful) one is writable */
    FD_ZERO(&w); FD_SET(f.c[0], &w);
    XEQ(U(select)(0, NULL, &w, NULL, &tv), 1);
    CHECK(x_isset(f.c[0], &w));
    drain(&f);
    fill_close(&f);
}
TEST(xud_backlog_queued_client_can_send_before_accept)
{
    struct fill f;
    SOCKET s;
    char b[8] = { 0 };
    UP();
    if (!fill_open(&f, 1, "bl_early.sock")) return;
    XEQ(fill_one(&f), 0);
    XEQ(U(send)(f.c[0], "early", 5, 0), 5);
    s = x_accept_wait(f.lis);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        x_rcvtimeo(s, 3000);
        XEQ(x_recv_n(s, b, 5), 5);
        CHECK(!memcmp(b, "early", 5));
        U(closesocket)(s);
    }
    fill_close(&f);
}
TEST(xud_backlog_accept_order_is_connect_order)
{
    struct fill f;
    int i;
    UP();
    if (!fill_open(&f, 2, "bl_order.sock")) return;
    for (i = 0; i < 6; i++) {
        XEQ(fill_one(&f), 0);
        XEQ(U(send)(f.c[i], (char *)&i, 4, 0), 4);
    }
    for (i = 0; i < 6; i++) {
        SOCKET s = x_accept_wait(f.lis);
        int v = -1;
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) break;
        x_rcvtimeo(s, 3000);
        XEQ(x_recv_n(s, (char *)&v, 4), 4);
        XEQ(v, i);
        U(closesocket)(s);
    }
    fill_close(&f);
}

/* ---- the listener goes away with connections queued ---- */
TEST(xud_backlog_listener_close_resets_unaccepted_clients)
{
    struct fill f;
    char b[4];
    int so = -1, l = sizeof so;
    WSAPOLLFD p;
    UP();
    if (!fill_open(&f, 2, "bl_gone.sock")) return;
    XEQ(fill_one(&f), 0);
    CHECK(x_wait(f.c[0], 1, 3000));                       /* connected as far as the client can tell */
    U(closesocket)(f.lis);
    f.lis = INVALID_SOCKET;
    x_blocking(f.c[0], TRUE);
    x_rcvtimeo(f.c[0], 2000);
    XEQ(U(recv)(f.c[0], b, 4, 0), -1);
    XEQ(x_err(), WSAECONNRESET);
    XEQ(U(send)(f.c[0], "x", 1, 0), -1);
    XEQ(x_err(), WSAECONNRESET);
    XEQ(U(send)(f.c[0], "x", 1, 0), -1);
    XEQ(x_err(), WSAECONNRESET);                          /* sticky */
    XEQ(U(getsockopt)(f.c[0], SOL_SOCKET, SO_ERROR, (char *)&so, &l), 0);
    XEQ(so, 0);
    p.fd = f.c[0]; p.events = POLLRDNORM | POLLWRNORM; p.revents = 0;
    XEQ(U(WSAPoll)(&p, 1, 200), 1);
    XEQ((unsigned short)p.revents, POLLERR | POLLHUP | POLLWRNORM);
    fill_close(&f);
}
TEST(xud_backlog_listener_close_does_not_reset_accepted_connections)
{
    TRIO(t, "bl_acc.sock");
    U(closesocket)(t.lis);
    t.lis = INVALID_SOCKET;
    {
        char b[4] = { 0 };
        XEQ(U(send)(t.cli, "ok", 2, 0), 2);
        XEQ(x_recv_n(t.srv, b, 2), 2);
        XEQ(U(send)(t.srv, "ko", 2, 0), 2);
        XEQ(x_recv_n(t.cli, b, 2), 2);
    }
    x_trio_close(&t);
}
TEST(xud_backlog_listener_close_then_new_listener_same_name_needs_delete)
{
    SOCKADDR_UN a;
    SOCKET l1, l2;
    UP();
    l1 = x_sock(); l2 = x_sock();
    if (l1 == INVALID_SOCKET || l2 == INVALID_SOCKET) return;
    x_addr(&a, x_path("bl_name.sock"));
    XEQ(x_bind(l1, &a), 0);
    XEQ(U(listen)(l1, 1), 0);
    U(closesocket)(l1);
    XEQ(x_bind(l2, &a), -1);
    XEQ(x_err(), WSAEADDRINUSE);
    DeleteFileA(a.sun_path);
    XEQ(x_bind(l2, &a), 0);
    XEQ(U(listen)(l2, 1), 0);
    U(closesocket)(l2);
    DeleteFileA(a.sun_path);
}
