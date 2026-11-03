/* accept() from several threads and over many cycles: each queued connection is handed to exactly one caller,
 * blocked callers are released by closesocket, and repeated bind/listen/accept/close cycles leave no residue.
 * Every thread is joined with a bound and every wait is limited to a few seconds.
 */
#include "bla.h"

struct worker { SOCKET l; SOCKET got; int err; int wsa; HANDLE th; };

static DWORD WINAPI acc_thread(void *p)
{
    struct worker *w = (struct worker *)p;
    w->got = w->wsa ? wacc(w->l, NULL, NULL, NULL, 0) : acc(w->l, NULL, NULL);
    w->err = w->got == INVALID_SOCKET ? werr() : 0;
    return 0;
}
static void worker_start(struct worker *w, SOCKET l, int wsa)
{
    memset(w, 0, sizeof *w);
    w->l = l; w->got = INVALID_SOCKET; w->wsa = wsa;
    w->th = CreateThread(NULL, 0, acc_thread, w, 0, NULL);
}

static void two_blockers(int wsa)
{
    struct sockaddr_in a;
    struct worker w1, w2;
    SOCKET l = listener(&a, 5), c1, c2;
    worker_start(&w1, l, wsa);
    worker_start(&w2, l, wsa);
    Sleep(100);
    c1 = dial(&a);
    c2 = dial(&a);
    CHECK(join(w1.th, 5000));
    CHECK(join(w2.th, 5000));
    CHECK(w1.got != INVALID_SOCKET);
    CHECK(w2.got != INVALID_SOCKET);
    CHECK(w1.got != w2.got);
    if (w1.got != INVALID_SOCKET) cls(w1.got);
    if (w2.got != INVALID_SOCKET) cls(w2.got);
    cls(c1); cls(c2); cls(l);
}
TEST(bla_thr_two_blocked_accepts_get_distinct_sockets)    { NEED(); two_blockers(0); }
TEST(bla_thr_two_blocked_wsaaccepts_get_distinct_sockets) { NEED(); two_blockers(1); }

TEST(bla_thr_one_connection_wakes_exactly_one_caller)
{
    struct sockaddr_in a;
    struct worker w1, w2;
    SOCKET l = listener(&a, 5), c;
    int done1, done2;
    NEED();
    worker_start(&w1, l, 0);
    worker_start(&w2, l, 0);
    Sleep(100);
    c = dial(&a);
    Sleep(300);
    done1 = WaitForSingleObject(w1.th, 0) == WAIT_OBJECT_0;
    done2 = WaitForSingleObject(w2.th, 0) == WAIT_OBJECT_0;
    EQ(done1 + done2, 1);
    /* release the other waiter with a second connection */
    {
        SOCKET c2 = dial(&a);
        CHECK(join(w1.th, 5000));
        CHECK(join(w2.th, 5000));
        cls(c2);
    }
    if (w1.got != INVALID_SOCKET) cls(w1.got);
    if (w2.got != INVALID_SOCKET) cls(w2.got);
    cls(c); cls(l);
}

static DWORD WINAPI closer(void *p)
{
    SOCKET *s = (SOCKET *)p;
    Sleep(250);
    cls(*s);
    return 0;
}

TEST(bla_thr_close_releases_all_blocked_callers)
{
    struct sockaddr_in a;
    struct worker w1, w2, w3;
    SOCKET l = listener(&a, 5), keep;
    HANDLE th;
    NEED();
    keep = l;
    worker_start(&w1, l, 0);
    worker_start(&w2, l, 1);
    worker_start(&w3, l, 0);
    Sleep(100);
    th = CreateThread(NULL, 0, closer, &keep, 0, NULL);
    CHECK(join(w1.th, 5000));
    CHECK(join(w2.th, 5000));
    CHECK(join(w3.th, 5000));
    CHECK(join(th, 5000));
    CHECK(w1.got == INVALID_SOCKET && w2.got == INVALID_SOCKET && w3.got == INVALID_SOCKET);
    t_note("callers released by closesocket got %s", w1.err == WSAEINTR ? "WSAEINTR" : w1.err == WSAENOTSOCK ? "WSAENOTSOCK" :
           w1.err == WSAEINVAL ? "WSAEINVAL" : "other");
}

TEST(bla_thr_accept_after_close_from_other_thread_is_notsock)
{
    struct sockaddr_in a;
    SOCKET l;
    NEED();
    l = listener(&a, 1);
    EQ(cls(l), 0);
    FAILS(acc(l, NULL, NULL), WSAENOTSOCK);
}

TEST(bla_thr_accept_on_one_thread_connect_on_another_both_ways)
{
    struct sockaddr_in a;
    struct worker w;
    struct cth c;
    SOCKET l = listener(&a, 1);
    char b;
    NEED();
    worker_start(&w, l, 0);
    cth_start(&c, &a);
    CHECK(cth_finish(&c, 5000));
    CHECK(join(w.th, 5000));
    EQ(c.rc, 0);
    CHECK(w.got != INVALID_SOCKET);
    if (w.got != INVALID_SOCKET && c.s != INVALID_SOCKET) {
        rcvto(w.got, 3000);
        EQ(snd(c.s, "z", 1), 1);
        EQ(rcv(w.got, &b, 1), 1);
        EQ(b, 'z');
    }
    if (w.got != INVALID_SOCKET) cls(w.got);
    if (c.s != INVALID_SOCKET) cls(c.s);
    cls(l);
}

TEST(bla_thr_getsockname_from_other_thread_while_accept_blocked)
{
    struct sockaddr_in a, got;
    struct worker w;
    SOCKET l = listener(&a, 1), c;
    int n = sizeof got;
    NEED();
    worker_start(&w, l, 0);
    Sleep(100);
    EQ(gsn(l, &got, &n), 0);                              /* the blocked accept does not hold the socket lock */
    CHECK(!memcmp(&got, &a, sizeof a));
    c = dial(&a);
    CHECK(join(w.th, 5000));
    if (w.got != INVALID_SOCKET) cls(w.got);
    cls(c); cls(l);
}

TEST(bla_thr_setsockopt_from_other_thread_while_accept_blocked)
{
    struct sockaddr_in a;
    struct worker w;
    SOCKET l = listener(&a, 1), c;
    DWORD one = 1;
    NEED();
    worker_start(&w, l, 0);
    Sleep(100);
    EQ(sso(l, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one), 0);
    c = dial(&a);
    CHECK(join(w.th, 5000));
    if (w.got != INVALID_SOCKET) cls(w.got);
    cls(c); cls(l);
}

/* ---- cycles ---- */

TEST(bla_cyc_bind_listen_accept_close_many_times)
{
    int i;
    NEED();
    for (i = 0; i < 25; i++) {
        struct sockaddr_in a;
        SOCKET l = listener(&a, 1), c, s;
        if (l == INVALID_SOCKET) { CHECK(0); break; }
        c = dial(&a);
        s = acc_wait(l, NULL, NULL, 3000);
        if (c == INVALID_SOCKET || s == INVALID_SOCKET) { CHECK(0); if (c != INVALID_SOCKET) cls(c); if (s != INVALID_SOCKET) cls(s); cls(l); break; }
        cls(s); cls(c); cls(l);
    }
    EQ(i, 25);
}

TEST(bla_cyc_one_listener_many_clients_in_sequence)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1);
    int i;
    NEED();
    for (i = 0; i < 40; i++) {
        SOCKET c = dial(&a), s;
        char b = (char)i, r = 0;
        if (c == INVALID_SOCKET) break;
        s = acc_wait(l, NULL, NULL, 3000);
        if (s == INVALID_SOCKET) { cls(c); break; }
        rcvto(s, 3000);
        if (snd(c, &b, 1) != 1 || rcv(s, &r, 1) != 1 || r != b) { cls(s); cls(c); break; }
        cls(s); cls(c);
    }
    EQ(i, 40);
    cls(l);
}

TEST(bla_cyc_many_listeners_open_at_once)
{
    SOCKET l[16];
    struct sockaddr_in a[16];
    int i, j;
    NEED();
    for (i = 0; i < 16; i++) { l[i] = listener(&a[i], 2); CHECK(l[i] != INVALID_SOCKET); }
    for (i = 0; i < 16; i++) for (j = i + 1; j < 16; j++) CHECK(a[i].sin_port != a[j].sin_port);
    for (i = 0; i < 16; i++) {
        SOCKET c = dial(&a[i]), s = acc_wait(l[i], NULL, NULL, 3000);
        CHECK(c != INVALID_SOCKET && s != INVALID_SOCKET);
        if (s != INVALID_SOCKET) cls(s);
        if (c != INVALID_SOCKET) cls(c);
    }
    for (i = 0; i < 16; i++) if (l[i] != INVALID_SOCKET) cls(l[i]);
}

TEST(bla_cyc_connections_route_to_the_right_listener)
{
    struct sockaddr_in a1, a2, p;
    SOCKET l1 = listener(&a1, 2), l2 = listener(&a2, 2), c1, c2, s;
    int n;
    NEED();
    c2 = dial(&a2);
    CHECK(!readable(l1, 100));
    CHECK(readable(l2, 3000));
    c1 = dial(&a1);
    CHECK(readable(l1, 3000));
    n = sizeof p;
    s = acc(l1, &p, &n);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in c1n;
        int m = sizeof c1n;
        EQ(gsn(c1, &c1n, &m), 0);
        CHECK(p.sin_port == c1n.sin_port);
        cls(s);
    }
    s = acc(l2, NULL, NULL);
    if (s != INVALID_SOCKET) cls(s);
    cls(c1); cls(c2); cls(l1); cls(l2);
}

TEST(bla_cyc_wsastartup_count_does_not_affect_listener)
{
    struct sockaddr_in a;
    WSADATA d;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    EQ(U(WSAStartup)(MAKEWORD(2, 2), &d), 0);            /* extra reference taken and released while a listener is open */
    c = dial(&a);
    s = acc_wait(l, NULL, NULL, 3000);
    CHECK(s != INVALID_SOCKET);
    EQ(U(WSACleanup)(), 0);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}
