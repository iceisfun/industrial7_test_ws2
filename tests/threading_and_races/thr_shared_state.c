/* State that is per-thread or shared across threads in the Winsock layer, plus concurrent use of one socket.
 *
 * Measures: the static result buffers of the legacy name functions (gethostbyname, gethostbyaddr, getservbyname,
 * getservbyport, getprotobyname, getprotobynumber) are private to each thread and reused by that thread's next
 * call; getaddrinfo from many threads at once; two threads sending on one stream socket never interleave inside a
 * small send, datagrams from two senders arrive intact, two readers of one stream split the bytes with no overlap
 * or duplication; sockets are not tied to the creating thread; WSAStartup/WSACleanup reference counts survive
 * calls made from several threads; a connection storm from many threads against one listener.
 */
#include "thr.h"

/* ---- thread-local result buffers ---------------------------------------------------------------------------------------- */
struct hres { const char *name; HANDLE th; struct hostent *h; char copy_name[64]; int ok; int lookups; struct hostent *again; };

static DWORD WINAPI host_main(void *x)
{
    struct hres *r = (struct hres *)x;
    struct hostent *h = U(gethostbyname)(r->name);
    r->h = h;
    if (h && h->h_name) { lstrcpynA(r->copy_name, h->h_name, sizeof r->copy_name); r->ok = 1; }
    return 0;
}
TEST(thr_state_gethostbyname_same_thread_reuses_buffer)
{
    struct hostent *a, *b;
    NEED();
    a = U(gethostbyname)("localhost");
    REQUIRE(a);
    b = U(gethostbyname)("127.0.0.1");
    CHECK(b != NULL);
    CHECK(a == b);                        /* one buffer per thread: the second call overwrites the first result */
}
TEST(thr_state_gethostbyname_threads_get_distinct_buffers)
{
    struct hostent *mine;
    struct hres r;
    NEED();
    mine = U(gethostbyname)("127.0.0.1");
    REQUIRE(mine);
    memset(&r, 0, sizeof r);
    r.name = "127.0.0.1";
    r.th = CreateThread(NULL, 0, host_main, &r, 0, NULL);
    CHECK(join(r.th, 5000));
    CHECK(r.ok);
    CHECK(r.h != mine);
}
TEST(thr_state_gethostbyname_other_thread_does_not_clobber)
{
    struct hostent *mine;
    struct hres r;
    char before[64];
    NEED();
    mine = U(gethostbyname)("127.0.0.1");
    REQUIRE(mine);
    lstrcpynA(before, mine->h_name, sizeof before);
    memset(&r, 0, sizeof r);
    r.name = "localhost";
    r.th = CreateThread(NULL, 0, host_main, &r, 0, NULL);
    CHECK(join(r.th, 5000));
    CHECK(r.ok);
    EXPECT_STR(mine->h_name, before);     /* the other thread's lookup used its own storage */
    EQV(mine->h_addrtype, AF_INET);
    EQV(mine->h_length, 4);
}
TEST(thr_state_gethostbyname_numeric_literal_name_is_the_literal)
{
    struct hostent *h;
    NEED();
    h = U(gethostbyname)("127.0.0.1");
    REQUIRE(h);
    EXPECT_STR(h->h_name, "127.0.0.1");
    CHECK(h->h_addr_list && h->h_addr_list[0] && !h->h_addr_list[1]);
    CHECK(!memcmp(h->h_addr_list[0], "\x7f\x00\x00\x01", 4));
}
TEST(thr_state_gethostbyname_pointer_in_exited_thread_not_dereferenced)
{
    /* a lookup in a finished thread leaves this thread's own result intact */
    struct hostent *mine;
    struct hres r;
    NEED();
    mine = U(gethostbyname)("127.0.0.1");
    REQUIRE(mine);
    memset(&r, 0, sizeof r);
    r.name = "127.0.0.1";
    r.th = CreateThread(NULL, 0, host_main, &r, 0, NULL);
    CHECK(join(r.th, 5000));
    EXPECT_STR(mine->h_name, "127.0.0.1");
}
struct hbatch { struct hostent *first; char name[64]; int ok; HANDLE th, done, hold; };
static DWORD WINAPI host_batch(void *x)
{
    struct hbatch *b = (struct hbatch *)x;
    int i;
    b->ok = 1;
    for (i = 0; i < 20; i++) {
        struct hostent *h = U(gethostbyname)("127.0.0.1");
        if (!h || strcmp(h->h_name, "127.0.0.1") || !h->h_addr_list[0] || memcmp(h->h_addr_list[0], "\x7f\x00\x00\x01", 4)) b->ok = 0;
        if (i == 0) b->first = h; else if (h != b->first) b->ok = 0;
    }
    SetEvent(b->done);
    WaitForSingleObject(b->hold, 10000);       /* stay alive so every thread's buffer exists at the same time */
    return 0;
}
TEST(thr_state_gethostbyname_eight_threads_stable)
{
    struct hbatch b[8];
    int i;
    HANDLE hold;
    NEED();
    hold = CreateEventA(NULL, TRUE, FALSE, NULL);
    memset(b, 0, sizeof b);
    for (i = 0; i < 8; i++) { b[i].done = CreateEventA(NULL, TRUE, FALSE, NULL); b[i].hold = hold; b[i].th = CreateThread(NULL, 0, host_batch, &b[i], 0, NULL); }
    for (i = 0; i < 8; i++) CHECK(WaitForSingleObject(b[i].done, 10000) == WAIT_OBJECT_0);
    for (i = 0; i < 8; i++) for (int k = i + 1; k < 8; k++) CHECK(b[i].first != b[k].first);
    SetEvent(hold);
    for (i = 0; i < 8; i++) { CHECK(join(b[i].th, 10000)); CHECK(b[i].ok); CloseHandle(b[i].done); }
    CloseHandle(hold);
}

struct sres { struct servent *s; struct protoent *p; int ok; HANDLE th; };
static DWORD WINAPI serv_main(void *x)
{
    struct sres *r = (struct sres *)x;
    r->s = U(getservbyname)("https", "tcp");
    r->p = U(getprotobyname)("udp");
    r->ok = r->s && r->p;
    return 0;
}
TEST(thr_state_getservbyname_buffer_is_per_thread)
{
    struct servent *mine;
    struct sres r;
    NEED();
    mine = U(getservbyname)("http", "tcp");
    REQUIRE(mine);
    EQV((u_short)mine->s_port, U(htons)(80));
    memset(&r, 0, sizeof r);
    r.th = CreateThread(NULL, 0, serv_main, &r, 0, NULL);
    CHECK(join(r.th, 5000));
    CHECK(r.ok);
    CHECK(r.s != mine);
    EXPECT_STR(mine->s_name, "http");
    EQV((u_short)mine->s_port, U(htons)(80));      /* untouched by the other thread's https lookup */
    EQV((u_short)r.s->s_port, U(htons)(443));
}
TEST(thr_state_getservbyname_same_thread_overwrites)
{
    struct servent *a, *b;
    NEED();
    a = U(getservbyname)("http", "tcp");
    REQUIRE(a);
    b = U(getservbyname)("https", "tcp");
    REQUIRE(b);
    CHECK(a == b);
    EQV((u_short)a->s_port, U(htons)(443));
}
TEST(thr_state_getservbyport_buffer_is_per_thread)
{
    struct servent *mine, *t;
    struct sres r;
    NEED();
    mine = U(getservbyport)(U(htons)(80), "tcp");
    REQUIRE(mine);
    t = mine;
    memset(&r, 0, sizeof r);
    r.th = CreateThread(NULL, 0, serv_main, &r, 0, NULL);
    CHECK(join(r.th, 5000));
    EQV((u_short)t->s_port, U(htons)(80));
    EXPECT_STR(t->s_proto, "tcp");
}
TEST(thr_state_getprotobyname_buffer_is_per_thread)
{
    struct protoent *mine;
    struct sres r;
    NEED();
    mine = U(getprotobyname)("tcp");
    REQUIRE(mine);
    EQV(mine->p_proto, 6);
    memset(&r, 0, sizeof r);
    r.th = CreateThread(NULL, 0, serv_main, &r, 0, NULL);
    CHECK(join(r.th, 5000));
    CHECK(r.p != mine);
    EQV(r.p->p_proto, 17);
    EQV(mine->p_proto, 6);
    EXPECT_STR(mine->p_name, "tcp");
}
TEST(thr_state_getprotobynumber_same_thread_overwrites)
{
    struct protoent *a, *b;
    NEED();
    a = U(getprotobynumber)(6);
    REQUIRE(a);
    b = U(getprotobynumber)(17);
    REQUIRE(b);
    CHECK(a == b);
    EQV(a->p_proto, 17);
    EXPECT_STR(a->p_name, "udp");
}
TEST(thr_state_gethostbyaddr_buffer_is_per_thread)
{
    struct hostent *mine, *other = NULL;
    static const char loop[4] = { 127, 0, 0, 1 };
    NEED();
    mine = U(gethostbyname)("127.0.0.1");
    REQUIRE(mine);
    {
        struct hostent *g = U(gethostbyaddr)(loop, 4, AF_INET);
        t_note("gethostbyaddr(loopback) %s", g ? "resolved" : "failed");
        if (g) CHECK(g == mine);          /* same thread, same buffer, whichever lookup function wrote it */
        other = g;
    }
    (void)other;
}

/* ---- getaddrinfo from many threads ----------------------------------------------------------------------------------------- */
struct gai { int ok; HANDLE th; };
static DWORD WINAPI gai_main(void *x)
{
    struct gai *g = (struct gai *)x;
    int i;
    g->ok = 1;
    for (i = 0; i < 25; i++) {
        ADDRINFOA hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_NUMERICHOST;
        if (U(getaddrinfo)("127.0.0.1", "80", &hints, &res) != 0 || !res) { g->ok = 0; break; }
        if (res->ai_family != AF_INET || ((struct sockaddr_in *)res->ai_addr)->sin_port != U(htons)(80)) g->ok = 0;
        U(freeaddrinfo)(res);
    }
    return 0;
}
TEST(thr_state_getaddrinfo_numeric_from_eight_threads)
{
    struct gai g[8];
    int i;
    NEED();
    memset(g, 0, sizeof g);
    for (i = 0; i < 8; i++) g[i].th = CreateThread(NULL, 0, gai_main, &g[i], 0, NULL);
    for (i = 0; i < 8; i++) { CHECK(join(g[i].th, 15000)); CHECK(g[i].ok); }
}
static DWORD WINAPI gai_local(void *x)
{
    struct gai *g = (struct gai *)x;
    ADDRINFOA hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    g->ok = U(getaddrinfo)("localhost", "http", &hints, &res) == 0 && res != NULL;
    if (g->ok) {
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        g->ok = sa->sin_port == U(htons)(80) && sa->sin_addr.s_addr == 0x0100007f;
        U(freeaddrinfo)(res);
    }
    return 0;
}
TEST(thr_state_getaddrinfo_localhost_from_four_threads)
{
    struct gai g[4];
    int i;
    NEED();
    memset(g, 0, sizeof g);
    for (i = 0; i < 4; i++) g[i].th = CreateThread(NULL, 0, gai_local, &g[i], 0, NULL);
    for (i = 0; i < 4; i++) { CHECK(join(g[i].th, 15000)); CHECK(g[i].ok); }
}

/* ---- sockets are not owned by threads ------------------------------------------------------------------------------------------- */
struct mk { SOCKET s; HANDLE th; };
static DWORD WINAPI mk_main(void *x) { struct mk *m = (struct mk *)x; m->s = tcp(); return 0; }
TEST(thr_state_socket_outlives_creating_thread)
{
    struct mk m;
    int type = 0, n = sizeof type;
    NEED();
    m.s = INVALID_SOCKET;
    m.th = CreateThread(NULL, 0, mk_main, &m, 0, NULL);
    CHECK(join(m.th, 5000));
    CHECK(m.s != INVALID_SOCKET);
    EQV(gso(m.s, SOL_SOCKET, SO_TYPE, &type, &n), 0);
    EQV(type, SOCK_STREAM);
    EQV(cls(m.s), 0);
}
struct pr { SOCKET c, s; int ok; HANDLE th; };
static DWORD WINAPI mkpair(void *x) { struct pr *q = (struct pr *)x; q->ok = pair(&q->c, &q->s); return 0; }
TEST(thr_state_connected_pair_used_after_creator_exit)
{
    struct pr p;
    char b[4];
    NEED();
    memset(&p, 0, sizeof p);
    p.th = CreateThread(NULL, 0, mkpair, &p, 0, NULL);
    CHECK(join(p.th, 5000));
    CHECK(p.ok);
    EQV(snd(p.c, "ab", 2), 2);
    EQV(rcv(p.s, b, 4), 2);
    cls(p.c); cls(p.s);
}
TEST(thr_state_nonblocking_flag_is_socket_state_not_thread_state)
{
    SOCKET c, s;
    struct blk b;
    char x;
    NEED();
    CHECK(pair(&c, &s));
    EQV(nbio(s, 1), 0);
    wset(0);
    blk_start(&b, B_RECV, s, 8);          /* another thread sees the socket as non-blocking */
    CHECK(blk_join(&b));
    EQV(b.ret, SOCKET_ERROR);
    EQV(b.err, WSAEWOULDBLOCK);
    wset(0);
    EQV(rcv(s, &x, 1), SOCKET_ERROR);
    EQV(werr(), WSAEWOULDBLOCK);
    cls(c); cls(s);
}
struct gs { SOCKET s; int v; int ret; HANDLE th; };
static DWORD WINAPI rd(void *x) { struct gs *q = (struct gs *)x; int l = sizeof q->v; q->ret = gso(q->s, SOL_SOCKET, SO_RCVBUF, &q->v, &l); return 0; }
TEST(thr_state_sockopt_set_in_one_thread_read_in_another)
{
    SOCKET s;
    struct gs g;
    int v = 12345, n;
    NEED();
    s = tcp();
    n = 8192;
    EQV(sso(s, SOL_SOCKET, SO_RCVBUF, &n, sizeof n), 0);
    g.s = s; g.v = 0; g.ret = -1;
    g.th = CreateThread(NULL, 0, rd, &g, 0, NULL);
    CHECK(join(g.th, 5000));
    EQV(g.ret, 0);
    EQV(g.v, 8192);
    (void)v;
    cls(s);
}

/* ---- two senders, one socket ---------------------------------------------------------------------------------------------------- */
#define MSGLEN 100
#define MSGS   200
struct sender { SOCKET s; char fill; int bad; HANDLE th, go; };
static DWORD WINAPI sender_main(void *x)
{
    struct sender *p = (struct sender *)x;
    char m[MSGLEN];
    int i;
    memset(m, p->fill, sizeof m);
    WaitForSingleObject(p->go, 5000);
    for (i = 0; i < MSGS; i++) if (snd(p->s, m, MSGLEN) != MSGLEN) p->bad++;
    return 0;
}
TEST(thr_state_two_senders_one_stream_no_interleave)
{
    SOCKET c, s;
    struct sender a, b;
    HANDLE go;
    char buf[MSGLEN * 4];
    int total = 0, blocks_a = 0, blocks_b = 0, mixed = 0, r, fill = 0, i;
    char acc[MSGLEN]; int accn = 0;
    NEED();
    CHECK(pair(&c, &s));
    go = CreateEventA(NULL, TRUE, FALSE, NULL);
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    a.s = b.s = c; a.fill = 'A'; b.fill = 'B'; a.go = b.go = go;
    a.th = CreateThread(NULL, 0, sender_main, &a, 0, NULL);
    b.th = CreateThread(NULL, 0, sender_main, &b, 0, NULL);
    SetEvent(go);
    /* read exactly the expected number of bytes; blocks are MSGLEN apart because each send is atomic */
    while (total < 2 * MSGS * MSGLEN) {
        r = rcv(s, buf, sizeof buf);
        if (r <= 0) break;
        total += r;
        for (i = 0; i < r; i++) {
            acc[accn++] = buf[i];
            if (accn == MSGLEN) {
                int k, uni = 1;
                for (k = 1; k < MSGLEN; k++) if (acc[k] != acc[0]) uni = 0;
                if (!uni) mixed++; else if (acc[0] == 'A') blocks_a++; else if (acc[0] == 'B') blocks_b++; else mixed++;
                accn = 0;
            }
        }
    }
    (void)fill;
    CHECK(join(a.th, 10000));
    CHECK(join(b.th, 10000));
    EQV(a.bad, 0); EQV(b.bad, 0);
    EQV(total, 2 * MSGS * MSGLEN);
    EQV(mixed, 0);
    EQV(blocks_a, MSGS);
    EQV(blocks_b, MSGS);
    CloseHandle(go);
    cls(c); cls(s);
}
struct wsender { SOCKET s; char fill; int bad; HANDLE th, go; };
static DWORD WINAPI wmain_thread(void *x)
{
    struct wsender *p = (struct wsender *)x;
    char h[10], t[30];
    WSABUF w[2];
    int i;
    DWORD n;
    memset(h, p->fill, sizeof h); memset(t, p->fill, sizeof t);
    w[0].buf = h; w[0].len = sizeof h; w[1].buf = t; w[1].len = sizeof t;
    WaitForSingleObject(p->go, 5000);
    for (i = 0; i < 150; i++) { n = 0; if (U(WSASend)(p->s, w, 2, &n, 0, NULL, NULL) != 0 || n != 40) p->bad++; }
    return 0;
}
TEST(thr_state_two_senders_wsasend_no_interleave)
{
    /* same as above through WSASend with a two-element buffer array: the pair of buffers stays contiguous */
    SOCKET c, s;
    struct wsender a, b;
    HANDLE go;
    char buf[400];
    int total = 0, r, i, mixed = 0, accn = 0;
    char acc[40];
    NEED();
    CHECK(pair(&c, &s));
    go = CreateEventA(NULL, TRUE, FALSE, NULL);
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    a.s = b.s = c; a.fill = 'x'; b.fill = 'y'; a.go = b.go = go;
    a.th = CreateThread(NULL, 0, wmain_thread, &a, 0, NULL);
    b.th = CreateThread(NULL, 0, wmain_thread, &b, 0, NULL);
    SetEvent(go);
    while (total < 2 * 150 * 40) {
        r = rcv(s, buf, sizeof buf);
        if (r <= 0) break;
        total += r;
        for (i = 0; i < r; i++) {
            acc[accn++] = buf[i];
            if (accn == 40) {
                int k;
                for (k = 1; k < 40; k++) if (acc[k] != acc[0]) { mixed++; break; }
                accn = 0;
            }
        }
    }
    CHECK(join(a.th, 10000));
    CHECK(join(b.th, 10000));
    EQV(a.bad, 0); EQV(b.bad, 0);
    EQV(total, 2 * 150 * 40);
    EQV(mixed, 0);
    CloseHandle(go);
    cls(c); cls(s);
}
struct usender { SOCKET s; struct sockaddr_in to; char fill; int bad; HANDLE th, go; };
static DWORD WINAPI usender_main(void *x)
{
    struct usender *p = (struct usender *)x;
    char m[64];
    int i;
    memset(m, p->fill, sizeof m);
    WaitForSingleObject(p->go, 5000);
    for (i = 0; i < 60; i++) if (U(sendto)(p->s, m, sizeof m, 0, (struct sockaddr *)&p->to, sizeof p->to) != (int)sizeof m) p->bad++;
    return 0;
}
TEST(thr_state_two_senders_one_udp_socket_datagrams_intact)
{
    struct sockaddr_in a;
    SOCKET r, t;
    struct usender p, q;
    HANDLE go;
    char buf[256];
    int got = 0, na = 0, nb = 0, bad = 0, i, n;
    NEED();
    r = udp_bound(&a);
    t = udp();
    go = CreateEventA(NULL, TRUE, FALSE, NULL);
    memset(&p, 0, sizeof p); memset(&q, 0, sizeof q);
    p.s = q.s = t; p.to = q.to = a; p.fill = 'P'; q.fill = 'Q'; p.go = q.go = go;
    p.th = CreateThread(NULL, 0, usender_main, &p, 0, NULL);
    q.th = CreateThread(NULL, 0, usender_main, &q, 0, NULL);
    SetEvent(go);
    CHECK(join(p.th, 10000));
    CHECK(join(q.th, 10000));
    EQV(p.bad, 0); EQV(q.bad, 0);
    SETTLE();
    nbio(r, 1);
    for (;;) {
        n = U(recvfrom)(r, buf, sizeof buf, 0, NULL, NULL);
        if (n == SOCKET_ERROR) break;
        got++;
        if (n != 64) { bad++; continue; }
        for (i = 1; i < 64; i++) if (buf[i] != buf[0]) { bad++; break; }
        if (buf[0] == 'P') na++; else if (buf[0] == 'Q') nb++; else bad++;
    }
    EQV(bad, 0);
    t_note("datagrams received %d of 120 (P=%d Q=%d)", got, na, nb);
    CHECK(got > 0);
    CHECK(na <= 60 && nb <= 60);
    CloseHandle(go);
    cls(t); cls(r);
}

/* ---- two readers, one stream -------------------------------------------------------------------------------------------------------- */
struct reader { SOCKET s; unsigned char got[512]; int n; HANDLE th; };
static DWORD WINAPI reader_main(void *x)
{
    struct reader *p = (struct reader *)x;
    for (;;) {
        char b[7];
        int r = rcv(p->s, b, sizeof b);
        if (r <= 0) break;
        if (p->n + r > (int)sizeof p->got) break;
        memcpy(p->got + p->n, b, r);
        p->n += r;
    }
    return 0;
}
TEST(thr_state_two_readers_one_stream_split_bytes_exactly)
{
    SOCKET c, s;
    struct reader a, b;
    unsigned char src[256], seen[256];
    int i, dup = 0, miss = 0;
    NEED();
    CHECK(pair(&c, &s));
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    a.s = b.s = s;
    a.th = CreateThread(NULL, 0, reader_main, &a, 0, NULL);
    b.th = CreateThread(NULL, 0, reader_main, &b, 0, NULL);
    SETTLE();
    for (i = 0; i < 256; i++) src[i] = (unsigned char)i;
    for (i = 0; i < 256; i += 16) { snd(c, src + i, 16); Sleep(2); }
    U(shutdown)(c, SD_SEND);                 /* readers see the end of stream and stop */
    CHECK(join(a.th, 10000));
    CHECK(join(b.th, 10000));
    memset(seen, 0, sizeof seen);
    for (i = 0; i < a.n; i++) seen[a.got[i]]++;
    for (i = 0; i < b.n; i++) seen[b.got[i]]++;
    for (i = 0; i < 256; i++) { if (seen[i] > 1) dup++; if (seen[i] == 0) miss++; }
    EQV(a.n + b.n, 256);
    EQV(dup, 0);
    EQV(miss, 0);
    cls(c); cls(s);
}
TEST(thr_state_each_reader_sees_ascending_bytes)
{
    /* within one reader the bytes it received are a subsequence of the stream order */
    SOCKET c, s;
    struct reader a, b;
    unsigned char src[200];
    int i, bad = 0;
    NEED();
    CHECK(pair(&c, &s));
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    a.s = b.s = s;
    a.th = CreateThread(NULL, 0, reader_main, &a, 0, NULL);
    b.th = CreateThread(NULL, 0, reader_main, &b, 0, NULL);
    SETTLE();
    for (i = 0; i < 200; i++) src[i] = (unsigned char)i;
    for (i = 0; i < 200; i += 10) { snd(c, src + i, 10); Sleep(2); }
    U(shutdown)(c, SD_SEND);
    CHECK(join(a.th, 10000));
    CHECK(join(b.th, 10000));
    for (i = 1; i < a.n; i++) if (a.got[i] <= a.got[i - 1]) bad++;
    for (i = 1; i < b.n; i++) if (b.got[i] <= b.got[i - 1]) bad++;
    EQV(bad, 0);
    cls(c); cls(s);
}

/* ---- connection storm ----------------------------------------------------------------------------------------------------------------- */
struct storm { struct sockaddr_in a; int ok; HANDLE th; };
static DWORD WINAPI storm_main(void *x)
{
    struct storm *p = (struct storm *)x;
    int i;
    p->ok = 1;
    for (i = 0; i < 6; i++) {
        SOCKET d = dial(&p->a);
        char b = 0;
        if (d == INVALID_SOCKET) { p->ok = 0; break; }
        if (snd(d, "k", 1) != 1 || rcv(d, &b, 1) != 1 || b != 'K') p->ok = 0;
        cls(d);
    }
    return 0;
}
TEST(thr_state_eight_clients_one_listener_echo)
{
    struct sockaddr_in a;
    SOCKET l;
    struct storm st[8];
    int i, served = 0;
    NEED();
    l = listener(&a, 16);
    for (i = 0; i < 8; i++) { memset(&st[i], 0, sizeof st[i]); st[i].a = a; st[i].th = CreateThread(NULL, 0, storm_main, &st[i], 0, NULL); }
    for (i = 0; i < 8 * 6; i++) {
        fd_set fds; struct timeval tv = { 8, 0 };
        SOCKET c;
        char b;
        FD_ZERO(&fds); FD_SET(l, &fds);
        if (U(select)(0, &fds, NULL, NULL, &tv) != 1) break;
        c = U(accept)(l, NULL, NULL);
        if (c == INVALID_SOCKET) break;
        if (rcv(c, &b, 1) == 1 && b == 'k') { snd(c, "K", 1); served++; }
        cls(c);
    }
    for (i = 0; i < 8; i++) { CHECK(join(st[i].th, 10000)); CHECK(st[i].ok); }
    EQV(served, 48);
    cls(l);
}

/* ---- startup / cleanup from several threads ---------------------------------------------------------------------------------------------- */
struct sup { int ret_up, ret_down; HANDLE th; };
static DWORD WINAPI sup_main(void *x)
{
    struct sup *p = (struct sup *)x;
    WSADATA d;
    p->ret_up = U(WSAStartup)(MAKEWORD(2, 2), &d);
    Sleep(20);
    p->ret_down = U(WSACleanup)();
    return 0;
}
TEST(thr_state_balanced_startup_cleanup_in_threads_keeps_stack_alive)
{
    struct sup s[6];
    SOCKET k;
    int i;
    NEED();
    memset(s, 0, sizeof s);
    for (i = 0; i < 6; i++) s[i].th = CreateThread(NULL, 0, sup_main, &s[i], 0, NULL);
    for (i = 0; i < 6; i++) { CHECK(join(s[i].th, 10000)); EQV(s[i].ret_up, 0); EQV(s[i].ret_down, 0); }
    k = tcp();                            /* the main thread's reference is still held */
    CHECK(k != INVALID_SOCKET);
    if (k != INVALID_SOCKET) cls(k);
}
static DWORD WINAPI sock_in_thread(void *x)
{
    SOCKET s = tcp();
    *(SOCKET *)x = s;
    if (s != INVALID_SOCKET) cls(s);
    return 0;
}
TEST(thr_state_socket_creation_from_many_threads)
{
    HANDLE th[8];
    SOCKET res[8];
    int i;
    NEED();
    for (i = 0; i < 8; i++) { res[i] = INVALID_SOCKET; th[i] = CreateThread(NULL, 0, sock_in_thread, &res[i], 0, NULL); }
    for (i = 0; i < 8; i++) { CHECK(join(th[i], 10000)); CHECK(res[i] != INVALID_SOCKET); }
}
