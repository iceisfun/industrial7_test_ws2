/* AFD listen-side control codes on stream endpoints, each driven by its literal code:
 *   0x1200b START_LISTEN, 0x1200c WAIT_FOR_LISTEN, 0x12090 WAIT_FOR_LISTEN_LIFO,
 *   0x12010 ACCEPT, 0x1208c DEFER_ACCEPT.
 * What is measured: input and output size validation, the state each request needs (bound, not yet
 * listening, listening), the sequence-number protocol that ties a waited-for connection to the accept or
 * defer that consumes it, ordering of pended waits, and the exact NTSTATUS of every refusal. A request
 * that the driver pends is completed by a loopback connection or cancelled by the test. */
#include "g5.h"
#pragma GCC diagnostic ignored "-Wmisleading-indentation"

/* A listener plus one connection queued on it and waited for; the sequence number identifies it. */
typedef struct { SOCKET l, c; struct sockaddr_in a; ULONG seq; } queued_t;
static int q_make(queued_t *q)
{
    q->l = g5_bound(SOCK_STREAM, &q->a);
    q->c = INVALID_SOCKET; q->seq = 0;
    if (q->l == INVALID_SOCKET) return 0;
    EXPECT_NTS(g5_raw_listen(q->l, 4, 0), ST_SUCCESS);
    q->c = g5_connect_nb(&q->a);
    EXPECT_NTS(g5_wait_listen(q->l, 0x1200c, &q->seq, NULL), ST_SUCCESS);
    return 1;
}
static void q_free(queued_t *q) { g5_close(q->c); g5_close(q->l); }
static LONG do_accept(SOCKET l, ULONG seq, HANDLE target, IO_STATUS_BLOCK *io)
{
    G5_ACCEPT a; memset(&a, 0, sizeof a); a.sequence = seq; a.accept = target;
    return g5_ctl(S(l), 0x12010, &a, sizeof a, NULL, 0, io, NULL);
}
static LONG do_defer(SOCKET l, ULONG seq, ULONG reject, IO_STATUS_BLOCK *io)
{
    G5_DEFER d; d.sequence = seq; d.reject = reject;
    return g5_ctl(S(l), 0x1208c, &d, sizeof d, NULL, 0, io, NULL);
}

/* ---- START_LISTEN 0x1200b ---------------------------------------------------------------------------- */
TEST(gap5_listen_input_shorter_than_12_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 1, 4, 8, 11 };
    for (int i = 0; i < 5; i++) {
        SOCKET s = g5_bound(SOCK_STREAM, NULL); unsigned char in[16]; memset(in, 0, sizeof in);
        EXPECT_NTSV(g5_ctl(S(s), 0x1200b, lens[i] ? in : NULL, lens[i], NULL, 0, NULL, NULL), ST_INVALID_PARAMETER, "short record");
        g5_close(s);
    }
}
TEST(gap5_listen_bound_stream_succeeds_and_accepts)
{
    G5_BEGIN();
    struct sockaddr_in a; SOCKET l = g5_bound(SOCK_STREAM, &a), c, s;
    IO_STATUS_BLOCK io;
    G5_LISTEN r; memset(&r, 0, sizeof r); r.backlog = 4;
    EXPECT_NTS(g5_ctl(S(l), 0x1200b, &r, sizeof r, NULL, 0, &io, NULL), ST_SUCCESS);
    EXPECT_EQ(io.Information, 0);
    c = g5_connect_nb(&a);
    CHECK(g5_readable(l, WAIT_MS));                 /* the readiness poll sees the connection queued by the raw listen */
    ULONG seq = 0; s = g5_tcp();
    EXPECT_NTS(g5_wait_listen(l, 0x1200c, &seq, NULL), ST_SUCCESS);
    EXPECT_NTS(do_accept(l, seq, S(s), NULL), ST_SUCCESS);
    g5_close(s); g5_close(c); g5_close(l);
}
TEST(gap5_listen_unbound_stream_refused)
{
    G5_BEGIN();
    SOCKET s = g5_tcp();
    EXPECT_NTS(g5_raw_listen(s, 4, 0), ST_INVALID_PARAMETER);
    g5_close(s);
}
TEST(gap5_listen_second_listen_refused)
{
    G5_BEGIN();
    SOCKET s = g5_bound(SOCK_STREAM, NULL);
    EXPECT_NTS(g5_raw_listen(s, 4, 0), ST_SUCCESS);
    EXPECT_NTS(g5_raw_listen(s, 4, 0), ST_INVALID_PARAMETER);
    EXPECT_NTS(g5_raw_listen(s, 50, 0), ST_INVALID_PARAMETER);
    g5_close(s);
}
TEST(gap5_listen_after_winsock_listen_refused)
{
    G5_BEGIN();
    SOCKET s = g5_listener(NULL);
    EXPECT_NTS(g5_raw_listen(s, 4, 0), ST_INVALID_PARAMETER);
    g5_close(s);
}
TEST(gap5_listen_datagram_endpoints_refused)
{
    G5_BEGIN();
    SOCKET u = g5_udp(), b = g5_bound(SOCK_DGRAM, NULL);
    EXPECT_NTS(g5_raw_listen(u, 4, 0), ST_INVALID_PARAMETER);
    EXPECT_NTS(g5_raw_listen(b, 4, 0), ST_INVALID_PARAMETER);
    g5_close(u); g5_close(b);
}
TEST(gap5_listen_connected_stream_refused)
{
    G5_BEGIN();
    SOCKET c, s;
    g5_pair(&c, &s);
    EXPECT_NTS(g5_raw_listen(c, 4, 0), ST_INVALID_PARAMETER);
    EXPECT_NTS(g5_raw_listen(s, 4, 0), ST_INVALID_PARAMETER);
    g5_close(c); g5_close(s);
}
TEST(gap5_listen_backlog_values_all_accepted)
{
    G5_BEGIN();
    /* zero is raised to one, large values are capped, and for these endpoints a negative count is used as
     * its magnitude: none of them is an error. */
    static const ULONG v[] = { 0, 1, 2, 5, 200, 201, 5000, 0x7fffffff, 0xffffffff, 0x80000000 };
    for (int i = 0; i < 10; i++) {
        struct sockaddr_in a; SOCKET l = g5_bound(SOCK_STREAM, &a), c, s;
        EXPECT_NTSV(g5_raw_listen(l, v[i], 0), ST_SUCCESS, "backlog value");
        c = g5_connect_nb(&a);
        ULONG seq = 0; s = g5_tcp();
        EXPECT_NTS(g5_wait_listen(l, 0x1200c, &seq, NULL), ST_SUCCESS);
        EXPECT_NTS(do_accept(l, seq, S(s), NULL), ST_SUCCESS);
        g5_close(s); g5_close(c); g5_close(l);
    }
}
TEST(gap5_listen_use_san_flag_without_helper_is_ignored)
{
    G5_BEGIN();
    /* the first byte selects the SAN path only when a SAN service helper is registered; none is on a stock
     * system, so a set byte is simply carried along */
    SOCKET l = g5_bound(SOCK_STREAM, NULL); G5_LISTEN r; memset(&r, 0, sizeof r);
    r.use_san = 1; r.backlog = 3;
    EXPECT_NTS(g5_ctl(S(l), 0x1200b, &r, sizeof r, NULL, 0, NULL, NULL), ST_SUCCESS);
    g5_close(l);
}
TEST(gap5_listen_larger_record_accepted)
{
    G5_BEGIN();
    SOCKET l = g5_bound(SOCK_STREAM, NULL); unsigned char r[64]; memset(r, 0, sizeof r);
    r[4] = 4;
    EXPECT_NTS(g5_ctl(S(l), 0x1200b, r, sizeof r, NULL, 0, NULL, NULL), ST_SUCCESS);
    g5_close(l);
}
TEST(gap5_listen_delayed_flag_accepted)
{
    G5_BEGIN();
    /* the delayed-accept form is accepted on a plain stream endpoint */
    SOCKET l = g5_bound(SOCK_STREAM, NULL);
    EXPECT_NTS(g5_raw_listen(l, 4, 1), ST_SUCCESS);
    g5_close(l);
}
/* ---- WAIT_FOR_LISTEN 0x1200c and the LIFO form 0x12090 ----------------------------------------------- */
#define WAIT_CODES(X) X(0x1200c, c1200c) X(0x12090, c12090)
#define WAIT_TESTS(code, nm) \
TEST(gap5_wait_##nm##_endpoint_not_listening_refused) { G5_BEGIN(); \
    SOCKET u = g5_tcp(), b = g5_bound(SOCK_STREAM, NULL), d = g5_bound(SOCK_DGRAM, NULL); G5_WAITRES r; \
    EXPECT_NTS(g5_ctl(S(u), code, NULL, 0, &r, sizeof r, NULL, NULL), ST_INVALID_PARAMETER); \
    EXPECT_NTS(g5_ctl(S(b), code, NULL, 0, &r, sizeof r, NULL, NULL), ST_INVALID_PARAMETER); \
    EXPECT_NTS(g5_ctl(S(d), code, NULL, 0, &r, sizeof r, NULL, NULL), ST_INVALID_PARAMETER); \
    g5_close(u); g5_close(b); g5_close(d); } \
TEST(gap5_wait_##nm##_output_shorter_than_12_refused) { G5_BEGIN(); \
    SOCKET l = g5_listener(NULL); unsigned char o[32]; static const ULONG lens[] = { 0, 1, 4, 8, 11 }; \
    for (int i = 0; i < 5; i++) EXPECT_NTS(g5_ctl(S(l), code, NULL, 0, lens[i] ? o : NULL, lens[i], NULL, NULL), ST_INVALID_PARAMETER); \
    g5_close(l); } \
TEST(gap5_wait_##nm##_pends_until_cancelled) { G5_BEGIN(); \
    SOCKET l = g5_listener(NULL); G5_WAITRES r; IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); \
    LONG first = g5_submit(S(l), ev, code, NULL, 0, &r, sizeof r, &io); \
    EXPECT_NTS(first, ST_PENDING); \
    CHECK(WaitForSingleObject(ev, 300) == WAIT_TIMEOUT);           /* nothing connected: it stays pended */ \
    { IO_STATUS_BLOCK cio; W.cancel(S(l), &cio); } \
    CHECK(WaitForSingleObject(ev, WAIT_MS) == WAIT_OBJECT_0); \
    EXPECT_NTS(io.Status, ST_CANCELLED); \
    CloseHandle(ev); g5_close(l); } \
TEST(gap5_wait_##nm##_reports_sequence_and_peer_name) { G5_BEGIN(); \
    struct sockaddr_in a, mine; SOCKET l = g5_listener(&a), c; struct { ULONG seq; struct sockaddr_in peer; } r; IO_STATUS_BLOCK io; int n = sizeof mine; \
    memset(&r, 0, sizeof r); \
    c = g5_connect_nb(&a); \
    EXPECT_NTS(g5_ctl(S(l), code, NULL, 0, &r, sizeof r, &io, NULL), ST_SUCCESS); \
    EXPECT_EQ(io.Information, 20);                       /* sequence, then the peer's socket address */ \
    EXPECT_EQ(r.peer.sin_family, AF_INET); \
    EXPECT_EQ(r.peer.sin_addr.s_addr, BE32(0x7f000001UL)); \
    CHECK(W.getsockname(c, (struct sockaddr *)&mine, &n) == 0); \
    EXPECT_EQ(r.peer.sin_port, mine.sin_port); \
    g5_close(c); g5_close(l); } \
TEST(gap5_wait_##nm##_output_must_hold_sequence_and_peer_address) { G5_BEGIN(); \
    struct sockaddr_in a; SOCKET l = g5_listener(&a), c; unsigned char o[64]; IO_STATUS_BLOCK io; ULONG n, first = 0; \
    c = g5_connect_nb(&a); \
    for (n = 12; n < 64; n++) { \
        LONG st = g5_ctl(S(l), code, NULL, 0, o, n, &io, NULL); \
        if (st == ST_SUCCESS) { first = n; break; } \
        t_check(st == ST_BUFFER_TOO_SMALL, __FILE__, __LINE__, "too small", "%lu bytes: 0x%08lx", (unsigned long)n, (unsigned long)st); \
    } \
    EXPECT_EQ(first, 20);                                /* sequence + a 16-byte socket address */ \
    g5_close(c); g5_close(l); } \
TEST(gap5_wait_##nm##_each_connection_gets_its_own_sequence) { G5_BEGIN(); \
    struct sockaddr_in a; SOCKET l = g5_listener(&a), c1, c2; G5_WAITRES r1, r2; memset(&r1, 0, sizeof r1); r2 = r1; \
    c1 = g5_connect_nb(&a); c2 = g5_connect_nb(&a); \
    EXPECT_NTS(g5_ctl(S(l), code, NULL, 0, &r1, sizeof r1, NULL, NULL), ST_SUCCESS); \
    EXPECT_NTS(g5_ctl(S(l), code, NULL, 0, &r2, sizeof r2, NULL, NULL), ST_SUCCESS); \
    CHECK(r1.sequence != r2.sequence); \
    g5_close(c1); g5_close(c2); g5_close(l); } \
TEST(gap5_wait_##nm##_connection_reported_once) { G5_BEGIN(); \
    struct sockaddr_in a; SOCKET l = g5_listener(&a), c; G5_WAITRES r; IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); \
    memset(&r, 0, sizeof r); \
    c = g5_connect_nb(&a); \
    EXPECT_NTS(g5_ctl(S(l), code, NULL, 0, &r, sizeof r, NULL, NULL), ST_SUCCESS); \
    EXPECT_NTS(g5_submit(S(l), ev, code, NULL, 0, &r, sizeof r, &io), ST_PENDING);   /* the same one is not reported again */ \
    CHECK(WaitForSingleObject(ev, 300) == WAIT_TIMEOUT); \
    { IO_STATUS_BLOCK cio; W.cancel(S(l), &cio); } WaitForSingleObject(ev, WAIT_MS); \
    CloseHandle(ev); g5_close(c); g5_close(l); }
WAIT_CODES(WAIT_TESTS)

/* Two waits pended before any connection: the plain form completes the earlier one first, the LIFO form
 * the later one first. */
static int which_wait_completes(ULONG code)
{
    struct sockaddr_in a; SOCKET l = g5_listener(&a), c; G5_WAITRES r1, r2; IO_STATUS_BLOCK io1, io2;
    HANDLE ev[2]; int which = -1; DWORD w;
    ev[0] = CreateEventW(NULL, TRUE, FALSE, NULL); ev[1] = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&r1, 0, sizeof r1); r2 = r1;
    EXPECT_NTS(g5_submit(S(l), ev[0], code, NULL, 0, &r1, sizeof r1, &io1), ST_PENDING);
    EXPECT_NTS(g5_submit(S(l), ev[1], code, NULL, 0, &r2, sizeof r2, &io2), ST_PENDING);
    c = g5_connect_nb(&a);
    w = WaitForMultipleObjects(2, ev, FALSE, WAIT_MS);
    if (w == WAIT_OBJECT_0 || w == WAIT_OBJECT_0 + 1) which = (int)(w - WAIT_OBJECT_0);
    if (which >= 0) EXPECT_NTS((which ? io2 : io1).Status, ST_SUCCESS);
    { IO_STATUS_BLOCK cio; W.cancel(S(l), &cio); }   /* completes whatever is still pended */
    WaitForSingleObject(ev[0], 2000); WaitForSingleObject(ev[1], 2000);
    CloseHandle(ev[0]); CloseHandle(ev[1]); g5_close(c); g5_close(l);
    return which;
}
TEST(gap5_wait_0x1200c_completes_oldest_wait_first) { G5_BEGIN(); EXPECT_EQ(which_wait_completes(0x1200c), 0); }
TEST(gap5_wait_0x12090_completes_newest_wait_first) { G5_BEGIN(); EXPECT_EQ(which_wait_completes(0x12090), 1); }

/* ---- ACCEPT 0x12010 ---------------------------------------------------------------------------------- */
TEST(gap5_accept_input_shorter_than_16_refused)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    SOCKET t = g5_tcp(); unsigned char in[16]; static const ULONG lens[] = { 0, 1, 8, 12, 15 };
    memset(in, 0, sizeof in); memcpy(in + 4, &q.seq, 4); memcpy(in + 8, &t, 8);
    for (int i = 0; i < 5; i++)
        EXPECT_NTS(g5_ctl(S(q.l), 0x12010, lens[i] ? in : NULL, lens[i], NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    g5_close(t); q_free(&q);
}
TEST(gap5_accept_listener_required)
{
    G5_BEGIN();
    SOCKET b = g5_bound(SOCK_STREAM, NULL), u = g5_tcp(), t = g5_tcp();
    EXPECT_NTS(do_accept(b, 1, S(t), NULL), ST_INVALID_PARAMETER);
    EXPECT_NTS(do_accept(u, 1, S(t), NULL), ST_INVALID_PARAMETER);
    g5_close(b); g5_close(u); g5_close(t);
}
TEST(gap5_accept_unknown_sequence_refused)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    SOCKET t = g5_tcp();
    EXPECT_NTS(do_accept(q.l, q.seq + 1000, S(t), NULL), ST_INVALID_PARAMETER);
    EXPECT_NTS(do_accept(q.l, 0xfffffff0, S(t), NULL), ST_INVALID_PARAMETER);
    EXPECT_NTS(do_accept(q.l, q.seq, S(t), NULL), ST_SUCCESS);       /* the real one is still there */
    g5_close(t); q_free(&q);
}
TEST(gap5_accept_null_handle_is_invalid_handle)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    EXPECT_NTS(do_accept(q.l, q.seq, NULL, NULL), ST_INVALID_HANDLE);
    EXPECT_NTS(do_accept(q.l, q.seq, (HANDLE)(ULONG_PTR)0x7ffc, NULL), ST_INVALID_HANDLE);   /* not a handle of this process */
    q_free(&q);
}
TEST(gap5_accept_non_file_handle_is_type_mismatch)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    EXPECT_NTS(do_accept(q.l, q.seq, ev, NULL), ST_TYPE_MISMATCH);
    CloseHandle(ev); q_free(&q);
}
TEST(gap5_accept_foreign_device_file_is_invalid_handle)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    HANDLE nul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (nul == INVALID_HANDLE_VALUE) { q_free(&q); t_skip("cannot open the null device"); return; }
    EXPECT_NTS(do_accept(q.l, q.seq, nul, NULL), ST_INVALID_HANDLE);     /* a file object, but not on the AFD device */
    CloseHandle(nul); q_free(&q);
}
TEST(gap5_accept_target_must_be_fresh)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    SOCKET bound = g5_bound(SOCK_STREAM, NULL), udp = g5_udp(), ok = g5_tcp();
    EXPECT_NTSV(do_accept(q.l, q.seq, S(bound), NULL), ST_INVALID_PARAMETER, "bound target");
    EXPECT_NTSV(do_accept(q.l, q.seq, S(udp), NULL), ST_INVALID_PARAMETER, "datagram target");
    EXPECT_NTSV(do_accept(q.l, q.seq, S(q.l), NULL), ST_INVALID_PARAMETER, "the listener itself");
    EXPECT_NTSV(do_accept(q.l, q.seq, S(ok), NULL), ST_SUCCESS, "refusals did not consume the connection");
    g5_close(bound); g5_close(udp); g5_close(ok); q_free(&q);
}
TEST(gap5_accept_consumes_sequence)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    SOCKET t1 = g5_tcp(), t2 = g5_tcp(); IO_STATUS_BLOCK io;
    EXPECT_NTS(do_accept(q.l, q.seq, S(t1), &io), ST_SUCCESS);
    EXPECT_EQ(io.Information, 0);
    EXPECT_NTS(do_accept(q.l, q.seq, S(t2), NULL), ST_INVALID_PARAMETER);
    g5_close(t1); g5_close(t2); q_free(&q);
}
TEST(gap5_accept_target_carries_the_connection)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    SOCKET t = g5_tcp(); char buf[8] = { 0 }; int r;
    EXPECT_NTS(do_accept(q.l, q.seq, S(t), NULL), ST_SUCCESS);
    /* tell the Winsock layer the raw-accepted socket belongs to the listener, as the extended accept does */
    r = W.setsockopt(t, SOL_SOCKET, 0x700B /* SO_UPDATE_ACCEPT_CONTEXT */, (char *)&q.l, sizeof q.l);
    EXPECT_EQ(r, 0);
    r = W.send(q.c, "ping", 4, 0);
    EXPECT_EQ(r, 4);
    r = W.recv(t, buf, sizeof buf, 0);
    EXPECT_EQ(r, 4);
    CHECK(!memcmp(buf, "ping", 4));
    g5_close(t); q_free(&q);
}
TEST(gap5_accept_target_takes_the_listeners_local_name)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    SOCKET t = g5_tcp(); struct sockaddr_in name; IO_STATUS_BLOCK io;
    EXPECT_NTS(do_accept(q.l, q.seq, S(t), NULL), ST_SUCCESS);
    memset(&name, 0, sizeof name);
    EXPECT_NTS(g5_ctl(S(t), 0x1202f, NULL, 0, &name, sizeof name, &io, NULL), ST_SUCCESS);   /* GET_ADDRESS */
    EXPECT_EQ(io.Information, sizeof name);
    EXPECT_EQ(name.sin_family, AF_INET);
    EXPECT_EQ(name.sin_addr.s_addr, BE32(0x7f000001UL));
    EXPECT_EQ(name.sin_port, q.a.sin_port);                  /* the accepted endpoint is named like the listener */
    g5_close(t); q_free(&q);
}

/* ---- DEFER_ACCEPT 0x1208c ----------------------------------------------------------------------------- */
TEST(gap5_defer_input_shorter_than_8_refused)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    unsigned char in[8]; static const ULONG lens[] = { 0, 1, 4, 7 };
    memset(in, 0, sizeof in); memcpy(in, &q.seq, 4);
    for (int i = 0; i < 4; i++) EXPECT_NTS(g5_ctl(S(q.l), 0x1208c, lens[i] ? in : NULL, lens[i], NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    q_free(&q);
}
TEST(gap5_defer_listener_required)
{
    G5_BEGIN();
    SOCKET b = g5_bound(SOCK_STREAM, NULL), u = g5_tcp();
    EXPECT_NTS(do_defer(b, 1, 0, NULL), ST_INVALID_PARAMETER);
    EXPECT_NTS(do_defer(u, 1, 0, NULL), ST_INVALID_PARAMETER);
    g5_close(b); g5_close(u);
}
TEST(gap5_defer_unknown_sequence_refused)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    EXPECT_NTS(do_defer(q.l, q.seq + 1000, 0, NULL), ST_INVALID_PARAMETER);
    EXPECT_NTS(do_defer(q.l, q.seq + 1000, 1, NULL), ST_INVALID_PARAMETER);
    q_free(&q);
}
TEST(gap5_defer_keep_returns_connection_to_the_wait_queue)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    SOCKET t = g5_tcp(); IO_STATUS_BLOCK io; ULONG seq2 = 0;
    EXPECT_NTS(do_defer(q.l, q.seq, 0, &io), ST_SUCCESS);
    EXPECT_EQ(io.Information, 0);
    EXPECT_NTS(do_accept(q.l, q.seq, S(t), NULL), ST_INVALID_PARAMETER);      /* the waited-for claim is released */
    EXPECT_NTS(g5_wait_listen(q.l, 0x1200c, &seq2, NULL), ST_SUCCESS);        /* and it is reported again */
    t_note("deferred connection reported again with the same sequence: %d", seq2 == q.seq);
    EXPECT_NTS(do_accept(q.l, seq2, S(t), NULL), ST_SUCCESS);
    g5_close(t); q_free(&q);
}
TEST(gap5_defer_reject_drops_the_connection)
{
    G5_BEGIN();
    queued_t q; if (!q_make(&q)) return;
    SOCKET t = g5_tcp(); char b[4]; int r;
    EXPECT_NTS(do_defer(q.l, q.seq, 1, NULL), ST_SUCCESS);
    EXPECT_NTS(do_accept(q.l, q.seq, S(t), NULL), ST_INVALID_PARAMETER);    /* the sequence is gone */
    /* the client side ends up with a dead connection: nothing is ever readable from it */
    CHECK(g5_readable(q.c, WAIT_MS));
    r = W.recv(q.c, b, sizeof b, 0);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W.WSAGetLastError(), WSAECONNRESET);
    g5_close(t); q_free(&q);
}
TEST(gap5_defer_reject_tests_only_the_low_byte)
{
    G5_BEGIN();
    /* a second field of 0x100 has a zero low byte: that is "keep", not "reject" */
    queued_t q; if (!q_make(&q)) return;
    ULONG seq2 = 0; SOCKET t = g5_tcp();
    EXPECT_NTS(do_defer(q.l, q.seq, 0x100, NULL), ST_SUCCESS);
    EXPECT_NTS(g5_wait_listen(q.l, 0x1200c, &seq2, NULL), ST_SUCCESS);       /* still there: reported again */
    EXPECT_NTS(do_accept(q.l, seq2, S(t), NULL), ST_SUCCESS);
    g5_close(t); q_free(&q);
}
