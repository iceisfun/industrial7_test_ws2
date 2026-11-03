/* WSAAccept() with a condition function: the verdict values, the arguments the callback receives, and what
 * becomes of the queued connection for each verdict.
 *
 * Verdicts: CF_ACCEPT (0) takes the connection, CF_DEFER (2) fails with WSATRY_AGAIN and leaves it queued,
 * CF_REJECT (1) fails with WSAECONNREFUSED and discards it, any other value is WSAEINVAL.  The callback
 * receives the caller's and the local address as WSABUFs, the callback data word untouched, and is not
 * invoked at all when an earlier check (handle, type, state, buffer length) already failed.
 *
 * The SO_CONDITIONAL_ACCEPT tests ask the stack to hold the handshake until the callback has decided; they
 * use a helper thread for the client and bounded waits everywhere.
 */
#include "bla.h"

/* ---- recording callback ---- */
static struct {
    volatile LONG calls;
    int verdict;
    DWORD_PTR data_seen;
    int caller_len, callee_len;
    unsigned short caller_family, callee_family;
    unsigned short caller_port, callee_port;
    unsigned long caller_addr, callee_addr;
    int have_caller_data, have_callee_data, have_sqos, have_cqos, have_group;
    int have_caller_buf, have_callee_buf;
} rec;

static void rec_reset(int verdict)
{
    memset(&rec, 0, sizeof rec);
    rec.verdict = verdict;
}

static int CALLBACK cond_record(LPWSABUF caller_id, LPWSABUF caller_data, LPQOS sqos, LPQOS cqos,
                                LPWSABUF callee_id, LPWSABUF callee_data, GROUP *group, DWORD_PTR data)
{
    InterlockedIncrement(&rec.calls);
    rec.data_seen = data;
    rec.have_caller_buf = caller_id != NULL;
    rec.have_callee_buf = callee_id != NULL;
    if (caller_id && caller_id->buf && caller_id->len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)caller_id->buf;
        rec.caller_len = (int)caller_id->len;
        rec.caller_family = a->sin_family;
        rec.caller_port = a->sin_port;
        rec.caller_addr = a->sin_addr.s_addr;
    }
    if (callee_id && callee_id->buf && callee_id->len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)callee_id->buf;
        rec.callee_len = (int)callee_id->len;
        rec.callee_family = a->sin_family;
        rec.callee_port = a->sin_port;
        rec.callee_addr = a->sin_addr.s_addr;
    }
    rec.have_caller_data = caller_data != NULL;
    rec.have_callee_data = callee_data != NULL;
    rec.have_sqos = sqos != NULL;
    rec.have_cqos = cqos != NULL;
    rec.have_group = group != NULL;
    return rec.verdict;
}

/* ---- verdict values ---- */

static void verdict_case(int verdict, int want_ok, int want_err)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    rec_reset(verdict);
    s = wacc(l, NULL, NULL, cond_record, 0x1234);
    EQ(rec.calls, 1);
    if (want_ok) {
        CHECK(s != INVALID_SOCKET);
        if (s != INVALID_SOCKET) cls(s);
    } else {
        EQ(s, INVALID_SOCKET);
        EQ(werr(), want_err);
    }
    cls(c); cls(l);
}
TEST(bla_cond_accept_verdict_returns_socket)        { NEED(); verdict_case(CF_ACCEPT, 1, 0); }
TEST(bla_cond_defer_verdict_is_try_again)           { NEED(); verdict_case(CF_DEFER, 0, WSATRY_AGAIN); }
TEST(bla_cond_reject_verdict_is_connrefused)        { NEED(); verdict_case(CF_REJECT, 0, WSAECONNREFUSED); }
TEST(bla_cond_verdict_3_is_einval)                  { NEED(); verdict_case(3, 0, WSAEINVAL); }
TEST(bla_cond_verdict_minus1_is_einval)             { NEED(); verdict_case(-1, 0, WSAEINVAL); }
TEST(bla_cond_verdict_100_is_einval)                { NEED(); verdict_case(100, 0, WSAEINVAL); }
TEST(bla_cond_verdict_int_min_is_einval)            { NEED(); verdict_case((int)0x80000000, 0, WSAEINVAL); }

/* ---- callback arguments ---- */

TEST(bla_cond_callback_data_is_passed_through)
{
    static const DWORD_PTR vals[] = { 0, 1, 0xdeadbeef, (DWORD_PTR)-1 };
    unsigned i;
    NEED();
    for (i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        struct sockaddr_in a;
        SOCKET l = listener(&a, 1), c = dial(&a), s;
        rec_reset(CF_ACCEPT);
        s = wacc(l, NULL, NULL, cond_record, vals[i]);
        CHECK(s != INVALID_SOCKET);
        CHECK(rec.data_seen == vals[i]);
        if (s != INVALID_SOCKET) cls(s);
        cls(c); cls(l);
    }
}

TEST(bla_cond_caller_id_is_the_client_name)
{
    struct sockaddr_in a, cn;
    SOCKET l, c, s;
    int n = sizeof cn;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    EQ(gsn(c, &cn, &n), 0);
    rec_reset(CF_ACCEPT);
    s = wacc(l, NULL, NULL, cond_record, 0);
    CHECK(s != INVALID_SOCKET);
    CHECK(rec.have_caller_buf);
    EQ(rec.caller_family, AF_INET);
    EQ(rec.caller_len, sizeof(struct sockaddr_in));
    CHECK(rec.caller_port == cn.sin_port);
    CHECK(rec.caller_addr == cn.sin_addr.s_addr);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

TEST(bla_cond_callee_id_is_the_listener_name)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    rec_reset(CF_ACCEPT);
    s = wacc(l, NULL, NULL, cond_record, 0);
    CHECK(s != INVALID_SOCKET);
    CHECK(rec.have_callee_buf);
    EQ(rec.callee_family, AF_INET);
    CHECK(rec.callee_port == a.sin_port);
    CHECK(rec.callee_addr == a.sin_addr.s_addr);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

TEST(bla_cond_callee_id_of_wildcard_listener_stays_wildcard)
{
    struct sockaddr_in w = any4(0), a, dst;
    SOCKET l, c, s;
    int n = sizeof a;
    NEED();
    l = tcp();
    EQ(bnd(l, &w, sizeof w), 0);
    EQ(gsn(l, &a, &n), 0);
    EQ(lsn(l, 1), 0);
    dst = lo4(0);
    dst.sin_port = a.sin_port;
    c = dial(&dst);
    rec_reset(CF_ACCEPT);
    s = wacc(l, NULL, NULL, cond_record, 0);
    CHECK(s != INVALID_SOCKET);
    CHECK(rec.callee_port == a.sin_port);
    CHECK(rec.callee_addr == 0);                         /* not resolved to the connection's local address */
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

TEST(bla_cond_arguments_presence_recorded)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    rec_reset(CF_ACCEPT);
    s = wacc(l, NULL, NULL, cond_record, 0);
    CHECK(s != INVALID_SOCKET);
    t_note("condition callback: caller data %s, callee data %s, caller QOS %s, callee QOS %s, group %s",
           rec.have_caller_data ? "buffer" : "NULL", rec.have_callee_data ? "buffer" : "NULL",
           rec.have_sqos ? "struct" : "NULL", rec.have_cqos ? "struct" : "NULL", rec.have_group ? "pointer" : "NULL");
    CHECK(rec.have_group);                  /* the result group is always writable by the callback */
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

TEST(bla_cond_invoked_once_per_attempt)
{
    struct sockaddr_in a;
    SOCKET l, c1, c2, s1, s2;
    NEED();
    l = listener(&a, 5);
    c1 = dial(&a); c2 = dial(&a);
    rec_reset(CF_ACCEPT);
    s1 = wacc(l, NULL, NULL, cond_record, 0);
    EQ(rec.calls, 1);
    s2 = wacc(l, NULL, NULL, cond_record, 0);
    EQ(rec.calls, 2);
    if (s1 != INVALID_SOCKET) cls(s1);
    if (s2 != INVALID_SOCKET) cls(s2);
    cls(c1); cls(c2); cls(l);
}

TEST(bla_cond_with_address_buffer_fills_it_for_accept)
{
    struct sockaddr_in a, from, cn;
    SOCKET l, c, s;
    int n = sizeof from, m = sizeof cn;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    EQ(gsn(c, &cn, &m), 0);
    rec_reset(CF_ACCEPT);
    s = wacc(l, &from, &n, cond_record, 0);
    CHECK(s != INVALID_SOCKET);
    EQ(n, sizeof from);
    CHECK(!memcmp(&from, &cn, sizeof cn));
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

/* ---- verdict consequences ---- */

TEST(bla_cond_defer_keeps_connection_and_repeats)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    rec_reset(CF_DEFER);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSATRY_AGAIN);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSATRY_AGAIN);
    EQ(rec.calls, 2);                                    /* asked again about the same connection */
    rec.verdict = CF_ACCEPT;
    s = wacc(l, NULL, NULL, cond_record, 0);
    CHECK(s != INVALID_SOCKET);
    EQ(rec.calls, 3);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

TEST(bla_cond_defer_preserves_queue_order)
{
    struct sockaddr_in a, n1, n2, p;
    SOCKET l, c1, c2, s;
    int l1 = sizeof n1, l2 = sizeof n2, m;
    NEED();
    l = listener(&a, 5);
    c1 = dial(&a); c2 = dial(&a);
    EQ(gsn(c1, &n1, &l1), 0); EQ(gsn(c2, &n2, &l2), 0);
    rec_reset(CF_DEFER);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSATRY_AGAIN);
    rec.verdict = CF_ACCEPT;
    m = sizeof p;
    s = wacc(l, &p, &m, cond_record, 0);
    CHECK(s != INVALID_SOCKET);
    CHECK(p.sin_port == n1.sin_port);                    /* the deferred connection is still first in line */
    if (s != INVALID_SOCKET) cls(s);
    cls(c1); cls(c2); cls(l);
}

TEST(bla_cond_reject_discards_connection)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    rec_reset(CF_REJECT);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSAECONNREFUSED);
    CHECK(!readable(l, 200));                            /* nothing left in the queue */
    s = INVALID_SOCKET;
    cls(c); cls(l);
}

TEST(bla_cond_reject_then_next_connection_accepted)
{
    struct sockaddr_in a, n2, p;
    SOCKET l, c1, c2, s;
    int l2 = sizeof n2, m = sizeof p;
    NEED();
    l = listener(&a, 5);
    c1 = dial(&a); c2 = dial(&a);
    EQ(gsn(c2, &n2, &l2), 0);
    rec_reset(CF_REJECT);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSAECONNREFUSED);
    rec.verdict = CF_ACCEPT;
    s = wacc(l, &p, &m, cond_record, 0);
    CHECK(s != INVALID_SOCKET);
    CHECK(p.sin_port == n2.sin_port);                    /* the first was thrown away, the second is served */
    if (s != INVALID_SOCKET) cls(s);
    cls(c1); cls(c2); cls(l);
}

TEST(bla_cond_reject_client_sees_failure_on_socket)
{
    struct sockaddr_in a;
    SOCKET l, c;
    char b;
    int r;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);                                         /* the handshake already completed in the stack */
    CHECK(c != INVALID_SOCKET);
    rec_reset(CF_REJECT);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSAECONNREFUSED);
    rcvto(c, 3000);
    r = rcv(c, &b, 1);
    CHECK(r == SOCKET_ERROR || r == 0);
    if (r == SOCKET_ERROR) t_note("client of a rejected connection sees %s", werr() == WSAECONNRESET ? "reset" : werr_class(werr()));
    else t_note("client of a rejected connection sees end of stream");
    cls(c); cls(l);
}

TEST(bla_cond_invalid_verdict_consumes_or_keeps_recorded)
{
    struct sockaddr_in a;
    SOCKET l, c;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    rec_reset(7);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSAEINVAL);
    t_note("connection after an invalid verdict is %s", readable(l, 200) ? "still queued" : "gone");
    cls(c); cls(l);
}

/* ---- the callback is skipped when an earlier check fails ---- */

TEST(bla_cond_not_called_for_closed_socket)
{
    SOCKET s;
    NEED();
    s = tcp();
    EQ(cls(s), 0);
    rec_reset(CF_ACCEPT);
    FAILS(wacc(s, NULL, NULL, cond_record, 0), WSAENOTSOCK);
    EQ(rec.calls, 0);
}

TEST(bla_cond_not_called_for_udp_socket)
{
    SOCKET s;
    NEED();
    s = udp();
    rec_reset(CF_ACCEPT);
    FAILS(wacc(s, NULL, NULL, cond_record, 0), WSAEOPNOTSUPP);
    EQ(rec.calls, 0);
    cls(s);
}

TEST(bla_cond_not_called_for_non_listening_socket)
{
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    rec_reset(CF_ACCEPT);
    FAILS(wacc(s, NULL, NULL, cond_record, 0), WSAEINVAL);
    EQ(rec.calls, 0);
    cls(s);
}

TEST(bla_cond_not_called_when_address_buffer_too_short)
{
    struct sockaddr_in a, buf;
    SOCKET l, c, s;
    int n = 8;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    rec_reset(CF_ACCEPT);
    FAILS(wacc(l, &buf, &n, cond_record, 0), WSAEFAULT);
    EQ(rec.calls, 0);
    n = sizeof buf;
    s = readable(l, 3000) ? wacc(l, &buf, &n, cond_record, 0) : INVALID_SOCKET;
    CHECK(s != INVALID_SOCKET);
    EQ(rec.calls, 1);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

TEST(bla_cond_not_called_on_empty_nonblocking_queue)
{
    struct sockaddr_in a;
    SOCKET l;
    NEED();
    l = listener(&a, 1);
    EQ(nbio(l, 1), 0);
    rec_reset(CF_ACCEPT);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSAEWOULDBLOCK);
    EQ(rec.calls, 0);
    cls(l);
}

TEST(bla_cond_null_callback_ignores_data_word)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    s = wacc(l, NULL, NULL, NULL, 0xdeadbeef);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

/* ---- callback that itself touches the listener ---- */

static int CALLBACK cond_probe_listener(LPWSABUF caller_id, LPWSABUF caller_data, LPQOS sqos, LPQOS cqos,
                                        LPWSABUF callee_id, LPWSABUF callee_data, GROUP *group, DWORD_PTR data)
{
    SOCKET l = (SOCKET)data;
    struct sockaddr_in n;
    int len = sizeof n;
    InterlockedIncrement(&rec.calls);
    rec.caller_port = gsn(l, &n, &len) == 0 ? n.sin_port : 0;      /* reused as "listener name readable" flag */
    return CF_ACCEPT;
}

TEST(bla_cond_callback_may_query_listener_name)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    rec_reset(CF_ACCEPT);
    s = wacc(l, NULL, NULL, cond_probe_listener, (DWORD_PTR)l);
    CHECK(s != INVALID_SOCKET);
    CHECK(rec.caller_port == a.sin_port);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

/* ---- SO_CONDITIONAL_ACCEPT: the handshake waits for the verdict ---- */

static SOCKET cond_listener(struct sockaddr_in *a)
{
    DWORD one = 1;
    SOCKET s = tcp();
    if (s == INVALID_SOCKET) return s;
    if (sso(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &one, sizeof one) != 0 || bind_lo(s, a) != 0 || lsn(s, 1) != 0) {
        cls(s);
        return INVALID_SOCKET;
    }
    return s;
}

TEST(bla_cond_so_conditional_accept_roundtrip)
{
    DWORD v = 0, one = 1, zero = 0;
    int n = sizeof v;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(sso(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &one, sizeof one), 0);
    wset(0x5a5a);
    if (gso(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &v, &n) == 0) {
        t_note("SO_CONDITIONAL_ACCEPT reads back %u after enabling", (unsigned)v);
        EQ(sso(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &zero, sizeof zero), 0);
        v = 0xdead; n = sizeof v;
        if (gso(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &v, &n) == 0)
            t_note("SO_CONDITIONAL_ACCEPT reads back %u after disabling", (unsigned)v);
    } else {
        t_note("getsockopt SO_CONDITIONAL_ACCEPT -> %s", werr_class(werr()));
    }
    cls(s);
}

TEST(bla_cond_so_conditional_accept_on_udp_recorded)
{
    DWORD one = 1;
    SOCKET s;
    NEED();
    s = udp();
    wset(0x5a5a);
    if (sso(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &one, sizeof one) == 0) t_note("SO_CONDITIONAL_ACCEPT on a datagram socket accepted");
    else t_note("SO_CONDITIONAL_ACCEPT on a datagram socket -> %s", werr_class(werr()));
    cls(s);
}

TEST(bla_cond_so_conditional_accept_after_listen_recorded)
{
    struct sockaddr_in a;
    DWORD one = 1;
    SOCKET s;
    NEED();
    s = listener(&a, 1);
    wset(0x5a5a);
    if (sso(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &one, sizeof one) == 0) t_note("SO_CONDITIONAL_ACCEPT after listen accepted");
    else t_note("SO_CONDITIONAL_ACCEPT after listen -> %s", werr_class(werr()));
    cls(s);
}

TEST(bla_cond_conditional_listener_accept_verdict_completes_client)
{
    struct sockaddr_in a;
    SOCKET l, s;
    struct cth c;
    NEED();
    l = cond_listener(&a);
    if (l == INVALID_SOCKET) { t_skip("SO_CONDITIONAL_ACCEPT could not be enabled"); return; }
    cth_start(&c, &a);
    if (!readable(l, 3000)) {
        t_note("conditional listener never became readable");
        cls(l);
        cth_finish(&c, 3000);
        if (c.s != INVALID_SOCKET) cls(c.s);
        return;
    }
    rec_reset(CF_ACCEPT);
    s = wacc(l, NULL, NULL, cond_record, 7);
    CHECK(s != INVALID_SOCKET);
    CHECK(cth_finish(&c, 5000));
    EQ(c.rc, 0);
    EQ(rec.calls, 1);
    if (s != INVALID_SOCKET) cls(s);
    if (c.s != INVALID_SOCKET) cls(c.s);
    cls(l);
}

TEST(bla_cond_conditional_listener_reject_verdict_refuses_client)
{
    struct sockaddr_in a;
    SOCKET l;
    struct cth c;
    NEED();
    l = cond_listener(&a);
    if (l == INVALID_SOCKET) { t_skip("SO_CONDITIONAL_ACCEPT could not be enabled"); return; }
    cth_start(&c, &a);
    if (!readable(l, 3000)) {
        t_note("conditional listener never became readable");
        cls(l);
        cth_finish(&c, 3000);
        if (c.s != INVALID_SOCKET) cls(c.s);
        return;
    }
    rec_reset(CF_REJECT);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSAECONNREFUSED);
    /* the refused client is neither connected nor refused promptly: its connect stays pending (it gives up
       with a timeout only after about twenty seconds), so abort it from here by closing its socket */
    Sleep(1500);
    CHECK(c.rc == -2);
    if (c.s != INVALID_SOCKET) cls(c.s);
    CHECK(cth_finish(&c, 5000));
    CHECK(c.rc == SOCKET_ERROR);
    cls(l);
}

TEST(bla_cond_conditional_listener_defer_keeps_client_waiting)
{
    struct sockaddr_in a;
    SOCKET l, s;
    struct cth c;
    NEED();
    l = cond_listener(&a);
    if (l == INVALID_SOCKET) { t_skip("SO_CONDITIONAL_ACCEPT could not be enabled"); return; }
    cth_start(&c, &a);
    if (!readable(l, 3000)) {
        t_note("conditional listener never became readable");
        cls(l);
        cth_finish(&c, 3000);
        if (c.s != INVALID_SOCKET) cls(c.s);
        return;
    }
    rec_reset(CF_DEFER);
    FAILS(wacc(l, NULL, NULL, cond_record, 0), WSATRY_AGAIN);
    EQ(rec.calls, 1);
    rec.verdict = CF_ACCEPT;
    s = wacc(l, NULL, NULL, cond_record, 0);
    CHECK(s != INVALID_SOCKET);
    CHECK(cth_finish(&c, 5000));
    EQ(c.rc, 0);
    if (s != INVALID_SOCKET) cls(s);
    if (c.s != INVALID_SOCKET) cls(c.s);
    cls(l);
}

TEST(bla_cond_plain_listener_client_connects_before_verdict)
{
    struct sockaddr_in a;
    SOCKET l, c;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);                                         /* completes with nobody calling WSAAccept */
    CHECK(c != INVALID_SOCKET);
    cls(c); cls(l);
}

TEST(bla_cond_conditional_listener_accept_without_callback)
{
    struct sockaddr_in a;
    SOCKET l, s;
    struct cth c;
    NEED();
    l = cond_listener(&a);
    if (l == INVALID_SOCKET) { t_skip("SO_CONDITIONAL_ACCEPT could not be enabled"); return; }
    cth_start(&c, &a);
    if (!readable(l, 3000)) {
        t_note("conditional listener never became readable");
        cls(l);
        cth_finish(&c, 3000);
        if (c.s != INVALID_SOCKET) cls(c.s);
        return;
    }
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    CHECK(cth_finish(&c, 5000));
    EQ(c.rc, 0);
    if (s != INVALID_SOCKET) cls(s);
    if (c.s != INVALID_SOCKET) cls(c.s);
    cls(l);
}
