/* The accept request: binding a waiting connection to a socket created by the caller.
 *
 * Input is a 16-byte block (SAN flag byte, the sequence number returned by wait-for-listen, and the handle
 * of the socket that is to become the accepted connection). The driver checks, in this order: the listener
 * is listening and the block is long enough; the handle resolves to a file object (invalid handle / wrong
 * object type are reported with the object manager's status); the target is an unused stream endpoint on
 * the same transport; and the sequence number names a connection that wait-for-listen handed out. Every one
 * of those refusals is a synchronous parameter error except the two handle errors. A successful accept
 * completes inside the submit call and moves no data; the accepted socket then works for send and receive
 * but, because the Winsock layer was bypassed, it holds no connection state of its own.
 */
#include "abl.h"

typedef struct { ULONG seq; struct sockaddr_in addr; } WFL4;

static ULONG next_seq(SOCKET l, struct sockaddr_in *peer) {
    WFL4 r; IO_STATUS_BLOCK io;
    memset(&r, 0, sizeof r);
    LONG st = abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL);
    CHECK_NS(st, NS_SUCCESS);
    if (peer) *peer = r.addr;
    return r.seq;
}
static LONG do_accept(SOCKET l, ULONG seq, HANDLE target, ULONG insz, LONG *first) {
    ABL_ACCEPT aa; IO_STATUS_BLOCK io;
    memset(&aa, 0, sizeof aa);
    aa.sequence = seq; aa.accept_handle = target;
    return abl_ctl(l, IO_ACCEPT, &aa, insz, NULL, 0, &io, first);
}
/* listener with one connection waiting and its sequence number already fetched */
typedef struct { SOCKET l, c; struct sockaddr_in addr, peer; ULONG seq; } AC;
static void ac_open(AC *x) {
    x->l = abl_listener(&x->addr);
    x->c = abl_client_to(&x->addr);
    CHECK(abl_wait_readable(x->l, WAIT_MS));
    x->seq = next_seq(x->l, &x->peer);
}
static void ac_close(AC *x) { abl_close(x->c); abl_close(x->l); }

TEST(abln_basic_accept_completes_synchronously) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); LONG first;
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, sizeof(ABL_ACCEPT), &first), NS_SUCCESS);
    CHECK_NS(first, NS_SUCCESS);
    abl_close(t); ac_close(&x);
}
TEST(abln_accept_iosb_information_zero) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); ABL_ACCEPT aa; IO_STATUS_BLOCK io;
    memset(&aa, 0, sizeof aa); aa.sequence = x.seq; aa.accept_handle = (HANDLE)t;
    CHECK_NS(abl_ctl(x.l, IO_ACCEPT, &aa, sizeof aa, NULL, 0, &io, NULL), NS_SUCCESS);
    CHECK_NS(io.Status, NS_SUCCESS);
    CHECK_INFO(io, 0);
    abl_close(t); ac_close(&x);
}
TEST(abln_accepted_socket_carries_data_both_ways) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); char buf[8];
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, sizeof(ABL_ACCEPT), NULL), NS_SUCCESS);
    CHECK(abl_wait_writable(x.c, WAIT_MS));
    abl_nonblock(x.c, 0);
    CHECK(W.send(t, "to-client", 9, 0) == 9);
    memset(buf, 0, sizeof buf);
    CHECK(W.recv(x.c, buf, 4, 0) == 4 && !memcmp(buf, "to-c", 4));
    CHECK(W.recv(x.c, buf, 5, 0) == 5 && !memcmp(buf, "lient", 5));
    CHECK(W.send(x.c, "up", 2, 0) == 2);
    memset(buf, 0, sizeof buf);
    CHECK(abl_wait_readable(t, WAIT_MS));
    CHECK(W.recv(t, buf, 2, 0) == 2 && !memcmp(buf, "up", 2));
    abl_close(t); ac_close(&x);
}
TEST(abln_data_sent_before_accept_is_delivered) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    CHECK(abl_wait_writable(x.c, WAIT_MS));
    abl_nonblock(x.c, 0);
    CHECK(W.send(x.c, "early", 5, 0) == 5);
    SOCKET t = abl_tcp(); char buf[8] = {0};
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, sizeof(ABL_ACCEPT), NULL), NS_SUCCESS);
    CHECK(abl_wait_readable(t, WAIT_MS));
    CHECK(W.recv(t, buf, 5, 0) == 5 && !memcmp(buf, "early", 5));
    abl_close(t); ac_close(&x);
}
TEST(abln_accepted_local_name_is_listener_name) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); struct sockaddr_in n; IO_STATUS_BLOCK io;
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, sizeof(ABL_ACCEPT), NULL), NS_SUCCESS);
    memset(&n, 0xcc, sizeof n);
    CHECK_NS(abl_raw_name(t, &n, sizeof n, &io), NS_SUCCESS);
    CHECK(!memcmp(&n, &x.addr, sizeof n));
    abl_close(t); ac_close(&x);
}
TEST(abln_accepted_socket_unknown_to_winsock_layer) {
    /* the Winsock layer never saw the connection: it holds no connection state for the new socket */
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); struct sockaddr_in n; int len = sizeof n;
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, sizeof(ABL_ACCEPT), NULL), NS_SUCCESS);
    SET_ERR(0);
    CHECK(W.getpeername(t, (struct sockaddr *)&n, &len) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAENOTCONN);
    abl_close(t); ac_close(&x);
}
TEST(abln_client_sees_listener_as_peer) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); struct sockaddr_in p; int len = sizeof p;
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, sizeof(ABL_ACCEPT), NULL), NS_SUCCESS);
    CHECK(abl_wait_writable(x.c, WAIT_MS));
    CHECK(W.getpeername(x.c, (struct sockaddr *)&p, &len) == 0);
    CHECK(!memcmp(&p, &x.addr, sizeof p));
    abl_close(t); ac_close(&x);
}

/* ---- refusals ---------------------------------------------------------------------------------------- */
TEST(abln_not_listening_refused) {
    ABL_BEGIN();
    SOCKET b = abl_bound(SOCK_STREAM, NULL), u = abl_tcp(), d = abl_bound(SOCK_DGRAM, NULL);
    SOCKET all[3] = { b, u, d };
    for (int i = 0; i < 3; i++) {
        SOCKET t = abl_tcp(); LONG first;
        LONG st = do_accept(all[i], 1, (HANDLE)t, sizeof(ABL_ACCEPT), &first);
        t_check((ULONG)st == NS_INVALID_PARAMETER && (ULONG)first == NS_INVALID_PARAMETER, __FILE__, __LINE__, "accept on non-listener", "kind %d: 0x%08lx", i, (unsigned long)st);
        abl_close(t); abl_close(all[i]);
    }
}
TEST(abln_short_input_refused) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp();
    for (ULONG n = 0; n < 16; n++) {
        LONG st = do_accept(x.l, x.seq, (HANDLE)t, n, NULL);
        t_check((ULONG)st == NS_INVALID_PARAMETER, __FILE__, __LINE__, "short accept input", "len %lu: 0x%08lx", (unsigned long)n, (unsigned long)st);
    }
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, 16, NULL), NS_SUCCESS);     /* the connection was not consumed */
    abl_close(t); ac_close(&x);
}
TEST(abln_longer_input_accepted) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp();
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, 17, NULL), NS_SUCCESS);
    abl_close(t); ac_close(&x);
}
TEST(abln_unknown_sequence_refused) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp();
    static const ULONG seqs[] = { 0x77777, 0xffffffffu, 2, 100 };
    for (size_t i = 0; i < sizeof seqs / sizeof seqs[0]; i++) {
        LONG st = do_accept(x.l, seqs[i] == x.seq ? seqs[i] + 5 : seqs[i], (HANDLE)t, 16, NULL);
        t_check((ULONG)st == NS_INVALID_PARAMETER, __FILE__, __LINE__, "unknown sequence", "seq 0x%lx: 0x%08lx", (unsigned long)seqs[i], (unsigned long)st);
    }
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, 16, NULL), NS_SUCCESS);
    abl_close(t); ac_close(&x);
}
TEST(abln_sequence_zero_names_a_returned_connection) {
    /* a zero sequence is not "unknown": it takes the connection that wait-for-listen has handed out */
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(), t2 = abl_tcp();
    CHECK_NS(do_accept(x.l, 0, (HANDLE)t, 16, NULL), NS_SUCCESS);
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t2, 16, NULL), NS_INVALID_PARAMETER);    /* it was the same connection */
    abl_close(t); abl_close(t2); ac_close(&x);
}
TEST(abln_sequence_zero_without_returned_connection_refused) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a);
    SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    SOCKET t = abl_tcp();
    CHECK_NS(do_accept(l, 0, (HANDLE)t, 16, NULL), NS_INVALID_PARAMETER);
    abl_close(t); abl_close(c); abl_close(l);
}
TEST(abln_sequence_is_single_use) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(), t2 = abl_tcp();
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, 16, NULL), NS_SUCCESS);
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t2, 16, NULL), NS_INVALID_PARAMETER);
    abl_close(t); abl_close(t2); ac_close(&x);
}
TEST(abln_sequence_must_come_from_wait_for_listen) {
    /* a connection that is queued but was never handed out cannot be accepted by guessing its number */
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a);
    SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    SOCKET t = abl_tcp();
    CHECK_NS(do_accept(l, 1, (HANDLE)t, 16, NULL), NS_INVALID_PARAMETER);
    abl_close(t); abl_close(c); abl_close(l);
}
TEST(abln_invalid_handle_value) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)(ULONG_PTR)0x7777c, 16, NULL), NS_INVALID_HANDLE);
    CHECK_NS(do_accept(x.l, x.seq, NULL, 16, NULL), NS_INVALID_HANDLE);
    SOCKET t = abl_tcp();
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, 16, NULL), NS_SUCCESS);       /* connection still there */
    abl_close(t); ac_close(&x);
}
TEST(abln_handle_of_other_object_type) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK_NS(do_accept(x.l, x.seq, ev, 16, NULL), 0xC0000024UL);              /* object type mismatch */
    CHECK_NS(do_accept(x.l, x.seq, GetCurrentProcess(), 16, NULL), 0xC0000024UL);
    CloseHandle(ev);
    abl_close(x.c); abl_close(x.l);
}
TEST(abln_target_is_listener_or_connected_or_datagram) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET cc, ss; abl_pair(&cc, &ss);
    SOCKET u = abl_udp();
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)x.l, 16, NULL), NS_INVALID_PARAMETER);       /* the listener itself */
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)x.c, 16, NULL), NS_INVALID_PARAMETER);       /* connected client */
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)cc, 16, NULL), NS_INVALID_PARAMETER);
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)ss, 16, NULL), NS_INVALID_PARAMETER);
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)u, 16, NULL), NS_INVALID_PARAMETER);         /* datagram endpoint */
    SOCKET t = abl_tcp();
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, 16, NULL), NS_SUCCESS);                  /* none of that consumed it */
    abl_close(t); abl_close(u); abl_close(cc); abl_close(ss); ac_close(&x);
}
TEST(abln_target_already_bound_refused) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET b = abl_bound(SOCK_STREAM, NULL);
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)b, 16, NULL), NS_INVALID_PARAMETER);
    abl_close(b); ac_close(&x);
}
TEST(abln_target_cannot_be_reused_after_accept) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp();
    CHECK_NS(do_accept(x.l, x.seq, (HANDLE)t, 16, NULL), NS_SUCCESS);
    SOCKET c2 = abl_client_to(&x.addr);
    CHECK(abl_wait_readable(x.l, WAIT_MS));
    ULONG s2 = next_seq(x.l, NULL);
    CHECK_NS(do_accept(x.l, s2, (HANDLE)t, 16, NULL), NS_INVALID_PARAMETER);       /* already a connection */
    SOCKET t2 = abl_tcp();
    CHECK_NS(do_accept(x.l, s2, (HANDLE)t2, 16, NULL), NS_SUCCESS);
    abl_close(t); abl_close(t2); abl_close(c2); ac_close(&x);
}
TEST(abln_accept_in_any_order) {
    ABL_BEGIN();
    struct sockaddr_in a, p1, p2; SOCKET l = abl_listener(&a);
    SOCKET c1 = abl_tcp(); CHECK(abl_connect(c1, &a) == 0);
    SOCKET c2 = abl_tcp(); CHECK(abl_connect(c2, &a) == 0);
    CHECK(abl_wait_readable(l, WAIT_MS));
    ULONG s1 = next_seq(l, &p1), s2 = next_seq(l, &p2);
    CHECK(s1 != s2);
    SOCKET t2 = abl_tcp(), t1 = abl_tcp();
    CHECK_NS(do_accept(l, s2, (HANDLE)t2, 16, NULL), NS_SUCCESS);          /* newest first */
    CHECK_NS(do_accept(l, s1, (HANDLE)t1, 16, NULL), NS_SUCCESS);
    CHECK(W.send(t2, "2", 1, 0) == 1);
    CHECK(W.send(t1, "1", 1, 0) == 1);
    char b = 0;
    CHECK(W.recv(c2, &b, 1, 0) == 1 && b == '2');
    CHECK(W.recv(c1, &b, 1, 0) == 1 && b == '1');
    abl_close(t1); abl_close(t2); abl_close(c1); abl_close(c2); abl_close(l);
}
TEST(abln_listener_closed_between_wait_and_accept) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); SOCKET dead = x.l;
    (void)dead;
    abl_close(x.l);
    char b;
    /* the queued connection was reset together with the listener */
    int r = W.recv(x.c, &b, 1, 0);
    CHECK(r == SOCKET_ERROR || r == 0);
    abl_close(t); abl_close(x.c);
}
TEST(abln_two_waiting_connections_back_to_back) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a);
    SOCKET cl[3], tg[3]; ULONG sq[3];
    for (int i = 0; i < 3; i++) { cl[i] = abl_tcp(); CHECK(abl_connect(cl[i], &a) == 0); }
    CHECK(abl_wait_readable(l, WAIT_MS));
    for (int i = 0; i < 3; i++) { sq[i] = next_seq(l, NULL); tg[i] = abl_tcp(); }
    CHECK(sq[1] == sq[0] + 1 && sq[2] == sq[1] + 1);
    for (int i = 0; i < 3; i++) CHECK_NS(do_accept(l, sq[i], (HANDLE)tg[i], 16, NULL), NS_SUCCESS);
    for (int i = 0; i < 3; i++) { abl_close(tg[i]); abl_close(cl[i]); }
    abl_close(l);
}
TEST(abln_san_flag_without_helper_accepted) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); ABL_ACCEPT aa; IO_STATUS_BLOCK io;
    memset(&aa, 0, sizeof aa); aa.use_san = 1; aa.sequence = x.seq; aa.accept_handle = (HANDLE)t;
    CHECK_NS(abl_ctl(x.l, IO_ACCEPT, &aa, sizeof aa, NULL, 0, &io, NULL), NS_SUCCESS);
    abl_close(t); ac_close(&x);
}
TEST(abln_output_buffer_ignored) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); ABL_ACCEPT aa; IO_STATUS_BLOCK io; BYTE out[16];
    memset(&aa, 0, sizeof aa); aa.sequence = x.seq; aa.accept_handle = (HANDLE)t;
    memset(out, 0x5a, sizeof out);
    CHECK_NS(abl_ctl(x.l, IO_ACCEPT, &aa, sizeof aa, out, sizeof out, &io, NULL), NS_SUCCESS);
    for (size_t i = 0; i < sizeof out; i++) if (out[i] != 0x5a) { CHECK(0); break; }
    abl_close(t); ac_close(&x);
}
TEST(abln_padding_bytes_ignored) {
    ABL_BEGIN();
    AC x; ac_open(&x);
    SOCKET t = abl_tcp(); ABL_ACCEPT aa; IO_STATUS_BLOCK io;
    memset(&aa, 0, sizeof aa); aa.pad[0] = aa.pad[1] = aa.pad[2] = 0xff; aa.sequence = x.seq; aa.accept_handle = (HANDLE)t;
    CHECK_NS(abl_ctl(x.l, IO_ACCEPT, &aa, sizeof aa, NULL, 0, &io, NULL), NS_SUCCESS);
    abl_close(t); ac_close(&x);
}
TEST(abln_v6_listener_accepts_v6_target) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET l = abl_sock(AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = abl_lo6(0), n; IO_STATUS_BLOCK io;
    CHECK_NS(abl_raw_bind(l, 0, &a, sizeof a, &n, sizeof n, &io), NS_SUCCESS);
    CHECK_NS(abl_raw_listen(l, 5, 0), NS_SUCCESS);
    CHECK_NS(abl_raw_name(l, &n, sizeof n, &io), NS_SUCCESS);
    SOCKET c = abl_sock(AF_INET6, SOCK_STREAM); abl_nonblock(c, 1);
    W.connect(c, (struct sockaddr *)&n, sizeof n);
    CHECK(abl_wait_readable(l, WAIT_MS));
    BYTE out[64]; memset(out, 0, sizeof out);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, sizeof out, &io, NULL), NS_SUCCESS);
    SOCKET t = abl_sock(AF_INET6, SOCK_STREAM);
    CHECK_NS(do_accept(l, *(ULONG *)out, (HANDLE)t, 16, NULL), NS_SUCCESS);
    abl_close(t); abl_close(c); abl_close(l);
}
