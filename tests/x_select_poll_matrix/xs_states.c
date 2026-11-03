/* State builders: each leaves st->s in a named state, using loopback only and ephemeral ports. */
#include "xs.h"

static void addr4(struct sockaddr_in *a, unsigned short port) { memset(a, 0, sizeof(*a)); a->sin_family = AF_INET; a->sin_addr.s_addr = XS_LOOP4; a->sin_port = port; }
static void addr6(struct sockaddr_in6 *a) { memset(a, 0, sizeof(*a)); a->sin6_family = AF_INET6; a->sin6_addr.s6_addr[15] = 1; }

static int bind_any(SOCKET s, int af, void *out, int *olen)
{
    struct sockaddr_in a4; struct sockaddr_in6 a6; int len;
    if (af == AF_INET6) { addr6(&a6); if (U(bind)(s, (struct sockaddr *)&a6, sizeof(a6))) return 0; len = sizeof(a6); if (U(getsockname)(s, (struct sockaddr *)out, &len)) return 0; }
    else { addr4(&a4, 0); if (U(bind)(s, (struct sockaddr *)&a4, sizeof(a4))) return 0; len = sizeof(a4); if (U(getsockname)(s, (struct sockaddr *)out, &len)) return 0; }
    if (olen) *olen = len;
    return 1;
}

typedef struct { char b[sizeof(struct sockaddr_in6)]; int len; } anyaddr;

static SOCKET listener(int af, int backlog, anyaddr *a)
{
    SOCKET s = xs_sock(af, SOCK_STREAM);
    if (s == INVALID_SOCKET) return s;
    if (!bind_any(s, af, a->b, &a->len) || U(listen)(s, backlog)) { xs_close(s); return INVALID_SOCKET; }
    return s;
}

/* Blocking-connected pair: st->s = client, st->peer = server side (accepted). */
static int conn(xs_st *st, int af)
{
    anyaddr a; SOCKET l = listener(af, 1, &a);
    if (l == INVALID_SOCKET) return 0;
    st->s = xs_sock(af, SOCK_STREAM);
    if (st->s == INVALID_SOCKET || U(connect)(st->s, (struct sockaddr *)a.b, a.len)) { xs_close(l); return 0; }
    st->peer = U(accept)(l, NULL, NULL);
    xs_close(l);
    return st->peer != INVALID_SOCKET;
}
static void swap_roles(xs_st *st) { SOCKET t = st->s; st->s = st->peer; st->peer = t; }
static int linger_close(SOCKET s) { struct linger lg = { 1, 0 }; U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg)); xs_close(s); return 1; }

#define B(n) static int b_##n(xs_st *st)

B(tcp_fresh)   { st->s = xs_sock(AF_INET, SOCK_STREAM); return st->s != INVALID_SOCKET; }
B(tcp_bound)   { struct sockaddr_in a; int l; st->s = xs_sock(AF_INET, SOCK_STREAM); return st->s != INVALID_SOCKET && bind_any(st->s, AF_INET, &a, &l); }
B(tcp_listen_idle) { anyaddr a; st->s = listener(AF_INET, 4, &a); return st->s != INVALID_SOCKET; }
B(tcp_listen_pending)
{
    anyaddr a; st->s = listener(AF_INET, 4, &a);
    if (st->s == INVALID_SOCKET) return 0;
    st->peer = xs_sock(AF_INET, SOCK_STREAM);
    if (U(connect)(st->peer, (struct sockaddr *)a.b, a.len)) return 0;
    return xs_wait(st->s, 'r', 3000);
}
B(tcp_listen_two_pending)
{
    anyaddr a; st->s = listener(AF_INET, 4, &a);
    if (st->s == INVALID_SOCKET) return 0;
    st->peer = xs_sock(AF_INET, SOCK_STREAM); st->aux = xs_sock(AF_INET, SOCK_STREAM);
    if (U(connect)(st->peer, (struct sockaddr *)a.b, a.len) || U(connect)(st->aux, (struct sockaddr *)a.b, a.len)) return 0;
    return xs_wait(st->s, 'r', 3000);
}
B(tcp_listen_after_accept)
{
    if (!b_tcp_listen_pending(st)) return 0;
    st->aux = U(accept)(st->s, NULL, NULL);
    xs_settle(50);
    return st->aux != INVALID_SOCKET;
}
B(tcp_listen_pending_peer_gone)   /* queued connection whose initiator closed before accept */
{
    if (!b_tcp_listen_pending(st)) return 0;
    xs_close(st->peer); st->peer = INVALID_SOCKET;
    xs_settle(100);
    return 1;
}
B(tcp_listen_shut)   /* listener after shutdown(SD_BOTH) is not a valid operation on stream listeners: record anyway */
{
    anyaddr a; st->s = listener(AF_INET, 4, &a);
    if (st->s == INVALID_SOCKET) return 0;
    U(shutdown)(st->s, SD_BOTH);
    xs_settle(50);
    return 1;
}
B(tcp_connecting_stuck)    /* nonblocking connect that cannot complete: accept queue full */
{
    anyaddr a; int i;
    SOCKET l = listener(AF_INET, 1, &a);
    if (l == INVALID_SOCKET) return 0;
    st->lst = l;
    for (i = 0; i < 8; i++) {
        SOCKET c = xs_sock(AF_INET, SOCK_STREAM);
        if (c == INVALID_SOCKET) return 0;
        xs_nb(c, 1);
        U(connect)(c, (struct sockaddr *)a.b, a.len);
        if (!xs_wait(c, 'w', 400)) { st->s = c; return 1; }   /* this one is stuck in SYN_SENT */
        if (st->nextra < XS_MAXX) st->extra[st->nextra++] = c; else xs_close(c);
    }
    return 0;
}
B(tcp_connect_nb_done)
{
    anyaddr a; st->lst = listener(AF_INET, 2, &a);
    if (st->lst == INVALID_SOCKET) return 0;
    st->s = xs_sock(AF_INET, SOCK_STREAM); xs_nb(st->s, 1);
    U(connect)(st->s, (struct sockaddr *)a.b, a.len);
    return xs_wait(st->s, 'w', 3000);
}
B(tcp_connect_nb_done_accepted)
{
    if (!b_tcp_connect_nb_done(st)) return 0;
    st->peer = U(accept)(st->lst, NULL, NULL);
    return st->peer != INVALID_SOCKET;
}
static int refused(xs_st *st, int nb)
{
    anyaddr a; SOCKET l = listener(AF_INET, 1, &a);
    if (l == INVALID_SOCKET) return 0;
    xs_close(l);                      /* nothing listens on that port any more */
    st->s = xs_sock(AF_INET, SOCK_STREAM);
    if (nb) xs_nb(st->s, 1);
    U(connect)(st->s, (struct sockaddr *)a.b, a.len);
    if (nb) return xs_wait(st->s, 'x', 3000) || xs_wait(st->s, 'r', 100);
    xs_settle(100);
    return 1;
}
B(tcp_connect_refused_nb)      { return refused(st, 1); }
B(tcp_connect_refused_nb_soerr_read)
{
    int e = 0, l = sizeof(e);
    if (!refused(st, 1)) return 0;
    U(getsockopt)(st->s, SOL_SOCKET, SO_ERROR, (char *)&e, &l);
    return 1;
}
B(tcp_connect_refused_blocking) { return refused(st, 0); }
B(tcp_conn_client)       { return conn(st, AF_INET); }
B(tcp_conn_server)       { if (!conn(st, AF_INET)) return 0; swap_roles(st); return 1; }
B(tcp_conn_nonblocking)  { if (!conn(st, AF_INET)) return 0; xs_nb(st->s, 1); return 1; }
B(tcp_data_client)       { if (!conn(st, AF_INET)) return 0; xs_send_n(st->peer, 5, 0); return xs_wait(st->s, 'r', 3000); }
B(tcp_data_server)       { if (!conn(st, AF_INET)) return 0; xs_send_n(st->s, 5, 0); swap_roles(st); return xs_wait(st->s, 'r', 3000); }
B(tcp_data_partial_read)
{
    char b[8];
    if (!b_tcp_data_client(st)) return 0;
    U(recv)(st->s, b, 2, 0);
    return 1;
}
B(tcp_data_drained)
{
    char b[16];
    if (!b_tcp_data_client(st)) return 0;
    return U(recv)(st->s, b, sizeof(b), 0) == 5;
}
B(tcp_data_both_ways)
{
    if (!b_tcp_data_client(st)) return 0;
    xs_send_n(st->s, 3, 0);
    return xs_wait(st->peer, 'r', 3000);
}
B(tcp_oob_pending)
{
    if (!conn(st, AF_INET)) return 0;
    if (xs_send_n(st->peer, 1, MSG_OOB) != 1) return 0;
    return xs_wait(st->s, 'x', 3000);
}
B(tcp_oob_with_data)
{
    if (!conn(st, AF_INET)) return 0;
    xs_send_n(st->peer, 4, 0);
    if (xs_send_n(st->peer, 1, MSG_OOB) != 1) return 0;
    return xs_wait(st->s, 'x', 3000) && xs_wait(st->s, 'r', 3000);
}
B(tcp_oob_inline)
{
    int on = 1;
    if (!conn(st, AF_INET)) return 0;
    U(setsockopt)(st->s, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof(on));
    if (xs_send_n(st->peer, 1, MSG_OOB) != 1) return 0;
    return xs_wait(st->s, 'r', 3000);
}
B(tcp_oob_consumed)
{
    char c;
    if (!b_tcp_oob_pending(st)) return 0;
    return U(recv)(st->s, &c, 1, MSG_OOB) == 1;
}
B(tcp_oob_consumed_data_left)
{
    char c;
    if (!b_tcp_oob_with_data(st)) return 0;
    return U(recv)(st->s, &c, 1, MSG_OOB) == 1;
}
B(tcp_oob_sender)     /* the side that sent urgent data */
{
    if (!b_tcp_oob_pending(st)) return 0;
    swap_roles(st);
    return 1;
}
B(tcp_peer_fin)       { if (!conn(st, AF_INET)) return 0; U(shutdown)(st->peer, SD_SEND); return xs_wait(st->s, 'r', 3000); }
B(tcp_peer_fin_data)  { if (!conn(st, AF_INET)) return 0; xs_send_n(st->peer, 5, 0); U(shutdown)(st->peer, SD_SEND); xs_wait(st->s, 'r', 3000); xs_settle(100); return 1; }
B(tcp_peer_fin_drained)
{
    char b[16];
    if (!b_tcp_peer_fin_data(st)) return 0;
    return U(recv)(st->s, b, sizeof(b), 0) == 5 && U(recv)(st->s, b, sizeof(b), 0) == 0;
}
B(tcp_peer_fin_data_drained)   /* FIN seen, data read, 0-byte read not yet issued */
{
    char b[16];
    if (!b_tcp_peer_fin_data(st)) return 0;
    return U(recv)(st->s, b, sizeof(b), 0) == 5;
}
B(tcp_peer_close)     { if (!conn(st, AF_INET)) return 0; xs_close(st->peer); st->peer = INVALID_SOCKET; return xs_wait(st->s, 'r', 3000); }
B(tcp_peer_close_data){ if (!conn(st, AF_INET)) return 0; xs_send_n(st->peer, 5, 0); xs_close(st->peer); st->peer = INVALID_SOCKET; xs_wait(st->s, 'r', 3000); xs_settle(100); return 1; }
B(tcp_peer_reset)     { if (!conn(st, AF_INET)) return 0; linger_close(st->peer); st->peer = INVALID_SOCKET; return xs_wait(st->s, 'r', 3000); }
B(tcp_peer_reset_data){ if (!conn(st, AF_INET)) return 0; xs_send_n(st->peer, 5, 0); xs_wait(st->s, 'r', 3000); linger_close(st->peer); st->peer = INVALID_SOCKET; xs_settle(150); return 1; }
B(tcp_peer_reset_after_recv_err)
{
    char b[16];
    if (!b_tcp_peer_reset(st)) return 0;
    U(recv)(st->s, b, sizeof(b), 0);   /* first receive reports the reset */
    return 1;
}
B(tcp_peer_reset_after_soerr_read)
{
    int e = 0, l = sizeof(e);
    if (!b_tcp_peer_reset(st)) return 0;
    U(getsockopt)(st->s, SOL_SOCKET, SO_ERROR, (char *)&e, &l);
    return 1;
}
B(tcp_local_shut_send)  { if (!conn(st, AF_INET)) return 0; U(shutdown)(st->s, SD_SEND); xs_settle(50); return 1; }
B(tcp_local_shut_recv)  { if (!conn(st, AF_INET)) return 0; U(shutdown)(st->s, SD_RECEIVE); xs_settle(50); return 1; }
B(tcp_local_shut_both)  { if (!conn(st, AF_INET)) return 0; U(shutdown)(st->s, SD_BOTH); xs_settle(50); return 1; }
B(tcp_local_shut_send_peer_fin)
{
    if (!conn(st, AF_INET)) return 0;
    U(shutdown)(st->s, SD_SEND); U(shutdown)(st->peer, SD_SEND);
    return xs_wait(st->s, 'r', 3000);
}
B(tcp_local_shut_recv_peer_sends)
{
    if (!conn(st, AF_INET)) return 0;
    U(shutdown)(st->s, SD_RECEIVE);
    xs_send_n(st->peer, 5, 0);
    xs_settle(250);
    return 1;
}
B(tcp_send_buffer_full)
{
    static char big[65536]; int total = 0, n, hit = 0;
    if (!conn(st, AF_INET)) return 0;
    xs_nb(st->s, 1);
    while (total < 256 * 1024 * 1024) {
        n = U(send)(st->s, big, sizeof(big), 0);
        if (n < 0) { hit = xs_err() == WSAEWOULDBLOCK; break; }
        total += n;
    }
    xs_settle(100);
    return hit;
}
B(tcp_closed)
{
    st->s = xs_sock(AF_INET, SOCK_STREAM);
    if (st->s == INVALID_SOCKET) return 0;
    xs_close(st->s);    /* st->s keeps the stale value; teardown closes it again, harmlessly */
    return 1;
}
B(tcp_closed_connected)
{
    if (!conn(st, AF_INET)) return 0;
    xs_close(st->s);
    return 1;
}
B(tcp_invalid_value) { st->s = (SOCKET)(ULONG_PTR)0x7ffffff0; return 1; }   /* never a valid handle value */

/* ---- UDP ----------------------------------------------------------------- */
B(udp_fresh) { st->s = xs_sock(AF_INET, SOCK_DGRAM); return st->s != INVALID_SOCKET; }
B(udp_bound) { struct sockaddr_in a; int l; st->s = xs_sock(AF_INET, SOCK_DGRAM); return st->s != INVALID_SOCKET && bind_any(st->s, AF_INET, &a, &l); }
static int udp_pair(xs_st *st, int connect_s)
{
    struct sockaddr_in a, p; int l, l2;
    st->s = xs_sock(AF_INET, SOCK_DGRAM); st->peer = xs_sock(AF_INET, SOCK_DGRAM);
    if (st->s == INVALID_SOCKET || st->peer == INVALID_SOCKET) return 0;
    if (!bind_any(st->s, AF_INET, &a, &l) || !bind_any(st->peer, AF_INET, &p, &l2)) return 0;
    if (connect_s && U(connect)(st->s, (struct sockaddr *)&p, l2)) return 0;
    return 1;
}
B(udp_connected)      { return udp_pair(st, 1); }
B(udp_data)
{
    struct sockaddr_in a; int l;
    if (!udp_pair(st, 0)) return 0;
    l = sizeof(a); U(getsockname)(st->s, (struct sockaddr *)&a, &l);
    U(sendto)(st->peer, "hello", 5, 0, (struct sockaddr *)&a, l);
    return xs_wait(st->s, 'r', 3000);
}
B(udp_zero_len)
{
    struct sockaddr_in a; int l;
    if (!udp_pair(st, 0)) return 0;
    l = sizeof(a); U(getsockname)(st->s, (struct sockaddr *)&a, &l);
    U(sendto)(st->peer, "", 0, 0, (struct sockaddr *)&a, l);
    return xs_wait(st->s, 'r', 3000);
}
B(udp_data_drained)
{
    char b[16];
    if (!b_udp_data(st)) return 0;
    return U(recv)(st->s, b, sizeof(b), 0) == 5;
}
B(udp_icmp_error)       /* datagram to a port nobody listens on: ICMP unreachable comes back */
{
    struct sockaddr_in a, dead; int l, ld;
    SOCKET d = xs_sock(AF_INET, SOCK_DGRAM);
    if (d == INVALID_SOCKET || !bind_any(d, AF_INET, &dead, &ld)) return 0;
    xs_close(d);
    st->s = xs_sock(AF_INET, SOCK_DGRAM);
    if (st->s == INVALID_SOCKET || !bind_any(st->s, AF_INET, &a, &l)) return 0;
    U(sendto)(st->s, "x", 1, 0, (struct sockaddr *)&dead, ld);
    xs_wait(st->s, 'r', 3000);
    xs_settle(100);
    return 1;
}
B(udp_icmp_error_consumed)
{
    char b[16];
    if (!b_udp_icmp_error(st)) return 0;
    xs_nb(st->s, 1);   /* a blocking receive could wait forever if no error is queued */
    U(recv)(st->s, b, sizeof(b), 0);
    xs_nb(st->s, 0);
    return 1;
}
B(udp_connected_icmp_error)
{
    struct sockaddr_in dead; int ld;
    SOCKET d = xs_sock(AF_INET, SOCK_DGRAM);
    if (d == INVALID_SOCKET || !bind_any(d, AF_INET, &dead, &ld)) return 0;
    xs_close(d);
    st->s = xs_sock(AF_INET, SOCK_DGRAM);
    if (st->s == INVALID_SOCKET || U(connect)(st->s, (struct sockaddr *)&dead, ld)) return 0;
    U(send)(st->s, "x", 1, 0);
    xs_wait(st->s, 'r', 3000);
    xs_settle(100);
    return 1;
}

/* ---- IPv6 loopback ------------------------------------------------------- */
B(tcp6_listen_pending)
{
    anyaddr a; st->s = listener(AF_INET6, 4, &a);
    if (st->s == INVALID_SOCKET) return 0;
    st->peer = xs_sock(AF_INET6, SOCK_STREAM);
    if (U(connect)(st->peer, (struct sockaddr *)a.b, a.len)) return 0;
    return xs_wait(st->s, 'r', 3000);
}
B(tcp6_conn_client)   { return conn(st, AF_INET6); }
B(tcp6_data_client)   { if (!conn(st, AF_INET6)) return 0; xs_send_n(st->peer, 5, 0); return xs_wait(st->s, 'r', 3000); }
B(tcp6_peer_fin)      { if (!conn(st, AF_INET6)) return 0; U(shutdown)(st->peer, SD_SEND); return xs_wait(st->s, 'r', 3000); }
B(tcp6_peer_reset)    { if (!conn(st, AF_INET6)) return 0; linger_close(st->peer); st->peer = INVALID_SOCKET; return xs_wait(st->s, 'r', 3000); }
B(udp6_data)
{
    struct sockaddr_in6 a, p; int l, l2;
    st->s = xs_sock(AF_INET6, SOCK_DGRAM); st->peer = xs_sock(AF_INET6, SOCK_DGRAM);
    if (st->s == INVALID_SOCKET || st->peer == INVALID_SOCKET) return 0;
    if (!bind_any(st->s, AF_INET6, &a, &l) || !bind_any(st->peer, AF_INET6, &p, &l2)) return 0;
    U(sendto)(st->peer, "hello", 5, 0, (struct sockaddr *)&a, l);
    return xs_wait(st->s, 'r', 3000);
}

#define S(n, w) { #n, b_##n, w }
const xs_state xs_states[] = {
    S(tcp_fresh, "created, never bound or connected"),
    S(tcp_bound, "bound to loopback, not listening"),
    S(tcp_listen_idle, "listening, nothing queued"),
    S(tcp_listen_pending, "listening, one connection queued"),
    S(tcp_listen_two_pending, "listening, two connections queued"),
    S(tcp_listen_after_accept, "listening, the queued connection accepted"),
    S(tcp_listen_pending_peer_gone, "listening, queued connection whose initiator closed"),
    S(tcp_listen_shut, "listening socket after shutdown both"),
    S(tcp_connecting_stuck, "nonblocking connect that stays in progress"),
    S(tcp_connect_nb_done, "nonblocking connect completed"),
    S(tcp_connect_nb_done_accepted, "nonblocking connect completed and accepted"),
    S(tcp_connect_refused_nb, "nonblocking connect refused, error pending"),
    S(tcp_connect_refused_nb_soerr_read, "refused nonblocking connect after SO_ERROR was read"),
    S(tcp_connect_refused_blocking, "blocking connect refused"),
    S(tcp_conn_client, "connected client, idle"),
    S(tcp_conn_server, "connected accepted side, idle"),
    S(tcp_conn_nonblocking, "connected client set nonblocking"),
    S(tcp_data_client, "client with 5 unread bytes"),
    S(tcp_data_server, "accepted side with 5 unread bytes"),
    S(tcp_data_partial_read, "client with 3 of 5 bytes left"),
    S(tcp_data_drained, "client after reading everything"),
    S(tcp_data_both_ways, "client with unread data, peer also has unread data"),
    S(tcp_oob_pending, "urgent byte pending, out-of-band mode"),
    S(tcp_oob_with_data, "ordinary data then urgent byte pending"),
    S(tcp_oob_inline, "urgent byte pending with SO_OOBINLINE"),
    S(tcp_oob_consumed, "urgent byte received with MSG_OOB"),
    S(tcp_oob_consumed_data_left, "urgent byte received, ordinary data left"),
    S(tcp_oob_sender, "the sender of an urgent byte"),
    S(tcp_peer_fin, "peer shut down its send side"),
    S(tcp_peer_fin_data, "data then FIN pending"),
    S(tcp_peer_fin_drained, "FIN consumed by a zero-byte receive"),
    S(tcp_peer_fin_data_drained, "FIN pending, data consumed"),
    S(tcp_peer_close, "peer closed gracefully"),
    S(tcp_peer_close_data, "peer sent data then closed"),
    S(tcp_peer_reset, "peer closed with zero linger (reset)"),
    S(tcp_peer_reset_data, "reset arrived while data was unread"),
    S(tcp_peer_reset_after_recv_err, "reset already reported by a receive"),
    S(tcp_peer_reset_after_soerr_read, "reset, SO_ERROR read"),
    S(tcp_local_shut_send, "local shutdown of the send side"),
    S(tcp_local_shut_recv, "local shutdown of the receive side"),
    S(tcp_local_shut_both, "local shutdown of both sides"),
    S(tcp_local_shut_send_peer_fin, "local send shutdown and peer FIN"),
    S(tcp_local_shut_recv_peer_sends, "receive side shut, peer sends data"),
    S(tcp_send_buffer_full, "nonblocking sender with a full send path"),
    S(tcp_closed, "closed handle value"),
    S(tcp_closed_connected, "connected socket just closed"),
    S(tcp_invalid_value, "value that is not a handle"),
    S(udp_fresh, "datagram socket, unbound"),
    S(udp_bound, "datagram socket, bound"),
    S(udp_connected, "datagram socket connected to a peer"),
    S(udp_data, "datagram queued"),
    S(udp_zero_len, "zero-length datagram queued"),
    S(udp_data_drained, "datagram read"),
    S(udp_icmp_error, "port unreachable reported on unconnected socket"),
    S(udp_icmp_error_consumed, "port unreachable consumed by a receive"),
    S(udp_connected_icmp_error, "port unreachable on a connected datagram socket"),
    S(tcp6_listen_pending, "IPv6 listener with a queued connection"),
    S(tcp6_conn_client, "IPv6 connected client, idle"),
    S(tcp6_data_client, "IPv6 client with unread data"),
    S(tcp6_peer_fin, "IPv6 peer FIN"),
    S(tcp6_peer_reset, "IPv6 peer reset"),
    S(udp6_data, "IPv6 datagram queued"),
};
const int xs_nstates = sizeof(xs_states) / sizeof(xs_states[0]);
