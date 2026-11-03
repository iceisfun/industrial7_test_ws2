/* The start-listen request on an endpoint handle.
 *
 * The request block is twelve bytes: a SAN flag byte, a 32-bit backlog and a 32-bit delayed-acceptance
 * word. The driver only accepts it on a bound stream endpoint that is not yet listening, validates the
 * input length (at least twelve bytes) and clamps the backlog instead of rejecting odd values. A request
 * that passes validation is handed to the transport and completes later (the submit call answers
 * "pending"). After it, the endpoint accepts connections that the wait-for-listen request can see.
 */
#include "abl.h"

static LONG listen_req(SOCKET s, ULONG san, ULONG backlog, ULONG delayed, ULONG insz, LONG *first) {
    BYTE buf[32]; ABL_LISTEN *l = (ABL_LISTEN *)buf;
    memset(buf, 0, sizeof buf);
    l->use_san = (UCHAR)san; l->backlog = backlog; l->delayed = delayed;
    return abl_ctl(s, IO_START_LISTEN, buf, insz, NULL, 0, NULL, first);
}
#define LISTEN_OK(s, bl) listen_req((s), 0, (bl), 0, 12, NULL)

/* ---- state errors -------------------------------------------------------------------------------- */
TEST(abll_unbound_refused) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); LONG first;
    CHECK_NS(listen_req(s, 0, 5, 0, 12, &first), NS_INVALID_PARAMETER);
    CHECK_NS(first, NS_INVALID_PARAMETER);            /* refused on the spot, not pended */
    abl_close(s);
}
TEST(abll_unbound_refusal_leaves_socket_usable) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in a = abl_lo4(0);
    CHECK_NS(LISTEN_OK(s, 5), NS_INVALID_PARAMETER);
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK_NS(LISTEN_OK(s, 5), NS_SUCCESS);
    abl_close(s);
}
TEST(abll_bound_succeeds_by_pending) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL); LONG first; IO_STATUS_BLOCK io;
    BYTE buf[12] = {0}; ((ABL_LISTEN *)buf)->backlog = 5;
    LONG st = abl_ctl(s, IO_START_LISTEN, buf, 12, NULL, 0, &io, &first);
    CHECK_NS(st, NS_SUCCESS);
    CHECK_NS(first, NS_PENDING);
    CHECK_NS(io.Status, NS_SUCCESS);
    CHECK_INFO(io, 0);
    abl_close(s);
}
TEST(abll_second_request_refused) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    CHECK_NS(LISTEN_OK(s, 5), NS_SUCCESS);
    CHECK_NS(LISTEN_OK(s, 5), NS_INVALID_PARAMETER);
    CHECK_NS(LISTEN_OK(s, 1), NS_INVALID_PARAMETER);
    abl_close(s);
}
TEST(abll_after_winsock_listen_refused) {
    ABL_BEGIN();
    SOCKET s = abl_listener(NULL);
    CHECK_NS(LISTEN_OK(s, 5), NS_INVALID_PARAMETER);
    abl_close(s);
}
TEST(abll_connected_client_refused) {
    ABL_BEGIN();
    SOCKET c, s; abl_pair(&c, &s);
    CHECK_NS(LISTEN_OK(c, 5), NS_INVALID_PARAMETER);
    CHECK_NS(LISTEN_OK(s, 5), NS_INVALID_PARAMETER);       /* the accepted side as well */
    abl_close(c); abl_close(s);
}
TEST(abll_datagram_refused) {
    ABL_BEGIN();
    SOCKET u = abl_udp(), b = abl_bound(SOCK_DGRAM, NULL);
    CHECK_NS(LISTEN_OK(u, 5), NS_INVALID_PARAMETER);
    CHECK_NS(LISTEN_OK(b, 5), NS_INVALID_PARAMETER);
    abl_close(u); abl_close(b);
}
TEST(abll_datagram_refusal_matches_winsock) {
    ABL_BEGIN();
    SOCKET b = abl_bound(SOCK_DGRAM, NULL);
    SET_ERR(0);
    CHECK(W.listen(b, 5) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEOPNOTSUPP);
    abl_close(b);
}
TEST(abll_unbound_matches_winsock) {
    ABL_BEGIN();
    SOCKET s = abl_tcp();
    CHECK(W.listen(s, 5) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEINVAL);
    abl_close(s);
}
TEST(abll_refused_connect_leaves_endpoint_bound_and_listenable) {
    /* a connect that is refused still bound the endpoint implicitly; the endpoint can then listen */
    ABL_BEGIN();
    struct sockaddr_in a, o; SOCKET l = abl_bound(SOCK_STREAM, &a);     /* bound, never listening: connect is refused */
    SOCKET c = abl_tcp();
    SET_ERR(0);
    CHECK(abl_connect(c, &a) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAECONNREFUSED);
    CHECK_NS(abl_raw_bind4(c, 0, LO4, 0, &o), NS_ADDRESS_ALREADY_ASSOCIATED);
    CHECK_NS(LISTEN_OK(c, 5), NS_SUCCESS);
    abl_close(c); abl_close(l);
}

/* ---- input length -------------------------------------------------------------------------------- */
TEST(abll_input_length_table) {
    ABL_BEGIN();
    static const struct { ULONG len; ULONG want; } t[] = {
        { 0, NS_INVALID_PARAMETER }, { 1, NS_INVALID_PARAMETER }, { 4, NS_INVALID_PARAMETER }, { 8, NS_INVALID_PARAMETER },
        { 11, NS_INVALID_PARAMETER }, { 12, NS_SUCCESS }, { 13, NS_SUCCESS }, { 16, NS_SUCCESS }, { 32, NS_SUCCESS },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        SOCKET s = abl_bound(SOCK_STREAM, NULL);
        LONG st = listen_req(s, 0, 5, 0, t[i].len, NULL);
        t_check((ULONG)st == t[i].want, __FILE__, __LINE__, "listen input length", "len %lu: got 0x%08lx want 0x%08lx", (unsigned long)t[i].len, (unsigned long)st, (unsigned long)t[i].want);
        abl_close(s);
    }
}
TEST(abll_short_input_leaves_endpoint_bound) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    CHECK_NS(listen_req(s, 0, 5, 0, 11, NULL), NS_INVALID_PARAMETER);
    CHECK_NS(listen_req(s, 0, 5, 0, 12, NULL), NS_SUCCESS);          /* still able to listen afterwards */
    abl_close(s);
}
TEST(abll_output_buffer_is_ignored) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL); BYTE out[64]; BYTE buf[12] = {0}; IO_STATUS_BLOCK io;
    ((ABL_LISTEN *)buf)->backlog = 5;
    memset(out, 0x5a, sizeof out);
    CHECK_NS(abl_ctl(s, IO_START_LISTEN, buf, 12, out, sizeof out, &io, NULL), NS_SUCCESS);
    for (size_t i = 0; i < sizeof out; i++) if (out[i] != 0x5a) { CHECK(0); break; }
    abl_close(s);
}

/* ---- backlog and flag values --------------------------------------------------------------------- */
TEST(abll_backlog_values_accepted) {
    ABL_BEGIN();
    static const ULONG v[] = { 0, 1, 2, 5, 199, 200, 201, 1000, 65535, 65536, 0x7fffffff, 0x80000000u, 0xffffffffu, 0xfffffffeu };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        SOCKET s = abl_bound(SOCK_STREAM, NULL);
        LONG st = listen_req(s, 0, v[i], 0, 12, NULL);
        t_check((ULONG)st == NS_SUCCESS, __FILE__, __LINE__, "backlog accepted", "backlog 0x%lx: got 0x%08lx", (unsigned long)v[i], (unsigned long)st);
        abl_close(s);
    }
}
TEST(abll_delayed_acceptance_values_accepted) {
    ABL_BEGIN();
    static const ULONG v[] = { 0, 1, 2, 0xff, 0x100, 0xffffffffu };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        SOCKET s = abl_bound(SOCK_STREAM, NULL);
        LONG st = listen_req(s, 0, 5, v[i], 12, NULL);
        t_check((ULONG)st == NS_SUCCESS, __FILE__, __LINE__, "delayed value accepted", "delayed 0x%lx: got 0x%08lx", (unsigned long)v[i], (unsigned long)st);
        abl_close(s);
    }
}
TEST(abll_san_flag_without_helper_accepted) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    CHECK_NS(listen_req(s, 1, 5, 0, 12, NULL), NS_SUCCESS);
    abl_close(s);
}
TEST(abll_padding_bytes_ignored) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL); BYTE buf[12];
    memset(buf, 0xff, sizeof buf);
    buf[0] = 0;                       /* SAN flag clear, the three padding bytes after it left set */
    *(ULONG *)(buf + 4) = 5; *(ULONG *)(buf + 8) = 0;
    CHECK_NS(abl_ctl(s, IO_START_LISTEN, buf, 12, NULL, 0, NULL, NULL), NS_SUCCESS);
    abl_close(s);
}
/* ---- effect through the Winsock layer ------------------------------------------------------------- */
TEST(abll_raw_listener_accepts_connections) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_bound(SOCK_STREAM, &a);
    CHECK_NS(LISTEN_OK(l, 5), NS_SUCCESS);
    SOCKET c = abl_tcp();
    CHECK(abl_connect(c, &a) == 0);                       /* the connect is taken by the transport */
    abl_close(c); abl_close(l);
}
TEST(abll_no_listener_refuses_connection) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_bound(SOCK_STREAM, &a);
    SOCKET c = abl_tcp();
    SET_ERR(0);
    CHECK(abl_connect(c, &a) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAECONNREFUSED);
    abl_close(c); abl_close(l);
}
TEST(abll_connection_refused_before_listen_then_accepted) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_bound(SOCK_STREAM, &a);
    SOCKET c1 = abl_tcp(), c2 = abl_tcp();
    CHECK(abl_connect(c1, &a) == SOCKET_ERROR);
    CHECK_NS(LISTEN_OK(l, 5), NS_SUCCESS);
    CHECK(abl_connect(c2, &a) == 0);
    abl_close(c1); abl_close(c2); abl_close(l);
}
TEST(abll_listen_keeps_bound_name) {
    ABL_BEGIN();
    struct sockaddr_in a, b, c; int len = sizeof b;
    SOCKET l = abl_bound(SOCK_STREAM, &a); IO_STATUS_BLOCK io;
    CHECK_NS(LISTEN_OK(l, 5), NS_SUCCESS);
    CHECK(W.getsockname(l, (struct sockaddr *)&b, &len) == 0);
    CHECK(!memcmp(&a, &b, sizeof a));
    memset(&c, 0xcc, sizeof c);
    CHECK_NS(abl_raw_name(l, &c, sizeof c, &io), NS_SUCCESS);
    CHECK(!memcmp(&a, &c, sizeof a));
    abl_close(l);
}
TEST(abll_listening_socket_still_holds_its_port) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_bound(SOCK_STREAM, &a);
    CHECK_NS(LISTEN_OK(l, 5), NS_SUCCESS);
    SOCKET o = abl_tcp(); struct sockaddr_in again = abl_lo4(a.sin_port);
    SET_ERR(0);
    CHECK(W.bind(o, (struct sockaddr *)&again, sizeof again) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEADDRINUSE);
    abl_close(o); abl_close(l);
}
TEST(abll_port_free_after_listener_closed) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_bound(SOCK_STREAM, &a);
    CHECK_NS(LISTEN_OK(l, 5), NS_SUCCESS);
    abl_close(l);
    SOCKET o = abl_tcp(); struct sockaddr_in again = abl_lo4(a.sin_port);
    CHECK(W.bind(o, (struct sockaddr *)&again, sizeof again) == 0);
    abl_close(o);
}
TEST(abll_v6_listener) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET s = abl_sock(AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = abl_lo6(0), out; IO_STATUS_BLOCK io;
    CHECK_NS(abl_raw_listen(s, 5, 0), NS_INVALID_PARAMETER);         /* unbound */
    CHECK_NS(abl_raw_bind(s, 0, &a, sizeof a, &out, sizeof out, &io), NS_SUCCESS);
    CHECK_NS(abl_raw_listen(s, 5, 0), NS_SUCCESS);
    CHECK_NS(abl_raw_listen(s, 5, 0), NS_INVALID_PARAMETER);
    abl_close(s);
}
TEST(abll_v6_datagram_refused) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET s = abl_sock(AF_INET6, SOCK_DGRAM); struct sockaddr_in6 a = abl_lo6(0), out; IO_STATUS_BLOCK io;
    CHECK_NS(abl_raw_bind(s, 0, &a, sizeof a, &out, sizeof out, &io), NS_SUCCESS);
    CHECK_NS(abl_raw_listen(s, 5, 0), NS_INVALID_PARAMETER);
    abl_close(s);
}
