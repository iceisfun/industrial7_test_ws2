/* Output-size protocols for wait-for-listen and a few accept/name corner cases that need a second look.
 *
 * Wait-for-listen has three zones: below twelve bytes the request is malformed (parameter error), from
 * twelve up to one byte short of the full answer it is "buffer too small" without consuming the waiting
 * connection, and from the full answer on it succeeds. The full answer is four bytes of sequence number
 * plus the peer's socket address (20 bytes for IPv4, 32 for IPv6).
 */
#include "abl.h"

typedef struct { ULONG seq; struct sockaddr_in addr; } WFL4;

static void wfl_zone_table(int v6) {
    ULONG full = v6 ? 32 : 20;
    struct sockaddr_in a; struct sockaddr_in6 a6, n6; SOCKET l; IO_STATUS_BLOCK io; SOCKET c;
    if (v6) {
        l = abl_sock(AF_INET6, SOCK_STREAM); a6 = abl_lo6(0);
        CHECK_NS(abl_raw_bind(l, 0, &a6, sizeof a6, &n6, sizeof n6, &io), NS_SUCCESS);
        CHECK_NS(abl_raw_listen(l, 4, 0), NS_SUCCESS);
        CHECK_NS(abl_raw_name(l, &n6, sizeof n6, &io), NS_SUCCESS);
        c = abl_sock(AF_INET6, SOCK_STREAM); abl_nonblock(c, 1);
        W.connect(c, (struct sockaddr *)&n6, sizeof n6);
    } else {
        l = abl_listener(&a);
        c = abl_client_to(&a);
    }
    CHECK(abl_wait_readable(l, WAIT_MS));
    for (ULONG n = 0; n < full; n++) {
        BYTE out[64]; LONG first;
        memset(out, 0xcc, sizeof out);
        LONG st = abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, n, &io, &first);
        ULONG want = n < 12 ? NS_INVALID_PARAMETER : NS_BUFFER_TOO_SMALL;
        t_check((ULONG)st == want && (ULONG)first == want, __FILE__, __LINE__, "wait-for-listen zone", "%s out %lu: got 0x%08lx want 0x%08lx", v6 ? "v6" : "v4", (unsigned long)n, (unsigned long)st, (unsigned long)want);
        CHECKF(out[0] == 0xcc, "output touched at out %lu", (unsigned long)n);
    }
    {
        BYTE out[64]; memset(out, 0xcc, sizeof out);
        CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, full, &io, NULL), NS_SUCCESS);   /* nothing was consumed */
        CHECK_INFO(io, full);
        CHECK(out[full] == 0xcc);
    }
    abl_close(c); abl_close(l);
}
TEST(ablw_v4_output_zones) { ABL_BEGIN(); wfl_zone_table(0); }
TEST(ablw_v6_output_zones) { ABL_BEGIN(); if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; } wfl_zone_table(1); }
TEST(ablw_lifo_output_zones) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c = abl_client_to(&a); BYTE out[64]; IO_STATUS_BLOCK io;
    CHECK(abl_wait_readable(l, WAIT_MS));
    CHECK_NS(abl_ctl(l, IO_WAIT_LISTEN_LIFO, NULL, 0, out, 11, &io, NULL), NS_INVALID_PARAMETER);
    CHECK_NS(abl_ctl(l, IO_WAIT_LISTEN_LIFO, NULL, 0, out, 12, &io, NULL), NS_BUFFER_TOO_SMALL);
    CHECK_NS(abl_ctl(l, IO_WAIT_LISTEN_LIFO, NULL, 0, out, 19, &io, NULL), NS_BUFFER_TOO_SMALL);
    CHECK_NS(abl_ctl(l, IO_WAIT_LISTEN_LIFO, NULL, 0, out, 20, &io, NULL), NS_SUCCESS);
    abl_close(c); abl_close(l);
}
TEST(abln_accept_after_peer_reset_reports_reset_on_receive) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    CHECK(abl_wait_writable(c, WAIT_MS));
    struct linger lg = { 1, 0 };
    CHECK(W.setsockopt(c, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg) == 0);
    abl_close(c);
    Sleep(200);
    WFL4 r; IO_STATUS_BLOCK io; memset(&r, 0, sizeof r);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL), NS_SUCCESS);
    SOCKET t = abl_tcp(); ABL_ACCEPT aa; memset(&aa, 0, sizeof aa); aa.sequence = r.seq; aa.accept_handle = (HANDLE)t;
    CHECK_NS(abl_ctl(l, IO_ACCEPT, &aa, sizeof aa, NULL, 0, &io, NULL), NS_SUCCESS);
    char b;
    SET_ERR(0);
    CHECK(W.recv(t, &b, 1, 0) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAECONNRESET);
    abl_close(t); abl_close(l);
}
TEST(abln_accepted_socket_outlives_listener) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    WFL4 r; IO_STATUS_BLOCK io; memset(&r, 0, sizeof r);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL), NS_SUCCESS);
    SOCKET t = abl_tcp(); ABL_ACCEPT aa; memset(&aa, 0, sizeof aa); aa.sequence = r.seq; aa.accept_handle = (HANDLE)t;
    CHECK_NS(abl_ctl(l, IO_ACCEPT, &aa, sizeof aa, NULL, 0, &io, NULL), NS_SUCCESS);
    abl_close(l);
    CHECK(abl_wait_writable(c, WAIT_MS));
    abl_nonblock(c, 0);
    CHECK(W.send(c, "z", 1, 0) == 1);
    char b = 0;
    CHECK(abl_wait_readable(t, WAIT_MS));
    CHECK(W.recv(t, &b, 1, 0) == 1 && b == 'z');
    abl_close(t); abl_close(c);
}
TEST(abla_v6_wildcard_name) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET s = abl_sock(AF_INET6, SOCK_STREAM); struct sockaddr_in6 w, o; IO_STATUS_BLOCK io; BYTE out[64];
    memset(&w, 0, sizeof w); w.sin6_family = AF_INET6;
    CHECK_NS(abl_raw_bind(s, 0, &w, sizeof w, &o, sizeof o, &io), NS_SUCCESS);
    CHECK_NS(abl_raw_name(s, out, sizeof out, &io), NS_SUCCESS);
    CHECK_INFO(io, sizeof(struct sockaddr_in6));
    struct sockaddr_in6 *n = (struct sockaddr_in6 *)out;
    CHECK(n->sin6_family == AF_INET6 && n->sin6_port != 0);
    for (int i = 0; i < 16; i++) CHECK(n->sin6_addr.u.Byte[i] == 0);
    abl_close(s);
}
