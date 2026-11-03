/* The local-address and remote-address requests.
 *
 * Get-address returns the endpoint's bound name as an ordinary socket address and needs a bound endpoint:
 * an unbound one is a parameter error whatever the output size is. The output must hold the whole socket
 * address of the family (16 bytes for IPv4, 28 for IPv6) except that anything shorter than a family field
 * (two bytes) is a parameter error and anything between that and the full size is "buffer too small".
 *
 * Get-remote-address returns the peer name that the Winsock layer stored in the endpoint context when it
 * connected the socket; an endpoint that Winsock did not connect has nothing to return and the request is
 * refused as an invalid connection. The byte count it reports is the size of the whole context block.
 */
#include "abl.h"

static LONG name_req(SOCKET s, void *out, ULONG n, IO_STATUS_BLOCK *io, LONG *first) {
    return abl_ctl(s, IO_GET_ADDRESS, NULL, 0, out, n, io, first);
}
static LONG remote_req(SOCKET s, void *out, ULONG n, IO_STATUS_BLOCK *io, LONG *first) {
    return abl_ctl(s, IO_GET_REMOTE, NULL, 0, out, n, io, first);
}

/* ---- local address, IPv4 -------------------------------------------------------------------------- */
typedef SOCKET (*mk_fn)(struct sockaddr_in *);
static SOCKET mk_tcp_bound(struct sockaddr_in *a) { return abl_bound(SOCK_STREAM, a); }
static SOCKET mk_udp_bound(struct sockaddr_in *a) { return abl_bound(SOCK_DGRAM, a); }
static SOCKET mk_listening(struct sockaddr_in *a) { return abl_listener(a); }

static void size_table(mk_fn mk, const char *what) {
    static const struct { ULONG n; ULONG st; } t[] = {
        { 0, NS_INVALID_PARAMETER }, { 1, NS_INVALID_PARAMETER },
        { 2, NS_BUFFER_TOO_SMALL }, { 3, NS_BUFFER_TOO_SMALL }, { 8, NS_BUFFER_TOO_SMALL }, { 12, NS_BUFFER_TOO_SMALL },
        { 15, NS_BUFFER_TOO_SMALL }, { 16, NS_SUCCESS }, { 17, NS_SUCCESS }, { 28, NS_SUCCESS }, { 64, NS_SUCCESS },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        struct sockaddr_in a; SOCKET s = mk(&a); BYTE out[64]; IO_STATUS_BLOCK io; LONG first;
        memset(out, 0xcc, sizeof out);
        LONG st = name_req(s, out, t[i].n, &io, &first);
        t_check((ULONG)st == t[i].st && (ULONG)first == t[i].st, __FILE__, __LINE__, "get-address size table", "%s out %lu: got 0x%08lx/0x%08lx want 0x%08lx",
                what, (unsigned long)t[i].n, (unsigned long)first, (unsigned long)st, (unsigned long)t[i].st);
        if (t[i].st == NS_SUCCESS) {
            CHECKF(io.Information == sizeof(struct sockaddr_in), "%s info %llu", what, (unsigned long long)io.Information);
            CHECKF(!memcmp(out, &a, sizeof a), "%s name", what);
            CHECKF(out[16] == 0xcc, "%s wrote past the address", what);
        } else {
            CHECKF(out[0] == 0xcc && out[1] == 0xcc, "%s output touched on failure", what);
        }
        abl_close(s);
    }
}
TEST(abla_tcp_bound_size_table) { ABL_BEGIN(); size_table(mk_tcp_bound, "tcp bound"); }
TEST(abla_udp_bound_size_table) { ABL_BEGIN(); size_table(mk_udp_bound, "udp bound"); }
TEST(abla_listening_size_table) { ABL_BEGIN(); size_table(mk_listening, "listener"); }

TEST(abla_unbound_always_parameter_error) {
    ABL_BEGIN();
    static const ULONG sizes[] = { 0, 1, 2, 15, 16, 28, 64 };
    for (int type = 0; type < 2; type++) {
        SOCKET s = abl_sock(AF_INET, type ? SOCK_DGRAM : SOCK_STREAM); BYTE out[64]; IO_STATUS_BLOCK io;
        for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
            LONG st = name_req(s, out, sizes[i], &io, NULL);
            t_check((ULONG)st == NS_INVALID_PARAMETER, __FILE__, __LINE__, "unbound get-address", "type %d out %lu: 0x%08lx", type, (unsigned long)sizes[i], (unsigned long)st);
        }
        abl_close(s);
    }
}
TEST(abla_connected_endpoints_report_local_name) {
    ABL_BEGIN();
    SOCKET c, s; abl_pair(&c, &s);
    SOCKET both[2] = { c, s };
    for (int i = 0; i < 2; i++) {
        struct sockaddr_in w, r; int len = sizeof w; IO_STATUS_BLOCK io;
        CHECK(W.getsockname(both[i], (struct sockaddr *)&w, &len) == 0);
        memset(&r, 0xcc, sizeof r);
        CHECK_NS(name_req(both[i], &r, sizeof r, &io, NULL), NS_SUCCESS);
        CHECK(!memcmp(&r, &w, sizeof r));
        CHECK_NS(name_req(both[i], &r, sizeof r - 1, &io, NULL), NS_BUFFER_TOO_SMALL);
    }
    abl_close(c); abl_close(s);
}
TEST(abla_connected_name_differs_between_ends) {
    ABL_BEGIN();
    SOCKET c, s; struct sockaddr_in rc, rs; IO_STATUS_BLOCK io;
    abl_pair(&c, &s);
    CHECK_NS(name_req(c, &rc, sizeof rc, &io, NULL), NS_SUCCESS);
    CHECK_NS(name_req(s, &rs, sizeof rs, &io, NULL), NS_SUCCESS);
    CHECK(rc.sin_port != rs.sin_port);
    CHECK(rc.sin_addr.s_addr == rs.sin_addr.s_addr);
    abl_close(c); abl_close(s);
}
TEST(abla_input_buffer_is_ignored) {
    ABL_BEGIN();
    struct sockaddr_in a, r; SOCKET s = abl_bound(SOCK_STREAM, &a); BYTE junk[32]; IO_STATUS_BLOCK io;
    memset(junk, 0x7e, sizeof junk);
    CHECK_NS(abl_ctl(s, IO_GET_ADDRESS, junk, sizeof junk, &r, sizeof r, &io, NULL), NS_SUCCESS);
    CHECK(!memcmp(&a, &r, sizeof a));
    abl_close(s);
}
TEST(abla_wildcard_bind_reports_zero_address_and_port) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in w = abl_lo4(0), r, q; int len = sizeof q; IO_STATUS_BLOCK io;
    w.sin_addr.s_addr = 0;
    CHECK(W.bind(s, (struct sockaddr *)&w, sizeof w) == 0);
    CHECK_NS(name_req(s, &r, sizeof r, &io, NULL), NS_SUCCESS);
    CHECK(r.sin_family == AF_INET);
    CHECK(r.sin_addr.s_addr == 0);
    CHECK(r.sin_port != 0);
    CHECK(W.getsockname(s, (struct sockaddr *)&q, &len) == 0);
    CHECK(!memcmp(&r, &q, sizeof r));
    abl_close(s);
}
TEST(abla_second_loopback_address_reported) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in w = abl_lo4(0), r; IO_STATUS_BLOCK io;
    w.sin_addr.s_addr = BE32(0x7f000002);
    CHECK(W.bind(s, (struct sockaddr *)&w, sizeof w) == 0);
    CHECK_NS(name_req(s, &r, sizeof r, &io, NULL), NS_SUCCESS);
    CHECK(r.sin_addr.s_addr == w.sin_addr.s_addr);
    abl_close(s);
}
TEST(abla_name_stable_across_listen) {
    ABL_BEGIN();
    struct sockaddr_in a, r1, r2; SOCKET s = abl_bound(SOCK_STREAM, &a); IO_STATUS_BLOCK io;
    CHECK_NS(name_req(s, &r1, sizeof r1, &io, NULL), NS_SUCCESS);
    CHECK(W.listen(s, 2) == 0);
    CHECK_NS(name_req(s, &r2, sizeof r2, &io, NULL), NS_SUCCESS);
    CHECK(!memcmp(&r1, &r2, sizeof r1));
    CHECK(!memcmp(&r1, &a, sizeof a));
    abl_close(s);
}
TEST(abla_name_survives_peer_close) {
    ABL_BEGIN();
    SOCKET c, s; struct sockaddr_in before, after; IO_STATUS_BLOCK io;
    abl_pair(&c, &s);
    CHECK_NS(name_req(c, &before, sizeof before, &io, NULL), NS_SUCCESS);
    W.shutdown(c, SD_BOTH);
    abl_close(s);
    Sleep(100);
    CHECK_NS(name_req(c, &after, sizeof after, &io, NULL), NS_SUCCESS);
    CHECK(!memcmp(&before, &after, sizeof before));
    abl_close(c);
}
TEST(abla_udp_connected_name) {
    ABL_BEGIN();
    struct sockaddr_in ua, n, q; int len = sizeof q; IO_STATUS_BLOCK io;
    SOCKET u1 = abl_bound(SOCK_DGRAM, &ua), u2 = abl_udp();
    CHECK(W.connect(u2, (struct sockaddr *)&ua, sizeof ua) == 0);
    CHECK_NS(name_req(u2, &n, sizeof n, &io, NULL), NS_SUCCESS);
    CHECK(W.getsockname(u2, (struct sockaddr *)&q, &len) == 0);
    CHECK(!memcmp(&n, &q, sizeof n));
    CHECK(n.sin_port != ua.sin_port);
    abl_close(u1); abl_close(u2);
}
TEST(abla_raw_bound_name_matches_request_output) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in o, r; IO_STATUS_BLOCK io;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_SUCCESS);
    CHECK_NS(name_req(s, &r, sizeof r, &io, NULL), NS_SUCCESS);
    CHECK(!memcmp(&o, &r, sizeof o));
    abl_close(s);
}

/* ---- local address, IPv6 -------------------------------------------------------------------------- */
TEST(abla_v6_size_table) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    static const struct { ULONG n; ULONG st; } t[] = {
        { 0, NS_INVALID_PARAMETER }, { 1, NS_INVALID_PARAMETER }, { 2, NS_BUFFER_TOO_SMALL }, { 16, NS_BUFFER_TOO_SMALL },
        { 24, NS_BUFFER_TOO_SMALL }, { 27, NS_BUFFER_TOO_SMALL }, { 28, NS_SUCCESS }, { 29, NS_SUCCESS }, { 64, NS_SUCCESS },
    };
    SOCKET s = abl_sock(AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = abl_lo6(0), b, q; int len = sizeof q; IO_STATUS_BLOCK io;
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(W.getsockname(s, (struct sockaddr *)&q, &len) == 0);
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        BYTE out[64]; memset(out, 0xcc, sizeof out);
        LONG st = name_req(s, out, t[i].n, &io, NULL);
        t_check((ULONG)st == t[i].st, __FILE__, __LINE__, "v6 get-address size table", "out %lu: got 0x%08lx want 0x%08lx", (unsigned long)t[i].n, (unsigned long)st, (unsigned long)t[i].st);
        if (t[i].st == NS_SUCCESS) {
            CHECK_INFO(io, sizeof(struct sockaddr_in6));
            memcpy(&b, out, sizeof b);
            CHECK(!memcmp(&b, &q, sizeof b));
        }
    }
    abl_close(s);
}
TEST(abla_v6_unbound_parameter_error) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET s = abl_sock(AF_INET6, SOCK_STREAM); BYTE out[64]; IO_STATUS_BLOCK io;
    CHECK_NS(name_req(s, out, sizeof out, &io, NULL), NS_INVALID_PARAMETER);
    abl_close(s);
}

/* ---- remote address ---------------------------------------------------------------------------------- */
TEST(ablr_not_connected_is_invalid_connection) {
    ABL_BEGIN();
    static const ULONG sizes[] = { 0, 1, 15, 16, 17, 64 };
    for (int kind = 0; kind < 5; kind++) {
        struct sockaddr_in a; SOCKET s;
        switch (kind) {
        case 0: s = abl_tcp(); break;
        case 1: s = abl_bound(SOCK_STREAM, &a); break;
        case 2: s = abl_listener(&a); break;
        case 3: s = abl_udp(); break;
        default: s = abl_bound(SOCK_DGRAM, &a); break;
        }
        for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
            BYTE out[64]; IO_STATUS_BLOCK io; LONG first;
            memset(out, 0xcc, sizeof out);
            LONG st = remote_req(s, out, sizes[i], &io, &first);
            t_check((ULONG)st == NS_INVALID_CONNECTION && (ULONG)first == NS_INVALID_CONNECTION, __FILE__, __LINE__, "unconnected get-remote",
                    "kind %d out %lu: 0x%08lx", kind, (unsigned long)sizes[i], (unsigned long)st);
            CHECKF(out[0] == 0xcc, "kind %d wrote output", kind);
        }
        abl_close(s);
    }
}
TEST(ablr_connected_client_returns_peer_name) {
    ABL_BEGIN();
    SOCKET c, s; struct sockaddr_in peer, r; int len = sizeof peer; IO_STATUS_BLOCK io;
    abl_pair(&c, &s);
    CHECK(W.getpeername(c, (struct sockaddr *)&peer, &len) == 0);
    memset(&r, 0xcc, sizeof r);
    CHECK_NS(remote_req(c, &r, sizeof r, &io, NULL), NS_SUCCESS);
    CHECK(!memcmp(&r, &peer, sizeof r));
    CHECK(io.Information >= sizeof r);
    t_note("remote-address byte count on a connected client: %llu", (unsigned long long)io.Information);
    abl_close(c); abl_close(s);
}
TEST(ablr_short_output_is_buffer_too_small) {
    ABL_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; BYTE out[64];
    abl_pair(&c, &s);
    for (ULONG n = 0; n < 16; n++) {
        memset(out, 0xcc, sizeof out);
        LONG st = remote_req(c, out, n, &io, NULL);
        t_check((ULONG)st == NS_BUFFER_TOO_SMALL, __FILE__, __LINE__, "short remote output", "out %lu: 0x%08lx", (unsigned long)n, (unsigned long)st);
        CHECKF(out[0] == 0xcc, "wrote output (out %lu)", (unsigned long)n);
    }
    abl_close(c); abl_close(s);
}
TEST(ablr_long_output_only_written_up_to_the_address) {
    ABL_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; BYTE out[64];
    abl_pair(&c, &s);
    memset(out, 0xcc, sizeof out);
    CHECK_NS(remote_req(c, out, sizeof out, &io, NULL), NS_SUCCESS);
    CHECK(out[16] == 0xcc);
    abl_close(c); abl_close(s);
}
TEST(ablr_accepted_endpoint_has_no_stored_peer) {
    /* the accepting side's context carries no peer name: the request succeeds and writes nothing */
    ABL_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; BYTE out[64];
    abl_pair(&c, &s);
    memset(out, 0xcc, sizeof out);
    CHECK_NS(remote_req(s, out, sizeof out, &io, NULL), NS_SUCCESS);
    for (size_t i = 0; i < sizeof out; i++) if (out[i] != 0xcc) { CHECKF(0, "byte %zu written", i); break; }
    CHECK_NS(remote_req(s, out, 0, &io, NULL), NS_SUCCESS);
    abl_close(c); abl_close(s);
}
TEST(ablr_udp_connected_has_no_stored_peer) {
    ABL_BEGIN();
    struct sockaddr_in ua; IO_STATUS_BLOCK io; BYTE out[64];
    SOCKET u1 = abl_bound(SOCK_DGRAM, &ua), u2 = abl_udp();
    CHECK(W.connect(u2, (struct sockaddr *)&ua, sizeof ua) == 0);
    CHECK_NS(remote_req(u2, out, sizeof out, &io, NULL), NS_INVALID_CONNECTION);
    abl_close(u1); abl_close(u2);
}
TEST(ablr_input_buffer_is_ignored) {
    ABL_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; struct sockaddr_in r, peer; int len = sizeof peer; BYTE junk[32];
    memset(junk, 0x7e, sizeof junk);
    abl_pair(&c, &s);
    CHECK_NS(abl_ctl(c, IO_GET_REMOTE, junk, sizeof junk, &r, sizeof r, &io, NULL), NS_SUCCESS);
    CHECK(W.getpeername(c, (struct sockaddr *)&peer, &len) == 0);
    CHECK(!memcmp(&r, &peer, sizeof r));
    abl_close(c); abl_close(s);
}
TEST(ablr_survives_shutdown_and_peer_close) {
    ABL_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; struct sockaddr_in r1, r2;
    abl_pair(&c, &s);
    CHECK_NS(remote_req(c, &r1, sizeof r1, &io, NULL), NS_SUCCESS);
    W.shutdown(c, SD_BOTH); abl_close(s); Sleep(100);
    CHECK_NS(remote_req(c, &r2, sizeof r2, &io, NULL), NS_SUCCESS);
    CHECK(!memcmp(&r1, &r2, sizeof r1));
    abl_close(c);
}
