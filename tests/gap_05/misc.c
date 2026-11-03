/* Remaining endpoint control codes with a request-validation contract of their own:
 *   0x120bb CONNECT_ALT (the second connect slot)   0x120c7 SUPER_CONNECT   0x12083 SUPER_ACCEPT
 *   0x120bf TLI_CONTROL                              0x120cf RECV_DATAGRAM_ALT   0x120d3 SEND_MESSAGE
 *   0x12113 UNBIND                                   0x1211b RIO
 *   0x1211f SOCKET_TRANSFER_BEGIN                    0x12123 SOCKET_TRANSFER_END
 * Each test states the request shape it sends. Valid use is exercised where it can be reproduced on
 * loopback; the rest is the exact refusal for undersized records, wrong endpoint kind and wrong state. */
#include "g5.h"
#pragma GCC diagnostic ignored "-Wmisleading-indentation"

/* connect request: 0x18-byte header followed by the raw socket address */
static ULONG conn_rec(unsigned char *r, const struct sockaddr_in *to)
{
    memset(r, 0, 0x18);
    memcpy(r + 0x18, to, sizeof *to);
    return 0x18 + sizeof *to;
}
static SOCKET dead_port(struct sockaddr_in *a)    /* a loopback address nothing listens on */
{
    SOCKET s = g5_bound(SOCK_STREAM, a);
    g5_close(s);
    return s;
}

/* ---- CONNECT 0x12007 shape, ALT slot 0x120bb ---------------------------------------------------------- */
#define CONNECT_TESTS(code, nm) \
TEST(gap5_connect_##nm##_request_shorter_than_0x18_refused) { G5_BEGIN(); \
    SOCKET s = g5_bound(SOCK_STREAM, NULL); unsigned char r[0x40]; static const ULONG lens[] = { 0, 1, 0x10, 0x17 }; \
    memset(r, 0, sizeof r); \
    for (int i = 0; i < 4; i++) EXPECT_NTS(g5_ctl(S(s), code, lens[i] ? r : NULL, lens[i], NULL, 0, NULL, NULL), ST_INVALID_PARAMETER); \
    g5_close(s); } \
TEST(gap5_connect_##nm##_output_of_1_to_15_bytes_refused) { G5_BEGIN(); \
    SOCKET s = g5_bound(SOCK_STREAM, NULL); unsigned char r[0x40], o[16]; struct sockaddr_in to = g5_lo4(BE16(9)); \
    ULONG n = conn_rec(r, &to); \
    for (ULONG k = 1; k < 16; k += 7) EXPECT_NTS(g5_ctl(S(s), code, r, n, o, k, NULL, NULL), ST_INVALID_PARAMETER); \
    EXPECT_NTS(g5_ctl(S(s), code, r, n, o, 15, NULL, NULL), ST_INVALID_PARAMETER); \
    g5_close(s); } \
TEST(gap5_connect_##nm##_reaches_loopback_listener) { G5_BEGIN(); \
    struct sockaddr_in a, mine, peer; int pn = sizeof peer; SOCKET l = g5_listener(&a), c = g5_bound(SOCK_STREAM, NULL), s; unsigned char r[0x40]; \
    ULONG n = conn_rec(r, &a); IO_STATUS_BLOCK io; \
    EXPECT_NTS(g5_ctl(S(c), code, r, n, NULL, 0, &io, NULL), ST_SUCCESS); \
    EXPECT_EQ(io.Information, 0); \
    CHECK(g5_readable(l, WAIT_MS)); \
    s = g5_readable(l, 1) ? W.accept(l, NULL, NULL) : INVALID_SOCKET; CHECK(s != INVALID_SOCKET); \
    memset(&mine, 0, sizeof mine); \
    EXPECT_NTS(g5_ctl(S(c), 0x1202f, NULL, 0, &mine, sizeof mine, NULL, NULL), ST_SUCCESS); \
    CHECK(W.getpeername(s, (struct sockaddr *)&peer, &pn) == 0); \
    EXPECT_EQ(peer.sin_port, mine.sin_port);               /* the listener's accepted side sees the raw-connected client */ \
    g5_close(s); g5_close(c); g5_close(l); } \
TEST(gap5_connect_##nm##_refused_when_nothing_listens) { G5_BEGIN(); \
    struct sockaddr_in a; SOCKET c, d = dead_port(&a); unsigned char r[0x40]; ULONG n; (void)d; \
    c = g5_bound(SOCK_STREAM, NULL); n = conn_rec(r, &a); \
    EXPECT_NTS(g5_ctl(S(c), code, r, n, NULL, 0, NULL, NULL), (LONG)0xC0000236); /* connection refused */ \
    g5_close(c); } \
TEST(gap5_connect_##nm##_twice_on_a_connected_endpoint_refused) { G5_BEGIN(); \
    struct sockaddr_in a; SOCKET l = g5_listener(&a), c = g5_bound(SOCK_STREAM, NULL); unsigned char r[0x40]; ULONG n = conn_rec(r, &a); \
    EXPECT_NTS(g5_ctl(S(c), code, r, n, NULL, 0, NULL, NULL), ST_SUCCESS); \
    LONG st = g5_ctl(S(c), code, r, n, NULL, 0, NULL, NULL); \
    EXPECT_NTS(st, ST_INVALID_PARAMETER); \
    g5_close(c); g5_close(l); } \
TEST(gap5_connect_##nm##_on_listening_endpoint_refused) { G5_BEGIN(); \
    struct sockaddr_in a; SOCKET l = g5_listener(&a); unsigned char r[0x40]; ULONG n = conn_rec(r, &a); \
    LONG st = g5_ctl(S(l), code, r, n, NULL, 0, NULL, NULL); \
    EXPECT_NTS(st, ST_INVALID_PARAMETER); \
    g5_close(l); }
CONNECT_TESTS(0x12007, c12007)
CONNECT_TESTS(0x120bb, c120bb)

/* ---- SUPER_CONNECT 0x120c7 --------------------------------------------------------------------------- */
TEST(gap5_superconnect_record_shorter_than_12_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 1, 4, 11 };
    SOCKET s = g5_bound(SOCK_STREAM, NULL); unsigned char r[0x40]; memset(r, 0, sizeof r);
    for (int i = 0; i < 4; i++) {
        EXPECT_NTS(g5_ctl(S(s), 0x120c7, lens[i] ? r : NULL, lens[i], NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    }
    g5_close(s);
}

/* ---- SUPER_ACCEPT 0x12083 ---------------------------------------------------------------------------- */
TEST(gap5_superaccept_requires_listening_endpoint)
{
    G5_BEGIN();
    SOCKET open = g5_tcp(), bound = g5_bound(SOCK_STREAM, NULL), t = g5_tcp(); unsigned char r[0x40], o[0x100];
    memset(r, 0, sizeof r); memcpy(r + 8, &t, 8);
    *(ULONG *)(r + 0x10) = 0x20; *(ULONG *)(r + 0x14) = 0x20;
    EXPECT_NTS(g5_ctl(S(open), 0x12083, r, sizeof r, o, sizeof o, NULL, NULL), ST_INVALID_PARAMETER);
    EXPECT_NTS(g5_ctl(S(bound), 0x12083, r, sizeof r, o, sizeof o, NULL, NULL), ST_INVALID_PARAMETER);
    g5_close(open); g5_close(bound); g5_close(t);
}
TEST(gap5_superaccept_output_smaller_than_address_space_refused)
{
    G5_BEGIN();
    /* the output must hold the local and the remote address blocks named in the record */
    SOCKET l = g5_listener(NULL), t = g5_tcp(); unsigned char r[0x40], o[0x100];
    memset(r, 0, sizeof r); memcpy(r + 8, &t, 8);
    *(ULONG *)(r + 0x10) = 0x20; *(ULONG *)(r + 0x14) = 0x20;
    LONG st = g5_ctl(S(l), 0x12083, r, sizeof r, o, 0x20, NULL, NULL);
    EXPECT_NTS(st, ST_BUFFER_TOO_SMALL);
    g5_close(l); g5_close(t);
}

/* record: use-san byte @0, accept endpoint @8, receive-data length @0x10, local-address length @0x14,
 * remote-address length @0x18; the output holds the three parts back to back */
static void sa_rec(unsigned char *r, SOCKET target, ULONG recv, ULONG loc, ULONG rem)
{
    memset(r, 0, 0x20);
    memcpy(r + 8, &target, 8);
    *(ULONG *)(r + 0x10) = recv; *(ULONG *)(r + 0x14) = loc; *(ULONG *)(r + 0x18) = rem;
}
TEST(gap5_superaccept_output_must_cover_all_three_parts)
{
    G5_BEGIN();
    SOCKET l = g5_listener(NULL), t = g5_tcp(); unsigned char r[0x20], o[0x100];
    sa_rec(r, t, 0, 32, 32);
    EXPECT_NTS(g5_ctl(S(l), 0x12083, r, sizeof r, o, 63, NULL, NULL), ST_BUFFER_TOO_SMALL);
    sa_rec(r, t, 16, 32, 32);
    EXPECT_NTS(g5_ctl(S(l), 0x12083, r, sizeof r, o, 79, NULL, NULL), ST_BUFFER_TOO_SMALL);
    g5_close(l); g5_close(t);
}
TEST(gap5_superaccept_remote_length_below_8_refused)
{
    G5_BEGIN();
    SOCKET l = g5_listener(NULL), t = g5_tcp(); unsigned char r[0x20], o[0x100];
    for (ULONG rem = 0; rem < 8; rem += 7) {
        sa_rec(r, t, 0, 32, rem);
        EXPECT_NTS(g5_ctl(S(l), 0x12083, r, sizeof r, o, sizeof o, NULL, NULL), ST_BUFFER_TOO_SMALL);
    }
    g5_close(l); g5_close(t);
}
TEST(gap5_superaccept_completes_when_a_client_connects)
{
    G5_BEGIN();
    struct sockaddr_in a; SOCKET l = g5_listener(&a), t = g5_tcp(), c; unsigned char r[0x20], o[0x100];
    IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    sa_rec(r, t, 0, 32, 32);
    memset(o, 0, sizeof o);
    EXPECT_NTS(g5_submit(S(l), ev, 0x12083, r, sizeof r, o, 64, &io), ST_PENDING);
    CHECK(WaitForSingleObject(ev, 300) == WAIT_TIMEOUT);          /* nothing connected yet */
    c = g5_connect_nb(&a);
    EXPECT_NTS(g5_finish(S(l), ev, &io, WAIT_MS), ST_SUCCESS);
    t_note("super accept information for 64 bytes of output and no receive data: %llu", (unsigned long long)io.Information);
    CloseHandle(ev); g5_close(t); g5_close(c); g5_close(l);
}
TEST(gap5_superaccept_pended_request_cancels)
{
    G5_BEGIN();
    SOCKET l = g5_listener(NULL), t = g5_tcp(); unsigned char r[0x20], o[0x100];
    IO_STATUS_BLOCK io, cio; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    sa_rec(r, t, 0, 32, 32);
    EXPECT_NTS(g5_submit(S(l), ev, 0x12083, r, sizeof r, o, 64, &io), ST_PENDING);
    W.cancel(S(l), &cio);
    CHECK(WaitForSingleObject(ev, WAIT_MS) == WAIT_OBJECT_0);
    EXPECT_NTS(io.Status, ST_CANCELLED);
    CloseHandle(ev); g5_close(t); g5_close(l);
}

/* ---- TLI_CONTROL 0x120bf ----------------------------------------------------------------------------- */
TEST(gap5_tli_record_shorter_than_0x20_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 4, 0x10, 0x18, 0x1f };
    SOCKET s = g5_tcp(), u = g5_udp(); unsigned char r[0x40]; memset(r, 0, sizeof r);
    for (int i = 0; i < 5; i++) {
        EXPECT_NTS(g5_ctl(S(s), 0x120bf, lens[i] ? r : NULL, lens[i], NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
        EXPECT_NTS(g5_ctl(S(u), 0x120bf, lens[i] ? r : NULL, lens[i], NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    }
    g5_close(s); g5_close(u);
}
TEST(gap5_tli_user_level_option_restricted_forms_refused)
{
    G5_BEGIN();
    /* record: level, option, kind, flag byte at +12. A request with the flag byte set at level 1, 2 or 3 is
     * only let through for level 3 with option 0; the others are refused before the transport sees them. */
    SOCKET s = g5_tcp(); unsigned char r[0x40];
    static const struct { ULONG level, opt; } k[] = { { 1, 0xfffc }, { 1, 0xfffd }, { 2, 0xfffc }, { 2, 0xfffd }, { 3, 5 } };
    for (int i = 0; i < 5; i++) {
        memset(r, 0, sizeof r);
        *(ULONG *)r = k[i].level; *(ULONG *)(r + 4) = k[i].opt; r[12] = 1;
        EXPECT_NTSV(g5_ctl(S(s), 0x120bf, r, sizeof r, NULL, 0, NULL, NULL), ST_INVALID_PARAMETER, "restricted form");
    }
    g5_close(s);
}

/* ---- RECV_DATAGRAM_ALT 0x120cf and SEND_MESSAGE 0x120d3 ---------------------------------------------- */
TEST(gap5_recvdg_alt_record_shorter_than_0x40_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 8, 0x28, 0x3f };
    SOCKET u = g5_bound(SOCK_DGRAM, NULL); unsigned char r[0x80]; memset(r, 0, sizeof r);
    for (int i = 0; i < 4; i++) {
        EXPECT_NTS(g5_ctl(S(u), 0x120cf, lens[i] ? r : NULL, lens[i], NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    }
    g5_close(u);
}
TEST(gap5_recvdg_standard_record_shorter_than_0x28_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 8, 0x20, 0x27 };
    SOCKET u = g5_bound(SOCK_DGRAM, NULL); unsigned char r[0x80]; memset(r, 0, sizeof r);
    for (int i = 0; i < 4; i++) EXPECT_NTS(g5_ctl(S(u), 0x1201b, lens[i] ? r : NULL, lens[i], NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    g5_close(u);
}
TEST(gap5_recvdg_alt_wrong_endpoint_kind_refused)
{
    G5_BEGIN();
    SOCKET t = g5_tcp(), b = g5_bound(SOCK_STREAM, NULL), un = g5_udp(); unsigned char r[0x80]; memset(r, 0, sizeof r);
    LONG a = g5_ctl(S(t), 0x120cf, r, sizeof r, NULL, 0, NULL, NULL);
    LONG c = g5_ctl(S(b), 0x120cf, r, sizeof r, NULL, 0, NULL, NULL);
    LONG d = g5_ctl(S(un), 0x120cf, r, sizeof r, NULL, 0, NULL, NULL);
    EXPECT_NTS(a, ST_INVALID_PARAMETER);
    EXPECT_NTS(c, ST_INVALID_PARAMETER);
    EXPECT_NTS(d, ST_INVALID_PARAMETER);       /* a datagram endpoint that was never bound */
    g5_close(t); g5_close(b); g5_close(un);
}
TEST(gap5_sendmsg_wrong_endpoint_kind_refused)
{
    G5_BEGIN();
    SOCKET t = g5_tcp(), b = g5_bound(SOCK_STREAM, NULL), un = g5_udp(); unsigned char r[0x80]; memset(r, 0, sizeof r);
    EXPECT_NTS(g5_ctl(S(t), 0x120d3, r, sizeof r, NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    EXPECT_NTS(g5_ctl(S(b), 0x120d3, r, sizeof r, NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    EXPECT_NTS(g5_ctl(S(un), 0x120d3, r, sizeof r, NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);   /* datagram, but not bound yet */
    g5_close(t); g5_close(b); g5_close(un);
}
TEST(gap5_sendmsg_empty_request_on_bound_datagram_refused)
{
    G5_BEGIN();
    SOCKET u = g5_bound(SOCK_DGRAM, NULL); unsigned char r[0x80]; memset(r, 0, sizeof r);
    LONG a = g5_ctl(S(u), 0x120d3, NULL, 0, NULL, 0, NULL, NULL);
    LONG b = g5_ctl(S(u), 0x120d3, r, 8, NULL, 0, NULL, NULL);
    EXPECT_NTS(a, ST_INVALID_PARAMETER);
    EXPECT_NTS(b, ST_INVALID_PARAMETER);
    g5_close(u);
}

/* ---- UNBIND 0x12113 ---------------------------------------------------------------------------------- */
static LONG unbind(HANDLE h, ULONG fam, ULONG len)
{
    unsigned char r[16]; memset(r, 0, sizeof r);
    *(ULONG *)r = fam;
    return g5_ctl(h, 0x12113, len ? r : NULL, len, NULL, 0, NULL, NULL);
}
TEST(gap5_unbind_record_shorter_than_8_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 1, 4, 7 };
    SOCKET s = g5_bound(SOCK_STREAM, NULL);
    for (int i = 0; i < 4; i++) EXPECT_NTS(unbind(S(s), AF_INET, lens[i]), ST_INVALID_PARAMETER);
    g5_close(s);
}
TEST(gap5_unbind_datagram_endpoint_not_supported)
{
    G5_BEGIN();
    SOCKET u = g5_bound(SOCK_DGRAM, NULL), un = g5_udp();
    EXPECT_NTS(unbind(S(u), AF_INET, 8), ST_NOT_SUPPORTED);
    EXPECT_NTS(unbind(S(un), AF_INET, 8), ST_NOT_SUPPORTED);
    g5_close(u); g5_close(un);
}
TEST(gap5_unbind_requires_bound_stream_not_listening)
{
    G5_BEGIN();
    SOCKET open = g5_tcp(), l = g5_listener(NULL), c, p;
    EXPECT_NTS(unbind(S(open), AF_INET, 8), ST_INVALID_PARAMETER);
    EXPECT_NTS(unbind(S(l), AF_INET, 8), ST_INVALID_PARAMETER);
    g5_pair(&c, &p);
    EXPECT_NTS(unbind(S(c), AF_INET, 8), ST_INVALID_PARAMETER);
    g5_close(open); g5_close(l); g5_close(c); g5_close(p);
}
TEST(gap5_unbind_bound_stream_returns_to_unbound)
{
    G5_BEGIN();
    SOCKET s = g5_bound(SOCK_STREAM, NULL);
    EXPECT_NTS(unbind(S(s), AF_INET, 8), ST_SUCCESS);
    EXPECT_NTS(unbind(S(s), AF_INET, 8), ST_INVALID_PARAMETER);       /* no longer bound */
    EXPECT_NTS(g5_raw_bind4(S(s), 0), ST_SUCCESS);                     /* free to bind again */
    EXPECT_NTS(unbind(S(s), AF_INET, 8), ST_SUCCESS);
    g5_close(s);
}
TEST(gap5_unbind_releases_the_port)
{
    G5_BEGIN();
    struct sockaddr_in a; SOCKET s = g5_bound(SOCK_STREAM, &a), t = g5_tcp();
    EXPECT_NTS(unbind(S(s), AF_INET, 8), ST_SUCCESS);
    EXPECT_NTS(g5_raw_bind4(S(t), a.sin_port), ST_SUCCESS);            /* the same port is bindable by another endpoint */
    g5_close(s); g5_close(t);
}
TEST(gap5_unbind_with_v6_family_accepted_for_v4_stream)
{
    G5_BEGIN();
    SOCKET s = g5_bound(SOCK_STREAM, NULL);
    EXPECT_NTS(unbind(S(s), AF_INET6, 8), ST_SUCCESS);
    g5_close(s);
}
/* ---- RIO 0x1211b ------------------------------------------------------------------------------------- */
/* Registered I/O requests are served on the driver's fast path. The first dword of the record selects the
 * operation. An endpoint that is neither a registered-I/O domain endpoint nor created for registered I/O
 * answers every operation as an invalid device request; a missing or short record is a parameter error
 * raised before that. */
TEST(gap5_rio_missing_or_short_record_is_parameter_error)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 1, 2, 3 };
    SOCKET s = g5_tcp(), u = g5_bound(SOCK_DGRAM, NULL); unsigned char r[8]; memset(r, 0, sizeof r);
    for (int i = 0; i < 4; i++) {
        EXPECT_NTS(g5_ctl(S(s), 0x1211b, lens[i] ? r : NULL, lens[i], NULL, 0, NULL, NULL), (LONG)0xC00000F0);
        EXPECT_NTS(g5_ctl(S(u), 0x1211b, lens[i] ? r : NULL, lens[i], NULL, 0, NULL, NULL), (LONG)0xC00000F0);
    }
    EXPECT_NTS(g5_ctl(S(s), 0x1211b, NULL, 16, NULL, 0, NULL, NULL), (LONG)0xC00000F0);   /* a length without a record */
    g5_close(s); g5_close(u);
}
TEST(gap5_rio_every_operation_invalid_device_request_on_ordinary_endpoint)
{
    G5_BEGIN();
    static const ULONG ops[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x100, 0xffffffff };
    SOCKET s = g5_tcp(), u = g5_bound(SOCK_DGRAM, NULL), l = g5_listener(NULL); unsigned char r[0x40];
    SOCKET all[] = { s, u, l };
    for (int k = 0; k < 3; k++) for (int i = 0; i < 15; i++) {
        memset(r, 0, sizeof r); *(ULONG *)r = ops[i];
        LONG st = g5_ctl(S(all[k]), 0x1211b, r, sizeof r, NULL, 0, NULL, NULL);
        t_check(st == ST_INVALID_DEVICE_REQ, __FILE__, __LINE__, "rio op", "endpoint %d op %lu: 0x%08lx", k, (unsigned long)ops[i], (unsigned long)st);
    }
    g5_close(s); g5_close(u); g5_close(l);
}
TEST(gap5_rio_request_answers_same_with_four_byte_record)
{
    G5_BEGIN();
    SOCKET c, p; unsigned char r[4] = { 3, 0, 0, 0 };
    g5_pair(&c, &p);
    EXPECT_NTS(g5_ctl(S(c), 0x1211b, r, 4, NULL, 0, NULL, NULL), ST_INVALID_DEVICE_REQ);
    EXPECT_NTS(g5_ctl(S(p), 0x1211b, r, 4, NULL, 0, NULL, NULL), ST_INVALID_DEVICE_REQ);
    g5_close(c); g5_close(p);
}
TEST(gap5_rio_enabled_endpoint_gets_past_the_kind_check)
{
    G5_BEGIN();
    /* an endpoint created with the registered-I/O flag is accepted for the per-socket operations
     * (3, 6, 7 and 9); the domain operations still need a domain endpoint */
    SOCKET s = W.WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED | 0x100);
    if (s == INVALID_SOCKET) { t_skip("registered I/O sockets not available"); return; }
    unsigned char r[0x40];
    static const struct { ULONG op; LONG want; } per_socket[] = { { 3, ST_INVALID_PARAMETER }, { 6, ST_INVALID_HANDLE }, { 7, ST_INVALID_HANDLE }, { 9, ST_INVALID_PARAMETER } };
    static const ULONG domain[] = { 0, 1, 2, 4, 5, 8 };
    for (int i = 0; i < 6; i++) {
        memset(r, 0, sizeof r); *(ULONG *)r = domain[i];
        EXPECT_NTSV(g5_ctl(S(s), 0x1211b, r, sizeof r, NULL, 0, NULL, NULL), ST_INVALID_DEVICE_REQ, "domain operation");
    }
    for (int i = 0; i < 4; i++) {
        memset(r, 0, sizeof r); *(ULONG *)r = per_socket[i].op;      /* an all-zero body: no queue, no buffers */
        EXPECT_NTSV(g5_ctl(S(s), 0x1211b, r, sizeof r, NULL, 0, NULL, NULL), per_socket[i].want, "per-socket operation");
    }
    g5_close(s);
}

/* ---- SOCKET_TRANSFER_BEGIN 0x1211f / END 0x12123 ----------------------------------------------------- */
#define XFER(code, nm) \
TEST(gap5_xfer_##nm##_succeeds_on_ordinary_endpoints_for_any_record) { G5_BEGIN(); \
    SOCKET t = g5_tcp(), b = g5_bound(SOCK_STREAM, NULL), l = g5_listener(NULL), u = g5_udp(), c, p; unsigned char r[0x40]; IO_STATUS_BLOCK io; \
    memset(r, 0xa5, sizeof r); g5_pair(&c, &p); \
    SOCKET all[] = { t, b, l, u, c, p }; \
    for (int i = 0; i < 6; i++) { \
        EXPECT_NTS(g5_ctl(S(all[i]), code, NULL, 0, NULL, 0, &io, NULL), ST_SUCCESS); \
        EXPECT_EQ(io.Information, 0); \
        EXPECT_NTS(g5_ctl(S(all[i]), code, r, sizeof r, r, sizeof r, &io, NULL), ST_SUCCESS); \
    } \
    g5_close(t); g5_close(b); g5_close(l); g5_close(u); g5_close(c); g5_close(p); } \
TEST(gap5_xfer_##nm##_directly_opened_endpoint_succeeds) { G5_BEGIN(); \
    LONG st; HANDLE h = g5_open_ep(EK_TCP4, 1, &st); \
    if (!h) { t_skip("endpoint cannot be opened directly (0x%08lx)", (unsigned long)st); return; } \
    EXPECT_NTS(g5_ctl(h, code, NULL, 0, NULL, 0, NULL, NULL), ST_SUCCESS); \
    g5_close_h(h); } \
TEST(gap5_xfer_##nm##_does_not_disturb_the_connection) { G5_BEGIN(); \
    SOCKET c, p; char b[16]; int n, sent; g5_pair(&c, &p); \
    EXPECT_NTS(g5_ctl(S(c), code, NULL, 0, NULL, 0, NULL, NULL), ST_SUCCESS); \
    sent = W.send(c, "abc", 3, 0); \
    EXPECT_EQ(sent, 3); \
    memset(b, 0, sizeof b); \
    n = W.recv(p, b, sizeof b, 0); \
    EXPECT_EQ(n, 3); \
    CHECK(!memcmp(b, "abc", 3)); \
    g5_close(c); g5_close(p); }
XFER(0x1211f, begin)
XFER(0x12123, end)
