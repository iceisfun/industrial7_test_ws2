/* Defer-accept, delayed acceptance, unbind and super-accept requests, plus bind address-form errors.
 *
 * Defer-accept takes the sequence number of a connection that wait-for-listen returned and a flag word.
 * With the flag clear the connection is handed back to the listener's waiting list; with it set the
 * connection is refused. Either way the sequence number stops being valid for accept. A listener started
 * with the delayed-acceptance word set holds the peer's handshake until the connection is accepted or
 * refused. Unbind needs an eight-byte request block and only exists for stream endpoints that bound by
 * themselves. Super-accept (the AcceptEx building block) judges the listener state first and the buffer
 * lengths second.
 */
#include "abl.h"

typedef struct { ULONG seq; struct sockaddr_in addr; } WFL4;

static ULONG wait_seq(SOCKET l) {
    WFL4 r; IO_STATUS_BLOCK io; memset(&r, 0, sizeof r);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL), NS_SUCCESS);
    return r.seq;
}
static LONG defer_req(SOCKET l, ULONG seq, ULONG flag, ULONG insz, LONG *first) {
    ABL_DEFER d; d.sequence = seq; d.defer = flag;
    return abl_ctl(l, IO_DEFER_ACCEPT, &d, insz, NULL, 0, NULL, first);
}
static LONG accept_req(SOCKET l, ULONG seq, SOCKET t) {
    ABL_ACCEPT aa; memset(&aa, 0, sizeof aa); aa.sequence = seq; aa.accept_handle = (HANDLE)t;
    return abl_ctl(l, IO_ACCEPT, &aa, sizeof aa, NULL, 0, NULL, NULL);
}

/* ---- defer-accept ---------------------------------------------------------------------------------- */
TEST(abld_not_listening_refused) {
    ABL_BEGIN();
    SOCKET b = abl_bound(SOCK_STREAM, NULL), u = abl_tcp(), d = abl_bound(SOCK_DGRAM, NULL);
    SOCKET all[3] = { b, u, d };
    for (int i = 0; i < 3; i++) {
        LONG first, st = defer_req(all[i], 1, 0, 8, &first);
        t_check((ULONG)st == NS_INVALID_PARAMETER && (ULONG)first == NS_INVALID_PARAMETER, __FILE__, __LINE__, "defer on non-listener", "kind %d: 0x%08lx", i, (unsigned long)st);
        abl_close(all[i]);
    }
}
TEST(abld_short_input_refused) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    ULONG seq = wait_seq(l);
    for (ULONG n = 0; n < 8; n++) {
        LONG st = defer_req(l, seq, 0, n, NULL);
        t_check((ULONG)st == NS_INVALID_PARAMETER, __FILE__, __LINE__, "short defer input", "len %lu: 0x%08lx", (unsigned long)n, (unsigned long)st);
    }
    SOCKET t = abl_tcp();
    CHECK_NS(accept_req(l, seq, t), NS_SUCCESS);               /* the connection is still returned, not consumed */
    abl_close(t); abl_close(c); abl_close(l);
}
TEST(abld_unknown_sequence_refused) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a);
    CHECK_NS(defer_req(l, 1, 0, 8, NULL), NS_INVALID_PARAMETER);             /* nothing has been returned yet */
    SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    CHECK_NS(defer_req(l, 1, 0, 8, NULL), NS_INVALID_PARAMETER);             /* queued, but not returned */
    ULONG seq = wait_seq(l);
    CHECK_NS(defer_req(l, seq + 100, 0, 8, NULL), NS_INVALID_PARAMETER);
    abl_close(c); abl_close(l);
}
TEST(abld_reject_resets_the_peer) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    ULONG seq = wait_seq(l);
    CHECK_NS(defer_req(l, seq, 1, 8, NULL), NS_SUCCESS);
    CHECK(abl_wait_readable(c, WAIT_MS));
    char b;
    SET_ERR(0);
    CHECK(W.recv(c, &b, 1, 0) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAECONNRESET);
    SOCKET t = abl_tcp();
    CHECK_NS(accept_req(l, seq, t), NS_INVALID_PARAMETER);                   /* the connection is gone */
    abl_close(t); abl_close(c); abl_close(l);
}
TEST(abld_sequence_is_spent_by_defer) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    ULONG seq = wait_seq(l);
    CHECK_NS(defer_req(l, seq, 0, 8, NULL), NS_SUCCESS);
    CHECK_NS(defer_req(l, seq, 0, 8, NULL), NS_INVALID_PARAMETER);
    SOCKET t = abl_tcp();
    CHECK_NS(accept_req(l, seq, t), NS_INVALID_PARAMETER);
    abl_close(t); abl_close(c); abl_close(l);
}
TEST(abld_deferred_connection_is_reported_again) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    ULONG seq = wait_seq(l);
    CHECK_NS(defer_req(l, seq, 0, 8, NULL), NS_SUCCESS);
    WFL4 r; IO_STATUS_BLOCK io; memset(&r, 0, sizeof r);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL), NS_SUCCESS);
    t_note("sequence of the deferred connection: first %lu, second %lu", (unsigned long)seq, (unsigned long)r.seq);
    SOCKET t = abl_tcp();
    CHECK_NS(accept_req(l, r.seq, t), NS_SUCCESS);
    abl_close(t); abl_close(c); abl_close(l);
}
TEST(abld_output_buffer_ignored) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    ULONG seq = wait_seq(l); ABL_DEFER d; BYTE out[16]; IO_STATUS_BLOCK io;
    d.sequence = seq; d.defer = 1; memset(out, 0x5a, sizeof out);
    CHECK_NS(abl_ctl(l, IO_DEFER_ACCEPT, &d, 8, out, sizeof out, &io, NULL), NS_SUCCESS);
    for (size_t i = 0; i < sizeof out; i++) if (out[i] != 0x5a) { CHECK(0); break; }
    abl_close(c); abl_close(l);
}

/* ---- delayed acceptance ---------------------------------------------------------------------------- */
TEST(abld_plain_listener_completes_handshake_before_accept) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_bound(SOCK_STREAM, &a);
    CHECK_NS(abl_raw_listen(l, 4, 0), NS_SUCCESS);
    SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_writable(c, WAIT_MS));                    /* connected although nobody asked the listener */
    abl_close(c); abl_close(l);
}
TEST(abld_delayed_listener_holds_the_handshake) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_bound(SOCK_STREAM, &a);
    CHECK_NS(abl_raw_listen(l, 4, 1), NS_SUCCESS);
    SOCKET c = abl_client_to(&a);
    CHECK(!abl_wait_writable(c, 500));                       /* still connecting */
    ULONG seq = wait_seq(l);                                 /* but the listener already sees it */
    CHECK(seq != 0);
    CHECK(!abl_wait_writable(c, 300));                       /* reporting it does not finish the handshake */
    abl_close(c); abl_close(l);
}
TEST(abld_delayed_listener_accept_finishes_handshake) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_bound(SOCK_STREAM, &a);
    CHECK_NS(abl_raw_listen(l, 4, 1), NS_SUCCESS);
    SOCKET c = abl_client_to(&a);
    ULONG seq = wait_seq(l);
    SOCKET t = abl_tcp();
    CHECK_NS(accept_req(l, seq, t), NS_SUCCESS);
    CHECK(abl_wait_writable(c, WAIT_MS));
    abl_nonblock(c, 0);
    CHECK(W.send(c, "d", 1, 0) == 1);
    char b = 0;
    CHECK(abl_wait_readable(t, WAIT_MS));
    CHECK(W.recv(t, &b, 1, 0) == 1 && b == 'd');
    abl_close(t); abl_close(c); abl_close(l);
}
TEST(abld_delayed_listener_reject_succeeds) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_bound(SOCK_STREAM, &a);
    CHECK_NS(abl_raw_listen(l, 4, 1), NS_SUCCESS);
    SOCKET c = abl_client_to(&a);
    ULONG seq = wait_seq(l);
    CHECK_NS(defer_req(l, seq, 1, 8, NULL), NS_SUCCESS);
    SOCKET t = abl_tcp();
    CHECK_NS(accept_req(l, seq, t), NS_INVALID_PARAMETER);   /* the rejected connection is gone */
    abl_close(t);
    int ready = abl_wait_writable(c, 1500);                 /* a failed connect also makes the socket writable */
    int err = 0, len = sizeof err;
    W.getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
    t_note("delayed reject: client socket ready %d, SO_ERROR %d", ready, err);
    abl_close(c); abl_close(l);
}

/* ---- waiter cancellation -------------------------------------------------------------------------- */
TEST(abld_cancelled_waiter_does_not_take_a_connection) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE o1[64], o2[64]; IO_STATUS_BLOCK i1, i2;
    HANDLE e1 = CreateEventW(NULL, TRUE, FALSE, NULL), e2 = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(o2, 0, sizeof o2);
    CHECK_NS(abl_submit(l, e1, IO_WAIT_FOR_LISTEN, NULL, 0, o1, sizeof o1, &i1), NS_PENDING);
    CHECK(abl_wait(l, e1, &i1, 100) == WAIT_TIMEOUT);          /* cancel it */
    CHECK_NS(i1.Status, NS_CANCELLED);
    CHECK_NS(abl_submit(l, e2, IO_WAIT_FOR_LISTEN, NULL, 0, o2, sizeof o2, &i2), NS_PENDING);
    SOCKET c = abl_client_to(&a);
    CHECK(WaitForSingleObject(e2, WAIT_MS) == WAIT_OBJECT_0);
    CHECK_NS(i2.Status, NS_SUCCESS);
    CHECK(*(ULONG *)o2 != 0);
    CloseHandle(e1); CloseHandle(e2); abl_close(c); abl_close(l);
}
TEST(abld_sequence_numbers_count_connections) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c[5];
    ULONG first = 0;
    for (int i = 0; i < 5; i++) {
        c[i] = abl_tcp();
        CHECK(abl_connect(c[i], &a) == 0);
        CHECK(abl_wait_readable(l, WAIT_MS));
        ULONG s = wait_seq(l);
        if (i == 0) first = s; else CHECKF(s == first + (ULONG)i, "connection %d: seq %lu after %lu", i, (unsigned long)s, (unsigned long)first);
        SOCKET t = abl_tcp();
        CHECK_NS(accept_req(l, s, t), NS_SUCCESS);
        abl_close(t);
    }
    for (int i = 0; i < 5; i++) abl_close(c[i]);
    abl_close(l);
}

/* ---- unbind ---------------------------------------------------------------------------------------- */
static LONG unbind_req(SOCKET s, ULONG insz, LONG *first) {
    BYTE in[64]; memset(in, 0, sizeof in);
    return abl_ctl(s, IO_UNBIND_SOCKET, in, insz, NULL, 0, NULL, first);
}
TEST(ablu_short_input_refused) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    for (ULONG n = 0; n < 8; n++) {
        LONG first, st = unbind_req(s, n, &first);
        t_check((ULONG)st == NS_INVALID_PARAMETER && (ULONG)first == NS_INVALID_PARAMETER, __FILE__, __LINE__, "short unbind input", "len %lu: 0x%08lx", (unsigned long)n, (unsigned long)st);
    }
    abl_close(s);
}
TEST(ablu_empty_block_is_accepted_and_changes_nothing) {
    ABL_BEGIN();
    struct sockaddr_in a, n; SOCKET s = abl_bound(SOCK_STREAM, &a); IO_STATUS_BLOCK io; struct sockaddr_in o;
    static const ULONG lens[] = { 8, 16, 64 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        LONG st = unbind_req(s, lens[i], NULL);
        t_check((ULONG)st == NS_SUCCESS, __FILE__, __LINE__, "unbind", "len %lu: 0x%08lx", (unsigned long)lens[i], (unsigned long)st);
    }
    CHECK_NS(abl_raw_name(s, &n, sizeof n, &io), NS_SUCCESS);
    CHECK(!memcmp(&a, &n, sizeof a));
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_ADDRESS_ALREADY_ASSOCIATED);      /* still bound */
    SOCKET other = abl_tcp();
    CHECK_NS(abl_raw_bind4(other, 0, LO4, a.sin_port, &o), NS_SHARING_VIOLATION);   /* and still holding the port */
    abl_close(other); abl_close(s);
}
TEST(ablu_refused_on_unbound_listening_and_connected) {
    ABL_BEGIN();
    SOCKET fresh = abl_tcp(), l = abl_listener(NULL), c, s;
    CHECK_NS(unbind_req(fresh, 8, NULL), NS_INVALID_PARAMETER);
    CHECK_NS(unbind_req(l, 8, NULL), NS_INVALID_PARAMETER);
    abl_pair(&c, &s);
    CHECK_NS(unbind_req(c, 8, NULL), NS_INVALID_PARAMETER);
    CHECK_NS(unbind_req(s, 8, NULL), NS_INVALID_PARAMETER);
    abl_close(fresh); abl_close(l); abl_close(c); abl_close(s);
}
TEST(ablu_datagram_endpoint_not_supported) {
    ABL_BEGIN();
    SOCKET u = abl_bound(SOCK_DGRAM, NULL), u0 = abl_udp();
    CHECK_NS(unbind_req(u, 8, NULL), NS_NOT_SUPPORTED);
    CHECK_NS(unbind_req(u0, 8, NULL), NS_NOT_SUPPORTED);
    abl_close(u); abl_close(u0);
}

/* ---- super-accept ---------------------------------------------------------------------------------- */
TEST(ablz_non_listener_refused) {
    ABL_BEGIN();
    SOCKET b = abl_bound(SOCK_STREAM, NULL), f = abl_tcp(), u = abl_bound(SOCK_DGRAM, NULL);
    SOCKET all[3] = { b, f, u };
    for (int i = 0; i < 3; i++) {
        BYTE in[128] = {0}; IO_STATUS_BLOCK io; LONG first;
        LONG st = abl_ctl(all[i], IO_SUPER_ACCEPT, in, 64, NULL, 0, &io, &first);
        t_check((ULONG)st == NS_INVALID_PARAMETER && (ULONG)first == NS_INVALID_PARAMETER, __FILE__, __LINE__, "super-accept on non-listener", "kind %d: 0x%08lx", i, (unsigned long)st);
        abl_close(all[i]);
    }
}
TEST(ablz_zeroed_block_has_no_usable_buffer) {
    /* a block of zeros names no accept socket and no receive space: the listener answers "buffer too small"
     * whatever input length is passed */
    ABL_BEGIN();
    static const ULONG lens[] = { 0, 16, 32, 64 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE in[128] = {0}; IO_STATUS_BLOCK io; LONG first;
        LONG st = abl_ctl(l, IO_SUPER_ACCEPT, in, lens[i], NULL, 0, &io, &first);
        t_check((ULONG)st == NS_BUFFER_TOO_SMALL && (ULONG)first == NS_BUFFER_TOO_SMALL, __FILE__, __LINE__, "super-accept zero block", "len %lu: 0x%08lx", (unsigned long)lens[i], (unsigned long)st);
        abl_close(l);
    }
}
TEST(ablz_failed_super_accept_leaves_listener_working) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE in[128] = {0};
    CHECK_NS(abl_ctl(l, IO_SUPER_ACCEPT, in, 64, NULL, 0, NULL, NULL), NS_BUFFER_TOO_SMALL);
    SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    SOCKET t = W.accept(l, NULL, NULL);
    CHECK(t != INVALID_SOCKET);
    abl_close(t); abl_close(c); abl_close(l);
}

/* ---- bind address forms ----------------------------------------------------------------------------- */
static LONG bind_with_family(USHORT family, ULONG salen, int af) {
    SOCKET s = abl_sock(af, SOCK_STREAM); BYTE sa[28], out[32]; IO_STATUS_BLOCK io;
    memset(sa, 0, sizeof sa);
    if (af == AF_INET) { struct sockaddr_in a = abl_lo4(0); memcpy(sa, &a, sizeof a); }
    else { struct sockaddr_in6 a = abl_lo6(0); memcpy(sa, &a, sizeof a); }
    *(USHORT *)sa = family;
    LONG st = abl_raw_bind(s, 0, sa, salen, out, sizeof out, &io);
    abl_close(s);
    return st;
}
TEST(ablb_family_zero_is_invalid_address_component) {
    ABL_BEGIN();
    CHECK_NS(bind_with_family(0, 16, AF_INET), NS_INVALID_ADDRESS_COMPONENT);
}
TEST(ablb_other_families_on_a_v4_endpoint_are_invalid_address) {
    ABL_BEGIN();
    CHECK_NS(bind_with_family(AF_INET6, 16, AF_INET), NS_INVALID_ADDRESS);
    CHECK_NS(bind_with_family(AF_UNIX, 16, AF_INET), NS_INVALID_ADDRESS);
}
TEST(ablb_full_v6_address_on_a_v4_endpoint) {
    ABL_BEGIN();
    CHECK_NS(bind_with_family(AF_INET6, 28, AF_INET), NS_INVALID_ADDRESS_COMPONENT);
}
TEST(ablb_input_longer_than_the_address_is_accepted) {
    /* the bound name is still sixteen bytes; the output block must be at least as long as the address part
     * of the input */
    ABL_BEGIN();
    static const ULONG lens[] = { 17, 20, 28, 32, 40 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        SOCKET s = abl_tcp(); BYTE big[48] = {0}, o[48]; struct sockaddr_in a = abl_lo4(0); IO_STATUS_BLOCK io;
        memcpy(big, &a, sizeof a);
        LONG st = abl_raw_bind(s, 0, big, lens[i], o, lens[i], &io);
        t_check((ULONG)st == NS_SUCCESS, __FILE__, __LINE__, "long bind input", "address length %lu: 0x%08lx", (unsigned long)lens[i], (unsigned long)st);
        CHECK_INFO(io, sizeof(struct sockaddr_in));
        abl_close(s);
    }
}
TEST(ablb_output_must_cover_the_input_address_length) {
    ABL_BEGIN();
    static const ULONG lens[] = { 17, 20, 32 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        SOCKET s = abl_tcp(); BYTE big[48] = {0}, o[48]; struct sockaddr_in a = abl_lo4(0); IO_STATUS_BLOCK io;
        memcpy(big, &a, sizeof a);
        LONG st = abl_raw_bind(s, 0, big, lens[i], o, lens[i] - 1, &io);
        t_check((ULONG)st == NS_INVALID_PARAMETER, __FILE__, __LINE__, "short bind output", "address length %lu, output %lu: 0x%08lx", (unsigned long)lens[i], (unsigned long)lens[i] - 1, (unsigned long)st);
        CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &a), NS_SUCCESS);                /* and it stayed unbound */
        abl_close(s);
    }
}
TEST(ablb_v6_flowinfo_accepted_and_not_echoed) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET s = abl_sock(AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = abl_lo6(0), o; IO_STATUS_BLOCK io;
    a.sin6_flowinfo = 5;
    memset(&o, 0xcc, sizeof o);
    CHECK_NS(abl_raw_bind(s, 0, &a, sizeof a, &o, sizeof o, &io), NS_SUCCESS);
    CHECK(o.sin6_flowinfo == 0);
    abl_close(s);
}
TEST(ablb_v6_loopback_scope_id_refused) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET s = abl_sock(AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = abl_lo6(0), o; IO_STATUS_BLOCK io;
    a.sin6_scope_id = 7;
    CHECK_NS(abl_raw_bind(s, 0, &a, sizeof a, &o, sizeof o, &io), NS_INVALID_ADDRESS_COMPONENT);
    abl_close(s);
}
TEST(ablb_winsock_bind_after_raw_bind_fails) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in o, w = abl_lo4(0);
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_SUCCESS);
    SET_ERR(0);
    CHECK(W.bind(s, (struct sockaddr *)&w, sizeof w) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEINVAL);
    abl_close(s);
}
