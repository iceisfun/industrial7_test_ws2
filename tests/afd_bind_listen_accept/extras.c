/* Handle kinds, reuse listeners and peer-address reporting.
 *
 * Part one drives the requests through handles that are not plain overlapped sockets: a synchronous socket
 * handle (the call itself waits for a pended request), a duplicated handle, a closed handle and handles of
 * other object kinds. Part two covers endpoints that share an address with the reuse request and the way
 * wait-for-listen reports peers that were bound to a specific local address first.
 */
#include "abl.h"

typedef struct { ULONG seq; struct sockaddr_in addr; } WFL4;

static SOCKET sync_sock(int type) {
    SOCKET s = W.WSASocketW(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP, NULL, 0, 0);
    CHECKF(s != INVALID_SOCKET, "socket creation failed, error %d", W.WSAGetLastError());
    abl_timeouts(s);
    return s;
}

/* ---- synchronous handles ---------------------------------------------------------------------------- */
TEST(ablx_sync_handle_bind_returns_final_status) {
    ABL_BEGIN();
    SOCKET s = sync_sock(SOCK_STREAM); struct sockaddr_in a = abl_lo4(0), o; IO_STATUS_BLOCK io; BYTE in[20] = {0};
    memcpy(in + 4, &a, sizeof a);
    LONG st = W.ioctl((HANDLE)s, NULL, NULL, NULL, &io, IO_BIND, in, sizeof in, &o, sizeof o);
    CHECK_NS(st, NS_SUCCESS);                      /* waited inside the call: never "pending" */
    CHECK_NS(io.Status, NS_SUCCESS);
    CHECK_INFO(io, sizeof o);
    CHECK(o.sin_port != 0);
    abl_close(s);
}
TEST(ablx_sync_handle_listen_returns_final_status) {
    ABL_BEGIN();
    SOCKET s = sync_sock(SOCK_STREAM); struct sockaddr_in a = abl_lo4(0);
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    ABL_LISTEN l; IO_STATUS_BLOCK io; memset(&l, 0, sizeof l); l.backlog = 3;
    LONG st = W.ioctl((HANDLE)s, NULL, NULL, NULL, &io, IO_START_LISTEN, &l, sizeof l, NULL, 0);
    CHECK_NS(st, NS_SUCCESS);
    CHECK_NS(io.Status, NS_SUCCESS);
    abl_close(s);
}
TEST(ablx_sync_handle_refusal_is_returned_directly) {
    ABL_BEGIN();
    SOCKET s = sync_sock(SOCK_STREAM); ABL_LISTEN l; IO_STATUS_BLOCK io; memset(&l, 0, sizeof l); l.backlog = 3;
    LONG st = W.ioctl((HANDLE)s, NULL, NULL, NULL, &io, IO_START_LISTEN, &l, sizeof l, NULL, 0);   /* unbound */
    CHECK_NS(st, NS_INVALID_PARAMETER);
    abl_close(s);
}
TEST(ablx_sync_handle_wait_for_listen_returns_queued_connection) {
    ABL_BEGIN();
    SOCKET s = sync_sock(SOCK_STREAM); struct sockaddr_in a = abl_lo4(0); int len = sizeof a;
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(W.getsockname(s, (struct sockaddr *)&a, &len) == 0);
    CHECK(W.listen(s, 3) == 0);
    SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(s, WAIT_MS));
    WFL4 r; IO_STATUS_BLOCK io; memset(&r, 0, sizeof r);
    LONG st = W.ioctl((HANDLE)s, NULL, NULL, NULL, &io, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r);
    CHECK_NS(st, NS_SUCCESS);
    CHECK_INFO(io, sizeof r);
    abl_close(c); abl_close(s);
}
TEST(ablx_sync_handle_get_address) {
    ABL_BEGIN();
    SOCKET s = sync_sock(SOCK_STREAM); struct sockaddr_in a = abl_lo4(0), q, n; int len = sizeof q; IO_STATUS_BLOCK io;
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(W.getsockname(s, (struct sockaddr *)&q, &len) == 0);
    LONG st = W.ioctl((HANDLE)s, NULL, NULL, NULL, &io, IO_GET_ADDRESS, NULL, 0, &n, sizeof n);
    CHECK_NS(st, NS_SUCCESS);
    CHECK_INFO(io, sizeof n);
    CHECK(!memcmp(&n, &q, sizeof n));
    abl_close(s);
}
TEST(ablx_non_overlapped_accept_target) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    WFL4 r; IO_STATUS_BLOCK io; memset(&r, 0, sizeof r);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL), NS_SUCCESS);
    SOCKET t = sync_sock(SOCK_STREAM); ABL_ACCEPT aa; memset(&aa, 0, sizeof aa); aa.sequence = r.seq; aa.accept_handle = (HANDLE)t;
    CHECK_NS(abl_ctl(l, IO_ACCEPT, &aa, sizeof aa, NULL, 0, &io, NULL), NS_SUCCESS);
    abl_close(t); abl_close(c); abl_close(l);
}

/* ---- other handle kinds ------------------------------------------------------------------------------ */
TEST(ablx_closed_handle_is_invalid_handle) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL); HANDLE h = (HANDLE)s; IO_STATUS_BLOCK io; struct sockaddr_in o;
    abl_close(s);
    SET_ERR(0);
    LONG st = W.ioctl(h, NULL, NULL, NULL, &io, IO_GET_ADDRESS, NULL, 0, &o, sizeof o);
    CHECK_NS(st, NS_INVALID_HANDLE);
}
TEST(ablx_event_handle_is_type_mismatch) {
    ABL_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); IO_STATUS_BLOCK io; struct sockaddr_in o;
    LONG st = W.ioctl(ev, NULL, NULL, NULL, &io, IO_GET_ADDRESS, NULL, 0, &o, sizeof o);
    CHECK_NS(st, 0xC0000024UL);
    CloseHandle(ev);
}
TEST(ablx_null_device_does_not_understand_afd_codes) {
    ABL_BEGIN();
    HANDLE h = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("cannot open the null device"); return; }
    IO_STATUS_BLOCK io; struct sockaddr_in o;
    LONG st = W.ioctl(h, NULL, NULL, NULL, &io, IO_GET_ADDRESS, NULL, 0, &o, sizeof o);
    t_check((ULONG)st != NS_SUCCESS && (ULONG)st != NS_PENDING, __FILE__, __LINE__, "null device refuses", "0x%08lx", (unsigned long)st);
    t_note("get-address on the null device: 0x%08lx", (unsigned long)st);
    CloseHandle(h);
}
TEST(ablx_duplicated_handle_reaches_same_endpoint) {
    ABL_BEGIN();
    struct sockaddr_in a, n; SOCKET s = abl_bound(SOCK_STREAM, &a); HANDLE d = NULL; IO_STATUS_BLOCK io;
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS));
    CHECK_NS(W.ioctl(d, NULL, NULL, NULL, &io, IO_GET_ADDRESS, NULL, 0, &n, sizeof n), NS_SUCCESS);
    CHECK(!memcmp(&a, &n, sizeof n));
    CloseHandle(d);
    abl_close(s);
}
TEST(ablx_listen_through_duplicate_marks_original_listening) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET s = abl_bound(SOCK_STREAM, &a); HANDLE d = NULL; IO_STATUS_BLOCK io; ABL_LISTEN l;
    memset(&l, 0, sizeof l); l.backlog = 3;
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS));
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    LONG st = W.ioctl(d, ev, NULL, NULL, &io, IO_START_LISTEN, &l, sizeof l, NULL, 0);
    if ((ULONG)st == NS_PENDING) { WaitForSingleObject(ev, WAIT_MS); st = io.Status; }
    CHECK_NS(st, NS_SUCCESS);
    CHECK_NS(abl_raw_listen(s, 3, 0), NS_INVALID_PARAMETER);       /* the original sees the listening state */
    SOCKET c = abl_tcp();
    CHECK(abl_connect(c, &a) == 0);
    abl_close(c); CloseHandle(ev); CloseHandle(d); abl_close(s);
}

/* ---- concurrent requests ------------------------------------------------------------------------------ */
TEST(ablx_get_address_while_wait_is_pending) {
    ABL_BEGIN();
    struct sockaddr_in a, n; SOCKET l = abl_listener(&a); BYTE out[64]; IO_STATUS_BLOCK io, io2;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK_NS(abl_submit(l, ev, IO_WAIT_FOR_LISTEN, NULL, 0, out, sizeof out, &io), NS_PENDING);
    CHECK_NS(abl_raw_name(l, &n, sizeof n, &io2), NS_SUCCESS);
    CHECK(!memcmp(&a, &n, sizeof n));
    CHECK(WaitForSingleObject(ev, 100) == WAIT_TIMEOUT);              /* the name request did not disturb the waiter */
    abl_close(l);
    CHECK(WaitForSingleObject(ev, WAIT_MS) == WAIT_OBJECT_0);
    CHECK_NS(io.Status, NS_CANCELLED);
    CloseHandle(ev);
}
TEST(ablx_closing_listener_cancels_every_waiter) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE out[3][64]; IO_STATUS_BLOCK io[3]; HANDLE ev[3];
    static const ULONG codes[3] = { IO_WAIT_FOR_LISTEN, IO_WAIT_LISTEN_LIFO, IO_WAIT_FOR_LISTEN };
    for (int i = 0; i < 3; i++) {
        ev[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        CHECK_NS(abl_submit(l, ev[i], codes[i], NULL, 0, out[i], 64, &io[i]), NS_PENDING);
    }
    abl_close(l);
    for (int i = 0; i < 3; i++) {
        CHECK(WaitForSingleObject(ev[i], WAIT_MS) == WAIT_OBJECT_0);
        CHECK_NS(io[i].Status, NS_CANCELLED);
        CloseHandle(ev[i]);
    }
}
TEST(ablx_waiters_on_two_listeners_are_independent) {
    ABL_BEGIN();
    struct sockaddr_in a1, a2; SOCKET l1 = abl_listener(&a1), l2 = abl_listener(&a2); BYTE o1[64], o2[64]; IO_STATUS_BLOCK i1, i2;
    HANDLE e1 = CreateEventW(NULL, TRUE, FALSE, NULL), e2 = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK_NS(abl_submit(l1, e1, IO_WAIT_FOR_LISTEN, NULL, 0, o1, sizeof o1, &i1), NS_PENDING);
    CHECK_NS(abl_submit(l2, e2, IO_WAIT_FOR_LISTEN, NULL, 0, o2, sizeof o2, &i2), NS_PENDING);
    SOCKET c = abl_client_to(&a2);
    CHECK(WaitForSingleObject(e2, WAIT_MS) == WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(e1, 200) == WAIT_TIMEOUT);
    abl_close(c); abl_close(l1); abl_close(l2);
    WaitForSingleObject(e1, WAIT_MS);
    CloseHandle(e1); CloseHandle(e2);
}

/* ---- reuse listeners and peers ----------------------------------------------------------------------- */
TEST(ablx_two_reuse_endpoints_can_both_listen_on_one_port) {
    ABL_BEGIN();
    SOCKET s1 = abl_tcp(), s2 = abl_tcp(); struct sockaddr_in o, n;
    CHECK_NS(abl_raw_bind4(s1, 1, LO4, 0, &o), NS_SUCCESS);
    CHECK_NS(abl_raw_listen(s1, 3, 0), NS_SUCCESS);
    CHECK_NS(abl_raw_bind4(s2, 1, LO4, o.sin_port, &n), NS_SUCCESS);
    CHECK_NS(abl_raw_listen(s2, 3, 0), NS_SUCCESS);
    abl_close(s1); abl_close(s2);
}
TEST(ablx_non_reuse_listener_blocks_reuse_bind) {
    ABL_BEGIN();
    SOCKET s1 = abl_tcp(), s2 = abl_tcp(); struct sockaddr_in o, n;
    CHECK_NS(abl_raw_bind4(s1, 0, LO4, 0, &o), NS_SUCCESS);
    CHECK_NS(abl_raw_listen(s1, 3, 0), NS_SUCCESS);
    CHECK_NS(abl_raw_bind4(s2, 1, LO4, o.sin_port, &n), 0xC0000022UL);
    abl_close(s1); abl_close(s2);
}
TEST(ablx_listen_bind_close_cycles_keep_the_port_usable) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET p = abl_bound(SOCK_STREAM, &a); abl_close(p);
    for (int i = 0; i < 16; i++) {
        SOCKET s = abl_tcp(); struct sockaddr_in o;
        t_check((ULONG)abl_raw_bind4(s, 0, LO4, a.sin_port, &o) == NS_SUCCESS, __FILE__, __LINE__, "cycle bind", "cycle %d", i);
        t_check((ULONG)abl_raw_listen(s, 3, 0) == NS_SUCCESS, __FILE__, __LINE__, "cycle listen", "cycle %d", i);
        abl_close(s);
    }
}
TEST(ablx_peer_bound_to_other_loopback_address_is_reported) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a);
    SOCKET c = abl_tcp(); struct sockaddr_in src = abl_lo4(0);
    src.sin_addr.s_addr = BE32(0x7f000002UL);
    CHECK(W.bind(c, (struct sockaddr *)&src, sizeof src) == 0);
    abl_nonblock(c, 1);
    W.connect(c, (struct sockaddr *)&a, sizeof a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    WFL4 r; IO_STATUS_BLOCK io; memset(&r, 0, sizeof r);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL), NS_SUCCESS);
    CHECK(r.addr.sin_addr.s_addr == BE32(0x7f000002UL));
    abl_close(c); abl_close(l);
}
TEST(ablx_many_peers_reported_with_their_own_ports) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); SOCKET c[4]; USHORT ports[4];
    for (int i = 0; i < 4; i++) {
        struct sockaddr_in n; int len = sizeof n;
        c[i] = abl_tcp(); CHECK(abl_connect(c[i], &a) == 0);
        CHECK(W.getsockname(c[i], (struct sockaddr *)&n, &len) == 0);
        ports[i] = n.sin_port;
    }
    CHECK(abl_wait_readable(l, WAIT_MS));
    for (int i = 0; i < 4; i++) {
        WFL4 r; IO_STATUS_BLOCK io; memset(&r, 0, sizeof r);
        CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL), NS_SUCCESS);
        CHECKF(r.addr.sin_port == ports[i], "peer %d port", i);
    }
    for (int i = 0; i < 4; i++) abl_close(c[i]);
    abl_close(l);
}
TEST(ablx_v6_data_flows_through_raw_accept) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET l = abl_sock(AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = abl_lo6(0), n; IO_STATUS_BLOCK io; BYTE out[64];
    CHECK_NS(abl_raw_bind(l, 0, &a, sizeof a, &n, sizeof n, &io), NS_SUCCESS);
    CHECK_NS(abl_raw_listen(l, 5, 0), NS_SUCCESS);
    CHECK_NS(abl_raw_name(l, &n, sizeof n, &io), NS_SUCCESS);
    SOCKET c = abl_sock(AF_INET6, SOCK_STREAM); abl_nonblock(c, 1);
    W.connect(c, (struct sockaddr *)&n, sizeof n);
    CHECK(abl_wait_readable(l, WAIT_MS));
    memset(out, 0, sizeof out);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, sizeof out, &io, NULL), NS_SUCCESS);
    SOCKET t = abl_sock(AF_INET6, SOCK_STREAM); ABL_ACCEPT aa; memset(&aa, 0, sizeof aa);
    aa.sequence = *(ULONG *)out; aa.accept_handle = (HANDLE)t;
    CHECK_NS(abl_ctl(l, IO_ACCEPT, &aa, sizeof aa, NULL, 0, &io, NULL), NS_SUCCESS);
    CHECK(abl_wait_writable(c, WAIT_MS));
    abl_nonblock(c, 0);
    CHECK(W.send(c, "6", 1, 0) == 1);
    char b = 0;
    CHECK(abl_wait_readable(t, WAIT_MS));
    CHECK(W.recv(t, &b, 1, 0) == 1 && b == '6');
    abl_close(t); abl_close(c); abl_close(l);
}
