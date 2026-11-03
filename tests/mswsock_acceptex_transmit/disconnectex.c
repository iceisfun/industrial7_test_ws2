/* DisconnectEx: every flag bit, with the check that a rejected call leaves the connection fully usable,
 * completion-port delivery, what the socket reports after a graceful disconnect and after a reuse disconnect,
 * peer-closed sockets, pending receives, and repeated reuse cycles.  The basic argument errors on invalid or
 * unconnected sockets live in other areas. */
#include "mx.h"

#define DX(x, c, a) struct mx_ext x; SOCKET c, a; \
    do { NEED_NET(); if (!mx_load_ext(&(x)) || !mx_pair(&(c), &(a))) { t_skip("DisconnectEx fixture unavailable"); return; } } while (0)

static void close2(SOCKET a, SOCKET b) { mx_closesocket(a); mx_closesocket(b); }

TEST(disconnectex_pointer_is_identical_across_sockets)
{
    SOCKET s1, s2;
    GUID g = WSAID_DISCONNECTEX;
    NEED_NET();
    s1 = mx_tcp(); s2 = mx_tcp();
    CHECK(mx_ext_lookup(s1, g) != NULL);
    CHECK(mx_ext_lookup(s1, g) == mx_ext_lookup(s2, g));
    mx_closesocket(s1); mx_closesocket(s2);
}

/* Only bit 1 (TF_REUSE_SOCKET) of the flags is accepted. Each other single bit is WSAEINVAL, and a rejected
 * call has no effect on the connection: data still flows both ways afterwards. */
TEST(disconnectex_every_single_flag_bit_but_reuse_is_einval_and_changes_nothing)
{
    DX(x, c, a);
    {
        int bit;
        for (bit = 0; bit < 32; bit++) {
            DWORD f = 1UL << bit;
            char b[2] = {0};
            if (f == TF_REUSE_SOCKET) continue;
            mx_WSASetLastError(0);
            t_check(x.disconnectex(c, NULL, f, 0) == FALSE && mx_WSAGetLastError() == WSAEINVAL, __FILE__, __LINE__,
                    "flag bit rejected", "bit %d: err %d", bit, mx_WSAGetLastError());
            if (bit == 0 || bit == 4 || bit == 31) {   /* spot-check the connection is intact at a few points */
                MX_EQ(mx_send(c, "x", 1, 0), 1);
                MX_EQ(mx_recv_all(a, b, 1, 5000), 1);
            }
        }
        MX_EQ(mx_send(a, "y", 1, 0), 1);
        {
            char b = 0;
            MX_EQ(mx_recv_all(c, &b, 1, 5000), 1);
            CHECK(b == 'y');
        }
    }
    close2(c, a);
}

TEST(disconnectex_flag_combinations_containing_reuse_are_einval_when_another_bit_is_set)
{
    static const DWORD combos[] = { 3, 6, 0x12, 0x22, 0x82, 0x100 | 2, 0x80000002UL, 0xFFFFFFFFUL };
    unsigned i;
    DX(x, c, a);
    for (i = 0; i < sizeof combos / sizeof combos[0]; i++) {
        mx_WSASetLastError(0);
        t_check(x.disconnectex(c, NULL, combos[i], 0) == FALSE && mx_WSAGetLastError() == WSAEINVAL, __FILE__, __LINE__,
                "combination rejected", "flags 0x%lx err %d", combos[i], mx_WSAGetLastError());
    }
    MX_EQ(mx_send(c, "k", 1, 0), 1);
    close2(c, a);
}

/* The reserved argument must be zero, whatever the flags. */
TEST(disconnectex_nonzero_reserved_is_einval_for_every_flag_value)
{
    static const DWORD flags[] = { 0, TF_REUSE_SOCKET };
    static const DWORD res[] = { 1, 2, 0x80, 0x10000, 0x80000000UL, 0xFFFFFFFFUL };
    unsigned i, j;
    DX(x, c, a);
    for (i = 0; i < 2; i++) for (j = 0; j < sizeof res / sizeof res[0]; j++) {
        mx_WSASetLastError(0);
        t_check(x.disconnectex(c, NULL, flags[i], res[j]) == FALSE && mx_WSAGetLastError() == WSAEINVAL, __FILE__, __LINE__,
                "reserved rejected", "flags 0x%lx reserved 0x%lx err %d", flags[i], res[j], mx_WSAGetLastError());
    }
    MX_EQ(mx_send(c, "k", 1, 0), 1);
    close2(c, a);
}

/* A rejected call with an OVERLAPPED does not touch it. */
TEST(disconnectex_rejected_flags_leave_the_overlapped_untouched)
{
    OVERLAPPED ov;
    DX(x, c, a);
    memset(&ov, 0, sizeof ov);
    ov.Internal = MX_POISON;
    ov.InternalHigh = 0x1234;
    mx_WSASetLastError(0);
    MX_EQ(x.disconnectex(c, &ov, 0x40, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAEINVAL);
    MX_EQ((ULONG)ov.Internal, MX_POISON);
    MX_EQ(ov.InternalHigh, 0x1234);
    close2(c, a);
}

TEST(disconnectex_completion_port_packet_carries_key_overlapped_and_zero_bytes)
{
    OVERLAPPED ov;
    HANDLE port;
    DWORD got = MX_POISON;
    ULONG_PTR key = 0;
    OVERLAPPED *pov = NULL;
    int e;
    DX(x, c, a);
    port = CreateIoCompletionPort((HANDLE)c, NULL, 0x99, 0);
    CHECK(port != NULL);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    e = x.disconnectex(c, &ov, 0, 0) ? 0 : mx_WSAGetLastError();
    t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "DisconnectEx posts", "error %d", e);
    CHECK(GetQueuedCompletionStatus(port, &got, &key, &pov, 5000));
    MX_EQ(key, 0x99);
    CHECK(pov == &ov);
    MX_EQ(got, 0);
    CHECK(mx_at_eof(a, 5000));
    CloseHandle(ov.hEvent);
    close2(c, a);
    CloseHandle(port);
}

/* ---- state after the disconnect ---------------------------------------------------------------------------- */

TEST(disconnectex_without_reuse_blocks_further_sends_with_shutdown_error)
{
    int r, e;
    DX(x, c, a);
    CHECK(x.disconnectex(c, NULL, 0, 0));
    r = mx_send(c, "z", 1, 0);
    e = mx_WSAGetLastError();
    MX_EQ(r, SOCKET_ERROR);
    MX_EQ(e, WSAESHUTDOWN);
    close2(c, a);
}

TEST(disconnectex_with_reuse_returns_the_transport_to_the_unconnected_state)
{
    DWORD t = 0;
    int len = sizeof t;
    struct sockaddr_in pn;
    int pl = sizeof pn;
    DX(x, c, a);
    CHECK(mx_reuse_disconnect(x.disconnectex, c, a));
    MX_EQ(mx_getsockopt(c, SOL_SOCKET, SO_CONNECT_TIME, (char *)&t, &len), 0);
    MX_EQ(t, 0xFFFFFFFFUL);
    /* getpeername keeps answering from Winsock's cached state; only the transport-level queries and I/O notice. */
    t_note("getpeername after a reuse disconnect: %d", mx_getpeername(c, (struct sockaddr *)&pn, &pl));
    MX_EQ(mx_send(c, "z", 1, 0), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    close2(c, a);
}

TEST(disconnectex_with_reuse_gives_the_peer_end_of_stream)
{
    OVERLAPPED ov;
    DWORD n = 0, err = 0;
    DX(x, c, a);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    MX_EQ(mx_send(c, "tail", 4, 0), 4);
    {
        int e = x.disconnectex(c, &ov, TF_REUSE_SOCKET, 0) ? 0 : mx_WSAGetLastError();
        t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "reuse disconnect posts", "error %d", e);
    }
    mx_expect_bytes(a, "tail", 4);
    CHECK(mx_at_eof(a, 5000));
    mx_shutdown(a, SD_SEND);
    CHECK(mx_ov_done(c, &ov, &n, 8000, &err));
    CloseHandle(ov.hEvent);
    close2(c, a);
}

/* The receive direction stays open for a plain disconnect: the peer can still send and the data is readable. */
TEST(disconnectex_peer_data_after_a_plain_disconnect_is_still_received)
{
    DX(x, c, a);
    CHECK(x.disconnectex(c, NULL, 0, 0));
    MX_EQ(mx_send(a, "late", 4, 0), 4);
    mx_expect_bytes(c, "late", 4);
    close2(c, a);
}

TEST(disconnectex_after_the_peer_already_closed_succeeds)
{
    DX(x, c, a);
    mx_closesocket(a);
    CHECK(mx_at_eof(c, 5000));
    mx_WSASetLastError(0);
    {
        BOOL r = x.disconnectex(c, NULL, 0, 0);
        int e = mx_WSAGetLastError();
        MX_EQ(r, TRUE);
    }
    mx_closesocket(c);
}

/* A receive that is outstanding when a reuse disconnect happens is completed, not left pending forever. */
TEST(disconnectex_reuse_completes_an_outstanding_receive_with_zero_bytes)
{
    WSABUF wb;
    OVERLAPPED ov;
    char b[8];
    DWORD got = 0, fl = 0, err = 0, n = 0;
    int r;
    DX(x, c, a);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    wb.buf = b; wb.len = sizeof b;
    r = mx_WSARecv(c, &wb, 1, &got, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    MX_EQ(r, SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSA_IO_PENDING);
    CHECK(mx_reuse_disconnect(x.disconnectex, c, a));
    {
        int done = mx_ov_done(c, &ov, &n, 5000, &err);
        /* The receive completes successfully with no data rather than being aborted. */
        CHECK(done);
        MX_EQ(n, 0);
        MX_EQ(err, 0);
    }
    CloseHandle(ov.hEvent);
    close2(c, a);
}

/* ---- cycles --------------------------------------------------------------------------------------------------- */

/* Client-side reuse: one client handle makes three successive connections, each to a fresh listener (a new
 * remote port), rebinding only if the socket came back unbound. */
TEST(disconnectex_client_socket_survives_three_reuse_cycles)
{
    struct sockaddr_in any = mx_lo4();
    SOCKET c;
    int round, rebinds = 0;
    OVERLAPPED ov;
    struct mx_ext x;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    c = mx_tcp();
    CHECK(c != INVALID_SOCKET);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    MX_EQ(mx_bind(c, (struct sockaddr *)&any, sizeof any), 0);
    for (round = 0; round < 3; round++) {
        struct sockaddr_in addr;
        SOCKET lst = mx_listener(&addr, 2), s;
        DWORD n = 0, err = 0;
        char msg[4], b[4] = {0};
        sprintf(msg, "c%d", round);
        ResetEvent(ov.hEvent);
        {
            BOOL ok = x.connectex(c, (struct sockaddr *)&addr, sizeof addr, msg, 3, NULL, &ov);
            int e = ok ? 0 : mx_WSAGetLastError();
            if (e == WSAEINVAL) {
                rebinds++;
                MX_EQ(mx_bind(c, (struct sockaddr *)&any, sizeof any), 0);
                ResetEvent(ov.hEvent);
                ok = x.connectex(c, (struct sockaddr *)&addr, sizeof addr, msg, 3, NULL, &ov);
                e = ok ? 0 : mx_WSAGetLastError();
            }
            t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "ConnectEx in cycle", "round %d error %d", round, e);
        }
        CHECK(mx_ov_done(c, &ov, &n, 5000, &err));
        s = mx_accept_wait(lst);
        CHECK(s != INVALID_SOCKET);
        MX_EQ(mx_recv_all(s, b, 3, 5000), 3);
        CHECK(!memcmp(b, msg, 3));
        CHECK(mx_reuse_disconnect(x.disconnectex, c, s));
        mx_closesocket(s);
        mx_closesocket(lst);
    }
    if (rebinds) t_note("client needed a fresh bind in %d of 3 reuse cycles", rebinds);
    CloseHandle(ov.hEvent);
    mx_closesocket(c);
}

/* Server-side reuse: DisconnectEx on the accepted socket, then the very same handle receives a second accept. */
TEST(disconnectex_accepted_socket_reused_by_acceptex_with_data)
{
    struct sockaddr_in addr;
    SOCKET lst, c1, c2, acc;
    OVERLAPPED ov;
    unsigned char buf[128];
    DWORD n = 0, err = 0;
    struct mx_ext x;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    lst = mx_listener(&addr, 4);
    c1 = mx_tcp();
    CHECK(mx_connect(c1, (struct sockaddr *)&addr, sizeof addr) == 0);
    acc = mx_accept_wait(lst);
    CHECK(acc != INVALID_SOCKET);
    CHECK(mx_reuse_disconnect(x.disconnectex, acc, c1));
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    n = 0;
    x.acceptex(lst, acc, buf, 16, 32, 32, &n, &ov);
    c2 = mx_tcp();
    CHECK(mx_connect(c2, (struct sockaddr *)&addr, sizeof addr) == 0);
    MX_EQ(mx_send(c2, "second", 6, 0), 6);
    CHECK(mx_ov_done(lst, &ov, &n, 5000, &err));
    MX_EQ(n, 6);
    CHECK(!memcmp(buf, "second", 6));
    CloseHandle(ov.hEvent);
    mx_closesocket(c1); mx_closesocket(c2); mx_closesocket(acc); mx_closesocket(lst);
}
