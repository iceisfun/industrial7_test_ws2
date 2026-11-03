/* GetAcceptExSockaddrs (the looked-up function and the exported wrapper), the exported AcceptEx/TransmitFile
 * wrappers, and WSARecvEx. 
 *
 * The looked-up GetAcceptExSockaddrs is a pure buffer parser: for each address whose slot length is non-zero it
 * reports a pointer to the slot and a length taken from the LAST TWO BYTES OF THAT SLOT (the transport stores the
 * real address length there); it never looks at the address family and writes nothing for a zero slot length.
 * The exported wrapper forwards to that function only after the exported AcceptEx has run once in the process;
 * before that it reports NULL/0 for everything. */
#include "xf.h"

typedef void (WINAPI *gaes_fn)(PVOID, DWORD, DWORD, DWORD, struct sockaddr **, LPINT, struct sockaddr **, LPINT);

static gaes_fn get_gaes(void) { GUID g = WSAID_GETACCEPTEXSOCKADDRS; return (gaes_fn)xf_fn(&g); }

#define NEED_GAES(f) gaes_fn f = get_gaes(); do { if (!f) { t_skip("GetAcceptExSockaddrs unavailable"); return; } } while (0)

/* A buffer where byte i holds i, with chosen "stored length" words patched into slot tails. */
static void fill(BYTE *b, size_t n) { size_t i; for (i = 0; i < n; i++) b[i] = (BYTE)i; }
static void put_len(BYTE *slot_end, unsigned v) { slot_end[-2] = (BYTE)v; slot_end[-1] = (BYTE)(v >> 8); }

TEST(xf_gaes_reports_slot_pointers_after_received_data)
{
    BYTE buf[256]; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
    NEED_GAES(f);
    fill(buf, sizeof buf);
    put_len(buf + 20 + 32, 16);
    put_len(buf + 20 + 32 + 48, 28);
    f(buf, 20, 32, 48, &l, &ll, &r, &rl);
    EXPECT_EQ(l, buf + 20);
    EXPECT_EQ(r, buf + 20 + 32);
    EXPECT_EQ(ll, 16);
    EXPECT_EQ(rl, 28);
}
TEST(xf_gaes_length_comes_from_last_two_bytes_of_slot)
{
    static const unsigned vals[] = {0, 1, 16, 28, 0x00FF, 0x0100, 0x1234, 0xABCD, 0xFFFF};
    unsigned i;
    NEED_GAES(f);
    for (i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        BYTE buf[128]; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
        fill(buf, sizeof buf);
        put_len(buf + 0 + 40, vals[i]);          /* local slot: [0,40) */
        put_len(buf + 0 + 40 + 40, vals[i] ^ 0x5A5A);
        f(buf, 0, 40, 40, &l, &ll, &r, &rl);
        CHECKF(ll == (int)vals[i], "local: stored 0x%x reported %d", vals[i], ll);
        CHECKF(rl == (int)(vals[i] ^ 0x5A5A), "remote: stored 0x%x reported %d", vals[i] ^ 0x5A5A, rl);
    }
}
TEST(xf_gaes_ignores_address_family_bytes)
{
    BYTE buf[128]; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
    NEED_GAES(f);
    memset(buf, 0xEE, sizeof buf);                 /* no valid family anywhere */
    put_len(buf + 32, 7);
    put_len(buf + 64, 9);
    f(buf, 0, 32, 32, &l, &ll, &r, &rl);
    EXPECT_EQ(l, buf);
    EXPECT_EQ(r, buf + 32);
    EXPECT_EQ(ll, 7);
    EXPECT_EQ(rl, 9);
}
TEST(xf_gaes_length_is_zero_extended)
{
    BYTE buf[64]; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
    NEED_GAES(f);
    fill(buf, sizeof buf);
    put_len(buf + 16, 0xFFFF);
    put_len(buf + 32, 0x8000);
    f(buf, 0, 16, 16, &l, &ll, &r, &rl);
    EXPECT_EQ(ll, 0xFFFF);
    EXPECT_EQ(rl, 0x8000);
}
TEST(xf_gaes_zero_local_slot_leaves_local_outputs_alone)
{
    BYTE buf[96]; struct sockaddr *l = (struct sockaddr *)(ULONG_PTR)0x11111111, *r = NULL; int ll = 0x22222222, rl = -1;
    NEED_GAES(f);
    fill(buf, sizeof buf);
    put_len(buf + 10 + 0 + 24, 16);
    f(buf, 10, 0, 24, &l, &ll, &r, &rl);
    EXPECT_EQ(l, 0x11111111);
    EXPECT_EQ(ll, 0x22222222);
    EXPECT_EQ(r, buf + 10);                   /* the remote slot starts right after the data when local is empty */
    EXPECT_EQ(rl, 16);
}
TEST(xf_gaes_zero_remote_slot_leaves_remote_outputs_alone)
{
    BYTE buf[96]; struct sockaddr *l = NULL, *r = (struct sockaddr *)(ULONG_PTR)0x33333333; int ll = -1, rl = 0x44444444;
    NEED_GAES(f);
    fill(buf, sizeof buf);
    put_len(buf + 5 + 24, 28);
    f(buf, 5, 24, 0, &l, &ll, &r, &rl);
    EXPECT_EQ(l, buf + 5);
    EXPECT_EQ(ll, 28);
    EXPECT_EQ(r, 0x33333333);
    EXPECT_EQ(rl, 0x44444444);
}
TEST(xf_gaes_both_slots_zero_touches_nothing)
{
    BYTE buf[16]; struct sockaddr *l = (struct sockaddr *)(ULONG_PTR)0x1, *r = (struct sockaddr *)(ULONG_PTR)0x2; int ll = 3, rl = 4;
    NEED_GAES(f);
    fill(buf, sizeof buf);
    f(buf, 8, 0, 0, &l, &ll, &r, &rl);
    EXPECT_EQ(l, 1); EXPECT_EQ(r, 2); EXPECT_EQ(ll, 3); EXPECT_EQ(rl, 4);
}
TEST(xf_gaes_receive_length_shifts_both_slots)
{
    unsigned rcv;
    NEED_GAES(f);
    for (rcv = 0; rcv <= 100; rcv += 25) {
        BYTE buf[256]; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
        fill(buf, sizeof buf);
        put_len(buf + rcv + 20, 111);
        put_len(buf + rcv + 20 + 20, 222);
        f(buf, rcv, 20, 20, &l, &ll, &r, &rl);
        CHECKF(l == (void *)(buf + rcv) && r == (void *)(buf + rcv + 20) && ll == 111 && rl == 222, "receive length %u", rcv);
    }
}
TEST(xf_gaes_does_not_modify_the_buffer)
{
    BYTE buf[128], copy[128]; struct sockaddr *l, *r; int ll, rl;
    NEED_GAES(f);
    fill(buf, sizeof buf);
    memcpy(copy, buf, sizeof buf);
    f(buf, 12, 40, 40, &l, &ll, &r, &rl);
    CHECK(!memcmp(buf, copy, sizeof buf));
}
TEST(xf_gaes_adjacent_slots_do_not_overlap)
{
    BYTE buf[256]; struct sockaddr *l, *r; int ll, rl;
    NEED_GAES(f);
    fill(buf, sizeof buf);
    f(buf, 0, 18, 34, &l, &ll, &r, &rl);
    EXPECT_EQ((BYTE *)r - (BYTE *)l, 18);
}
TEST(xf_gaes_matches_what_acceptex_stores_for_ipv4)
{
    /* An accepted connection: the transport has written 16 into the tail of both slots. */
    PAIR(p);
    {
        GUID ga = WSAID_ACCEPTEX; LPFN_ACCEPTEX ax = (LPFN_ACCEPTEX)xf_fn(&ga);
        gaes_fn f = get_gaes();
        SOCKET acc; BYTE buf[2 * 32]; DWORD got = 0; WSAOVERLAPPED ov; SOCKET c2; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
        struct sockaddr_in local, remote; int len;
        if (!ax || !f) { xf_pair_close(&p); t_skip("functions unavailable"); return; }
        acc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        c2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
        memset(buf, 0xCC, sizeof buf);
        if (!ax(p.lst, acc, buf, 0, 32, 32, &got, &ov) && WSAGetLastError() != ERROR_IO_PENDING) {
            CHECKF(0, "AcceptEx failed: %d", WSAGetLastError());
        } else if (connect(c2, (struct sockaddr *)&p.addr, sizeof p.addr) == 0) {
            DWORD n, fl;
            CHECK(xf_ov_wait(p.lst, &ov, &n, &fl, 5000));
            f(buf, 0, 32, 32, &l, &ll, &r, &rl);
            EXPECT_EQ(l, buf); EXPECT_EQ(r, buf + 32);
            EXPECT_EQ(ll, sizeof(struct sockaddr_in));
            EXPECT_EQ(rl, sizeof(struct sockaddr_in));
            len = sizeof local; memset(&local, 0, sizeof local);
            CHECK(getsockname(c2, (struct sockaddr *)&remote, &(int){sizeof remote}) == 0);
            CHECK(!memcmp(&((struct sockaddr_in *)r)->sin_port, &remote.sin_port, 2));   /* peer port == client's own port */
        }
        closesocket(c2); closesocket(acc); WSACloseEvent(ov.hEvent);
    }
    xf_pair_close(&p);
}

/* ---- the exported wrapper: cold start, then warmed by the exported AcceptEx --------------------------- */

CHILD(xf_gaes_cold)
{
    typedef void (WINAPI *exp_fn)(PVOID, DWORD, DWORD, DWORD, struct sockaddr **, LPINT, struct sockaddr **, LPINT);
    exp_fn f = (exp_fn)t_proc_in("mswsock.dll", "GetAcceptExSockaddrs");
    BYTE buf[64]; struct sockaddr *l = (void *)(ULONG_PTR)1, *r = (void *)(ULONG_PTR)2; int ll = 3, rl = 4;
    if (!f) return 10;
    memset(buf, 0, sizeof buf);
    f(buf, 0, 16, 16, &l, &ll, &r, &rl);
    if (l != NULL || r != NULL) return 1;
    if (ll != 0 || rl != 0) return 2;
    /* NULL out-pointers are tolerated while cold */
    f(buf, 0, 16, 16, NULL, NULL, NULL, NULL);
    return 0;
}
TEST(xf_gaes_export_reports_nothing_before_acceptex_ran)
{
    DWORD rc = t_run_child("xf_gaes_cold", "", 30000);
    CHECKF(rc == 0, "child result %lu", rc);
}

CHILD(xf_gaes_warm)
{
    typedef void (WINAPI *exp_fn)(PVOID, DWORD, DWORD, DWORD, struct sockaddr **, LPINT, struct sockaddr **, LPINT);
    typedef BOOL (WINAPI *ax_fn)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);
    exp_fn f = (exp_fn)t_proc_in("mswsock.dll", "GetAcceptExSockaddrs");
    ax_fn ax = (ax_fn)t_proc_in("mswsock.dll", "AcceptEx");
    struct xf_pair p; SOCKET acc, c2; BYTE buf[64]; DWORD got = 0, n, fl; WSAOVERLAPPED ov;
    struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1, rc = 0;
    WSADATA d;
    if (!f || !ax) return 10;
    if (WSAStartup(MAKEWORD(2, 2), &d)) return 11;
    if (!xf_pair_open(&p)) { xf_pair_close(&p); return 12; }
    acc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    c2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    memset(buf, 0xCC, sizeof buf);
    if (!ax(p.lst, acc, buf, 0, 32, 32, &got, &ov) && WSAGetLastError() != ERROR_IO_PENDING) rc = 13;
    else if (connect(c2, (struct sockaddr *)&p.addr, sizeof p.addr)) rc = 14;
    else if (!xf_ov_wait(p.lst, &ov, &n, &fl, 5000)) rc = 15;
    else {
        f(buf, 0, 32, 32, &l, &ll, &r, &rl);
        if (l != (void *)buf || r != (void *)(buf + 32)) rc = 1;
        else if (ll != (int)sizeof(struct sockaddr_in) || rl != (int)sizeof(struct sockaddr_in)) rc = 2;
    }
    closesocket(c2); closesocket(acc); WSACloseEvent(ov.hEvent); xf_pair_close(&p);
    return rc;
}
TEST(xf_gaes_export_works_after_exported_acceptex_ran)
{
    DWORD rc = t_run_child("xf_gaes_warm", "", 60000);
    CHECKF(rc == 0, "child result %lu", rc);
}

/* ---- exported AcceptEx / TransmitFile wrappers: the lookup failures surface unchanged ----------------------- */

TEST(xf_export_acceptex_invalid_listener_is_notsock)
{
    typedef BOOL (WINAPI *ax_fn)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);
    ax_fn ax = (ax_fn)t_proc_in("mswsock.dll", "AcceptEx");
    BYTE buf[64]; DWORD got = 0; WSAOVERLAPPED ov;
    NEED_NET();
    REQUIRE(ax);
    memset(&ov, 0, sizeof ov);
    WSASetLastError(0);
    CHECK(!ax(INVALID_SOCKET, INVALID_SOCKET, buf, 0, 32, 32, &got, &ov));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}
TEST(xf_export_acceptex_closed_listener_is_notsock)
{
    typedef BOOL (WINAPI *ax_fn)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);
    ax_fn ax = (ax_fn)t_proc_in("mswsock.dll", "AcceptEx");
    struct sockaddr_in a; SOCKET l; BYTE buf[64]; DWORD got = 0; WSAOVERLAPPED ov;
    NEED_NET();
    REQUIRE(ax);
    l = xf_listener(&a, 1);
    REQUIRE(l != INVALID_SOCKET);
    closesocket(l);
    memset(&ov, 0, sizeof ov);
    WSASetLastError(0);
    CHECK(!ax(l, INVALID_SOCKET, buf, 0, 32, 32, &got, &ov));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}
TEST(xf_export_transmitfile_invalid_socket_is_notsock)
{
    typedef BOOL (WINAPI *tf_fn)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);
    tf_fn tf = (tf_fn)t_proc_in("mswsock.dll", "TransmitFile");
    NEED_NET();
    REQUIRE(tf);
    WSASetLastError(0);
    CHECK(!tf(INVALID_SOCKET, NULL, 0, 0, NULL, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}
TEST(xf_export_transmitfile_unconnected_is_notconn)
{
    typedef BOOL (WINAPI *tf_fn)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);
    tf_fn tf = (tf_fn)t_proc_in("mswsock.dll", "TransmitFile");
    SOCKET s;
    NEED_NET();
    REQUIRE(tf);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(0);
    CHECK(!tf(s, NULL, 0, 0, NULL, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}
TEST(xf_export_transmitfile_sends_header_buffer)
{
    typedef BOOL (WINAPI *tf_fn)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);
    tf_fn tf = (tf_fn)t_proc_in("mswsock.dll", "TransmitFile");
    TRANSMIT_FILE_BUFFERS tb; char head[] = "exported-wrapper", got[32];
    REQUIRE(tf);
    PAIR(p);
    memset(&tb, 0, sizeof tb);
    tb.Head = head; tb.HeadLength = sizeof head - 1;
    WSASetLastError(0);
    CHECKF(tf(p.cli, NULL, 0, 0, NULL, &tb, 0), "err=%d", WSAGetLastError());
    memset(got, 0, sizeof got);
    EXPECT_EQ(xf_read_all(p.srv, got, sizeof head - 1), sizeof head - 1);
    CHECK(!memcmp(got, head, sizeof head - 1));
    xf_pair_close(&p);
}
TEST(xf_export_transmitfile_and_looked_up_function_agree_on_errors)
{
    typedef BOOL (WINAPI *tf_fn)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);
    GUID g = WSAID_TRANSMITFILE; tf_fn viaexp = (tf_fn)t_proc_in("mswsock.dll", "TransmitFile"), viaptr = (tf_fn)xf_fn(&g);
    SOCKET s; int e1, e2;
    NEED_NET();
    REQUIRE(viaexp && viaptr);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(0); CHECK(!viaexp(s, NULL, 0, 0, NULL, NULL, 0)); e1 = WSAGetLastError();
    WSASetLastError(0); CHECK(!viaptr(s, NULL, 0, 0, NULL, NULL, 0)); e2 = WSAGetLastError();
    EXPECT_EQ(e1, e2);
    closesocket(s);
}

/* ---- WSARecvEx (exported by the provider module) --------------------------------------------------------- */

typedef int (WINAPI *recvex_fn)(SOCKET, char *, int, int *);
#define NEED_RECVEX(f) recvex_fn f = (recvex_fn)t_proc_in("mswsock.dll", "WSARecvEx"); do { if (!f) { t_skip("WSARecvEx missing"); return; } } while (0)

TEST(xf_recvex_invalid_socket_is_notsock_and_zeroes_flags)
{
    char b[4]; int fl = 0x1234, r;
    NEED_NET(); NEED_RECVEX(f);
    WSASetLastError(0);
    r = f(INVALID_SOCKET, b, sizeof b, &fl);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    EXPECT_EQ(fl, 0);
}
TEST(xf_recvex_reads_stream_data_and_leaves_flags_zero)
{
    char b[16]; int fl = 0x7777, r;
    NEED_RECVEX(f);
    PAIR(p);
    CHECK(send(p.cli, "abcdef", 6, 0) == 6);
    WAIT_READABLE(p.srv);
    memset(b, 0, sizeof b);
    r = f(p.srv, b, sizeof b, &fl);
    EXPECT_EQ(r, 6);
    CHECK(!memcmp(b, "abcdef", 6));
    EXPECT_EQ(fl, 0);
    xf_pair_close(&p);
}
TEST(xf_recvex_ignores_incoming_flag_value_so_peek_is_not_requested)
{
    /* The wrapper clears the flags before receiving, so a MSG_PEEK passed in is not honoured: the data is consumed. */
    char b[8]; int fl = MSG_PEEK, r;
    NEED_RECVEX(f);
    PAIR(p);
    CHECK(send(p.cli, "xyz", 3, 0) == 3);
    WAIT_READABLE(p.srv);
    r = f(p.srv, b, sizeof b, &fl);
    EXPECT_EQ(r, 3);
    CHECK(!xf_readable(p.srv, 200));     /* nothing left: it was consumed */
    xf_pair_close(&p);
}
TEST(xf_recvex_truncated_datagram_reports_partial)
{
    SOCKET a, b; struct sockaddr_in addr; int len = sizeof addr, fl = 0, r; char buf[4];
    NEED_NET(); NEED_RECVEX(f);
    a = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    b = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(a != INVALID_SOCKET && b != INVALID_SOCKET);
    xf_loop4(&addr);
    CHECK(bind(a, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(getsockname(a, (struct sockaddr *)&addr, &len) == 0);
    CHECK(sendto(b, "0123456789", 10, 0, (struct sockaddr *)&addr, sizeof addr) == 10);
    WAIT_READABLE(a);
    WSASetLastError(0);
    r = f(a, buf, sizeof buf, &fl);
    CHECKF(r == 4, "returned %d err=%d", r, WSAGetLastError());
    CHECKF(fl & MSG_PARTIAL, "flags 0x%x", fl);
    closesocket(a); closesocket(b);
}
TEST(xf_recvex_complete_datagram_has_no_partial_flag)
{
    SOCKET a, b; struct sockaddr_in addr; int len = sizeof addr, fl = 0x55, r; char buf[16];
    NEED_NET(); NEED_RECVEX(f);
    a = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    b = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(a != INVALID_SOCKET && b != INVALID_SOCKET);
    xf_loop4(&addr);
    CHECK(bind(a, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(getsockname(a, (struct sockaddr *)&addr, &len) == 0);
    CHECK(sendto(b, "0123", 4, 0, (struct sockaddr *)&addr, sizeof addr) == 4);
    WAIT_READABLE(a);
    r = f(a, buf, sizeof buf, &fl);
    EXPECT_EQ(r, 4);
    EXPECT_EQ(fl, 0);
    closesocket(a); closesocket(b);
}
TEST(xf_recvex_graceful_close_returns_zero)
{
    char b[4]; int fl = 0, r;
    NEED_RECVEX(f);
    PAIR(p);
    shutdown(p.cli, SD_SEND);
    WAIT_READABLE(p.srv);
    r = f(p.srv, b, sizeof b, &fl);
    EXPECT_EQ(r, 0);
    xf_pair_close(&p);
}
TEST(xf_recvex_nonblocking_empty_is_wouldblock)
{
    char b[4]; int fl = 0, r; u_long one = 1;
    NEED_RECVEX(f);
    PAIR(p);
    CHECK(ioctlsocket(p.srv, FIONBIO, &one) == 0);
    WSASetLastError(0);
    r = f(p.srv, b, sizeof b, &fl);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    xf_pair_close(&p);
}
