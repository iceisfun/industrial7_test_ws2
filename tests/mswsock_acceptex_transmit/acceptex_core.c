/* AcceptEx, reached both through the pointer SIO_GET_EXTENSION_FUNCTION_POINTER hands out and through the
 * mswsock.dll export: where the two routes diverge (the export asks the provider for the pointer first, so a
 * socket the provider cannot resolve fails before the kernel is involved), data-length protocol, completion
 * through a completion port, queued connections, concurrent calls, SO_UPDATE_ACCEPT_CONTEXT and the effect of
 * not calling it, and reuse of an accept socket.  Address-length validation and the basic invalid-socket
 * errors of the extension pointer are covered by other areas and are not repeated here. */
#include "mx.h"

#define ADDR4 ((DWORD)(sizeof(struct sockaddr_in) + 16))

struct ax {
    struct mx_ext x;
    SOCKET lst;
    struct sockaddr_in addr;
    OVERLAPPED ov;
    unsigned char buf[4096];
};

static int ax_open(struct ax *a, int listening)
{
    memset(a, 0, sizeof *a);
    a->lst = INVALID_SOCKET;
    if (!mx_up() || !mx_load_ext(&a->x)) return 0;
    a->lst = listening ? mx_listener(&a->addr, 8) : mx_bound(&a->addr);
    a->ov.hEvent = mx_event();
    return a->lst != INVALID_SOCKET && a->ov.hEvent;
}

static void ax_close(struct ax *a)
{
    if (a->lst != INVALID_SOCKET) mx_abort(a->lst, &a->ov);
    if (a->ov.hEvent) CloseHandle(a->ov.hEvent);
}

#define AX(a, listening) \
    do { if (!ax_open(&(a), (listening))) { ax_close(&(a)); t_skip("AcceptEx fixture unavailable"); return; } } while (0)

/* Post an AcceptEx through the extension pointer; returns 0 when it completed synchronously, else the error. */
static int ax_post(struct ax *a, SOCKET acc, DWORD rl, DWORD ll, DWORD rr, OVERLAPPED *ov)
{
    DWORD n = 0;
    BOOL r;
    ResetEvent(ov->hEvent);
    r = a->x.acceptex(a->lst, acc, a->buf, rl, ll, rr, &n, ov);
    return r ? 0 : mx_WSAGetLastError();
}

/* Connect a client to the listener; *local gets the client's own address. */
static SOCKET ax_client(struct ax *a, struct sockaddr_in *local)
{
    int len = sizeof *local;
    SOCKET c = mx_tcp();
    CHECK(c != INVALID_SOCKET && mx_connect(c, (struct sockaddr *)&a->addr, sizeof a->addr) == 0);
    if (local) CHECK(mx_getsockname(c, (struct sockaddr *)local, &len) == 0);
    return c;
}

static int ax_update(SOCKET acc, SOCKET lst)
{
    return mx_setsockopt(acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&lst, sizeof lst);
}

/* ---- export route versus extension pointer ------------------------------------------------------------- */

/* The mswsock export first asks the socket for the extension pointer with WSAIoctl; when that fails the
 * kernel is never reached, so the OVERLAPPED is left exactly as the caller prepared it. */
TEST(acceptex_export_with_invalid_listener_leaves_overlapped_untouched)
{
    struct ax a;
    BOOL r;
    DWORD n = 0;
    AX(a, 1);
    {
        SOCKET acc = mx_tcp();
        LPFN_ACCEPTEX fn = UIN("mswsock.dll", AcceptEx);
        REQUIRE(fn);
        a.ov.Internal = MX_POISON;
        mx_WSASetLastError(0);
        r = fn(INVALID_SOCKET, acc, a.buf, 0, ADDR4, ADDR4, &n, &a.ov);
        MX_EQ(r, FALSE);
        MX_EQ(mx_WSAGetLastError(), WSAENOTSOCK);
        MX_EQ((ULONG)a.ov.Internal, MX_POISON);
        mx_closesocket(acc);
    }
    ax_close(&a);
}

/* Through the extension pointer the same call does reach the kernel, which marks the request pending first. */
TEST(acceptex_pointer_with_invalid_listener_marks_overlapped_pending)
{
    struct ax a;
    SOCKET acc;
    AX(a, 1);
    acc = mx_tcp();
    a.ov.Internal = MX_POISON;
    mx_WSASetLastError(0);
    MX_EQ(a.x.acceptex(INVALID_SOCKET, acc, a.buf, 0, ADDR4, ADDR4, NULL, &a.ov), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTSOCK);
    MX_EQ((ULONG)a.ov.Internal, MX_STATUS_PENDING);
    mx_closesocket(acc);
    ax_close(&a);
}

/* A closed listener handle fails the provider lookup the same way as INVALID_SOCKET. */
TEST(acceptex_export_with_closed_listener_is_notsock)
{
    struct ax a;
    SOCKET dead, acc;
    DWORD n = 0;
    LPFN_ACCEPTEX fn = UIN("mswsock.dll", AcceptEx);
    AX(a, 1);
    REQUIRE(fn);
    dead = mx_tcp();
    acc = mx_tcp();            /* created first so the closed value cannot be handed out again */
    mx_closesocket(dead);
    a.ov.Internal = MX_POISON;
    mx_WSASetLastError(0);
    MX_EQ(fn(dead, acc, a.buf, 0, ADDR4, ADDR4, &n, &a.ov), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTSOCK);
    MX_EQ((ULONG)a.ov.Internal, MX_POISON);
    mx_closesocket(acc);
    ax_close(&a);
}

/* A handle that is not a socket at all (an event) is rejected by the provider lookup too. */
TEST(acceptex_export_with_non_socket_handle_is_notsock)
{
    struct ax a;
    SOCKET acc;
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    DWORD n = 0;
    LPFN_ACCEPTEX fn = UIN("mswsock.dll", AcceptEx);
    AX(a, 1);
    REQUIRE(fn);
    acc = mx_tcp();
    mx_WSASetLastError(0);
    MX_EQ(fn((SOCKET)ev, acc, a.buf, 0, ADDR4, ADDR4, &n, &a.ov), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTSOCK);
    mx_closesocket(acc);
    CloseHandle(ev);
    ax_close(&a);
}

/* Argument failures that do not depend on how the provider is reached must be identical on both routes. */
struct bad_case { const char *name; int listening; int acc_kind; int null_buf; int null_ov; int err; };
enum { ACC_FRESH, ACC_INVALID, ACC_UDP };

TEST(acceptex_export_and_pointer_report_the_same_argument_errors)
{
    static const struct bad_case cases[] = {
        { "listener not listening",   0, ACC_FRESH,   0, 0, WSAEINVAL },
        { "invalid accept socket",    1, ACC_INVALID, 0, 0, WSAENOTSOCK },
        { "datagram accept socket",   1, ACC_UDP,     0, 0, WSAEINVAL },
        { "null overlapped",          1, ACC_FRESH,   0, 1, ERROR_INVALID_PARAMETER },
        { "null output buffer",       1, ACC_FRESH,   1, 0, WSAEFAULT },
    };
    LPFN_ACCEPTEX exp = UIN("mswsock.dll", AcceptEx);
    unsigned i, route;
    REQUIRE(exp);
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        for (route = 0; route < 2; route++) {
            struct ax a;
            SOCKET acc;
            BOOL r;
            DWORD n = 0;
            if (!ax_open(&a, cases[i].listening)) { ax_close(&a); t_skip("fixture"); return; }
            acc = cases[i].acc_kind == ACC_INVALID ? INVALID_SOCKET
                : cases[i].acc_kind == ACC_UDP ? mx_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : mx_tcp();
            mx_WSASetLastError(0);
            r = (route ? exp : a.x.acceptex)(a.lst, acc, cases[i].null_buf ? NULL : a.buf, 0, ADDR4, ADDR4, &n,
                                             cases[i].null_ov ? NULL : &a.ov);
            t_check(r == FALSE, __FILE__, __LINE__, cases[i].name, "route %u unexpectedly succeeded", route);
            t_check(mx_WSAGetLastError() == cases[i].err, __FILE__, __LINE__, cases[i].name,
                    "route %u error %d want %d", route, mx_WSAGetLastError(), cases[i].err);
            if (acc != INVALID_SOCKET) mx_closesocket(acc);
            ax_close(&a);
        }
    }
}

/* A complete accept through the export: the connection is delivered, bytes are zero without receive data, and
 * GetAcceptExSockaddrs (also through its export) reports the connecting peer. */
TEST(acceptex_export_accepts_a_connection_and_sockaddrs_export_parses_it)
{
    struct ax a;
    SOCKET acc, cli;
    struct sockaddr_in local, *pl = NULL, *pr = NULL;
    int ll = 0, rl = 0;
    DWORD n = MX_POISON, err = 0;
    BOOL r;
    LPFN_ACCEPTEX fn = UIN("mswsock.dll", AcceptEx);
    LPFN_GETACCEPTEXSOCKADDRS gs = UIN("mswsock.dll", GetAcceptExSockaddrs);
    AX(a, 1);
    REQUIRE(fn); REQUIRE(gs);
    acc = mx_tcp();
    r = fn(a.lst, acc, a.buf, 0, ADDR4, ADDR4, &n, &a.ov);
    t_check(r || mx_WSAGetLastError() == ERROR_IO_PENDING, __FILE__, __LINE__, "export posts", "err %d", mx_WSAGetLastError());
    cli = ax_client(&a, &local);
    CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    MX_EQ(n, 0);
    gs(a.buf, 0, ADDR4, ADDR4, (struct sockaddr **)&pl, &ll, (struct sockaddr **)&pr, &rl);
    CHECK(pl && pr);
    if (pl && pr) {
        MX_EQ(ll, sizeof(struct sockaddr_in));
        MX_EQ(rl, sizeof(struct sockaddr_in));
        CHECK(!memcmp(pr, &local, sizeof local));
        MX_EQ(pl->sin_port, a.addr.sin_port);
    }
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* With receive space the export path completes on data and reports the byte count. */
TEST(acceptex_export_completes_on_first_data_with_byte_count)
{
    struct ax a;
    SOCKET acc, cli;
    DWORD n = 0, err = 0;
    LPFN_ACCEPTEX fn = UIN("mswsock.dll", AcceptEx);
    AX(a, 1);
    REQUIRE(fn);
    acc = mx_tcp();
    fn(a.lst, acc, a.buf, 16, ADDR4, ADDR4, &n, &a.ov);
    cli = ax_client(&a, NULL);
    CHECK(WaitForSingleObject(a.ov.hEvent, 300) == WAIT_TIMEOUT);   /* no data yet: the call stays pending */
    MX_EQ(mx_send(cli, "xyz", 3, 0), 3);
    CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    MX_EQ(n, 3);
    CHECK(!memcmp(a.buf, "xyz", 3));
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* Every pointer family the provider offers is one function: two TCP sockets resolve the same AcceptEx. */
TEST(acceptex_pointer_is_identical_across_sockets)
{
    SOCKET s1, s2;
    GUID g = WSAID_ACCEPTEX;
    NEED_NET();
    s1 = mx_tcp();
    s2 = mx_tcp();
    CHECK(mx_ext_lookup(s1, g) != NULL);
    CHECK(mx_ext_lookup(s1, g) == mx_ext_lookup(s2, g));
    mx_closesocket(s1);
    mx_closesocket(s2);
}

TEST(acceptex_pointer_differs_from_export_entry)
{
    SOCKET s;
    GUID g = WSAID_ACCEPTEX;
    FARPROC exp = (FARPROC)UIN("mswsock.dll", AcceptEx);
    NEED_NET();
    REQUIRE(exp);
    s = mx_tcp();
    /* The export is a thin wrapper that resolves and then calls the provider function. */
    CHECK((void *)exp != mx_ext_lookup(s, g));
    mx_closesocket(s);
}

/* ---- receive-data length protocol ------------------------------------------------------------------------ */

/* The call completes as soon as any data arrives, even when less than the reserved space. */
TEST(acceptex_completes_with_fewer_bytes_than_reserved)
{
    struct ax a;
    SOCKET acc, cli;
    DWORD n = 0, err = 0;
    AX(a, 1);
    acc = mx_tcp();
    MX_EQ(ax_post(&a, acc, 64, ADDR4, ADDR4, &a.ov), ERROR_IO_PENDING);
    cli = ax_client(&a, NULL);
    MX_EQ(mx_send(cli, "hello", 5, 0), 5);
    CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    MX_EQ(n, 5);
    CHECK(!memcmp(a.buf, "hello", 5));
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* More data than reserved: exactly the reserved amount lands in the buffer, the rest stays readable. */
TEST(acceptex_surplus_data_stays_on_the_accepted_socket)
{
    struct ax a;
    SOCKET acc, cli;
    unsigned char msg[100], got[100];
    DWORD n = 0, err = 0;
    int i;
    AX(a, 1);
    for (i = 0; i < 100; i++) msg[i] = (unsigned char)(i + 1);
    acc = mx_tcp();
    MX_EQ(ax_post(&a, acc, 40, ADDR4, ADDR4, &a.ov), ERROR_IO_PENDING);
    cli = ax_client(&a, NULL);
    MX_EQ(mx_send(cli, (char *)msg, 100, 0), 100);
    CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    CHECK(n >= 1 && n <= 40);
    CHECK(!memcmp(a.buf, msg, n));
    /* Whatever AcceptEx did not take is still in the accepted socket's receive queue, in order. */
    MX_EQ(mx_recv_all(acc, got, 100 - n, 5000), 100 - n);
    CHECK(!memcmp(got, msg + n, 100 - n));
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* With zero receive length the call completes on connection alone and later data is plain stream data. */
TEST(acceptex_zero_receive_length_leaves_all_data_on_the_socket)
{
    struct ax a;
    SOCKET acc, cli;
    DWORD n = MX_POISON, err = 0;
    char b[8] = {0};
    AX(a, 1);
    acc = mx_tcp();
    MX_EQ(ax_post(&a, acc, 0, ADDR4, ADDR4, &a.ov), ERROR_IO_PENDING);
    cli = ax_client(&a, NULL);
    CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    MX_EQ(n, 0);
    MX_EQ(mx_send(cli, "ping", 4, 0), 4);
    MX_EQ(mx_recv_all(acc, b, 4, 5000), 4);
    CHECK(!memcmp(b, "ping", 4));
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* ---- buffer layout --------------------------------------------------------------------------------------- */

static void check_v4_slot(const unsigned char *slot, DWORD slot_len, const struct sockaddr_in *want, const char *what)
{
    struct sockaddr_in got;
    unsigned short len = (unsigned short)(slot[slot_len - 2] | (slot[slot_len - 1] << 8));
    memcpy(&got, slot, sizeof got);
    t_check(len == sizeof(struct sockaddr_in), __FILE__, __LINE__, what, "length field %u", len);
    t_check(got.sin_family == AF_INET && got.sin_port == want->sin_port && got.sin_addr.s_addr == want->sin_addr.s_addr,
            __FILE__, __LINE__, what, "address bytes differ");
}

/* The kernel lays the buffer out as [data][local slot][remote slot]; each slot starts with the sockaddr and
 * ends with a 16-bit length, whatever the slot size. */
static void layout_case(DWORD rl, DWORD ll, DWORD rr)
{
    struct ax a;
    SOCKET acc, cli;
    struct sockaddr_in local;
    DWORD n = 0, err = 0, total = rl + ll + rr;
    AX(a, 1);
    memset(a.buf, 0xCD, sizeof a.buf);
    acc = mx_tcp();
    MX_EQ(ax_post(&a, acc, rl, ll, rr, &a.ov), ERROR_IO_PENDING);
    cli = ax_client(&a, &local);
    if (rl) MX_EQ(mx_send(cli, "0123456789abcdef0123456789abcdef", (int)rl > 32 ? 32 : (int)rl, 0), (int)rl > 32 ? 32 : (int)rl);
    CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    check_v4_slot(a.buf + rl, ll, &a.addr, "local slot is the listener address");
    check_v4_slot(a.buf + rl + ll, rr, &local, "remote slot is the client address");
    {
        DWORD i, clean = 1;
        for (i = total; i < total + 64; i++) if (a.buf[i] != 0xCD) clean = 0;
        t_check(clean, __FILE__, __LINE__, "bytes after the remote slot untouched", "buffer overrun");
    }
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}
TEST(acceptex_layout_minimum_slots)          { layout_case(0, ADDR4, ADDR4); }
TEST(acceptex_layout_wide_slots)             { layout_case(0, ADDR4 + 100, ADDR4 + 40); }
TEST(acceptex_layout_asymmetric_slots)       { layout_case(0, ADDR4 + 8, ADDR4 + 200); }
TEST(acceptex_layout_with_receive_data)      { layout_case(32, ADDR4, ADDR4); }
TEST(acceptex_layout_with_receive_data_wide) { layout_case(32, ADDR4 + 64, ADDR4 + 64); }

TEST(acceptex_received_data_occupies_only_the_front_of_the_buffer)
{
    struct ax a;
    SOCKET acc, cli;
    DWORD n = 0, err = 0, i, clean = 1;
    AX(a, 1);
    memset(a.buf, 0xCD, sizeof a.buf);
    acc = mx_tcp();
    MX_EQ(ax_post(&a, acc, 8, ADDR4, ADDR4, &a.ov), ERROR_IO_PENDING);
    cli = ax_client(&a, NULL);
    MX_EQ(mx_send(cli, "AB", 2, 0), 2);
    CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    MX_EQ(n, 2);
    CHECK(a.buf[0] == 'A' && a.buf[1] == 'B');
    /* The reserved space beyond the two received bytes is not zeroed or reused. */
    for (i = 2; i < 8; i++) if (a.buf[i] != 0xCD) clean = 0;
    CHECK(clean);
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* An IPv6 listener needs sizeof(sockaddr_in6)+16 per slot, and the slot length field reads 28. */
TEST(acceptex_ipv6_listener_slots)
{
    struct ax a;
    SOCKET lst6, acc, cli;
    struct sockaddr_in6 sa, peer, *pl = NULL, *pr = NULL;
    int len = sizeof sa, ll = 0, rl = 0;
    DWORD slot = (DWORD)sizeof(struct sockaddr_in6) + 16, n = 0, err = 0;
    AX(a, 1);
    lst6 = mx_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (lst6 == INVALID_SOCKET) { ax_close(&a); t_skip("no IPv6"); return; }
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.u.Byte[15] = 1;
    if (mx_bind(lst6, (struct sockaddr *)&sa, sizeof sa) || mx_listen(lst6, 4) ||
        mx_getsockname(lst6, (struct sockaddr *)&sa, &len)) {
        mx_closesocket(lst6); ax_close(&a); t_skip("IPv6 loopback unavailable"); return;
    }
    acc = mx_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    n = 0;
    ResetEvent(a.ov.hEvent);
    a.x.acceptex(lst6, acc, a.buf, 0, slot, slot, &n, &a.ov);
    cli = mx_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    CHECK(mx_connect(cli, (struct sockaddr *)&sa, sizeof sa) == 0);
    len = sizeof peer;
    CHECK(mx_getsockname(cli, (struct sockaddr *)&peer, &len) == 0);
    CHECK(mx_ov_done(lst6, &a.ov, &n, 5000, &err));
    a.x.gaes(a.buf, 0, slot, slot, (struct sockaddr **)&pl, &ll, (struct sockaddr **)&pr, &rl);
    MX_EQ(ll, sizeof(struct sockaddr_in6));
    MX_EQ(rl, sizeof(struct sockaddr_in6));
    CHECK(pl && pr && !memcmp(&pl->sin6_addr, &sa.sin6_addr, 16) && pl->sin6_port == sa.sin6_port);
    CHECK(pr && !memcmp(&pr->sin6_addr, &peer.sin6_addr, 16) && pr->sin6_port == peer.sin6_port);
    mx_closesocket(cli);
    mx_closesocket(acc);
    mx_abort(lst6, &a.ov);
    ax_close(&a);
}

/* ---- queues and concurrency ----------------------------------------------------------------------------- */

#define NCONC 4
TEST(acceptex_concurrent_calls_each_take_one_connection)
{
    struct ax a;
    SOCKET acc[NCONC], cli[NCONC];
    OVERLAPPED ov[NCONC];
    struct sockaddr_in local[NCONC];
    unsigned char bufs[NCONC][ADDR4 * 2];
    int i, j, seen[NCONC] = {0};
    AX(a, 1);
    for (i = 0; i < NCONC; i++) {
        DWORD n = 0;
        memset(&ov[i], 0, sizeof ov[i]);
        ov[i].hEvent = mx_event();
        acc[i] = mx_tcp();
        a.x.acceptex(a.lst, acc[i], bufs[i], 0, ADDR4, ADDR4, &n, &ov[i]);
        MX_EQ(mx_WSAGetLastError(), ERROR_IO_PENDING);
    }
    for (i = 0; i < NCONC; i++) cli[i] = ax_client(&a, &local[i]);
    for (i = 0; i < NCONC; i++) {
        DWORD n = 0, err = 0;
        struct sockaddr_in *pr = NULL, *pl = NULL;
        int ll = 0, rl = 0;
        CHECK(mx_ov_done(a.lst, &ov[i], &n, 5000, &err));
        a.x.gaes(bufs[i], 0, ADDR4, ADDR4, (struct sockaddr **)&pl, &ll, (struct sockaddr **)&pr, &rl);
        for (j = 0; pr && j < NCONC; j++) if (pr->sin_port == local[j].sin_port) seen[j]++;
    }
    /* Each client port shows up exactly once across the four completions. */
    for (j = 0; j < NCONC; j++) MX_EQ(seen[j], 1);
    for (i = 0; i < NCONC; i++) {
        mx_closesocket(cli[i]);
        mx_closesocket(acc[i]);
        CloseHandle(ov[i].hEvent);
    }
    ax_close(&a);
}

TEST(acceptex_connections_queued_before_the_call_are_still_delivered)
{
    struct ax a;
    SOCKET acc[3], cli[3];
    struct sockaddr_in local[3];
    int i, j, seen[3] = {0};
    AX(a, 1);
    for (i = 0; i < 3; i++) cli[i] = ax_client(&a, &local[i]);
    for (i = 0; i < 3; i++) {
        OVERLAPPED ov;
        unsigned char b[ADDR4 * 2];
        struct sockaddr_in *pl = NULL, *pr = NULL;
        int ll = 0, rl = 0, e;
        DWORD n = 0, err = 0;
        memset(&ov, 0, sizeof ov);
        ov.hEvent = mx_event();
        acc[i] = mx_tcp();
        e = 0;
        if (!a.x.acceptex(a.lst, acc[i], b, 0, ADDR4, ADDR4, &n, &ov)) e = mx_WSAGetLastError();
        t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "post queued accept", "error %d", e);
        CHECK(mx_ov_done(a.lst, &ov, &n, 5000, &err));
        a.x.gaes(b, 0, ADDR4, ADDR4, (struct sockaddr **)&pl, &ll, (struct sockaddr **)&pr, &rl);
        for (j = 0; pr && j < 3; j++) if (pr->sin_port == local[j].sin_port) seen[j]++;
        CloseHandle(ov.hEvent);
    }
    for (j = 0; j < 3; j++) MX_EQ(seen[j], 1);
    for (i = 0; i < 3; i++) { mx_closesocket(cli[i]); mx_closesocket(acc[i]); }
    ax_close(&a);
}

/* A call that fails validation leaves the accept socket unconsumed and reusable. */
TEST(acceptex_failed_call_leaves_accept_socket_usable)
{
    struct ax a;
    SOCKET acc, cli, nl;
    struct sockaddr_in unused;
    DWORD n = 0, err = 0;
    AX(a, 1);
    acc = mx_tcp();
    nl = mx_bound(&unused);   /* bound but not listening */
    mx_WSASetLastError(0);
    MX_EQ(a.x.acceptex(nl, acc, a.buf, 0, ADDR4, ADDR4, &n, &a.ov), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAEINVAL);
    MX_EQ(ax_post(&a, acc, 0, ADDR4, ADDR4, &a.ov), ERROR_IO_PENDING);
    cli = ax_client(&a, NULL);
    CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    mx_closesocket(nl);
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* ---- completion port -------------------------------------------------------------------------------------- */

TEST(acceptex_completion_port_packet_carries_key_overlapped_and_bytes)
{
    struct ax a;
    SOCKET acc, cli;
    HANDLE port;
    DWORD n = 0, got = MX_POISON;
    ULONG_PTR key = 0;
    OVERLAPPED *pov = NULL;
    AX(a, 1);
    port = CreateIoCompletionPort((HANDLE)a.lst, NULL, 0x5151, 0);
    CHECK(port != NULL);
    acc = mx_tcp();
    MX_EQ(ax_post(&a, acc, 16, ADDR4, ADDR4, &a.ov), ERROR_IO_PENDING);
    cli = ax_client(&a, NULL);
    MX_EQ(mx_send(cli, "abcd", 4, 0), 4);
    CHECK(GetQueuedCompletionStatus(port, &got, &key, &pov, 5000));
    MX_EQ(key, 0x5151);
    CHECK(pov == &a.ov);
    MX_EQ(got, 4);
    (void)n;
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
    CloseHandle(port);
}

TEST(acceptex_pending_call_hides_the_connection_from_select)
{
    struct ax a;
    SOCKET acc, cli;
    DWORD n = 0, err = 0;
    AX(a, 1);
    acc = mx_tcp();
    MX_EQ(ax_post(&a, acc, 0, ADDR4, ADDR4, &a.ov), ERROR_IO_PENDING);
    cli = ax_client(&a, NULL);
    CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    /* The connection was consumed by the extended accept, so a plain accept has nothing left to take. */
    CHECK(!mx_readable(a.lst, 200));
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* ---- SO_UPDATE_ACCEPT_CONTEXT and connection time ------------------------------------------------------- */

static int ax_accept_one(struct ax *a, SOCKET *acc, SOCKET *cli, struct sockaddr_in *local)
{
    DWORD n = 0, err = 0;
    *acc = mx_tcp();
    if (ax_post(a, *acc, 0, ADDR4, ADDR4, &a->ov) != ERROR_IO_PENDING) return 0;
    *cli = ax_client(a, local);
    return mx_ov_done(a->lst, &a->ov, &n, 5000, &err);
}

TEST(acceptex_context_update_succeeds_and_names_follow_the_listener)
{
    struct ax a;
    SOCKET acc, cli;
    struct sockaddr_in local, sn, pn;
    int l1 = sizeof sn, l2 = sizeof pn;
    AX(a, 1);
    CHECK(ax_accept_one(&a, &acc, &cli, &local));
    MX_EQ(ax_update(acc, a.lst), 0);
    MX_EQ(mx_getsockname(acc, (struct sockaddr *)&sn, &l1), 0);
    MX_EQ(mx_getpeername(acc, (struct sockaddr *)&pn, &l2), 0);
    MX_EQ(sn.sin_port, a.addr.sin_port);
    MX_EQ(pn.sin_port, local.sin_port);
    MX_EQ(pn.sin_addr.s_addr, local.sin_addr.s_addr);
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

TEST(acceptex_shutdown_after_context_update_gives_peer_end_of_stream)
{
    struct ax a;
    SOCKET acc, cli;
    AX(a, 1);
    CHECK(ax_accept_one(&a, &acc, &cli, NULL));
    MX_EQ(ax_update(acc, a.lst), 0);
    MX_EQ(mx_shutdown(acc, SD_SEND), 0);
    CHECK(mx_at_eof(cli, 5000));
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* Until the context is updated the Winsock layer does not know the socket is connected. */
TEST(acceptex_shutdown_and_names_without_context_update_are_notconn)
{
    struct ax a;
    SOCKET acc, cli;
    struct sockaddr_in sn;
    int len = sizeof sn;
    AX(a, 1);
    CHECK(ax_accept_one(&a, &acc, &cli, NULL));
    MX_EQ(mx_getpeername(acc, (struct sockaddr *)&sn, &len), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    MX_EQ(mx_shutdown(acc, SD_SEND), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* The option value is a SOCKET: a shorter length, or no value, is WSAEFAULT. */
TEST(acceptex_context_update_with_short_option_length_is_efault)
{
    struct ax a;
    SOCKET acc, cli;
    AX(a, 1);
    CHECK(ax_accept_one(&a, &acc, &cli, NULL));
    MX_EQ(mx_setsockopt(acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&a.lst, 2), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAEFAULT);
    MX_EQ(mx_setsockopt(acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, NULL, 0), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAEFAULT);
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

TEST(acceptex_connect_time_is_unset_before_and_set_after)
{
    struct ax a;
    SOCKET acc, cli;
    DWORD t = 0;
    int len = sizeof t;
    AX(a, 1);
    acc = mx_tcp();
    MX_EQ(mx_getsockopt(acc, SOL_SOCKET, SO_CONNECT_TIME, (char *)&t, &len), 0);
    MX_EQ(t, 0xFFFFFFFFUL);   /* documented sentinel for a socket that is not connected */
    MX_EQ(ax_post(&a, acc, 0, ADDR4, ADDR4, &a.ov), ERROR_IO_PENDING);
    cli = ax_client(&a, NULL);
    {
        DWORD n = 0, err = 0;
        CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
    }
    len = sizeof t;
    t = 0xFFFFFFFFUL;
    MX_EQ(mx_getsockopt(acc, SOL_SOCKET, SO_CONNECT_TIME, (char *)&t, &len), 0);
    CHECK(t != 0xFFFFFFFFUL && t < 60);
    mx_closesocket(cli);
    mx_closesocket(acc);
    ax_close(&a);
}

/* ---- reuse -------------------------------------------------------------------------------------------------- */

/* DisconnectEx(TF_REUSE_SOCKET) on the accepted socket makes the same handle usable for the next AcceptEx;
 * three rounds on one handle, data verified each time. */
TEST(acceptex_accept_socket_survives_three_reuse_rounds)
{
    struct ax a;
    SOCKET acc;
    int round;
    AX(a, 1);
    acc = mx_tcp();
    for (round = 0; round < 3; round++) {
        SOCKET cli;
        DWORD n = 0, err = 0;
        char b[4] = {0};
        char msg[4];
        sprintf(msg, "r%d", round);
        MX_EQ(ax_post(&a, acc, 0, ADDR4, ADDR4, &a.ov), ERROR_IO_PENDING);
        cli = ax_client(&a, NULL);
        CHECK(mx_ov_done(a.lst, &a.ov, &n, 5000, &err));
        MX_EQ(ax_update(acc, a.lst), 0);
        MX_EQ(mx_send(cli, msg, 3, 0), 3);
        MX_EQ(mx_recv_all(acc, b, 3, 5000), 3);
        CHECK(!memcmp(b, msg, 3));
        mx_closesocket(cli);
        CHECK(mx_reuse_disconnect(a.x.disconnectex, acc, INVALID_SOCKET));   /* the client is already closed */
    }
    mx_closesocket(acc);
    ax_close(&a);
}
