/* Bounded create/close soak: 2000 cycles per socket flavour and per lifecycle shape. Each cycle must succeed,
 * every created value must be a distinct-while-open nonzero multiple of four, closing must succeed once and
 * fail with WSAENOTSOCK the second time, and the process handle count after the loop must stay within a small
 * constant of the baseline taken after one warm-up cycle (no per-cycle leak). */
#include "xs.h"

#define CYCLES 2000
#define HANDLE_SLACK 6

typedef struct { const char *name; int af, type, proto; DWORD flags; } flavour;

static const flavour kFlavours[] = {
    { "tcp4",            AF_INET,  SOCK_STREAM, IPPROTO_TCP, 0 },
    { "udp4",            AF_INET,  SOCK_DGRAM,  IPPROTO_UDP, 0 },
    { "tcp6",            AF_INET6, SOCK_STREAM, IPPROTO_TCP, 0 },
    { "udp6",            AF_INET6, SOCK_DGRAM,  IPPROTO_UDP, 0 },
    { "tcp4_ovl",        AF_INET,  SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED },
    { "udp4_ovl",        AF_INET,  SOCK_DGRAM,  IPPROTO_UDP, WSA_FLAG_OVERLAPPED },
    { "tcp4_noinherit",  AF_INET,  SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT },
    { "udp4_noinherit",  AF_INET,  SOCK_DGRAM,  IPPROTO_UDP, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT },
    { "tcp4_nonovl",     AF_INET,  SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_NO_HANDLE_INHERIT },
    { "unix_stream",     AF_UNIX,  SOCK_STREAM, 0, WSA_FLAG_OVERLAPPED },
    { "tcp4_proto0",     AF_INET,  SOCK_STREAM, 0, 0 },
    { "udp4_proto0",     AF_INET,  SOCK_DGRAM,  0, 0 },
};

static SOCKET make(const flavour *f)
{
    return WSASocketW(f->af, f->type, f->proto, NULL, 0, f->flags);
}

/* One flavour, plain create+close, the baseline relation and the double-close status. */
static void soak_create_close(const flavour *f)
{
    int i, bad_make = 0, bad_close = 0, bad_double = 0, bad_val = 0;
    DWORD base, after;
    SOCKET warm;
    XS_BEGIN();
    warm = make(f);
    if (warm == INVALID_SOCKET) {
        t_skip("%s sockets not available (error %d)", f->name, WSAGetLastError());
        xs_end(); return;
    }
    closesocket(warm);
    base = xs_handles();
    for (i = 0; i < CYCLES; i++) {
        SOCKET s = make(f);
        if (s == INVALID_SOCKET) { bad_make++; continue; }
        if (s == 0 || (s & 3)) bad_val++;
        if (closesocket(s) != 0) bad_close++;
        WSASetLastError(0);
        if (closesocket(s) != SOCKET_ERROR || WSAGetLastError() != WSAENOTSOCK) bad_double++;
    }
    after = xs_handles();
    EXPECT_EQ(bad_make, 0);
    EXPECT_EQ(bad_close, 0);
    EXPECT_EQ(bad_val, 0);
    EXPECT_EQ(bad_double, 0);
    CHECKF(after <= base + HANDLE_SLACK, "handles before %lu after %lu", base, after);
    xs_end();
}
#define FLAVOUR_TEST(idx, id) TEST(soak_create_close_2000_##id) { soak_create_close(&kFlavours[idx]); }
FLAVOUR_TEST(0, tcp4)
FLAVOUR_TEST(1, udp4)
FLAVOUR_TEST(2, tcp6)
FLAVOUR_TEST(3, udp6)
FLAVOUR_TEST(4, tcp4_ovl)
FLAVOUR_TEST(5, udp4_ovl)
FLAVOUR_TEST(6, tcp4_noinherit)
FLAVOUR_TEST(7, udp4_noinherit)
FLAVOUR_TEST(8, tcp4_nonovl)
FLAVOUR_TEST(9, unix_stream)
FLAVOUR_TEST(10, tcp4_proto0)
FLAVOUR_TEST(11, udp4_proto0)

/* The flavour table itself: create a few of each simultaneously; every value distinct and valid. */
TEST(soak_values_distinct_while_open_per_flavour)
{
    size_t k;
    XS_BEGIN();
    for (k = 0; k < sizeof kFlavours / sizeof kFlavours[0]; k++) {
        SOCKET s[64];
        int i, j, made = 0, dup = 0;
        for (i = 0; i < 64; i++) { s[i] = make(&kFlavours[k]); if (s[i] != INVALID_SOCKET) made++; }
        if (made == 0) { t_note("%s: not available", kFlavours[k].name); continue; }
        EXPECT_EQ(made, 64);
        for (i = 0; i < 64; i++) for (j = i + 1; j < 64; j++)
            if (s[i] != INVALID_SOCKET && s[i] == s[j]) dup++;
        EXPECT_EQ(dup, 0);
        for (i = 0; i < 64; i++) if (s[i] != INVALID_SOCKET) closesocket(s[i]);
    }
    xs_end();
}

/* Create, bind to an ephemeral loopback port, close. The next cycle must be able to bind again. */
static void soak_bind(int type, int proto)
{
    int i, bad = 0;
    DWORD base, after;
    XS_BEGIN();
    { SOCKET w = socket(AF_INET, type, proto); closesocket(w); }
    base = xs_handles();
    for (i = 0; i < CYCLES; i++) {
        struct sockaddr_in a; SOCKET s = socket(AF_INET, type, proto);
        xs_lo4(&a, 0);
        if (s == INVALID_SOCKET || bind(s, (struct sockaddr *)&a, sizeof a) != 0) bad++;
        if (s != INVALID_SOCKET) closesocket(s);
    }
    after = xs_handles();
    EXPECT_EQ(bad, 0);
    CHECKF(after <= base + HANDLE_SLACK, "handles before %lu after %lu", base, after);
    xs_end();
}
TEST(soak_bind_close_2000_tcp) { soak_bind(SOCK_STREAM, IPPROTO_TCP); }
TEST(soak_bind_close_2000_udp) { soak_bind(SOCK_DGRAM, IPPROTO_UDP); }

/* Listen then close. No port is pinned, so repeated listeners never collide. */
TEST(soak_listen_close_2000)
{
    int i, bad = 0;
    DWORD base, after;
    XS_BEGIN();
    { struct sockaddr_in a; SOCKET w = xs_listener(&a, 1); closesocket(w); }
    base = xs_handles();
    for (i = 0; i < CYCLES; i++) {
        struct sockaddr_in a; SOCKET s = xs_listener(&a, 1 + (i & 7));
        if (s == INVALID_SOCKET) bad++; else closesocket(s);
    }
    after = xs_handles();
    EXPECT_EQ(bad, 0);
    CHECKF(after <= base + HANDLE_SLACK, "handles before %lu after %lu", base, after);
    xs_end();
}

/* Create, attach an event with WSAEventSelect, close socket then event. */
static void soak_eventselect(int type, int proto)
{
    int i, bad = 0;
    DWORD base, after;
    XS_BEGIN();
    base = xs_handles();
    for (i = 0; i < CYCLES; i++) {
        SOCKET s = socket(AF_INET, type, proto);
        WSAEVENT e = WSACreateEvent();
        if (s == INVALID_SOCKET || e == WSA_INVALID_EVENT) { bad++; }
        else if (WSAEventSelect(s, e, FD_READ | FD_WRITE | FD_CLOSE) != 0) bad++;
        if (s != INVALID_SOCKET) closesocket(s);
        if (e != WSA_INVALID_EVENT) WSACloseEvent(e);
    }
    after = xs_handles();
    EXPECT_EQ(bad, 0);
    CHECKF(after <= base + HANDLE_SLACK, "handles before %lu after %lu", base, after);
    xs_end();
}
TEST(soak_eventselect_close_2000_tcp) { soak_eventselect(SOCK_STREAM, IPPROTO_TCP); }
TEST(soak_eventselect_close_2000_udp) { soak_eventselect(SOCK_DGRAM, IPPROTO_UDP); }

/* Option round trip per cycle: a set value reads back as set on a fresh socket every time. */
static void soak_options(int type, int proto)
{
    int i, bad = 0;
    XS_BEGIN();
    for (i = 0; i < CYCLES; i++) {
        SOCKET s = socket(AF_INET, type, proto);
        DWORD v = 1000 + (i & 15), got = 0; int len = sizeof got;
        if (s == INVALID_SOCKET) { bad++; continue; }
        if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&v, sizeof v) != 0) bad++;
        if (getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&got, &len) != 0 || got != v) bad++;
        closesocket(s);
    }
    EXPECT_EQ(bad, 0);
    xs_end();
}
TEST(soak_rcvtimeo_roundtrip_2000_tcp) { soak_options(SOCK_STREAM, IPPROTO_TCP); }
TEST(soak_rcvtimeo_roundtrip_2000_udp) { soak_options(SOCK_DGRAM, IPPROTO_UDP); }

/* A fresh socket reports its documented initial type and not-connected state every cycle. */
TEST(soak_fresh_socket_reports_type_and_unconnected_2000)
{
    int i, bad_type = 0, bad_conn = 0;
    XS_BEGIN();
    for (i = 0; i < CYCLES; i++) {
        int type = (i & 1) ? SOCK_DGRAM : SOCK_STREAM, got = 0, len = sizeof got;
        SOCKET s = socket(AF_INET, type, 0);
        struct sockaddr_in pn; int pl = sizeof pn;
        if (s == INVALID_SOCKET) { bad_type++; continue; }
        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&got, &len) != 0 || got != type) bad_type++;
        WSASetLastError(0);
        if (W(getpeername)(s, (struct sockaddr *)&pn, &pl) != SOCKET_ERROR || WSAGetLastError() != WSAENOTCONN) bad_conn++;
        closesocket(s);
    }
    EXPECT_EQ(bad_type, 0);
    EXPECT_EQ(bad_conn, 0);
    xs_end();
}

/* Connected pairs: 1000 pairs, client hard-closed (RST) so no TIME_WAIT piles up. Handle relation holds. */
TEST(soak_connected_pairs_1000_leave_handles_flat)
{
    int i, bad = 0, echoed = 0;
    DWORD base, after;
    XS_BEGIN();
    { SOCKET c, s; if (xs_pair(&c, &s)) { closesocket(c); closesocket(s); } }
    base = xs_handles();
    for (i = 0; i < 1000; i++) {
        SOCKET c, s; char b = 0;
        LINGER lg = { 1, 0 };
        if (!xs_pair(&c, &s)) { bad++; continue; }
        setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
        setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
        if (send(c, "x", 1, 0) == 1 && recv(s, &b, 1, 0) == 1 && b == 'x') echoed++;
        closesocket(c); closesocket(s);
    }
    after = xs_handles();
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(echoed, 1000);
    CHECKF(after <= base + HANDLE_SLACK, "handles before %lu after %lu", base, after);
    xs_end();
}

/* A pending overlapped datagram receive is cancelled by close each cycle; the event is signalled once. */
TEST(soak_close_with_pending_overlapped_recv_1000_udp)
{
    int i, bad = 0, signalled = 0;
    DWORD base, after;
    XS_BEGIN();
    base = xs_handles();
    for (i = 0; i < 1000; i++) {
        struct sockaddr_in a; SOCKET s = xs_udp(&a);
        WSAOVERLAPPED ov; WSABUF wb; char buf[16]; DWORD got = 0, fl = 0;
        int r;
        if (s == INVALID_SOCKET) { bad++; continue; }
        memset(&ov, 0, sizeof ov);
        ov.hEvent = WSACreateEvent();
        wb.buf = buf; wb.len = sizeof buf;
        r = WSARecv(s, &wb, 1, &got, &fl, &ov, NULL);
        if (r != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING) bad++;
        closesocket(s);
        if (WaitForSingleObject(ov.hEvent, XS_WAIT_MS) == WAIT_OBJECT_0) signalled++;
        WSACloseEvent(ov.hEvent);
    }
    after = xs_handles();
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(signalled, 1000);
    CHECKF(after <= base + HANDLE_SLACK, "handles before %lu after %lu", base, after);
    xs_end();
}

/* Same with a pending overlapped stream receive on a connected socket. */
TEST(soak_close_with_pending_overlapped_recv_500_tcp)
{
    int i, bad = 0, signalled = 0;
    XS_BEGIN();
    for (i = 0; i < 500; i++) {
        SOCKET c, s; WSAOVERLAPPED ov; WSABUF wb; char buf[16]; DWORD got = 0, fl = 0;
        LINGER lg = { 1, 0 };
        if (!xs_pair_ex(&c, &s, WSA_FLAG_OVERLAPPED)) { bad++; continue; }
        setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
        memset(&ov, 0, sizeof ov);
        ov.hEvent = WSACreateEvent();
        wb.buf = buf; wb.len = sizeof buf;
        if (WSARecv(c, &wb, 1, &got, &fl, &ov, NULL) != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING) bad++;
        closesocket(c);
        if (WaitForSingleObject(ov.hEvent, XS_WAIT_MS) == WAIT_OBJECT_0) signalled++;
        WSACloseEvent(ov.hEvent);
        closesocket(s);
    }
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(signalled, 500);
    xs_end();
}

/* WSAStartup/WSACleanup pairs interleaved with socket creation: sockets work only inside the pair. */
TEST(soak_startup_socket_cleanup_cycles_1000)
{
    int i, bad_in = 0, bad_out = 0;
    for (i = 0; i < 1000; i++) {
        WSADATA d; SOCKET s;
        if (WSAStartup(MAKEWORD(2, 2), &d) != 0) { bad_in++; continue; }
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) bad_in++; else closesocket(s);
        WSACleanup();
    }
    EXPECT_EQ(bad_in, 0);
    WSASetLastError(0);
    { SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (s != INVALID_SOCKET) { bad_out++; closesocket(s); } }
    EXPECT_EQ(bad_out, 0);
    EXPECT_EQ(WSAGetLastError(), WSANOTINITIALISED);
}
