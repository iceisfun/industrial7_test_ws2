/* AcceptEx discovery: WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_ACCEPTEX) as a step of its own, kept apart from
 * the operation results of every other file.  Covers the output-size protocol, the GUID input-length rule, which socket
 * kinds are served, and that one pointer is handed out regardless of socket or family. */
#include "fx.h"

static const GUID g_acceptex = WSAID_ACCEPTEX;

static int lookup(SOCKET s, const GUID *g, DWORD gl, void *out, DWORD ol, DWORD *n)
{
    return fx_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (LPVOID)g, gl, out, ol, n, NULL, NULL);
}

/* The lookup succeeds and reports exactly one pointer's worth of output. */
FX_BOTH(disc_returns_one_pointer)
{
    SOCKET s; void *p = NULL; DWORD n = 0xFFFF;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    s = fx_stream(af);
    if (s == INVALID_SOCKET) { t_skip("family unavailable"); return; }
    CHECK(lookup(s, &g_acceptex, sizeof g_acceptex, &p, sizeof p, &n) == 0);
    EXPECT_EQ(n, sizeof(void *));
    CHECK(p != NULL);
    fx_closesocket(s);
}

/* Output buffers shorter than a pointer fail with WSAEFAULT and write no byte count. */
FX_BOTH(disc_output_shorter_than_a_pointer_is_efault)
{
    static const DWORD sizes[] = { 0, 1, 4, 7 };
    SOCKET s; unsigned i;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    s = fx_stream(af);
    if (s == INVALID_SOCKET) { t_skip("family unavailable"); return; }
    for (i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        void *p = NULL; DWORD n = 0x1234;
        int r = lookup(s, &g_acceptex, sizeof g_acceptex, &p, sizes[i], &n);
        CHECKF(r == SOCKET_ERROR, "out=%lu", sizes[i]);
        if (r == SOCKET_ERROR) FX_EQ(fx_WSAGetLastError(), WSAEFAULT);
        EXPECT_EQ(p, NULL);
    }
    fx_closesocket(s);
}

/* The output buffer may be larger than a pointer; the count stays at one pointer. */
FX_BOTH(disc_output_larger_than_a_pointer_reports_pointer_size)
{
    static const DWORD sizes[] = { 8, 9, 16, 64 };
    SOCKET s; unsigned i;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    s = fx_stream(af);
    if (s == INVALID_SOCKET) { t_skip("family unavailable"); return; }
    for (i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        unsigned char out[64]; DWORD n = 0;
        memset(out, 0, sizeof out);
        CHECKF(lookup(s, &g_acceptex, sizeof g_acceptex, out, sizes[i], &n) == 0, "out=%lu", sizes[i]);
        EXPECT_EQ(n, sizeof(void *));
    }
    fx_closesocket(s);
}

/* The GUID must be at least 16 bytes: 0, 15 are WSAEFAULT, 16 and 17 serve the pointer. */
FX_BOTH(disc_guid_input_length_protocol)
{
    static const struct { DWORD len; int ok; } rows[] = { {0, 0}, {1, 0}, {8, 0}, {15, 0}, {16, 1}, {17, 1} };
    GUID padded[2];
    SOCKET s; unsigned i;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    s = fx_stream(af);
    if (s == INVALID_SOCKET) { t_skip("family unavailable"); return; }
    memset(padded, 0, sizeof padded);
    padded[0] = g_acceptex;
    for (i = 0; i < sizeof rows / sizeof *rows; i++) {
        void *p = NULL; DWORD n = 0;
        int r = lookup(s, padded, rows[i].len, &p, sizeof p, &n);
        CHECKF((r == 0) == rows[i].ok, "len=%lu r=%d", rows[i].len, r);
        if (rows[i].ok) { CHECK(p != NULL); EXPECT_EQ(n, sizeof p); }
        else { FX_EQ(r, SOCKET_ERROR); FX_EQ(fx_WSAGetLastError(), WSAEFAULT); EXPECT_EQ(p, NULL); }
    }
    fx_closesocket(s);
}

/* No input buffer at all is the same WSAEFAULT as a short one. */
FX_BOTH(disc_null_guid_is_efault)
{
    SOCKET s; void *p = NULL; DWORD n = 0; int r;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    s = fx_stream(af);
    if (s == INVALID_SOCKET) { t_skip("family unavailable"); return; }
    r = fx_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, NULL, 0, &p, sizeof p, &n, NULL, NULL);
    FX_EQ(r, SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAEFAULT);
    fx_closesocket(s);
}

/* The pointer does not depend on the socket: TCP sockets, a listening socket and a datagram socket of the
 * same family all receive the same address, and so does a socket of the other family. */
FX_BOTH(disc_one_pointer_for_every_socket_kind)
{
    SOCKET tcp, lst, udp, other; fx_addr a; void *p0 = NULL, *p1 = NULL, *p2 = NULL, *p3 = NULL; DWORD n = 0;
    int oaf = af == AF_INET ? AF_INET6 : AF_INET;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    tcp = fx_stream(af);
    if (tcp == INVALID_SOCKET) { t_skip("family unavailable"); return; }
    lst = fx_listener_on(af, &a, 2);
    udp = fx_socket(af, SOCK_DGRAM, IPPROTO_UDP);
    other = fx_stream(oaf);
    CHECK(lookup(tcp, &g_acceptex, sizeof g_acceptex, &p0, sizeof p0, &n) == 0);
    CHECK(lst != INVALID_SOCKET && lookup(lst, &g_acceptex, sizeof g_acceptex, &p1, sizeof p1, &n) == 0);
    CHECK(udp != INVALID_SOCKET && lookup(udp, &g_acceptex, sizeof g_acceptex, &p2, sizeof p2, &n) == 0);
    EXPECT_EQ(p1, p0);
    EXPECT_EQ(p2, p0);
    if (other != INVALID_SOCKET) {
        CHECK(lookup(other, &g_acceptex, sizeof g_acceptex, &p3, sizeof p3, &n) == 0);
        EXPECT_EQ(p3, p0);
    } else t_note("other family unavailable");
    fx_close_all(tcp, lst, udp);
    if (other != INVALID_SOCKET) fx_closesocket(other);
}

/* A closed socket cannot be asked: WSAENOTSOCK, nothing written. */
FX_BOTH(disc_closed_socket_is_enotsock)
{
    SOCKET s; void *p = NULL; DWORD n = 0; int r;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    s = fx_stream(af);
    if (s == INVALID_SOCKET) { t_skip("family unavailable"); return; }
    fx_closesocket(s);
    r = lookup(s, &g_acceptex, sizeof g_acceptex, &p, sizeof p, &n);
    FX_EQ(r, SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAENOTSOCK);
    EXPECT_EQ(p, NULL);
}

/* Discovery is its own result: the three pointers the fixture needs are all offered for the family, and the
 * discovery verdict does not depend on a listener existing. */
FX_BOTH(disc_companion_functions_are_offered)
{
    struct fx f;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    {
        SOCKET s = fx_stream(af);
        if (s == INVALID_SOCKET) { t_skip("family unavailable"); return; }
        fx_closesocket(s);
    }
    CHECK(fx_discover(&f, af));
    CHECK(f.acceptex != NULL);
    CHECK(f.gaes != NULL);
    CHECK(f.disconnectex != NULL);
    CHECK((void *)f.acceptex != (void *)f.gaes);
    CHECK((void *)f.acceptex != (void *)f.disconnectex);
}

/* The pointer is stable across independent lookups. */
FX_BOTH(disc_pointer_is_stable)
{
    struct fx a, b;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    if (!fx_discover(&a, af)) { t_skip("AcceptEx not offered"); return; }
    CHECK(fx_discover(&b, af));
    EXPECT_EQ(a.acceptex, b.acceptex);
    EXPECT_EQ(a.gaes, b.gaes);
    EXPECT_EQ(a.disconnectex, b.disconnectex);
}

/* The v4 and v6 lookups return one and the same function. */
TEST(disc_pointer_is_shared_between_families)
{
    struct fx a, b;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    if (!fx_discover(&a, AF_INET)) { t_skip("v4 AcceptEx not offered"); return; }
    if (!fx_discover(&b, AF_INET6)) { t_skip("v6 AcceptEx not offered"); return; }
    EXPECT_EQ(a.acceptex, b.acceptex);
    EXPECT_EQ(a.gaes, b.gaes);
    EXPECT_EQ(a.disconnectex, b.disconnectex);
}

/* Lengths that are not the exact pointer size or GUID size: an input of zero bytes and an output of zero bytes are
 * the same WSAEFAULT even when the other buffer is fine. */
FX_BOTH(disc_zero_length_buffers_are_efault)
{
    SOCKET s; void *p = NULL; DWORD n = 0; int r;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    s = fx_stream(af);
    if (s == INVALID_SOCKET) { t_skip("family unavailable"); return; }
    r = fx_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (LPVOID)&g_acceptex, 0, &p, sizeof p, &n, NULL, NULL);
    FX_EQ(r, SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAEFAULT);
    r = fx_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (LPVOID)&g_acceptex, sizeof g_acceptex, &p, 0, &n, NULL, NULL);
    FX_EQ(r, SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAEFAULT);
    fx_closesocket(s);
}

/* Handing an OVERLAPPED to the lookup does not defer it: it still completes in the call with the full result. */
FX_BOTH(disc_overlapped_lookup_completes_synchronously)
{
    SOCKET s; void *p = NULL, *q = NULL; DWORD n = 0; WSAOVERLAPPED ov; int r;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    s = fx_stream(af);
    if (s == INVALID_SOCKET) { t_skip("family unavailable"); return; }
    CHECK(lookup(s, &g_acceptex, sizeof g_acceptex, &q, sizeof q, &n) == 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = fx_event();
    r = fx_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (LPVOID)&g_acceptex, sizeof g_acceptex, &p, sizeof p, &n, &ov, NULL);
    FX_EQ(r, 0);
    EXPECT_EQ(n, sizeof p);
    EXPECT_EQ(p, q);
    CloseHandle(ov.hEvent);
    fx_closesocket(s);
}
