/* Measures the FIONBIO (blocking mode) socket I/O control through WSAIoctl and the SIO_KEEPALIVE_VALS
 * control: input-length rules, byte-count reporting, overlapped completion (completion port, APC) and
 * the interaction of FIONBIO with WSAEventSelect. */
#include "lift07.h"

L7TEST(l07_fionbio_no_output_ptr)
{
    u_long one = 1; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    l7_seterr(L7_UNSET);
    r = l7_ioctl(s, FIONBIO, &one, sizeof(one), NULL, 0, NULL, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "r=%d err=%d", r, l7_err());
    l7_close(s);
}

L7TEST(l07_fionbio_short_input_rejected)
{
    u_long one = 1; int r; DWORD size = 0; OVERLAPPED ov = {0};
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    r = l7_ioctl(s, FIONBIO, &one, sizeof(one) - 1, NULL, 0, &size, &ov, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "r=%d err=%d", r, l7_err());
    l7_close(s);
}

L7TEST(l07_fionbio_sync_reports_zero_bytes)
{
    u_long one = 1; int r; DWORD size = L7_UNSET;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    l7_seterr(L7_UNSET);
    r = l7_ioctl(s, FIONBIO, &one, sizeof(one), NULL, 0, &size, NULL, NULL);
    CHECKF(r == 0 && l7_err() == 0, "r=%d err=%d", r, l7_err());
    CHECKF(size == 0, "size %lu", size);
    l7_close(s);
}

L7TEST(l07_fionbio_longer_input_accepted)
{
    /* Only a too-short input is an error; extra input bytes are ignored. */
    u_long one = 1; int r; DWORD size = 0;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    r = l7_ioctl(s, FIONBIO, &one, sizeof(one) + 1, NULL, 0, &size, NULL, NULL);
    CHECKF(r == 0, "err=%d", l7_err());
    l7_close(s);
}

L7TEST(l07_fionbio_overlapped_inline_completion)
{
    u_long one = 1; int r; DWORD size = L7_UNSET; OVERLAPPED ov = {0}; HANDLE port;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    port = l7_port_for(s);
    l7_ov_poison(&ov);
    r = l7_ioctl(s, FIONBIO, &one, sizeof(one), NULL, 0, &size, &ov, NULL);
    CHECKF(r == 0, "err=%d", l7_err());
    CHECKF(size == 0, "size %lu", size);
    l7_expect_packet_ok(port, &ov, "FIONBIO");
    /* byte-count pointer still mandatory with an overlapped structure */
    r = l7_ioctl(s, FIONBIO, &one, sizeof(one), NULL, 0, NULL, &ov, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "r=%d err=%d", r, l7_err());
    CloseHandle(port);
    l7_close(s);
}

L7TEST(l07_fionbio_blocking_refused_after_event_select)
{
    /* WSAEventSelect forces the socket non-blocking; asking for blocking mode afterwards fails with
     * WSAEINVAL and reports zero bytes. */
    u_long one = 1, zero = 0; int r; DWORD size = L7_UNSET;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    CHECK(U(WSAEventSelect)(s, ev, FD_READ) == 0);
    r = l7_ioctl(s, FIONBIO, &one, sizeof(one), NULL, 0, &size, NULL, NULL);
    CHECKF(r == 0, "setting non-blocking failed (%d)", l7_err());
    size = L7_UNSET;
    r = l7_ioctl(s, FIONBIO, &zero, sizeof(zero), NULL, 0, &size, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEINVAL, "r=%d err=%d", r, l7_err());
    CHECKF(size == 0, "size %lu", size);
    l7_close(s);
    CloseHandle(ev);
}

L7TEST(l07_fionbio_apc_delivery)
{
    u_long one = 1; int r; DWORD size = L7_UNSET; OVERLAPPED ov = {0};
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    r = l7_ioctl(s, FIONBIO, &one, sizeof(one), NULL, 0, NULL, &ov, l7_apc);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "r=%d err=%d", r, l7_err());
    l7_apc_reset();
    r = l7_ioctl(s, FIONBIO, &one, sizeof(one), NULL, 0, &size, &ov, l7_apc);
    CHECKF(r == 0, "err=%d", l7_err());
    CHECKF(size == 0, "size %lu", size);
    l7_expect_apc(&ov, 0, "FIONBIO");
    l7_close(s);
}

/* ---- SIO_KEEPALIVE_VALS ---------------------------------------------- */
static void ka_make(struct tcp_keepalive *k, ULONG on, ULONG time, ULONG interval)
{
    k->onoff = on; k->keepalivetime = time; k->keepaliveinterval = interval;
}

L7TEST(l07_keepalive_input_size_rules)
{
    struct tcp_keepalive k; DWORD size; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    ka_make(&k, 0, 0, 0);
    /* empty input and a NULL input buffer are both WSAEFAULT, and the byte count is zeroed anyway */
    l7_seterr(L7_UNSET); size = L7_UNSET;
    r = l7_ioctl(s, SIO_KEEPALIVE_VALS, &k, 0, NULL, 0, &size, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT && size == 0, "empty input: r=%d err=%d size=%lu", r, l7_err(), size);
    l7_seterr(L7_UNSET); size = L7_UNSET;
    r = l7_ioctl(s, SIO_KEEPALIVE_VALS, NULL, sizeof(k), NULL, 0, &size, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT && size == 0, "NULL input: r=%d err=%d size=%lu", r, l7_err(), size);
    l7_close(s);
}

L7TEST(l07_keepalive_sync_success)
{
    struct tcp_keepalive k; DWORD size = L7_UNSET; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    ka_make(&k, 0, 0, 0);
    l7_seterr(L7_UNSET);
    r = l7_ioctl(s, SIO_KEEPALIVE_VALS, &k, sizeof(k), NULL, 0, &size, NULL, NULL);
    CHECKF(r == 0 && l7_err() == 0 && size == 0, "r=%d err=%d size=%lu", r, l7_err(), size);
    l7_close(s);
}

L7TEST(l07_keepalive_byte_count_ptr_required)
{
    struct tcp_keepalive k; OVERLAPPED ov = {0}; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    ka_make(&k, 0, 0, 0);
    r = l7_ioctl(s, SIO_KEEPALIVE_VALS, &k, sizeof(k), NULL, 0, NULL, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "plain: r=%d err=%d", r, l7_err());
    r = l7_ioctl(s, SIO_KEEPALIVE_VALS, &k, sizeof(k), NULL, 0, NULL, &ov, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "overlapped: r=%d err=%d", r, l7_err());
    l7_close(s);
}

L7TEST(l07_keepalive_overlapped_short_input)
{
    /* A rejected overlapped request leaves the byte count alone and marks the structure pending. */
    struct tcp_keepalive k; OVERLAPPED ov = {0}; DWORD size = L7_UNSET; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    ka_make(&k, 0, 0, 0);
    l7_seterr(L7_UNSET);
    l7_ov_poison(&ov);
    r = l7_ioctl(s, SIO_KEEPALIVE_VALS, &k, sizeof(k) - 1, NULL, 0, &size, &ov, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "r=%d err=%d", r, l7_err());
    CHECKF(size == L7_UNSET, "size %lu", size);
    CHECKF((NTSTATUS)ov.Internal == L7_STATUS_PENDING, "Internal %#lx", (NTSTATUS)ov.Internal);
    CHECKF(ov.InternalHigh == L7_UNSET, "InternalHigh %Iu", ov.InternalHigh);
    l7_close(s);
}

L7TEST(l07_keepalive_overlapped_completion)
{
    /* The byte count is not touched on the overlapped path; completion is inline and queues a packet. */
    struct tcp_keepalive k; OVERLAPPED ov = {0}; DWORD size = L7_UNSET; int r; HANDLE port;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    port = l7_port_for(s);
    ka_make(&k, 0, 0, 0);
    l7_seterr(L7_UNSET);
    l7_ov_poison(&ov);
    r = l7_ioctl(s, SIO_KEEPALIVE_VALS, &k, sizeof(k), NULL, 0, &size, &ov, NULL);
    CHECKF(r == 0 && l7_err() == 0, "r=%d err=%d", r, l7_err());
    CHECKF(size == L7_UNSET, "size %lu", size);
    l7_expect_packet_ok(port, &ov, "SIO_KEEPALIVE_VALS");
    CloseHandle(port);
    l7_close(s);
}

L7TEST(l07_keepalive_value_combinations)
{
    static const struct { ULONG on, time, interval; } v[] = {
        {1, 0, 0}, {1, 1000, 1000}, {1, 10000, 10000}, {1, 100, 100}, {0, 100, 100},
    };
    struct tcp_keepalive k; DWORD size; int r; unsigned i;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    for (i = 0; i < sizeof(v) / sizeof(v[0]); ++i) {
        ka_make(&k, v[i].on, v[i].time, v[i].interval);
        r = l7_ioctl(s, SIO_KEEPALIVE_VALS, &k, sizeof(k), NULL, 0, &size, NULL, NULL);
        CHECKF(r == 0, "row %u (%lu,%lu,%lu): err=%d", i, v[i].on, v[i].time, v[i].interval, l7_err());
    }
    l7_close(s);
}

L7TEST(l07_keepalive_apc_delivery)
{
    struct tcp_keepalive k; OVERLAPPED ov = {0}; DWORD size = L7_UNSET; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    ka_make(&k, 1, 1000, 1000);
    r = l7_ioctl(s, SIO_KEEPALIVE_VALS, &k, sizeof(k), NULL, 0, NULL, &ov, l7_apc);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "r=%d err=%d", r, l7_err());
    l7_apc_reset();
    r = l7_ioctl(s, SIO_KEEPALIVE_VALS, &k, sizeof(k), NULL, 0, &size, &ov, l7_apc);
    CHECKF(r == 0, "err=%d", l7_err());
    CHECKF(size == 0, "size %lu", size);
    l7_expect_apc(&ov, 0, "SIO_KEEPALIVE_VALS");
    l7_close(s);
}
