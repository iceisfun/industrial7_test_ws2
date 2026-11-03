/* SIO_ADDRESS_LIST_QUERY through WSAIoctl.
 * Measures the buffer-size protocol (required size reported with WSAEFAULT, WSAEINVAL for a buffer too small to
 * even hold a count), that nothing is written on failure, that the returned size equals the header plus the
 * sockaddr lengths, that the NULL bytes-returned pointer is rejected, and how an OVERLAPPED / completion routine
 * is treated: errors are reported synchronously and leave the OVERLAPPED alone, a successful query completes
 * inline but still posts a zero-byte packet / runs the routine with error 0 and size 0.
 */
#include "w.h"

#define HDR ((DWORD)FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address[0]))
#define BUFSZ 4096

struct alq {
    SOCKET s;
    HANDLE port;
    union { SOCKET_ADDRESS_LIST list; char raw[BUFSZ]; } u;
    DWORD full;               /* size the provider reports for a complete list */
};

static int alq_open(struct alq *q, int with_port)
{
    DWORD size = 0;
    int ret;
    memset(q, 0, sizeof *q);
    q->s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (q->s == INVALID_SOCKET) return 0;
    if (with_port) q->port = w_port_for(q->s, 123);
    ret = p_WSAIoctl(q->s, SIO_ADDRESS_LIST_QUERY, NULL, 0, NULL, 0, &size, NULL, NULL);
    q->full = size;
    return ret == SOCKET_ERROR;
}
static void alq_close(struct alq *q)
{
    if (q->port) CloseHandle(q->port);
    if (q->s != INVALID_SOCKET) p_closesocket(q->s);
}
#define ALQ_BEGIN(q) ALQ_BEGIN_P(q, 1)
#define ALQ_BEGIN_P(q, port) struct alq q; W_BEGIN(); if (!alq_open(&q, port)) { alq_close(&q); t_skip("no inet socket"); return; }

TEST(lift10_addrlist_size_query_reports_efault)
{
    ALQ_BEGIN(q);
    DWORD size = 0;
    int ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, NULL, 0, &size, NULL, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAEFAULT);
    CHECK(size >= HDR);
    alq_close(&q);
}

TEST(lift10_addrlist_size_matches_header_plus_sockaddrs)
{
    ALQ_BEGIN(q);
    DWORD size = 0, want;
    int ret;
    LONG i;
    p_WSASetLastError(0);
    ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, q.u.raw, BUFSZ, &size, NULL, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(p_WSAGetLastError(), 0);
    EXPECT_EQ(size, q.full);
    /* documented layout: the count, then an array of that many SOCKET_ADDRESS, then the sockaddr bodies */
    want = FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address[q.u.list.iAddressCount]);
    for (i = 0; i < q.u.list.iAddressCount; ++i) want += q.u.list.Address[i].iSockaddrLength;
    EXPECT_EQ(size, want);
    alq_close(&q);
}

TEST(lift10_addrlist_null_bytes_returned_is_efault)
{
    ALQ_BEGIN(q);
    int ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, q.u.raw, BUFSZ, NULL, NULL, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAEFAULT);
    alq_close(&q);
}

TEST(lift10_addrlist_null_buffer_with_length_reports_size)
{
    ALQ_BEGIN(q);
    DWORD size = W_SENT;
    int ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, NULL, BUFSZ, &size, NULL, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAEFAULT);
    EXPECT_EQ(size, q.full);
    alq_close(&q);
}

TEST(lift10_addrlist_zero_length_buffer_reports_size)
{
    ALQ_BEGIN(q);
    DWORD size = W_SENT;
    int ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, q.u.raw, 0, &size, NULL, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAEFAULT);
    EXPECT_EQ(size, q.full);
    alq_close(&q);
}

/* Too small to hold even the count: a different error, and no size is reported. */
TEST(lift10_addrlist_one_byte_buffer_is_einval)
{
    ALQ_BEGIN(q);
    DWORD size = W_SENT;
    int ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, q.u.raw, 1, &size, NULL, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAEINVAL);
    EXPECT_EQ(size, 0);
    alq_close(&q);
}

/* Header-sized buffer: holds the count field but not the list; fails with the size and writes nothing. */
TEST(lift10_addrlist_header_only_buffer_is_untouched)
{
    ALQ_BEGIN(q);
    DWORD size = W_SENT;
    int ret;
    if (q.full <= HDR) { alq_close(&q); t_skip("host has no inet addresses; header-sized buffer would succeed"); return; }
    memset(q.u.raw, 0xcc, sizeof q.u.raw);
    ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, q.u.raw, HDR, &size, NULL, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAEFAULT);
    EXPECT_EQ(size, q.full);
    EXPECT_EQ((DWORD)q.u.list.iAddressCount, 0xcccccccc);
    alq_close(&q);
}

/* With an OVERLAPPED the failures are still synchronous and the OVERLAPPED is not touched. */
TEST(lift10_addrlist_overlapped_failures_are_synchronous)
{
    ALQ_BEGIN(q);
    OVERLAPPED ov;
    DWORD size;
    int ret;
    static const struct { DWORD outlen; int err; } rows[] = { {0, WSAEFAULT}, {1, WSAEINVAL}, {HDR, WSAEFAULT} };
    unsigned i;
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        if (rows[i].outlen == HDR && q.full <= HDR) continue;
        memset(q.u.raw, 0xcc, sizeof q.u.raw);
        memset(&ov, 0, sizeof ov);
        ov.Internal = W_SENT;
        ov.InternalHigh = W_SENT;
        size = W_SENT;
        ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, q.u.raw, rows[i].outlen, &size, &ov, NULL);
        CHECKF(ret == SOCKET_ERROR, "row %u ret %d", i, ret);
        CHECKF(p_WSAGetLastError() == rows[i].err, "row %u err %d", i, p_WSAGetLastError());
        CHECKF(size == (rows[i].err == WSAEINVAL ? 0 : q.full), "row %u size %lu", i, size);
        CHECKF(ov.Internal == W_SENT, "row %u Internal touched", i);
        CHECKF(ov.InternalHigh == W_SENT, "row %u InternalHigh touched", i);
        if (rows[i].outlen == HDR) EXPECT_EQ((DWORD)q.u.list.iAddressCount, 0xcccccccc);
    }
    alq_close(&q);
}

TEST(lift10_addrlist_overlapped_success_completes_inline_and_posts_packet)
{
    ALQ_BEGIN(q);
    OVERLAPPED ov;
    DWORD size = W_SENT;
    struct w_cp r;
    int ret;
    memset(&ov, 0, sizeof ov);
    ov.Internal = W_SENT;
    ov.InternalHigh = W_SENT;
    p_WSASetLastError(0);
    ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, q.u.raw, BUFSZ, &size, &ov, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(p_WSAGetLastError(), 0);
    EXPECT_EQ(size, q.full);

    r = w_dequeue(q.port, 0);
    CHECK(r.ret);
    EXPECT_EQ(r.bytes, 0);
    EXPECT_EQ(r.key, 123);
    CHECK(r.ov == &ov);
    EXPECT_EQ(ov.Internal, 0);
    EXPECT_EQ(ov.InternalHigh, 0);
    w_expect_empty(q.port, 0);
    alq_close(&q);
}

TEST(lift10_addrlist_completion_routine_runs_with_zero_size)
{
    /* a completion routine cannot be combined with a socket attached to a completion port */
    ALQ_BEGIN_P(q, 0);
    OVERLAPPED ov;
    DWORD size = W_SENT, w;
    int ret;
    memset(&ov, 0, sizeof ov);
    /* NULL bytes-returned pointer is rejected even when a routine is supplied. */
    ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, q.u.raw, BUFSZ, NULL, &ov, w_socket_apc);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAEFAULT);

    w_apc_reset();
    ret = p_WSAIoctl(q.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, q.u.raw, BUFSZ, &size, &ov, w_socket_apc);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(size, q.full);
    w = SleepEx(0, TRUE);
    EXPECT_EQ(w, WAIT_IO_COMPLETION);
    EXPECT_EQ(w_apc_count, 1);
    EXPECT_EQ(w_apc_error, 0);
    EXPECT_EQ(w_apc_size, 0);
    CHECK(w_apc_ov == &ov);
    alq_close(&q);
}
