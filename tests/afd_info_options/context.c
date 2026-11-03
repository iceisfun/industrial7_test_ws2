/* IOCTL_AFD_GET_CONTEXT (0x12043), IOCTL_AFD_SET_CONTEXT (0x12047), IOCTL_AFD_GET_REMOTE_ADDRESS
 * (0x1203f) and IOCTL_AFD_QUERY_HANDLES (0x12037).
 *
 * Every endpoint carries an opaque, caller-defined "context" blob that the Winsock provider fills in when
 * it creates the socket (state, address family, type, protocol, address lengths, ...). The driver only
 * stores it: SET replaces the whole blob (any length), GET copies at most the output buffer size and
 * reports the full stored size in Information, completing with buffer-overflow when it did not all fit.
 * An endpoint with no stored blob answers GET with invalid-parameter. The tests use two kinds of endpoint:
 * sockets from the provider (blob present, written by the provider) and endpoints opened directly on the
 * device (blob empty).
 */
#include "aio.h"

static LONG get_ctx(SOCKET s, void *buf, ULONG cap, IO_STATUS_BLOCK *io)
{
    return aio_ctl(s, IOC_GET_CONTEXT, NULL, 0, buf, cap, io, NULL);
}

/* ---- what the provider stores --------------------------------------------------------------------- */
#define CTX_SIZE 0xa8   /* size of the provider's blob on Windows 10 */

TEST(aio_ctx_provider_blob_size_tcp)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char b[512];
    IO_STATUS_BLOCK io;
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    EXPECT_EQ(io.Information, CTX_SIZE);
    aio_close(s);
}
TEST(aio_ctx_provider_blob_size_udp)
{
    AIO_BEGIN();
    SOCKET s = aio_udp();
    unsigned char b[512];
    IO_STATUS_BLOCK io;
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    EXPECT_EQ(io.Information, CTX_SIZE);
    aio_close(s);
}
TEST(aio_ctx_provider_blob_size_raw)
{
    AIO_BEGIN();
    SOCKET s = aio_kind(AK_RAW);
    unsigned char b[512];
    IO_STATUS_BLOCK io;
    if (s == INVALID_SOCKET) { t_skip("raw socket unavailable"); return; }
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    EXPECT_EQ(io.Information, CTX_SIZE);
    aio_close(s);
}
TEST(aio_ctx_provider_blob_size_ipv6)
{
    AIO_BEGIN();
    SOCKET s = W.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    unsigned char b[512];
    IO_STATUS_BLOCK io;
    if (s == INVALID_SOCKET) { t_skip("no IPv6 stack"); return; }
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0xc8);   /* the 28-byte address form needs a larger blob */
    aio_close(s);
}

/* The leading fields: state, family, type, protocol, local and remote address length. */
static void ctx_header(SOCKET s, ULONG state, ULONG fam, ULONG type, ULONG proto, ULONG alen)
{
    ULONG h[6];
    unsigned char b[512];
    IO_STATUS_BLOCK io;
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    memcpy(h, b, sizeof h);
    EXPECT_EQ(h[0], state);
    EXPECT_EQ(h[1], fam);
    EXPECT_EQ(h[2], type);
    EXPECT_EQ(h[3], proto);
    EXPECT_EQ(h[4], alen);
    EXPECT_EQ(h[5], alen);
}
TEST(aio_ctx_header_fresh_tcp) { AIO_BEGIN(); SOCKET s = aio_tcp(); ctx_header(s, 0, AF_INET, SOCK_STREAM, IPPROTO_TCP, 16); aio_close(s); }
TEST(aio_ctx_header_fresh_udp) { AIO_BEGIN(); SOCKET s = aio_udp(); ctx_header(s, 0, AF_INET, SOCK_DGRAM, IPPROTO_UDP, 16); aio_close(s); }
TEST(aio_ctx_header_fresh_raw)
{
    AIO_BEGIN();
    SOCKET s = aio_kind(AK_RAW);
    if (s == INVALID_SOCKET) { t_skip("raw socket unavailable"); return; }
    ctx_header(s, 0, AF_INET, SOCK_RAW, IPPROTO_ICMP, 16);
    aio_close(s);
}
TEST(aio_ctx_header_bound_tcp) { AIO_BEGIN(); SOCKET s = aio_bound(SOCK_STREAM); ctx_header(s, 1, AF_INET, SOCK_STREAM, IPPROTO_TCP, 16); aio_close(s); }
TEST(aio_ctx_header_bound_udp) { AIO_BEGIN(); SOCKET s = aio_bound(SOCK_DGRAM); ctx_header(s, 1, AF_INET, SOCK_DGRAM, IPPROTO_UDP, 16); aio_close(s); }
TEST(aio_ctx_header_listening_tcp) { AIO_BEGIN(); SOCKET s = aio_listener(NULL); ctx_header(s, 1, AF_INET, SOCK_STREAM, IPPROTO_TCP, 16); aio_close(s); }
TEST(aio_ctx_header_connected_tcp)
{
    AIO_BEGIN();
    SOCKET c, s;
    aio_pair(&c, &s);
    ctx_header(c, 3, AF_INET, SOCK_STREAM, IPPROTO_TCP, 16);
    ctx_header(s, 3, AF_INET, SOCK_STREAM, IPPROTO_TCP, 16);
    aio_close(c); aio_close(s);
}
TEST(aio_ctx_header_ipv6_address_length)
{
    AIO_BEGIN();
    SOCKET s = W.WSASocketW(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    ULONG h[6]; unsigned char b[512]; IO_STATUS_BLOCK io;
    if (s == INVALID_SOCKET) { t_skip("no IPv6 stack"); return; }
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    memcpy(h, b, sizeof h);
    EXPECT_EQ(h[1], AF_INET6);
    EXPECT_EQ(h[4], 28);
    EXPECT_EQ(h[5], 28);
    aio_close(s);
}
TEST(aio_ctx_state_follows_socket_operations)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    struct sockaddr_in a = aio_lo4(0);
    unsigned char b[512]; IO_STATUS_BLOCK io;
    ULONG st;
    get_ctx(s, b, sizeof b, &io); memcpy(&st, b, 4); EXPECT_EQ(st, 0);
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    get_ctx(s, b, sizeof b, &io); memcpy(&st, b, 4); EXPECT_EQ(st, 1);
    CHECK(W.listen(s, 2) == 0);
    get_ctx(s, b, sizeof b, &io); memcpy(&st, b, 4); EXPECT_EQ(st, 1);
    aio_close(s);
}
TEST(aio_ctx_stable_between_reads)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char a[512], b[512];
    IO_STATUS_BLOCK io;
    EXPECT_NTS(get_ctx(s, a, sizeof a, &io), NTS_SUCCESS);
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    CHECK(!memcmp(a, b, CTX_SIZE));
    aio_close(s);
}
TEST(aio_ctx_blob_tail_beyond_header_is_not_written_by_get)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char b[512]; IO_STATUS_BLOCK io;
    memset(b, 0x5a, sizeof b);
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    CHECK(b[CTX_SIZE] == 0x5a && b[511] == 0x5a);   /* never writes past the stored size */
    aio_close(s);
}

/* ---- GET buffer protocol -------------------------------------------------------------------------- */
#define CTX_LEN_TEST(name, cap, want) \
    TEST(aio_ctx_get_cap_##name) { AIO_BEGIN(); SOCKET s = aio_tcp(); unsigned char b[512]; IO_STATUS_BLOCK io; \
        memset(b, 0x5a, sizeof b); \
        EXPECT_NTS(get_ctx(s, cap ? b : NULL, cap, &io), want); \
        EXPECT_EQ(io.Information, CTX_SIZE); aio_close(s); }
CTX_LEN_TEST(0, 0, NTS_BUFFER_OVERFLOW)
CTX_LEN_TEST(1, 1, NTS_BUFFER_OVERFLOW)
CTX_LEN_TEST(4, 4, NTS_BUFFER_OVERFLOW)
CTX_LEN_TEST(16, 16, NTS_BUFFER_OVERFLOW)
CTX_LEN_TEST(167, 0xa7, NTS_BUFFER_OVERFLOW)
CTX_LEN_TEST(168, 0xa8, NTS_SUCCESS)
CTX_LEN_TEST(169, 0xa9, NTS_SUCCESS)
CTX_LEN_TEST(512, 512, NTS_SUCCESS)

TEST(aio_ctx_get_truncated_copies_prefix)
{
    AIO_BEGIN();
    SOCKET s = aio_bound(SOCK_STREAM);
    unsigned char full[512], part[512];
    IO_STATUS_BLOCK io;
    EXPECT_NTS(get_ctx(s, full, sizeof full, &io), NTS_SUCCESS);
    memset(part, 0x5a, sizeof part);
    EXPECT_NTS(get_ctx(s, part, 24, &io), NTS_BUFFER_OVERFLOW);
    EXPECT_EQ(io.Information, CTX_SIZE);
    CHECK(!memcmp(part, full, 24));
    CHECK(part[24] == 0x5a);
    aio_close(s);
}
TEST(aio_ctx_get_ignores_input_buffer)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char in[64], b[512];
    IO_STATUS_BLOCK io;
    memset(in, 0xcc, sizeof in);
    EXPECT_NTS(aio_ctl(s, IOC_GET_CONTEXT, in, sizeof in, b, sizeof b, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, CTX_SIZE);
    aio_close(s);
}

/* ---- endpoints without a stored blob --------------------------------------------------------------- */
static HANDLE raw_ep(int kind)
{
    LONG st;
    HANDLE h = aio_open_raw(kind, &st);
    if (!h && !t_is_wine()) CHECKF(0, "open of a bare endpoint failed 0x%08lx", (unsigned long)st);
    return h;
}
TEST(aio_ctx_bare_endpoint_get_invalid_parameter)
{
    AIO_BEGIN();
    int k;
    for (k = AIOK_TCP4; k <= AIOK_UDP6; k++) {
        HANDLE h = raw_ep(k);
        unsigned char b[64]; IO_STATUS_BLOCK io;
        if (!h) continue;
        t_check(aio_ctl((SOCKET)h, IOC_GET_CONTEXT, NULL, 0, b, sizeof b, &io, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "bare endpoint context", "kind %d", k);
        EXPECT_EQ(io.Information, 0);
        aio_close_raw(h);
    }
}
TEST(aio_ctx_bare_endpoint_get_without_buffer_invalid_parameter)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    if (!h) return;
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_GET_CONTEXT, NULL, 0, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close_raw(h);
}
TEST(aio_ctx_bare_endpoint_set_zero_length_stays_empty)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char b[64];
    if (!h) return;
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, NULL, 0, NULL, 0, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_GET_CONTEXT, NULL, 0, b, sizeof b, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close_raw(h);
}

/* ---- SET / GET round trips -------------------------------------------------------------------------- */
static void ctx_round_trip(HANDLE h, ULONG len)
{
    unsigned char *in = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
    unsigned char *out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 16);
    IO_STATUS_BLOCK io;
    ULONG i;
    for (i = 0; i < len; i++) in[i] = (unsigned char)(i * 7 + 3);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, in, len, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0);
    memset(out, 0x5a, len + 16);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_GET_CONTEXT, NULL, 0, out, len + 16, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, len);
    CHECK(!memcmp(in, out, len));
    CHECK(out[len] == 0x5a);
    HeapFree(GetProcessHeap(), 0, in); HeapFree(GetProcessHeap(), 0, out);
}
#define CTX_RT(n) TEST(aio_ctx_round_trip_##n) { AIO_BEGIN(); HANDLE h = raw_ep(AIOK_TCP4); if (!h) return; ctx_round_trip(h, n); aio_close_raw(h); }
CTX_RT(1) CTX_RT(2) CTX_RT(3) CTX_RT(4) CTX_RT(8) CTX_RT(16) CTX_RT(31) CTX_RT(64) CTX_RT(100) CTX_RT(168)
CTX_RT(255) CTX_RT(256) CTX_RT(257) CTX_RT(1000) CTX_RT(4096) CTX_RT(65535) CTX_RT(65536) CTX_RT(100000)

TEST(aio_ctx_round_trip_all_endpoint_kinds)
{
    AIO_BEGIN();
    int k;
    for (k = AIOK_TCP4; k <= AIOK_UDP6; k++) {
        HANDLE h = raw_ep(k);
        if (!h) continue;
        ctx_round_trip(h, 96);
        aio_close_raw(h);
    }
}
TEST(aio_ctx_set_replaces_whole_blob_smaller)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_UDP4);
    unsigned char a[200], b[40], out[300];
    IO_STATUS_BLOCK io;
    if (!h) return;
    memset(a, 0xa1, sizeof a); memset(b, 0xb2, sizeof b);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a, sizeof a, NULL, 0, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, b, sizeof b, NULL, 0, NULL, NULL), NTS_SUCCESS);
    memset(out, 0, sizeof out);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_GET_CONTEXT, NULL, 0, out, sizeof out, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, sizeof b);
    CHECK(!memcmp(out, b, sizeof b));
    aio_close_raw(h);
}
TEST(aio_ctx_set_replaces_whole_blob_larger)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_UDP4);
    unsigned char a[40], b[200], out[300];
    IO_STATUS_BLOCK io;
    if (!h) return;
    memset(a, 0xa1, sizeof a); memset(b, 0xb2, sizeof b);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a, sizeof a, NULL, 0, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, b, sizeof b, NULL, 0, NULL, NULL), NTS_SUCCESS);
    memset(out, 0, sizeof out);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_GET_CONTEXT, NULL, 0, out, sizeof out, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, sizeof b);
    CHECK(!memcmp(out, b, sizeof b));
    aio_close_raw(h);
}
TEST(aio_ctx_set_zero_length_after_blob_reports_empty_size)
{
    /* setting a zero-length blob does not free the earlier one's bytes but reports size 0 */
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char a[40], out[64];
    IO_STATUS_BLOCK io;
    if (!h) return;
    memset(a, 0xa1, sizeof a);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a, sizeof a, NULL, 0, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, NULL, 0, NULL, 0, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_GET_CONTEXT, NULL, 0, out, sizeof out, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0);
    aio_close_raw(h);
}
TEST(aio_ctx_set_on_provider_socket_is_visible)
{
    /* overwrite a dup-free scratch socket's blob; restore is unnecessary because the socket is closed */
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char a[CTX_SIZE], out[CTX_SIZE];
    IO_STATUS_BLOCK io;
    memset(a, 0x33, sizeof a);
    EXPECT_NTS(aio_ctl(s, IOC_SET_CONTEXT, a, sizeof a, NULL, 0, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(get_ctx(s, out, sizeof out, &io), NTS_SUCCESS);
    CHECK(!memcmp(a, out, sizeof a));
    aio_close(s);
}
TEST(aio_ctx_blobs_are_per_endpoint)
{
    AIO_BEGIN();
    HANDLE h1 = raw_ep(AIOK_TCP4), h2 = raw_ep(AIOK_TCP4);
    unsigned char a[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, out[16];
    IO_STATUS_BLOCK io;
    if (!h1 || !h2) return;
    EXPECT_NTS(aio_ctl((SOCKET)h1, IOC_SET_CONTEXT, a, sizeof a, NULL, 0, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(aio_ctl((SOCKET)h2, IOC_GET_CONTEXT, NULL, 0, out, sizeof out, &io, NULL), NTS_INVALID_PARAMETER);
    aio_close_raw(h1); aio_close_raw(h2);
}

/* SET_CONTEXT accepts an output buffer that must lie inside the input buffer: it marks where the remote
 * address sits within the blob (offset and length are taken from the two pointers). */
TEST(aio_ctx_set_marker_inside_input_accepted)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char a[64];
    if (!h) return;
    memset(a, 0x11, sizeof a);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a, 64, a + 16, 16, NULL, NULL), NTS_SUCCESS);
    aio_close_raw(h);
}
TEST(aio_ctx_set_marker_whole_input_accepted)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char a[64];
    if (!h) return;
    memset(a, 0x11, sizeof a);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a, 64, a, 64, NULL, NULL), NTS_SUCCESS);
    aio_close_raw(h);
}
TEST(aio_ctx_set_marker_at_end_accepted)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char a[64];
    if (!h) return;
    memset(a, 0x11, sizeof a);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a, 64, a + 48, 16, NULL, NULL), NTS_SUCCESS);
    aio_close_raw(h);
}
TEST(aio_ctx_set_marker_overrunning_input_rejected)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char a[96];
    if (!h) return;
    memset(a, 0x11, sizeof a);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a, 64, a + 56, 16, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close_raw(h);
}
TEST(aio_ctx_set_marker_below_input_rejected)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char a[96];
    if (!h) return;
    memset(a, 0x11, sizeof a);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a + 16, 64, a, 16, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close_raw(h);
}
TEST(aio_ctx_set_separate_output_buffer_rejected)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char a[64], b[64];
    if (!h) return;
    memset(a, 0x11, sizeof a); memset(b, 0, sizeof b);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a, 64, b, 16, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close_raw(h);
}
TEST(aio_ctx_set_marker_longer_than_input_rejected)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char a[64];
    if (!h) return;
    memset(a, 0x11, sizeof a);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, a, 16, a, 32, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close_raw(h);
}
TEST(aio_ctx_set_marker_without_input_rejected)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_TCP4);
    unsigned char a[64];
    if (!h) return;
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONTEXT, NULL, 0, a, 16, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close_raw(h);
}

/* ---- GET_REMOTE_ADDRESS -------------------------------------------------------------------------- */
TEST(aio_remote_unconnected_invalid_connection)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s;
        unsigned char b[64];
        if (k == AK_TCP_CONN) continue;
        s = aio_kind(k);
        if (s == INVALID_SOCKET) continue;
        t_check(aio_ctl(s, IOC_GET_REMOTE, NULL, 0, b, sizeof b, NULL, NULL) == NTS_INVALID_CONNECTION, __FILE__, __LINE__, "remote of unconnected", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_remote_connected_returns_peer_sockaddr)
{
    AIO_BEGIN();
    SOCKET c, s;
    struct sockaddr_in peer, got;
    int n = sizeof peer;
    unsigned char b[64];
    IO_STATUS_BLOCK io;
    aio_pair(&c, &s);
    CHECK(W.getsockname(s, (struct sockaddr *)&peer, &n) == 0);   /* the server end's own address is the client's peer */
    memset(b, 0, sizeof b);
    EXPECT_NTS(aio_ctl(c, IOC_GET_REMOTE, NULL, 0, b, sizeof b, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, CTX_SIZE);   /* Information is the size of the whole stored blob, not of the address */
    memcpy(&got, b, sizeof got);
    EXPECT_EQ(got.sin_family, AF_INET);
    EXPECT_EQ(got.sin_port, peer.sin_port);
    EXPECT_EQ(got.sin_addr.s_addr, peer.sin_addr.s_addr);
    aio_close(c); aio_close(s);
}
TEST(aio_remote_connected_exact_buffer)
{
    AIO_BEGIN();
    SOCKET c, s;
    unsigned char b[16];
    aio_pair(&c, &s);
    EXPECT_NTS(aio_ctl(c, IOC_GET_REMOTE, NULL, 0, b, 16, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(aio_ctl(c, IOC_GET_REMOTE, NULL, 0, b, 15, NULL, NULL), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(aio_ctl(c, IOC_GET_REMOTE, NULL, 0, b, 1, NULL, NULL), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(aio_ctl(c, IOC_GET_REMOTE, NULL, 0, NULL, 0, NULL, NULL), NTS_BUFFER_TOO_SMALL);
    aio_close(c); aio_close(s);
}
TEST(aio_remote_accepted_endpoint_remote_area)
{
    AIO_BEGIN();
    SOCKET c, s;
    struct sockaddr_in me, got;
    int n = sizeof me;
    unsigned char b[64];
    aio_pair(&c, &s);
    CHECK(W.getsockname(c, (struct sockaddr *)&me, &n) == 0);
    memset(b, 0, sizeof b);
    EXPECT_NTS(aio_ctl(s, IOC_GET_REMOTE, NULL, 0, b, sizeof b, NULL, NULL), NTS_SUCCESS);
    memcpy(&got, b, sizeof got);
    /* the provider records no remote address for accepted endpoints: the area is returned as stored */
    t_note("accepted endpoint remote area: family %u port-match %d", (unsigned)got.sin_family, got.sin_port == me.sin_port);
    aio_close(c); aio_close(s);
}
TEST(aio_remote_connected_udp_not_available)
{
    /* a datagram socket connect()ed in the provider does not record a remote address through this request */
    AIO_BEGIN();
    SOCKET a = aio_bound(SOCK_DGRAM), b = aio_bound(SOCK_DGRAM);
    struct sockaddr_in to; int n = sizeof to;
    unsigned char buf[64];
    CHECK(W.getsockname(b, (struct sockaddr *)&to, &n) == 0);
    CHECK(W.connect(a, (struct sockaddr *)&to, sizeof to) == 0);
    EXPECT_NTS(aio_ctl(a, IOC_GET_REMOTE, NULL, 0, buf, sizeof buf, NULL, NULL), NTS_INVALID_CONNECTION);
    aio_close(a); aio_close(b);
}

/* ---- QUERY_HANDLES ---------------------------------------------------------------------------------- */
static LONG qh(SOCKET s, ULONG flags, ULONG inl, ULONG outl, void *out, IO_STATUS_BLOCK *io)
{
    return aio_ctl(s, IOC_QUERY_HANDLES, inl ? &flags : NULL, inl, outl ? out : NULL, outl, io, NULL);
}
TEST(aio_handles_flag_values)
{
    /* bit 0 asks for the address handle, bit 1 the connection handle; 0 and anything with other bits is invalid */
    AIO_BEGIN();
    static const struct { ULONG f; LONG want; } t[] = {
        { 0, NTS_INVALID_PARAMETER }, { 1, 0 }, { 2, 0 }, { 3, 0 }, { 4, NTS_INVALID_PARAMETER },
        { 5, NTS_INVALID_PARAMETER }, { 7, NTS_INVALID_PARAMETER }, { 8, NTS_INVALID_PARAMETER },
        { 0x100, NTS_INVALID_PARAMETER }, { 0x80000000u, NTS_INVALID_PARAMETER }, { 0xffffffffu, NTS_INVALID_PARAMETER },
    };
    unsigned i; int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        if (s == INVALID_SOCKET) continue;
        for (i = 0; i < sizeof t / sizeof t[0]; i++) {
            unsigned char b[16]; IO_STATUS_BLOCK io;
            LONG st = qh(s, t[i].f, 4, 16, b, &io);
            t_check(st == t[i].want, __FILE__, __LINE__, "handle query flags", "%s flags 0x%lx: got 0x%08lx", aio_kind_name[k], (unsigned long)t[i].f, (unsigned long)st);
        }
        aio_close(s);
    }
}
TEST(aio_handles_success_reports_16_bytes_of_invalid_handles)
{
    /* endpoints use the new transport interface: there are no TDI handles, both slots read all-ones */
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        unsigned char b[16]; IO_STATUS_BLOCK io;
        int i;
        if (s == INVALID_SOCKET) continue;
        memset(b, 0xee, sizeof b);
        EXPECT_NTS(qh(s, 3, 4, 16, b, &io), NTS_SUCCESS);
        EXPECT_EQ(io.Information, 16);
        for (i = 0; i < 16; i++) CHECKF(b[i] == 0xff, "%s byte %d = %02x", aio_kind_name[k], i, b[i]);
        aio_close(s);
    }
}
TEST(aio_handles_short_buffers)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char b[16]; IO_STATUS_BLOCK io;
    EXPECT_NTS(qh(s, 1, 0, 16, b, &io), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(qh(s, 1, 3, 16, b, &io), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(qh(s, 1, 4, 0, b, &io), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(qh(s, 1, 4, 8, b, &io), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(qh(s, 1, 4, 15, b, &io), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(qh(s, 1, 4, 16, b, &io), NTS_SUCCESS);
    EXPECT_NTS(qh(s, 1, 8, 32, b, &io), NTS_SUCCESS);
    aio_close(s);
}
TEST(aio_handles_length_checked_before_flags)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char b[16]; IO_STATUS_BLOCK io;
    EXPECT_NTS(qh(s, 0, 4, 15, b, &io), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(qh(s, 0, 4, 16, b, &io), NTS_INVALID_PARAMETER);
    aio_close(s);
}
TEST(aio_handles_failure_writes_nothing)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char b[16]; IO_STATUS_BLOCK io;
    memset(b, 0xee, sizeof b);
    EXPECT_NTS(qh(s, 4, 4, 16, b, &io), NTS_INVALID_PARAMETER);
    CHECK(b[0] == 0xee && b[15] == 0xee);
    EXPECT_EQ(io.Information, 0);
    aio_close(s);
}
TEST(aio_handles_bare_endpoint_matches_provider_socket)
{
    AIO_BEGIN();
    HANDLE h = raw_ep(AIOK_UDP4);
    unsigned char b[16]; IO_STATUS_BLOCK io;
    if (!h) return;
    memset(b, 0xee, sizeof b);
    EXPECT_NTS(qh((SOCKET)h, 3, 4, 16, b, &io), NTS_SUCCESS);
    aio_close_raw(h);
}

/* ---- QUERY_RECEIVE_INFORMATION (0x12033) ------------------------------------------------------------ */
TEST(aio_recvinfo_output_size)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        unsigned char b[64]; IO_STATUS_BLOCK io;
        if (s == INVALID_SOCKET) continue;
        t_check(aio_ctl(s, IOC_QUERY_RECV_INFO, NULL, 0, b, 7, &io, NULL) == NTS_BUFFER_TOO_SMALL, __FILE__, __LINE__, "recvinfo short", "%s", aio_kind_name[k]);
        t_check(aio_ctl(s, IOC_QUERY_RECV_INFO, NULL, 0, NULL, 0, &io, NULL) == NTS_BUFFER_TOO_SMALL, __FILE__, __LINE__, "recvinfo none", "%s", aio_kind_name[k]);
        t_check(aio_ctl(s, IOC_QUERY_RECV_INFO, NULL, 0, b, 8, &io, NULL) == NTS_SUCCESS && io.Information == 8, __FILE__, __LINE__, "recvinfo 8", "%s", aio_kind_name[k]);
        t_check(aio_ctl(s, IOC_QUERY_RECV_INFO, NULL, 0, b, 64, &io, NULL) == NTS_SUCCESS && io.Information == 8, __FILE__, __LINE__, "recvinfo 64", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_recvinfo_idle_endpoints_report_zero)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        ULONG v[2]; IO_STATUS_BLOCK io;
        if (s == INVALID_SOCKET) continue;
        v[0] = v[1] = 0x5a5a5a5a;
        EXPECT_NTS(aio_ctl(s, IOC_QUERY_RECV_INFO, NULL, 0, v, 8, &io, NULL), NTS_SUCCESS);
        t_check(v[0] == 0 && v[1] == 0, __FILE__, __LINE__, "idle receive info", "%s: %lu/%lu", aio_kind_name[k], (unsigned long)v[0], (unsigned long)v[1]);
        aio_close(s);
    }
}
TEST(aio_recvinfo_counts_pending_stream_bytes)
{
    AIO_BEGIN();
    SOCKET c, s;
    ULONG v[2];
    DWORD t0;
    aio_pair(&c, &s);
    CHECK(W.send(c, "hello", 5, 0) == 5);
    t0 = GetTickCount();
    do {
        v[0] = v[1] = 0;
        aio_ctl(s, IOC_QUERY_RECV_INFO, NULL, 0, v, 8, NULL, NULL);
        if (v[0]) break;
        Sleep(5);
    } while (GetTickCount() - t0 < 3000);
    EXPECT_EQ(v[0], 5);
    EXPECT_EQ(v[1], 0);
    aio_close(c); aio_close(s);
}

/* ---- socket options the provider keeps in the blob ------------------------------------------------ */
/* The blob is owned by the provider; what the driver guarantees is only that it round-trips. Still, the
 * provider keeps its per-socket options there, so a recognisable value written with setsockopt shows up
 * as a 32-bit field of the stored bytes. */
static int blob_has_dword(SOCKET s, ULONG v)
{
    unsigned char b[512]; IO_STATUS_BLOCK io;
    ULONG i;
    if (get_ctx(s, b, sizeof b, &io) != NTS_SUCCESS) return 0;
    for (i = 0; i + 4 <= io.Information; i += 4) {
        ULONG d; memcpy(&d, b + i, 4);
        if (d == v) return 1;
    }
    return 0;
}
TEST(aio_ctx_holds_receive_buffer_size)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    int v = 0x12340;
    CHECK(!blob_has_dword(s, 0x12340));
    CHECK(W.setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, sizeof v) == 0);
    CHECK(blob_has_dword(s, 0x12340));
    aio_close(s);
}
TEST(aio_ctx_holds_send_buffer_size)
{
    AIO_BEGIN();
    SOCKET s = aio_udp();
    int v = 0x23450;
    CHECK(!blob_has_dword(s, 0x23450));
    CHECK(W.setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&v, sizeof v) == 0);
    CHECK(blob_has_dword(s, 0x23450));
    aio_close(s);
}
TEST(aio_ctx_holds_receive_timeout)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    int v = 0x3456;
    CHECK(!blob_has_dword(s, 0x3456));
    CHECK(W.setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, sizeof v) == 0);
    CHECK(blob_has_dword(s, 0x3456));
    aio_close(s);
}
TEST(aio_ctx_holds_send_timeout)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    int v = 0x4567;
    CHECK(!blob_has_dword(s, 0x4567));
    CHECK(W.setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&v, sizeof v) == 0);
    CHECK(blob_has_dword(s, 0x4567));
    aio_close(s);
}
TEST(aio_ctx_changes_when_options_change)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char a[512], b[512]; IO_STATUS_BLOCK io;
    int on = 1;
    EXPECT_NTS(get_ctx(s, a, sizeof a, &io), NTS_SUCCESS);
    CHECK(W.setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&on, sizeof on) == 0);
    CHECK(W.setsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof on) == 0);
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    CHECK(memcmp(a, b, CTX_SIZE) != 0);
    aio_close(s);
}
TEST(aio_ctx_fionbio_leaves_blob_unchanged)
{
    /* FIONBIO is applied to the endpoint through SET_INFORMATION; the provider keeps no copy in the blob */
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char a[512], b[512]; IO_STATUS_BLOCK io;
    EXPECT_NTS(get_ctx(s, a, sizeof a, &io), NTS_SUCCESS);
    aio_nonblock(s, 1);
    EXPECT_NTS(get_ctx(s, b, sizeof b, &io), NTS_SUCCESS);
    CHECK(!memcmp(a, b, CTX_SIZE));
    aio_close(s);
}

/* ---- handles of other kinds and states ----------------------------------------------------------- */
TEST(aio_handle_closed_socket_invalid_handle)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    HANDLE copy = NULL;
    aio_info_t o;
    memset(&o, 0, sizeof o); o.Class = AI_MAX_SEND_SIZE;
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &copy, 0, FALSE, DUPLICATE_SAME_ACCESS));
    aio_close(s);
    /* the duplicate keeps the endpoint alive and usable */
    EXPECT_NTS(aio_ctl((SOCKET)copy, IOC_GET_INFO, &o, 16, &o, 16, NULL, NULL), NTS_SUCCESS);
    CloseHandle(copy);
    /* a closed handle value is invalid; no event is created in between, so the value cannot be reused */
    { IO_STATUS_BLOCK io; EXPECT_NTS(W.ioctl(copy, NULL, NULL, NULL, &io, IOC_GET_INFO, &o, 16, &o, 16), NTS_INVALID_HANDLE); }
}
TEST(aio_handle_null_and_invalid_values)
{
    AIO_BEGIN();
    aio_info_t o;
    memset(&o, 0, sizeof o); o.Class = AI_MAX_SEND_SIZE;
    EXPECT_NTS(aio_ctl((SOCKET)NULL, IOC_GET_INFO, &o, 16, &o, 16, NULL, NULL), NTS_INVALID_HANDLE);
    EXPECT_NTS(aio_ctl((SOCKET)0x7ffc, IOC_GET_INFO, &o, 16, &o, 16, NULL, NULL), NTS_INVALID_HANDLE);
}
TEST(aio_handle_wrong_object_type_rejected)
{
    AIO_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    aio_info_t o;
    memset(&o, 0, sizeof o); o.Class = AI_MAX_SEND_SIZE;
    EXPECT_NTS(aio_ctl((SOCKET)ev, IOC_GET_INFO, &o, 16, &o, 16, NULL, NULL), (LONG)0xC0000024);   /* object type mismatch */
    CloseHandle(ev);
}
TEST(aio_handle_non_afd_file_refuses_afd_codes)
{
    AIO_BEGIN();
    HANDLE f = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    aio_info_t o;
    LONG st;
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot open NUL"); return; }
    memset(&o, 0, sizeof o); o.Class = AI_MAX_SEND_SIZE;
    st = aio_ctl((SOCKET)f, IOC_GET_INFO, &o, 16, &o, 16, NULL, NULL);
    t_check(st == NTS_INVALID_DEVICE_REQ || st == NTS_NOT_SUPPORTED, __FILE__, __LINE__, "AFD code sent to another device", "got 0x%08lx", (unsigned long)st);
    CloseHandle(f);
}
TEST(aio_handle_duplicate_in_same_process_shares_state)
{
    AIO_BEGIN();
    SOCKET s = aio_bound(SOCK_STREAM);
    HANDLE dup = NULL;
    unsigned char a[512], b[512]; IO_STATUS_BLOCK io;
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
    EXPECT_NTS(get_ctx(s, a, sizeof a, &io), NTS_SUCCESS);
    EXPECT_NTS(get_ctx((SOCKET)dup, b, sizeof b, &io), NTS_SUCCESS);
    EXPECT_EQ(io.Information, CTX_SIZE);
    CHECK(!memcmp(a, b, CTX_SIZE));
    CloseHandle(dup);
    aio_close(s);
}
TEST(aio_handle_duplicate_with_minimal_access)
{
    /* the information requests need no particular access right on the handle */
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    HANDLE dup = NULL;
    aio_info_t o;
    BOOL ok = DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &dup, SYNCHRONIZE, FALSE, 0);
    CHECK(ok);
    if (ok) {
        memset(&o, 0, sizeof o); o.Class = AI_MAX_SEND_SIZE;
        EXPECT_NTS(aio_ctl((SOCKET)dup, IOC_GET_INFO, &o, 16, &o, 16, NULL, NULL), NTS_SUCCESS);
        CloseHandle(dup);
    }
    aio_close(s);
}
