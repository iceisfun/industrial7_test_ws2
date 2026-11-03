/* Measures the less common WSAIoctl controls: control codes the stream provider rejects, SIO_BASE_HANDLE,
 * SIO_GET_EXTENSION_FUNCTION_POINTER (known and unknown GUIDs), SIO_IDEAL_SEND_BACKLOG_QUERY and
 * SIO_ENABLE_CIRCULAR_QUEUEING.  Each is observed through the plain call, an overlapped call with a
 * completion port, and an overlapped call with a completion routine (APC). */
#include "lift07.h"

/* ---- control codes the provider does not implement -------------------- */
static const DWORD un_codes[] = {0xdeadbeef, FIOASYNC, 0x667e, SIO_FLUSH};

L7TEST(l07_ioctl_unsupported_needs_bytes_ptr_with_overlapped)
{
    unsigned i; int r; OVERLAPPED ov = {0}; SOCKET s;
    for (i = 0; i < 4; ++i) {
        s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        REQUIRE(s != INVALID_SOCKET);
        l7_seterr(L7_UNSET);
        r = l7_ioctl(s, un_codes[i], NULL, 0, NULL, 0, NULL, &ov, NULL);
        CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "code %#lx: r=%d err=%d", un_codes[i], r, l7_err());
        l7_close(s);
    }
}

L7TEST(l07_ioctl_unsupported_sync_is_opnotsupp)
{
    unsigned i; int r; DWORD size; SOCKET s;
    for (i = 0; i < 4; ++i) {
        s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        REQUIRE(s != INVALID_SOCKET);
        l7_seterr(L7_UNSET); size = L7_UNSET;
        r = l7_ioctl(s, un_codes[i], NULL, 0, NULL, 0, &size, NULL, NULL);
        CHECKF(r == SOCKET_ERROR && l7_err() == WSAEOPNOTSUPP, "code %#lx: r=%d err=%d", un_codes[i], r, l7_err());
        CHECKF(size == 0, "code %#lx: size %lu", un_codes[i], size);
        l7_close(s);
    }
}

L7TEST(l07_ioctl_unsupported_overlapped_completes_with_error_packet)
{
    /* The overlapped form reports "pending" to the caller and posts the failure to the completion port. */
    unsigned i; int r; DWORD size; OVERLAPPED ov = {0}; HANDLE port; SOCKET s;
    for (i = 0; i < 4; ++i) {
        s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        REQUIRE(s != INVALID_SOCKET);
        port = l7_port_for(s);
        l7_seterr(L7_UNSET); size = L7_UNSET; l7_ov_poison(&ov);
        r = l7_ioctl(s, un_codes[i], NULL, 0, NULL, 0, &size, &ov, NULL);
        CHECKF(r == SOCKET_ERROR && l7_err() == ERROR_IO_PENDING, "code %#lx: r=%d err=%d", un_codes[i], r, l7_err());
        CHECKF(size == L7_UNSET, "code %#lx: size %lu", un_codes[i], size);
        l7_expect_packet_unsupported(port, &ov, "unsupported control");
        CloseHandle(port);
        l7_close(s);
    }
}

L7TEST(l07_ioctl_unsupported_apc_receives_opnotsupp)
{
    unsigned i; int r; DWORD size; OVERLAPPED ov = {0}; SOCKET s;
    for (i = 0; i < 4; ++i) {
        s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        REQUIRE(s != INVALID_SOCKET);
        r = l7_ioctl(s, un_codes[i], NULL, 0, NULL, 0, NULL, &ov, l7_apc);
        CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "code %#lx without count: r=%d err=%d", un_codes[i], r, l7_err());
        l7_apc_reset(); size = L7_UNSET;
        r = l7_ioctl(s, un_codes[i], NULL, 0, NULL, 0, &size, &ov, l7_apc);
        CHECKF(r == SOCKET_ERROR && l7_err() == ERROR_IO_PENDING, "code %#lx: r=%d err=%d", un_codes[i], r, l7_err());
        CHECKF(size == L7_UNSET, "code %#lx: size %lu", un_codes[i], size);
        l7_expect_apc(&ov, WSAEOPNOTSUPP, "unsupported control");
        l7_close(s);
    }
}

/* ---- SIO_BASE_HANDLE ------------------------------------------------------ */
static const struct { int af, type, proto; } bh_cfg[] = {
    {AF_INET, SOCK_STREAM, IPPROTO_TCP}, {AF_INET, SOCK_DGRAM, IPPROTO_UDP},
    {AF_INET6, SOCK_STREAM, IPPROTO_TCP}, {AF_INET6, SOCK_DGRAM, IPPROTO_UDP},
};

L7TEST(l07_base_handle_sync_returns_same_handle)
{
    unsigned i; int r; DWORD size; SOCKET s, base;
    for (i = 0; i < 4; ++i) {
        s = l7_sock(bh_cfg[i].af, bh_cfg[i].type, bh_cfg[i].proto);
        if (s == INVALID_SOCKET) continue;
        l7_seterr(L7_UNSET); size = L7_UNSET; base = L7_UNSET;
        r = l7_ioctl(s, SIO_BASE_HANDLE, NULL, 0, &base, sizeof(base), &size, NULL, NULL);
        CHECKF(r == 0 && l7_err() == 0, "cfg %u: r=%d err=%d", i, r, l7_err());
        CHECKF(size == sizeof(base), "cfg %u: size %lu", i, size);
        CHECKF(base == s, "cfg %u: base differs from the socket", i);
        l7_close(s);
    }
}

L7TEST(l07_base_handle_overlapped_needs_bytes_ptr)
{
    unsigned i; int r; OVERLAPPED ov = {0}; SOCKET s, base;
    for (i = 0; i < 4; ++i) {
        s = l7_sock(bh_cfg[i].af, bh_cfg[i].type, bh_cfg[i].proto);
        if (s == INVALID_SOCKET) continue;
        l7_seterr(L7_UNSET);
        r = l7_ioctl(s, SIO_BASE_HANDLE, NULL, 0, &base, sizeof(base), NULL, &ov, NULL);
        CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "cfg %u: r=%d err=%d", i, r, l7_err());
        l7_close(s);
    }
}

L7TEST(l07_base_handle_overlapped_is_not_supported)
{
    /* Only the synchronous form is implemented: the overlapped form completes with "not supported" and
     * leaves the output untouched. */
    unsigned i; int r; DWORD size; OVERLAPPED ov = {0}; HANDLE port; SOCKET s, base;
    for (i = 0; i < 4; ++i) {
        s = l7_sock(bh_cfg[i].af, bh_cfg[i].type, bh_cfg[i].proto);
        if (s == INVALID_SOCKET) continue;
        port = l7_port_for(s);
        l7_seterr(L7_UNSET); size = L7_UNSET; base = L7_UNSET; l7_ov_poison(&ov);
        r = l7_ioctl(s, SIO_BASE_HANDLE, NULL, 0, &base, sizeof(base), &size, &ov, NULL);
        CHECKF(r == SOCKET_ERROR && l7_err() == ERROR_IO_PENDING, "cfg %u: r=%d err=%d", i, r, l7_err());
        CHECKF(size == L7_UNSET, "cfg %u: size %lu", i, size);
        l7_expect_packet_unsupported(port, &ov, "SIO_BASE_HANDLE");
        CHECKF(base == (SOCKET)L7_UNSET, "cfg %u: output was written", i);
        CloseHandle(port);
        l7_close(s);
    }
}

L7TEST(l07_base_handle_apc_receives_opnotsupp)
{
    unsigned i; int r; DWORD size; OVERLAPPED ov = {0}; SOCKET s, base;
    for (i = 0; i < 4; ++i) {
        s = l7_sock(bh_cfg[i].af, bh_cfg[i].type, bh_cfg[i].proto);
        if (s == INVALID_SOCKET) continue;
        r = l7_ioctl(s, SIO_BASE_HANDLE, NULL, 0, &base, sizeof(base), NULL, &ov, l7_apc);
        CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "cfg %u without count: r=%d err=%d", i, r, l7_err());
        l7_apc_reset(); size = L7_UNSET; base = L7_UNSET;
        r = l7_ioctl(s, SIO_BASE_HANDLE, NULL, 0, &base, sizeof(base), &size, &ov, l7_apc);
        CHECKF(r == SOCKET_ERROR && l7_err() == ERROR_IO_PENDING, "cfg %u: r=%d err=%d", i, r, l7_err());
        CHECKF(size == L7_UNSET, "cfg %u: size %lu", i, size);
        l7_expect_apc(&ov, WSAEOPNOTSUPP, "SIO_BASE_HANDLE");
        CHECKF(base == (SOCKET)L7_UNSET, "cfg %u: output was written", i);
        l7_close(s);
    }
}

/* ---- SIO_GET_EXTENSION_FUNCTION_POINTER ---------------------------------- */
L7TEST(l07_extfunc_overlapped_needs_bytes_ptr)
{
    GUID g = WSAID_ACCEPTEX; void *f; OVERLAPPED ov = {0}; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    l7_seterr(L7_UNSET);
    r = l7_ioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &f, sizeof(f), NULL, &ov, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "r=%d err=%d", r, l7_err());
    l7_close(s);
}

L7TEST(l07_extfunc_sync_lookup)
{
    GUID g = WSAID_ACCEPTEX; void *f = NULL; DWORD size = L7_UNSET; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    l7_seterr(L7_UNSET);
    r = l7_ioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &f, sizeof(f), &size, NULL, NULL);
    CHECKF(r == 0 && l7_err() == 0, "r=%d err=%d", r, l7_err());
    CHECKF(size == sizeof(f), "size %lu", size);
    CHECK(f != NULL);
    l7_close(s);
}

L7TEST(l07_extfunc_overlapped_inline_completion)
{
    GUID g = WSAID_ACCEPTEX; void *f = NULL; DWORD size = L7_UNSET; int r; OVERLAPPED ov = {0}; HANDLE port;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    port = l7_port_for(s);
    l7_seterr(L7_UNSET); l7_ov_poison(&ov);
    r = l7_ioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &f, sizeof(f), &size, &ov, NULL);
    CHECKF(r == 0 && l7_err() == 0, "r=%d err=%d", r, l7_err());
    CHECKF(size == sizeof(f), "size %lu", size);
    l7_expect_packet_ok(port, &ov, "extension lookup");
    CloseHandle(port);
    l7_close(s);
}

L7TEST(l07_extfunc_unknown_guid)
{
    /* An unknown GUID fails with WSAEINVAL before anything is queued: the overlapped structure and the byte
     * count are left alone and no completion packet appears. */
    GUID g = {0xdeadbeef, 0, 0, {0}}; void *f = NULL; DWORD size = L7_UNSET; int r;
    OVERLAPPED ov = {0}, *got = NULL; HANDLE port; ULONG_PTR key; DWORD n; BOOL q;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    port = l7_port_for(s);
    l7_ov_poison(&ov);
    r = l7_ioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &f, sizeof(f), &size, &ov, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEINVAL, "r=%d err=%d", r, l7_err());
    CHECKF(size == L7_UNSET, "size %lu", size);
    CHECKF(ov.Internal == L7_UNSET && ov.InternalHigh == L7_UNSET, "overlapped touched");
    q = GetQueuedCompletionStatus(port, &n, &key, &got, 0);
    CHECKF(!q && GetLastError() == WAIT_TIMEOUT, "packet queued (q=%d err=%lu)", q, GetLastError());
    CloseHandle(port);
    l7_close(s);
}

L7TEST(l07_extfunc_apc_delivery)
{
    GUID g = WSAID_ACCEPTEX; void *f = NULL; DWORD size = L7_UNSET; int r; OVERLAPPED ov = {0};
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    r = l7_ioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &f, sizeof(f), NULL, &ov, l7_apc);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "r=%d err=%d", r, l7_err());
    l7_apc_reset();
    r = l7_ioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &f, sizeof(f), &size, &ov, l7_apc);
    CHECKF(r == 0, "err=%d", l7_err());
    CHECKF(size == sizeof(f), "size %lu", size);
    l7_expect_apc(&ov, 0, "extension lookup");
    l7_close(s);
}

L7TEST(l07_extfunc_documented_guids_resolve)
{
    /* The extension functions Microsoft documents for TCP sockets must all be handed out. */
    GUID gs[] = {WSAID_ACCEPTEX, WSAID_CONNECTEX, WSAID_DISCONNECTEX, WSAID_GETACCEPTEXSOCKADDRS,
                 WSAID_TRANSMITFILE, WSAID_TRANSMITPACKETS, WSAID_WSARECVMSG};
    unsigned i; void *f; DWORD size; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    for (i = 0; i < sizeof(gs) / sizeof(gs[0]); ++i) {
        f = NULL; size = 0;
        r = l7_ioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &gs[i], sizeof(GUID), &f, sizeof(f), &size, NULL, NULL);
        CHECKF(r == 0 && f != NULL && size == sizeof(f), "guid %u: r=%d err=%d", i, r, l7_err());
    }
    l7_close(s);
}

/* ---- SIO_IDEAL_SEND_BACKLOG_QUERY / SIO_ENABLE_CIRCULAR_QUEUEING ----------- */
L7TEST(l07_backlog_query_unconnected_stream)
{
    ULONG backlog = 0; DWORD size; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    r = l7_ioctl(s, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, &backlog, sizeof(backlog), &size, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAENOTCONN, "r=%d err=%d", r, l7_err());
    l7_close(s);
}

L7TEST(l07_backlog_query_connected_stream)
{
    ULONG backlog = 0; DWORD size; int r;
    L7_PAIR(cl, sv);
    r = l7_ioctl(cl, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, &backlog, sizeof(backlog), &size, NULL, NULL);
    CHECKF(r == 0, "err=%d", l7_err());
    if (r == 0) {
        CHECKF(backlog == 0x10000, "backlog %#lx", backlog);
        t_note("ideal send backlog on a fresh loopback connection: %s", backlog == 0x10000 ? "64 KiB" : "other");
    }
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_backlog_query_datagram_unsupported)
{
    ULONG backlog = 0; DWORD size; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);
    r = l7_ioctl(s, SIO_IDEAL_SEND_BACKLOG_QUERY, NULL, 0, &backlog, sizeof(backlog), &size, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEOPNOTSUPP, "r=%d err=%d", r, l7_err());
    l7_close(s);
}

L7TEST(l07_circular_queueing_on_datagram)
{
    DWORD size; int r;
    SOCKET s = l7_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);
    r = l7_ioctl(s, SIO_ENABLE_CIRCULAR_QUEUEING, NULL, 0, NULL, 0, &size, NULL, NULL);
    CHECKF(r == 0, "err=%d", l7_err());
    l7_close(s);
}
